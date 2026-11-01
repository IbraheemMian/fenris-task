"""Local-only application log analysis. No agents, hosted APIs or frameworks."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

import requests

DEFAULT_MODEL = "qwen3:1.7b"
DEFAULT_URL = "http://127.0.0.1:11434"
SEVERITIES = ("low", "medium", "high", "critical")
FIELDS = {"id", "category", "severity", "title", "evidence", "affected", "explanation", "next_step"}
PROMPT_DIR = Path(__file__).resolve().parent / "prompts"
# The Ollama JSON schema controls shape; Python validates evidence and semantics separately.
MODEL_FORMAT = {
    "type": "object", "additionalProperties": False,
    "properties": {"findings": {"type": "array", "maxItems": 8, "items": {
        "type": "object", "additionalProperties": False,
        "properties": {
            "category": {"type": "string", "enum": ["technical", "ux"]},
            "severity": {"type": "string", "enum": list(SEVERITIES)},
            "title": {"type": "string"},
            "evidence": {"type": "array", "items": {"type": "integer"}, "minItems": 1},
            "affected": {"type": "string"},
            "explanation": {"type": "string"},
            "next_step": {"type": "string"},
        },
        "required": ["category", "severity", "title", "evidence", "affected", "explanation", "next_step"]
    }}}, "required": ["findings"]
}
EVENT_RE = re.compile(r"^\s*(?:\[?\d{4}-\d\d-\d\d[ T]\d\d:\d\d:\d\d|\d\d:\d\d:\d\d|\[?(?:DEBUG|INFO|WARN|WARNING|ERROR|FATAL|CRITICAL)\b)", re.I)
SIGNAL_RE = re.compile(r"\b(?:error|exception|failed|failure|timeout|timed out|latency|slow|retry|retries|crash|oom|out.of.memory|memory|cpu|disk|denied|unauthorized|forbidden|429|500|502|503|504|tap|click|abandon|cancel|feedback|unresponsive|stuck|login|checkout|payment|security|warn|warning)\b", re.I)
# Evidence must be independently suggestive of the claim; generic tokens are insufficient.
TECH_RE = re.compile(r"\b(?:error|exception|failed|failure|timeout|timed out|crash|oom|out.of.memory|cpu|disk|denied|unauthorized|forbidden|429|5\d\d|memory|latency|warning|warn)\b", re.I)
UX_RE = re.compile(r"\b(?:retry|retries|tap|click|abandon|cancel|feedback|screen|loading|slow|timeout|timed out|error|failed|failure|frustrat|stuck|checkout|login|payment|unable|unfinished)\b", re.I)
SENSITIVE_RE = [
    (re.compile(r"(?i)\b(?:email|e-mail)\s*[=:]\s*[^\s,;]+"), "email=[REDACTED]"),
    (re.compile(r"(?i)\b[\w.+-]+@[\w.-]+\.[A-Z]{2,}\b"), "[EMAIL]"),
    (re.compile(r"(?i)\b(?:password|passwd|token|api[_-]?key|authorization|cookie|session[_-]?id|user[_-]?id|device[_-]?id|ip)\s*[=:]\s*[^\s,;]+"), "[PRIVATE_FIELD]"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "[IP]"),
]

def redact(text: str) -> str:
    for pattern, replacement in SENSITIVE_RE:
        text = pattern.sub(replacement, text)
    return text


def load_lines(path: Path) -> list[str]:
    if not path.is_file():
        raise FileNotFoundError(f"Log file not found: {path}. Provide an existing app_logs.txt path.")
    return path.read_text(encoding="utf-8", errors="replace").splitlines()


def split_events(lines: list[str]) -> list[list[int]]:
    """Keep timestamped entries with their multiline stack-trace continuations."""
    groups: list[list[int]] = []
    for number, line in enumerate(lines, 1):
        if not groups or EVENT_RE.match(line):
            groups.append([number])
        else:
            groups[-1].append(number)
    return groups


def make_windows(lines: list[str], max_lines: int = 50, overlap: int = 8) -> list[list[int]]:
    """Bound context while preserving multiline events when practical."""
    if max_lines < 2 or overlap < 0 or overlap >= max_lines:
        raise ValueError("Require max_lines >= 2 and 0 <= overlap < max_lines")
    events = split_events(lines)
    if not events:
        return []
    windows: list[list[int]] = []
    current: list[int] = []
    for event in events:
        if len(event) > max_lines:
            if current:
                windows.append(current)
                current = []
            for start in range(0, len(event), max_lines):
                windows.append(event[start:start + max_lines])
            continue
        if current and len(current) + len(event) > max_lines:
            windows.append(current)
            # Carry recent complete events where feasible, never repeat an identical window.
            tail: list[int] = []
            for prior in reversed(split_window_events(current, lines)):
                if len(tail) + len(prior) > min(overlap, max_lines - len(event)):
                    break
                tail = prior + tail
            current = tail
        current.extend(event)
    if current and (not windows or current != windows[-1]):
        windows.append(current)
    return windows


def split_window_events(numbers: list[int], lines: list[str]) -> list[list[int]]:
    groups: list[list[int]] = []
    for number in numbers:
        if not groups or EVENT_RE.match(lines[number - 1]):
            groups.append([number])
        else:
            groups[-1].append(number)
    return groups


def candidate_windows(lines: list[str], max_lines: int, overlap: int) -> list[list[int]]:
    """Plain Python filters uninteresting windows, but preserves neighboring context."""
    return [w for w in make_windows(lines, max_lines, overlap)
            if any(SIGNAL_RE.search(lines[i - 1]) for i in w)]


def repair_json(raw: str) -> dict:
    """Repair common wrappers/trailing commas. Never execute model output."""
    raw = raw.strip().removeprefix("\ufeff")
    if raw.startswith("```"):
        raw = re.sub(r"^```(?:json)?\s*", "", raw, flags=re.I)
        raw = re.sub(r"\s*```$", "", raw)
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        start = raw.find("{")
        end = raw.rfind("}")
        if start < 0 or end <= start:
            raise ValueError("Model did not return a JSON object") from None
        subset = raw[start:end + 1]
        subset = re.sub(r",\s*([}\]])", r"\1", subset)
        try:
            parsed = json.loads(subset)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid model JSON: {exc.msg}") from exc
    if isinstance(parsed, list):
        parsed = {"findings": parsed}
    if not isinstance(parsed, dict) or not isinstance(parsed.get("findings"), list):
        raise ValueError("Expected JSON object with a findings array")
    return parsed


def validate_finding(item: dict, lines: list[str], allowed: set[int]) -> dict:
    """Fail closed for schema, references, and coarse content relevance."""
    if not isinstance(item, dict):
        raise ValueError("Finding is not an object")
    # IDs are assigned by Python after merging; the model cannot choose them.
    item = {k: v for k, v in item.items() if k != "id"}
    required = FIELDS - {"id"}
    if set(item) != required:
        raise ValueError(f"Finding fields must be exactly {sorted(required)}")
    if item["category"] not in ("technical", "ux") or item["severity"] not in SEVERITIES:
        raise ValueError("Invalid category or severity")
    for field in ("title", "affected", "explanation", "next_step"):
        if not isinstance(item[field], str) or not item[field].strip() or len(item[field]) > 500:
            raise ValueError(f"Invalid {field}")
    if "\n" in item["title"] or "\n" in item["next_step"]:
        raise ValueError("Title and next_step must be single-line")
    if len(re.split(r"(?<=[.!?])\s+", item["explanation"].strip())) > 3:
        raise ValueError("Explanation must have at most three sentences")
    evidence = item["evidence"]
    if not isinstance(evidence, list) or not evidence or len(evidence) > 12 or any(type(n) is not int for n in evidence):
        raise ValueError("Evidence must be nonempty integer line numbers")
    if any(n not in allowed or n < 1 or n > len(lines) for n in evidence):
        raise ValueError("Evidence line does not exist or is outside the analyzed window")
    cited_text = " ".join(lines[n - 1] for n in evidence)
    signal = TECH_RE if item["category"] == "technical" else UX_RE
    if not signal.search(cited_text):
        raise ValueError("Evidence does not contain a relevant technical/UX signal")
    # This semantic screen is deliberately conservative; manual evaluation is still required.
    item["evidence"] = sorted(set(evidence))
    return item


def deduplicate(items: list[dict]) -> list[dict]:
    """Merge overlapping windows for same-category related evidence; retain both categories."""
    merged: list[dict] = []
    for item in items:
        evidence = set(item["evidence"])
        match = next((old for old in merged if old["category"] == item["category"] and
                      (evidence & set(old["evidence"]) or
                       (item["title"].casefold().strip() == old["title"].casefold().strip() and
                        min(abs(a-b) for a in evidence for b in old["evidence"]) <= 8))), None)
        if match:
            match["evidence"] = sorted(evidence | set(match["evidence"]))[:12]
            if SEVERITIES.index(item["severity"]) > SEVERITIES.index(match["severity"]):
                match["severity"] = item["severity"]
        else:
            merged.append(dict(item))
    merged.sort(key=lambda f: (-SEVERITIES.index(f["severity"]), min(f["evidence"])))
    for i, item in enumerate(merged, 1):
        item["id"] = f"F{i:03d}"
    return merged


def build_prompt(template: str, numbers: list[int], lines: list[str]) -> str:
    excerpt = "\n".join(f"L{n}: {redact(lines[n-1])[:500]}" for n in numbers)
    return template.replace("{{LOG_WINDOW}}", excerpt)


class OllamaClient:
    def __init__(self, url: str, model: str, *, timeout: int = 240, seed: int = 42,
                 temperature: float = 0, num_ctx: int = 4096):
        self.url, self.model = url.rstrip("/"), model
        self.timeout, self.seed, self.temperature, self.num_ctx = timeout, seed, temperature, num_ctx

    def check(self) -> None:
        try:
            response = requests.get(f"{self.url}/api/tags", timeout=8)
            response.raise_for_status()
            available = {entry.get("name") for entry in response.json().get("models", [])}
        except requests.RequestException as exc:
            raise RuntimeError(f"Cannot reach local Ollama at {self.url}; start the Ollama container. {exc}") from exc
        if self.model not in available:
            raise RuntimeError(f"Model '{self.model}' not installed. Run: docker exec ollama ollama pull {self.model}")

    def complete(self, prompt: str) -> str:
        payload = {
            "model": self.model, "stream": False, "think": False,
            "messages": [{"role": "user", "content": prompt}],
            "format": MODEL_FORMAT,
            "options": {"temperature": self.temperature, "seed": self.seed,
                        "num_ctx": self.num_ctx, "num_predict": 1200},
            "keep_alive": "2m",
        }
        try:
            response = requests.post(f"{self.url}/api/chat", json=payload, timeout=self.timeout)
            response.raise_for_status()
            return response.json()["message"]["content"]
        except (requests.RequestException, KeyError, ValueError) as exc:
            raise RuntimeError(f"Local Ollama request failed: {exc}") from exc


def analyze(lines: list[str], model_call: Callable[[str], str], *, prompt_version: str = "v2",
            max_lines: int = 40, overlap: int = 8, progress: Callable[[str], None] | None = None) -> tuple[list[dict], list[str]]:
    template_path = PROMPT_DIR / f"{prompt_version}.txt"
    if not template_path.is_file():
        raise ValueError(f"Prompt not found: {template_path}")
    template = template_path.read_text(encoding="utf-8")
    windows = candidate_windows(lines, max_lines, overlap)
    all_findings: list[dict] = []
    warnings: list[str] = []
    for index, window in enumerate(windows, 1):
        if progress:
            progress(f"Window {index}/{len(windows)}: lines {window[0]}–{window[-1]}")
        prompt = build_prompt(template, window, lines)
        try:
            response = repair_json(model_call(prompt))
            for candidate in response["findings"][:8]:
                try:
                    all_findings.append(validate_finding(candidate, lines, set(window)))
                except ValueError as exc:
                    warnings.append(f"Window {index}: discarded finding: {exc}")
        except (RuntimeError, ValueError) as exc:
            warnings.append(f"Window {index}: no usable model response: {exc}")
    return deduplicate(all_findings), warnings


def write_outputs(out: Path, findings: list[dict], warnings: list[str], *,
                  source: Path, model: str, version: str, max_lines: int, overlap: int,
                  seed: int, temperature: float, num_ctx: int) -> None:
    out.mkdir(parents=True, exist_ok=True)
    # findings.json is exactly the requested list. Provenance is in the separate metadata file.
    (out / "findings.json").write_text(json.dumps(findings, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    metadata = {
        "source_file": source.name, "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "model": model, "prompt_version": version,
        "prompt_sha256": hashlib.sha256((PROMPT_DIR / f"{version}.txt").read_bytes()).hexdigest(),
        "temperature": temperature, "seed": seed, "num_ctx": num_ctx,
        "window_max_lines": max_lines, "window_overlap": overlap,
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "findings_count": len(findings), "warnings": warnings,
    }
    (out / "run_metadata.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    labels = Counter(f["category"] for f in findings)
    report = ["# Daily application log report", "", f"**Findings:** {len(findings)} ({labels['technical']} technical, {labels['ux']} UX).", "",
              "Findings are model-assisted and require review; severity is indicative.", ""]
    # Avoid copying personal data: only short redacted titles, sanitized explanations and actions.
    for f in findings[:12]:
        title = redact(f["title"].replace("\n", " "))[:100]
        explanation = redact(f["explanation"].replace("\n", " "))[:190]
        step = redact(f["next_step"].replace("\n", " "))[:140]
        report.extend([f"## {f['severity'].upper()} — {title} ({f['category']})",
                       f"Lines: {', '.join(map(str, f['evidence']))}.", explanation,
                       f"Next: {step}", ""])
    if len(findings) > 12:
        report.append(f"_Additional {len(findings) - 12} findings in findings.json._")
    (out / "report.md").write_text("\n".join(report).rstrip() + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Local-only Ollama log analyzer")
    parser.add_argument("logfile", type=Path, help="Input app_logs.txt")
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--url", default=DEFAULT_URL)
    parser.add_argument("--out", type=Path, default=Path("output"))
    parser.add_argument("--prompt", choices=["v1", "v2"], default="v2")
    parser.add_argument("--window-lines", type=int, default=40)
    parser.add_argument("--overlap", type=int, default=8)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--temperature", type=float, default=0)
    parser.add_argument("--num-ctx", type=int, default=4096)
    args = parser.parse_args(argv)
    try:
        lines = load_lines(args.logfile)
        client = OllamaClient(args.url, args.model, seed=args.seed,
                              temperature=args.temperature, num_ctx=args.num_ctx)
        client.check()
        print(f"Analyzing {len(lines)} lines with {args.model} (prompt {args.prompt})", flush=True)
        started = time.monotonic()
        findings, warnings = analyze(lines, client.complete, prompt_version=args.prompt,
                                     max_lines=args.window_lines, overlap=args.overlap,
                                     progress=lambda s: print(s, flush=True))
        write_outputs(args.out, findings, warnings, source=args.logfile, model=args.model,
                      version=args.prompt, max_lines=args.window_lines, overlap=args.overlap,
                      seed=args.seed, temperature=args.temperature, num_ctx=args.num_ctx)
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    counts = Counter(f["category"] for f in findings)
    print(f"Done in {time.monotonic()-started:.1f}s: {len(findings)} findings "
          f"({counts['technical']} technical, {counts['ux']} UX), {len(warnings)} warnings.")
    print(f"Written: {args.out / 'findings.json'}, {args.out / 'report.md'}, {args.out / 'run_metadata.json'}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
