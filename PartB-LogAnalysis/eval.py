"""Local evaluation: prepare three labeled windows, then score v1 against v2."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
from analyzer import OllamaClient, analyze, load_lines, make_windows


def scaffold(lines: list[str], destination: Path, count: int = 3, size: int = 40) -> None:
    """Create windows from the REAL log; do not fabricate ground truth."""
    windows = make_windows(lines, size, overlap=0)
    if len(windows) < count:
        raise ValueError(f"Need at least {count} windows of 20–80 lines; file provides {len(windows)}")
    candidates = [w for w in windows if 20 <= len(w) <= 80]
    if len(candidates) < count:
        raise ValueError("Need at least 3 windows of 20–80 real lines")
    # Spread across the log; reproducible indexes.
    positions = [round(i * (len(candidates) - 1) / (count - 1)) for i in range(count)]
    destination.mkdir(parents=True, exist_ok=True)
    manifest = []
    for i, pos in enumerate(positions, 1):
        nums = candidates[pos]
        name = f"window_{i}"
        (destination / f"{name}.txt").write_text("\n".join(f"L{n}: {lines[n-1]}" for n in nums) + "\n", encoding="utf-8")
        # Human must inspect, label and justify issues by hand; blank labels are not evaluation.
        manifest.append({"window": name, "start_line": nums[0], "end_line": nums[-1],
                         "gold": [], "labeled_by_human": False})
    (destination / "gold.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"Created {count} real windows and gold.json in {destination}. Label gold.json manually before evaluating.")


def compare(predictions: list[dict], gold: list[dict]) -> dict:
    """Category + overlapping cited evidence = one-to-one match. Manual review recommended."""
    matched = set()
    hits, false_alarms = [], []
    for found in predictions:
        target = next((i for i, expected in enumerate(gold) if i not in matched
                       and found["category"] == expected["category"]
                       and set(found["evidence"]) & set(expected["evidence"])), None)
        if target is None:
            false_alarms.append({"title": found["title"], "evidence": found["evidence"],
                                 "category": found["category"]})
        else:
            matched.add(target)
            hits.append({"title": gold[target]["title"], "category": gold[target]["category"]})
    misses = [g for i, g in enumerate(gold) if i not in matched]
    return {"hits": hits, "misses": misses, "false_alarms": false_alarms,
            "counts": {"hits": len(hits), "misses": len(misses), "false_alarms": len(false_alarms)}}


def main() -> int:
    p = argparse.ArgumentParser(description="Compare local model prompts with hand-labeled log windows")
    p.add_argument("logfile", type=Path)
    p.add_argument("--prepare", action="store_true", help="Create real 20–80 line windows for manual labeling")
    p.add_argument("--eval-dir", type=Path, default=Path("eval_data"))
    p.add_argument("--model", default="qwen3:1.7b")
    p.add_argument("--url", default="http://127.0.0.1:11434")
    p.add_argument("--out", type=Path, default=Path("output") / "evaluation.json")
    args = p.parse_args()
    try:
        lines = load_lines(args.logfile)
        if args.prepare:
            scaffold(lines, args.eval_dir)
            return 0
        labels = json.loads((args.eval_dir / "gold.json").read_text(encoding="utf-8"))
        if len(labels) < 3 or not all(row.get("labeled_by_human") for row in labels):
            raise ValueError("Complete the human labels in eval_data/gold.json for at least three windows")
        client = OllamaClient(args.url, args.model)
        client.check()
        results = {}
        for version in ("v1", "v2"):
            total = {"hits": 0, "misses": 0, "false_alarms": 0}
            details = []
            for row in labels:
                begin, end = row["start_line"], row["end_line"]
                if not (1 <= begin <= end <= len(lines) and 20 <= end - begin + 1 <= 80):
                    raise ValueError("Invalid evaluation window range")
                window = lines[begin-1:end]
                # Preserve ORIGINAL line numbers even though analyzing a subset.
                virtual_lines = [""] * (begin - 1) + window
                predicted, warnings = analyze(virtual_lines, client.complete, prompt_version=version,
                                               max_lines=80, overlap=0,
                                               progress=lambda msg: print(f"{version} {row['window']} {msg}", flush=True))
                comparison = compare(predicted, row["gold"])
                for key in total:
                    total[key] += comparison["counts"][key]
                details.append({"window": row["window"], **comparison, "warnings": warnings})
            results[version] = {"totals": total, "windows": details}
            print(f"{version}: hits={total['hits']}, misses={total['misses']}, false alarms={total['false_alarms']}")
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps({"model": args.model, "results": results}, indent=2) + "\n", encoding="utf-8")
        print(f"Evaluation saved to {args.out}")
        return 0
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        p.exit(1, f"Error: {exc}\n")

if __name__ == "__main__":
    raise SystemExit(main())
