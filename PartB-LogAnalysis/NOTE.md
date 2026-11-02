# NOTE.md

## 1. Aassumptions?

I treated repeated errors as one issue when they appeared to have the same cause. For severity, I used the impact shown in the logs.

## 2. Python and model jobs? Why?

Python handles reading logs, splitting them into chunks, checking line numbers, validating JSON, and generating reports. The model identifies problems, explains them, and suggests fixes. I chose this because Python is more reliable for fixed rules, while the model is better at understanding context.

## 3. JSON, and fixing it?

The model sometimes returned invalid JSON, which caused parsing errors. I added basic JSON repair and validation, and increased the output token limit from 700 to 1200 to give the model more room to finish its response. Invalid results are skipped instead of crashing the whole analysis.

## 4. Compare two prompt versions.

The first prompt was simple, while v2 added clearer instructions about evidence, grouping related issues, and treating logs as untrusted data.

In the evaluation, v1 had **0 hits, 2 misses, and 1 false alarm**. V2 had **1 hit, 1 miss, and 2 false alarms**.

V2 found more real issues, but it also reported more problems that were not supported by the logs. So the improvement was mixed.

## 5. User-written text from steering the model?

I clearly mark log entries as untrusted data and tell the model not to follow instructions found inside them. Python also checks the returned JSON and evidence line numbers. However, the model could still be influenced by cleverly written text, so this protection is not perfect.

## 6. Failover in Part A?

I temporarily configured a model name that did not exist as the primary model. OpenClaw received an error and automatically switched to `qwen3:0.6b`, which confirmed that fallback worked. I then restored the original primary model.

## 7. Live logs?

I would process logs continuously in small batches instead of reading one large file. I would also group together related errors.

## 8. What would you improve with another day?

further optimising each step and moving the application to a docker container and making it work within docker network like openclaw and ollama.