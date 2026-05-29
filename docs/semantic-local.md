# Local Semantic Scanner

LLM-WAF can optionally run a local semantic prompt-injection classifier in addition to deterministic rules.

This feature is **default-off**. The base install does not include model runtime dependencies and does not download a model.

## Install

```bash
pip install "llm-waf[semantic]"
```

## Configure

```env
SEMANTIC_LOCAL=true
SEMANTIC_LOCAL_MODEL_PATH=/models/prompt-injection/model.onnx
SEMANTIC_LOCAL_TOKENIZER_PATH=/models/prompt-injection/tokenizer.json
SEMANTIC_LOCAL_THRESHOLD=0.85
SEMANTIC_LOCAL_ACTION=log_only
SEMANTIC_LOCAL_MAX_CHARS=4000
SEMANTIC_LOCAL_TIMEOUT_SECONDS=2.0
```

Start with `SEMANTIC_LOCAL_ACTION=log_only`. Review audit findings before switching input scanning to `block`.

## Model Contract

The ONNX adapter expects a binary text classifier exported with Hugging Face-style inputs:

- `input_ids`
- `attention_mask`
- optional `token_type_ids`

The positive prompt-injection class is expected at output index `1`. A single scalar output is treated as a probability if it is already in `[0, 1]`; otherwise it is passed through a sigmoid.

## Safety Defaults

- Long text is truncated to `SEMANTIC_LOCAL_MAX_CHARS`.
- Inference runs with `SEMANTIC_LOCAL_TIMEOUT_SECONDS`.
- Model errors use the existing gateway behavior:
    - `FAIL_CLOSED=false`: record scanner error and continue with deterministic findings.
    - `FAIL_CLOSED=true`: fail closed like other scanner failures.
- Output scanning currently records semantic findings as `log_only`; response rewriting remains handled by deterministic output redaction.

## Evaluation Slice

Use the checked-in regex-miss slice to measure whether a candidate semantic model actually improves WAF coverage beyond the deterministic rules:

```bash
python -B scripts/evaluate.py --direction input --dataset tests/eval_set_regex_miss.jsonl --show-misses
```

This dataset is not a default CI gate. It contains paraphrased instruction-priority attacks, multilingual attacks, and indirect-injection samples from RAG/tool-like text that conservative regex rules are expected to miss. Keep nearby benign hard negatives in the same file so model tuning does not hide a false-positive problem.

Before recommending a model, record the candidate name, license, model size, export format, and CPU p50/p95 latency here. Do not switch `SEMANTIC_LOCAL_ACTION=block` until the regex-miss slice and benign hard negatives have been reviewed against your own traffic.
