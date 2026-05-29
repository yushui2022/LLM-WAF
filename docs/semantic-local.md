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
