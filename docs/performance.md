# Performance

This document records the benchmark method for LLM-WAF so we can compare changes over time without guessing.

## What The Benchmark Measures

The current benchmark focuses on the gateway paths that matter for production readiness:

- Allowed OpenAI-compatible buffered requests
- Blocked OpenAI-compatible input requests
- OpenAI-compatible streaming requests
- Anthropic native buffered requests
- Anthropic native streaming requests

The benchmark runs in-process with a fake upstream provider, so it measures gateway overhead rather than provider latency or network jitter.

## How To Run It

```bash
python -B scripts/benchmark.py --iterations 50 --warmup 5
python -B scripts/benchmark.py --iterations 50 --warmup 5 --json
```

## Interpreting The Output

- `p50`, `p95`, and `p99` are end-to-end request timings through the gateway.
- `ttfb_p50` and `ttfb_p95` are first-byte timings for streaming cases.
- Because the benchmark uses a fake upstream, the numbers are useful for comparing code changes, not for estimating real provider latency.

## Local Baseline

The exact numbers will vary by machine, but the current in-process benchmark on the Codex desktop environment is:

| Case | p50 | p95 | p99 |
|---|---:|---:|---:|
| OpenAI buffered allowed | 31.79 ms | 38.57 ms | 39.06 ms |
| OpenAI input blocked | 23.98 ms | 25.82 ms | 26.79 ms |
| OpenAI streaming allowed | 42.98 ms | 52.83 ms | 53.36 ms |
| Anthropic buffered allowed | 32.58 ms | 38.60 ms | 39.20 ms |
| Anthropic streaming allowed | 46.42 ms | 49.24 ms | 50.44 ms |

Use this benchmark as a regression guard:

- buffered paths should not jump unexpectedly after scanner or audit changes
- streaming TTFB should stay bounded when `STREAM_HOLD_BACK_FRAMES=1`
- Anthropic and OpenAI-compatible paths should remain in the same latency class unless protocol-specific logic changes

When you change scanning, redaction, or streaming code, re-run the benchmark and compare the JSON output against the last known baseline in your branch or release note.
