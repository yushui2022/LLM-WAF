#!/usr/bin/env bash
set -euo pipefail

curl -N http://localhost:8080/v1/chat/completions \
  -H "content-type: application/json" \
  -d '{
    "model": "gpt-4o-mini",
    "stream": true,
    "messages": [
      {"role": "user", "content": "Write a short hello message."}
    ]
  }'

