# Threat Model and Non-Goals

LLM-WAF is a zero-intrusion gateway WAF for OpenAI-compatible traffic. It is
designed to reduce risk from prompt injection, sensitive-data leakage, unsafe
tool output, and policy violations without requiring application code changes.

## What It Defends Against

- direct prompt injection in user messages
- obvious indirect injection in tool output or retrieved text
- accidental secret or PII leakage in requests and responses
- policy violations that can be detected before or after the upstream call
- audit blindness, by keeping request decisions and findings visible

## What It Does Not Defend Against

- a fully compromised upstream model or provider
- attacks that are already committed by the application before traffic reaches
  the gateway
- every semantic bypass, especially when the attack is intentionally novel or
  highly obfuscated
- payloads that have already left the gateway in a streaming response before a
  later chunk triggers a detection
- unsafe downstream actions performed by tools outside the gateway's control

## Operational Assumptions

- the gateway sits on the request path for the traffic it is meant to protect
- operators keep rules, eval sets, and policies current for their domain
- secret redaction is validated in the deployment path, not assumed
- streaming hold-back settings are chosen with the application's leakage risk
  and latency budget in mind

## Practical Boundary

The project aims to make common attacks visible and expensive, not to promise
perfect semantic safety. That is deliberate: the gateway is a firewall-like
control plane, not a substitute for application trust boundaries, model
hardening, or downstream authorization.
