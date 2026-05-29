# Security Policy

## Reporting Security Issues

Use a private GitHub Security Advisory for vulnerabilities that may affect
customers, deployed gateways, rule quality, or secret handling.

Do not open a public issue for:

- prompt-injection bypasses
- false negatives that can be reproduced on real payloads
- secret redaction regressions
- audit/logging leaks
- remote code execution, SSRF, or request-smuggling findings

If GitHub Security Advisories are unavailable in your environment, file a
private issue titled `SECURITY` and include:

- affected version or commit
- attack path and reproduction steps
- expected vs. observed behavior
- whether the issue leaks prompts, secrets, or audit data

## Response Expectations

We aim to acknowledge confirmed reports quickly and publish a fix before public
disclosure when the issue is exploitable in a live deployment.

## Supported Versions

- `main`
- the latest tagged release

Security fixes are applied to the current line first. Backports depend on the
severity and whether the issue affects released builds.
