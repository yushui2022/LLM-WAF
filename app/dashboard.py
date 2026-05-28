"""Minimal built-in dashboard."""

from __future__ import annotations

from collections import Counter
from html import escape
from typing import Any


def render_dashboard(events: list[dict[str, Any]]) -> str:
    recent = list(reversed(events))
    stats = Counter(event.get("decision", "unknown") for event in events)
    total = len(events)
    findings = sum(int(event.get("finding_count", 0)) for event in events)
    tokens = sum(_total_tokens(event) for event in events)
    total_cost = sum(_total_cost(event) for event in events)

    rows = "\n".join(_render_row(event) for event in recent)
    if not rows:
        rows = '<tr><td colspan="11" class="empty">No requests yet. Send traffic through /v1/chat/completions.</td></tr>'

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta http-equiv="refresh" content="10">
  <title>LLM-WAF Dashboard</title>
  <style>
    :root {{ color-scheme: light; --border:#d7dee8; --muted:#627083; --bg:#f6f8fb; --ink:#182230; }}
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Arial, sans-serif; background: var(--bg); color: var(--ink); }}
    header {{ padding: 24px 28px 14px; background: #fff; border-bottom: 1px solid var(--border); }}
    h1 {{ margin: 0 0 6px; font-size: 24px; letter-spacing: 0; }}
    .sub {{ color: var(--muted); font-size: 14px; }}
    main {{ padding: 22px 28px 32px; }}
    .stats {{ display: grid; grid-template-columns: repeat(7, minmax(130px, 1fr)); gap: 12px; margin-bottom: 18px; }}
    .stat {{ background: #fff; border: 1px solid var(--border); border-radius: 8px; padding: 14px; }}
    .label {{ color: var(--muted); font-size: 12px; text-transform: uppercase; }}
    .value {{ font-size: 28px; font-weight: 700; margin-top: 4px; }}
    table {{ width: 100%; border-collapse: collapse; background: #fff; border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }}
    th, td {{ padding: 10px 12px; border-bottom: 1px solid var(--border); text-align: left; font-size: 13px; vertical-align: top; }}
    th {{ background: #eef2f7; color: #334155; font-weight: 700; }}
    tr:last-child td {{ border-bottom: 0; }}
    code {{ font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: 12px; }}
    .pill {{ display: inline-block; border-radius: 999px; padding: 3px 8px; font-size: 12px; font-weight: 700; }}
    .allowed {{ background: #e7f7ed; color: #17633a; }}
    .redacted {{ background: #fff3d9; color: #7a4b00; }}
    .blocked {{ background: #ffe5e5; color: #9d1c1c; }}
    .error {{ background: #eceff3; color: #4b5563; }}
    .empty {{ color: var(--muted); text-align: center; padding: 28px; }}
    .findings {{ max-width: 360px; color: #334155; }}
    @media (max-width: 900px) {{
      .stats {{ grid-template-columns: repeat(2, minmax(130px, 1fr)); }}
      table {{ display: block; overflow-x: auto; }}
    }}
  </style>
</head>
<body>
  <header>
    <h1>LLM-WAF Dashboard</h1>
    <div class="sub">Auto-refreshes every 10 seconds. Shows the most recent audited requests.</div>
  </header>
  <main>
    <section class="stats">
      {_stat("Requests", total)}
      {_stat("Allowed", stats.get("allowed", 0))}
      {_stat("Redacted", stats.get("redacted", 0))}
      {_stat("Blocked", stats.get("blocked", 0))}
      {_stat("Findings", findings)}
      {_stat("Tokens", tokens)}
      {_stat("Cost", _format_cost(total_cost))}
    </section>
    <table>
      <thead>
        <tr>
          <th>Time</th>
          <th>Decision</th>
          <th>Model</th>
          <th>Principal</th>
          <th>Stream</th>
          <th>Status</th>
          <th>Tokens</th>
          <th>Cost</th>
          <th>Latency</th>
          <th>Trace</th>
          <th>Findings</th>
        </tr>
      </thead>
      <tbody>{rows}</tbody>
    </table>
  </main>
</body>
</html>"""


def _stat(label: str, value: int) -> str:
    return f'<div class="stat"><div class="label">{escape(label)}</div><div class="value">{value}</div></div>'


def _render_row(event: dict[str, Any]) -> str:
    decision = escape(str(event.get("decision", "unknown")))
    status = escape(str(event.get("upstream_status", event.get("status_code", ""))))
    trace_id = escape(str(event.get("trace_id", "")))
    model = escape(str(event.get("model", "")))
    principal = escape(str(event.get("principal", "anonymous")))
    stream = "yes" if event.get("stream") else "no"
    tokens = _total_tokens(event)
    cost = _total_cost(event)
    latency = event.get("latency_ms")
    latency_text = "" if latency is None else f"{latency} ms"
    findings = event.get("findings", []) or []
    finding_text = "<br>".join(
        f"<code>{escape(str(f.get('rule_id', '')))}</code>: {escape(str(f.get('evidence', '')))}"
        for f in findings[:3]
    )
    if len(findings) > 3:
        finding_text += f"<br>+{len(findings) - 3} more"

    return f"""<tr>
      <td>{escape(str(event.get("ts", "")))}</td>
      <td><span class="pill {decision}">{decision}</span></td>
      <td>{model}</td>
      <td><code>{principal}</code></td>
      <td>{stream}</td>
      <td>{status}</td>
      <td>{tokens or ""}</td>
      <td>{escape(_format_cost(cost)) if cost else ""}</td>
      <td>{escape(latency_text)}</td>
      <td><code>{trace_id[:12]}</code></td>
      <td class="findings">{finding_text}</td>
    </tr>"""


def _total_tokens(event: dict[str, Any]) -> int:
    usage = event.get("usage")
    if not isinstance(usage, dict):
        return 0
    value = usage.get("total_tokens")
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    prompt = usage.get("prompt_tokens")
    completion = usage.get("completion_tokens")
    if isinstance(prompt, int) and isinstance(completion, int):
        return prompt + completion
    return 0


def _total_cost(event: dict[str, Any]) -> float:
    cost = event.get("cost")
    if not isinstance(cost, dict):
        return 0.0
    value = cost.get("total_cost")
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return 0.0
    return 0.0


def _format_cost(value: float) -> str:
    if value <= 0:
        return "$0"
    if value < 0.01:
        return f"${value:.6f}"
    return f"${value:.4f}"
