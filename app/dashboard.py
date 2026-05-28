"""Minimal built-in dashboard."""

from __future__ import annotations

from collections import Counter
from html import escape
from typing import Any


def render_dashboard(events: list[dict[str, Any]], filters: dict[str, str] | None = None) -> str:
    active_filters = _normalize_filters(filters)
    filtered_events = _filter_events(events, active_filters)
    recent = list(reversed(filtered_events))
    stats = Counter(event.get("decision", "unknown") for event in filtered_events)
    total = len(filtered_events)
    findings = sum(int(event.get("finding_count", 0)) for event in filtered_events)
    tokens = sum(_total_tokens(event) for event in filtered_events)
    total_cost = sum(_total_cost(event) for event in filtered_events)

    rows = "\n".join(_render_row(event) for event in recent)
    if not rows:
        rows = '<tr><td colspan="11" class="empty">No matching requests. Adjust filters or send traffic through /v1/chat/completions.</td></tr>'

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
    .filters {{ display: flex; flex-wrap: wrap; gap: 12px; align-items: end; margin-bottom: 18px; padding: 14px; background: #fff; border: 1px solid var(--border); border-radius: 8px; }}
    .field {{ display: grid; gap: 4px; }}
    label {{ color: var(--muted); font-size: 12px; text-transform: uppercase; }}
    select {{ min-width: 150px; padding: 7px 9px; border: 1px solid var(--border); border-radius: 6px; background: #fff; color: var(--ink); }}
    button, .clear {{ padding: 8px 11px; border: 1px solid var(--border); border-radius: 6px; background: #182230; color: #fff; font-weight: 700; text-decoration: none; }}
    .clear {{ background: #fff; color: #334155; }}
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
    .finding {{ margin: 0 0 8px; }}
    .evidence {{ margin-top: 2px; color: var(--muted); }}
    .tags {{ margin: 0 0 8px; }}
    .tag {{ display: inline-block; border: 1px solid var(--border); border-radius: 999px; padding: 2px 7px; margin: 0 4px 4px 0; background: #f8fafc; color: #334155; font-size: 11px; }}
    .tag.critical {{ border-color: #f0b4b4; background: #ffe5e5; color: #9d1c1c; }}
    .tag.high {{ border-color: #f3d08a; background: #fff3d9; color: #7a4b00; }}
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
    {_render_filters(events, active_filters)}
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


def _render_filters(events: list[dict[str, Any]], active_filters: dict[str, str]) -> str:
    decisions = _options(["allowed", "redacted", "blocked", "error"], _event_values(events, "decision"))
    categories = _options([], _event_finding_values(events, "category"))
    severities = _options(["critical", "high", "medium", "low", "info"], _event_finding_values(events, "severity"))
    return f"""<form class="filters" method="get" action="/dashboard">
      {_select("decision", "Decision", decisions, active_filters.get("decision", ""))}
      {_select("category", "Category", categories, active_filters.get("category", ""))}
      {_select("severity", "Severity", severities, active_filters.get("severity", ""))}
      <button type="submit">Apply</button>
      <a class="clear" href="/dashboard">Clear</a>
    </form>"""


def _select(name: str, label: str, options: list[str], selected: str) -> str:
    option_html = ['<option value="">All</option>']
    for option in options:
        is_selected = " selected" if option == selected else ""
        option_html.append(f'<option value="{escape(option)}"{is_selected}>{escape(option)}</option>')
    return (
        f'<div class="field"><label for="{escape(name)}">{escape(label)}</label>'
        f'<select id="{escape(name)}" name="{escape(name)}">{"".join(option_html)}</select></div>'
    )


def _normalize_filters(filters: dict[str, str] | None) -> dict[str, str]:
    if not filters:
        return {}
    return {
        key: str(filters.get(key, "")).strip()
        for key in ("decision", "category", "severity")
        if str(filters.get(key, "")).strip()
    }


def _filter_events(events: list[dict[str, Any]], filters: dict[str, str]) -> list[dict[str, Any]]:
    if not filters:
        return events
    return [event for event in events if _matches_filters(event, filters)]


def _matches_filters(event: dict[str, Any], filters: dict[str, str]) -> bool:
    decision = filters.get("decision")
    if decision and str(event.get("decision", "")) != decision:
        return False

    category = filters.get("category")
    if category and category not in _finding_values(event, "category"):
        return False

    severity = filters.get("severity")
    if severity and severity not in _finding_values(event, "severity"):
        return False

    return True


def _event_values(events: list[dict[str, Any]], field: str) -> list[str]:
    return sorted({str(event.get(field, "")).strip() for event in events if str(event.get(field, "")).strip()})


def _event_finding_values(events: list[dict[str, Any]], field: str) -> list[str]:
    values: set[str] = set()
    for event in events:
        values.update(_finding_values(event, field))
    return sorted(values)


def _finding_values(event: dict[str, Any], field: str) -> set[str]:
    findings = event.get("findings", []) or []
    values = {str(finding.get(field, "")).strip() for finding in findings if str(finding.get(field, "")).strip()}
    summary = event.get("finding_summary")
    if isinstance(summary, dict):
        key = f"by_{field}"
        grouped = summary.get(key)
        if isinstance(grouped, dict):
            values.update(str(value).strip() for value in grouped if str(value).strip())
    return values


def _options(defaults: list[str], discovered: list[str]) -> list[str]:
    seen: set[str] = set()
    options: list[str] = []
    for value in defaults + discovered:
        if value in seen:
            continue
        seen.add(value)
        options.append(value)
    return options


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
    finding_text = _render_finding_summary(event) + "".join(_render_finding(f) for f in findings[:3])
    if len(findings) > 3:
        finding_text += f'<div class="evidence">+{len(findings) - 3} more</div>'

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


def _render_finding_summary(event: dict[str, Any]) -> str:
    summary = event.get("finding_summary")
    if not isinstance(summary, dict):
        summary = _summarize_findings(event.get("findings", []) or [])

    badges: list[str] = []
    max_severity = str(summary.get("max_severity", "none"))
    if max_severity != "none":
        badges.append(_tag(max_severity, css_class=max_severity))

    by_category = summary.get("by_category", {})
    if isinstance(by_category, dict):
        for category, count in list(by_category.items())[:3]:
            badges.append(_tag(f"{category}:{count}"))

    if not badges:
        return ""
    return '<div class="tags">' + "".join(badges) + "</div>"


def _render_finding(finding: dict[str, Any]) -> str:
    rule_id = escape(str(finding.get("rule_id", "")))
    category = str(finding.get("category", "unknown") or "unknown")
    severity = str(finding.get("severity", "unknown") or "unknown")
    action = str(finding.get("action", "unknown") or "unknown")
    evidence = escape(str(finding.get("evidence", "")))
    return (
        '<div class="finding">'
        f"<code>{rule_id}</code> "
        f"{_tag(severity, css_class=severity)}"
        f"{_tag(category)}"
        f"{_tag(action)}"
        f'<div class="evidence">{evidence}</div>'
        "</div>"
    )


def _tag(text: str, css_class: str = "") -> str:
    class_name = "tag"
    if css_class:
        class_name += " " + escape(css_class)
    return f'<span class="{class_name}">{escape(text)}</span>'


def _summarize_findings(findings: list[dict[str, Any]]) -> dict[str, Any]:
    by_category = Counter(str(finding.get("category", "unknown") or "unknown") for finding in findings)
    by_severity = Counter(str(finding.get("severity", "unknown") or "unknown") for finding in findings)
    return {
        "by_category": dict(by_category),
        "max_severity": _max_severity(by_severity),
    }


def _max_severity(counts: Counter[str]) -> str:
    order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    if not counts:
        return "none"
    return max(counts, key=lambda severity: order.get(severity, 0))


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
