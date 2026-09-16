#!/usr/bin/env python3
"""Generate a deterministic, self-contained HTML report from normalized run data."""

from __future__ import annotations

import json
from collections import Counter
from html import escape
from pathlib import Path
from typing import Any, Iterable


SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
LIMITATION_STATES = (
    "UNKNOWN",
    "NOT_EVALUATED",
    "TARGET_ROOT_CONTEXT_REQUIRED",
    "RUNTIME_CONTEXT_REQUIRED",
)


def _text(value: Any) -> str:
    if value is None:
        return "—"
    if isinstance(value, bool):
        return "Yes" if value else "No"
    return str(value)


def _html(value: Any) -> str:
    return escape(_text(value), quote=True)


def _load_object(path: Path, label: str) -> dict[str, Any]:
    try:
        with path.open(encoding="utf-8") as source:
            value = json.load(source)
    except json.JSONDecodeError as exc:
        raise ValueError(f"malformed JSON in {label}: {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must contain a JSON object: {path}")
    return value


def load_run(run_root: Path) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    run_root = run_root.resolve()
    if not run_root.is_dir():
        raise ValueError(f"run directory does not exist: {run_root}")
    run = _load_object(run_root / "run.json", "run metadata")
    inventory = _load_object(run_root / "normalized" / "inventory.json", "inventory")
    findings = _load_object(run_root / "normalized" / "findings.json", "findings")
    if not isinstance(inventory.get("records"), list):
        raise ValueError("inventory must contain a 'records' array")
    if not isinstance(findings.get("findings"), list):
        raise ValueError("findings document must contain a 'findings' array")
    return run, inventory, findings


def _walk_strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for nested in value.values():
            yield from _walk_strings(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from _walk_strings(nested)


def _definition_rows(rows: Iterable[tuple[str, Any]]) -> str:
    return "".join(
        f"<dt>{_html(label)}</dt><dd>{_html(value)}</dd>" for label, value in rows
    )


def _finding_html(item: dict[str, Any], index: int) -> str:
    severity = str(item.get("severity", "INFO")).upper()
    if severity not in SEVERITIES:
        severity = "INFO"
    evidence = item.get("evidence_refs")
    if not isinstance(evidence, list):
        evidence = []
    evidence_html = (
        "<ul class=\"compact\">"
        + "".join(f"<li><code>{_html(reference)}</code></li>" for reference in evidence)
        + "</ul>"
        if evidence else "<p class=\"muted\">No evidence references recorded.</p>"
    )
    description = item.get("description")
    description_html = (
        f"<p>{_html(description)}</p>" if description
        else "<p class=\"muted\">No description field in normalized finding.</p>"
    )
    return f"""
    <article class="finding">
      <div class="finding-title"><span class="badge severity-{severity.lower()}">{_html(severity)}</span>
        <h3>{_html(item.get('title', f'Finding {index}'))}</h3></div>
      <dl>{_definition_rows((
          ('Rule ID', item.get('rule_id')),
          ('Affected path', item.get('affected_path')),
          ('Component ID', item.get('component_id')),
          ('Confidence', item.get('confidence')),
          ('Classification', item.get('classification')),
      ))}</dl>
      <h4>Description</h4>{description_html}
      <h4>Remediation</h4><p>{_html(item.get('remediation'))}</p>
      <h4>Evidence references</h4>{evidence_html}
    </article>"""


def _component_html(record: dict[str, Any], index: int) -> str:
    elf = record.get("elf") if isinstance(record.get("elf"), dict) else {}
    permissions = record.get("permissions") if isinstance(record.get("permissions"), dict) else {}
    file_permissions = (
        permissions.get("file") if isinstance(permissions.get("file"), dict) else {}
    )
    dynamic = (
        record.get("dynamic_linking")
        if isinstance(record.get("dynamic_linking"), dict) else {}
    )
    hardening = record.get("hardening") if isinstance(record.get("hardening"), dict) else {}
    hardening_html = "".join(
        f"<li><span>{_html(name.replace('_', ' ').title())}</span> "
        f"<strong>{_html(value.get('status') if isinstance(value, dict) else value)}</strong></li>"
        for name, value in sorted(hardening.items())
    ) or "<li>Not available</li>"
    dependencies = record.get("dependencies")
    if not isinstance(dependencies, list):
        dependencies = []
    dependency_rows = "".join(
        "<tr>"
        f"<td>{_html(dependency.get('dependency_name'))}</td>"
        f"<td>{_html(dependency.get('resolution_status'))}</td>"
        f"<td>{_html(dependency.get('resolved_path'))}</td>"
        "</tr>"
        for dependency in dependencies if isinstance(dependency, dict)
    ) or '<tr><td colspan="3" class="muted">No dependencies recorded.</td></tr>'
    return f"""
    <article class="component">
      <h3>{_html(record.get('path', f'Component {index}'))}</h3>
      <dl>{_definition_rows((
          ('Component ID', record.get('component_id')),
          ('Type', record.get('type')),
          ('Status', record.get('status')),
          ('ELF class', elf.get('class')),
          ('Machine', elf.get('machine')),
          ('Build ID', elf.get('build_id')),
          ('Mode', file_permissions.get('mode')),
          ('Writable by non-owner', file_permissions.get('writable_by_non_owner')),
          ('Linkage', dynamic.get('linkage')),
          ('Custom search path', dynamic.get('custom_search_path')),
      ))}</dl>
      <h4>Hardening</h4><ul class="status-list">{hardening_html}</ul>
      <h4>Dependencies</h4>
      <div class="table-wrap"><table><thead><tr><th>Name</th><th>Status</th><th>Resolved path</th></tr></thead>
      <tbody>{dependency_rows}</tbody></table></div>
    </article>"""


def render_report(
    run: dict[str, Any], inventory: dict[str, Any], findings_document: dict[str, Any],
) -> str:
    records = inventory.get("records")
    findings = findings_document.get("findings")
    if not isinstance(records, list) or not isinstance(findings, list):
        raise ValueError("inventory records and findings must be arrays")
    severity_counts = Counter(
        str(item.get("severity", "")).upper()
        for item in findings if isinstance(item, dict)
    )
    summary_cards = "".join(
        f'<div class="metric severity-{severity.lower()}"><strong>{severity_counts[severity]}</strong>'
        f"<span>{severity.title()}</span></div>"
        for severity in SEVERITIES
    )
    summary_cards += (
        f'<div class="metric"><strong>{len(findings)}</strong><span>Total</span></div>'
    )
    finding_content = (
        "".join(
            _finding_html(item, index)
            for index, item in enumerate(findings, start=1) if isinstance(item, dict)
        )
        if findings else '<p class="empty">0 security findings</p>'
    )
    inventory_summary = inventory.get("summary")
    if not isinstance(inventory_summary, dict):
        inventory_summary = {}
    inventory_cards = "".join(
        f'<div class="metric"><strong>{_html(inventory_summary.get(key, 0))}</strong>'
        f"<span>{_html(label)}</span></div>"
        for key, label in (
            ("total", "Components"),
            ("elf_executable", "Executables"),
            ("elf_shared_object", "Shared objects"),
            ("malformed_elf", "Malformed ELF"),
            ("unsupported", "Unsupported"),
        )
    )
    component_content = "".join(
        _component_html(record, index)
        for index, record in enumerate(records, start=1) if isinstance(record, dict)
    ) or '<p class="empty">No inventory records.</p>'
    limitations = Counter(
        value for value in _walk_strings((inventory, findings_document))
        if value in LIMITATION_STATES
    )
    limitation_items = "".join(
        f"<li><code>{_html(state)}</code>: {_html(limitations[state])} occurrence(s)</li>"
        for state in LIMITATION_STATES if limitations[state]
    ) or "<li>No tracked limitation states observed.</li>"
    schema = inventory.get("schema_version", run.get("schema_version"))
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Linux ELF Security Report — {_html(run.get('run_id'))}</title>
  <style>
    :root {{ color-scheme: light; --ink:#172033; --muted:#667085; --line:#d9dee8; --panel:#fff; --bg:#f4f6fa; }}
    * {{ box-sizing:border-box; }} body {{ margin:0; background:var(--bg); color:var(--ink); font:15px/1.55 system-ui,sans-serif; }}
    main {{ max-width:1100px; margin:auto; padding:32px 20px 60px; }} header,section {{ background:var(--panel); border:1px solid var(--line); border-radius:12px; padding:24px; margin-bottom:20px; }}
    h1,h2,h3,h4 {{ line-height:1.25; }} h1 {{ margin-top:0; }} h2 {{ border-bottom:1px solid var(--line); padding-bottom:10px; }}
    dl {{ display:grid; grid-template-columns:minmax(150px,220px) 1fr; gap:7px 16px; }} dt {{ color:var(--muted); }} dd {{ margin:0; overflow-wrap:anywhere; }}
    .metrics {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(120px,1fr)); gap:10px; }} .metric {{ border:1px solid var(--line); border-radius:9px; padding:14px; display:flex; flex-direction:column; }}
    .metric strong {{ font-size:24px; }} .metric span,.muted {{ color:var(--muted); }} .finding,.component {{ border:1px solid var(--line); border-radius:9px; padding:18px; margin-top:14px; }}
    .finding-title {{ display:flex; align-items:center; gap:10px; }} .finding-title h3 {{ margin:0; }} .badge {{ border-radius:999px; color:white; font-weight:700; padding:3px 9px; font-size:12px; }}
    .severity-critical .badge,.badge.severity-critical {{ background:#7a1538; }} .severity-high .badge,.badge.severity-high {{ background:#b42318; }} .severity-medium .badge,.badge.severity-medium {{ background:#b54708; }} .severity-low .badge,.badge.severity-low {{ background:#175cd3; }} .severity-info .badge,.badge.severity-info {{ background:#475467; }}
    .compact,.status-list {{ padding-left:20px; }} code {{ background:#eef1f6; padding:2px 5px; border-radius:4px; overflow-wrap:anywhere; }} .empty {{ font-size:18px; font-weight:700; }}
    .table-wrap {{ overflow-x:auto; }} table {{ width:100%; border-collapse:collapse; }} th,td {{ border-bottom:1px solid var(--line); text-align:left; padding:8px; overflow-wrap:anywhere; }}
    @media (max-width:650px) {{ dl {{ grid-template-columns:1fr; }} dt {{ font-weight:700; }} }}
  </style>
</head>
<body><main>
  <header><h1>Linux ELF Security Report</h1><dl>{_definition_rows((
      ('Run ID', run.get('run_id')),
      ('Target', run.get('target')),
      ('Target root', run.get('target_root')),
      ('Started', run.get('started_at')),
      ('Finished', run.get('finished_at')),
      ('Schema version', schema),
  ))}</dl></header>
  <section><h2>Finding summary</h2><div class="metrics">{summary_cards}</div></section>
  <section><h2>Findings</h2>{finding_content}</section>
  <section><h2>Inventory summary</h2><div class="metrics">{inventory_cards}</div>{component_content}</section>
  <section><h2>Limitations and interpretation</h2>
    <p>Unknown, unevaluated, or context-required states are evidence limitations, not confirmed security findings.</p>
    <ul>{limitation_items}</ul>
  </section>
</main></body></html>
"""


def generate_report(run_root: Path, output_path: Path | None = None) -> Path:
    run_root = run_root.resolve()
    run, inventory, findings = load_run(run_root)
    destination = output_path.resolve() if output_path else run_root / "report.html"
    report = render_report(run, inventory, findings)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.tmp")
    temporary.write_text(report, encoding="utf-8")
    temporary.replace(destination)
    return destination
