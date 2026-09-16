#!/usr/bin/env python3
"""Generate a deterministic, self-contained HTML report from normalized run data."""
from __future__ import annotations

import json
import os
from collections import Counter
from html import escape
from pathlib import Path, PurePath
from typing import Any

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
ELF_TYPES = ("elf_executable", "elf_shared_object")

def _text(value: Any) -> str:
    if value is None or value == "": return "—"
    if isinstance(value, bool): return "Yes" if value else "No"
    return str(value)

def _html(value: Any) -> str:
    return escape(_text(value), quote=True)

def _load_object(path: Path, label: str) -> dict[str, Any]:
    try:
        with path.open(encoding="utf-8") as source: value = json.load(source)
    except json.JSONDecodeError as exc:
        raise ValueError(f"malformed JSON in {label}: {path}: {exc}") from exc
    if not isinstance(value, dict): raise ValueError(f"{label} must contain a JSON object: {path}")
    return value

def load_run(run_root: Path) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    run_root = run_root.resolve()
    if not run_root.is_dir(): raise ValueError(f"run directory does not exist: {run_root}")
    run = _load_object(run_root / "run.json", "run metadata")
    inventory = _load_object(run_root / "normalized" / "inventory.json", "inventory")
    findings = _load_object(run_root / "normalized" / "findings.json", "findings")
    if not isinstance(inventory.get("records"), list): raise ValueError("inventory must contain a 'records' array")
    if not isinstance(findings.get("findings"), list): raise ValueError("findings document must contain a 'findings' array")
    return run, inventory, findings

def _display_root(run: dict[str, Any], records: list[dict[str, Any]]) -> Path | None:
    target_value = run.get("target")
    if not isinstance(target_value, str) or not target_value: return None
    target = Path(target_value)
    target_is_file = any(record.get("path") == target_value for record in records)
    explicit = run.get("target_root")
    if isinstance(explicit, str) and explicit and explicit != os.sep: return Path(explicit)
    return target.parent if target_is_file else target

def _display_path(value: Any, root: Path | None) -> Any:
    if not isinstance(value, str) or not value or root is None: return value
    path = Path(value)
    if not path.is_absolute(): return value
    try: relative = path.relative_to(root)
    except ValueError: return value
    if str(relative) == ".": return root.name or path.name
    return str(PurePath(root.name) / relative) if root.name else str(relative)

def _basename(record: dict[str, Any]) -> str:
    value = record.get("path")
    return Path(value).name if isinstance(value, str) else "Binary"

def _status(record: dict[str, Any], name: str) -> str | None:
    hardening = record.get("hardening")
    value = hardening.get(name) if isinstance(hardening, dict) else None
    return str(value.get("status")) if isinstance(value, dict) and value.get("status") else None

def _short_status(name: str, status: str | None, shared: bool = False) -> str:
    if name == "nx": return {"ENABLED":"Enabled", "DISABLED":"Disabled"}.get(status, "—")
    if name == "pie": return "DSO / PIC" if shared else {"ENABLED":"PIE", "DISABLED":"No PIE"}.get(status, "—")
    if name in {"stack_canary", "fortify"}: return {"ENABLED":"Yes", "DISABLED":"No", "NOT_DETECTED":"No"}.get(status, "—")
    if name == "relro": return {"FULL":"Full", "PARTIAL":"Partial", "NONE":"None"}.get(status, "—")
    return "—"

def _search_path(record: dict[str, Any], name: str) -> str:
    dynamic = record.get("dynamic_linking")
    value = dynamic.get(name) if isinstance(dynamic, dict) else None
    if not isinstance(value, dict) or not value.get("present"): return "—"
    values = value.get("original_values")
    return "; ".join(map(str, values)) if isinstance(values, list) and values else "Present"

def _architecture(record: dict[str, Any]) -> str:
    elf = record.get("elf") if isinstance(record.get("elf"), dict) else {}
    return " / ".join(str(x) for x in (elf.get("class"), record.get("architecture") or elf.get("machine")) if x) or "—"

def _indicator_class(name: str, value: str) -> str:
    if value == "—" or name in {"architecture", "stripped"}:
        return "indicator-neutral"
    suspicious = {
        "nx": {"Disabled"},
        "pie": {"No PIE"},
        "stack_canary": {"No"},
        "relro": {"None"},
        "fortify": {"No"},
    }
    review = {
        "relro": {"Partial"},
        "rpath": {"Present"},
        "runpath": {"Present"},
    }
    if value in suspicious.get(name, set()):
        return "indicator-alert"
    if value in review.get(name, set()) or name in {"rpath", "runpath"}:
        return "indicator-review"
    return "indicator-good"

def _overview_table(records: list[dict[str, Any]], shared: bool) -> str:
    rows = []
    for record in records:
        cells = [("architecture", _architecture(record)),
                 ("nx", _short_status("nx", _status(record,"nx"))),
                 ("pie", _short_status("pie", _status(record,"pie"), shared)),
                 ("stack_canary", _short_status("stack_canary", _status(record,"stack_canary"))),
                 ("relro", _short_status("relro", _status(record,"relro"))),
                 ("rpath", _search_path(record,"rpath")),
                 ("runpath", _search_path(record,"runpath")),
                 ("fortify", _short_status("fortify", _status(record,"fortify"))),
                 ("stripped", "—")]
        review = record.get("review_items") if isinstance(record.get("review_items"), list) else []
        review_values = [item.get("value") for item in review if isinstance(item, dict) and item.get("value")]
        review_html = ""
        if review_values:
            review_html = '<div class="review-cues"><strong>Review:</strong>' + "".join(
                f'<code>{_html(value)}</code>' for value in review_values[:20]
            ) + '</div>'
        rows.append(f'<tr><td><strong>{_html(_basename(record))}</strong>{review_html}</td>' +
                    "".join(f'<td><span class="indicator {_indicator_class(name, value)}">{_html(value)}</span></td>'
                            for name, value in cells) + "</tr>")
    body = "".join(rows) or '<tr><td colspan="10" class="muted">No matching ELF binaries.</td></tr>'
    first, pie = ("Shared Object", "PIE/PIC") if shared else ("Executable", "PIE")
    return ('<div class="table-wrap"><table class="overview"><thead><tr>' +
            f'<th>{first}</th><th>Architecture</th><th>NX</th><th>{pie}</th><th>Stack Canary</th>' +
            '<th>RELRO</th><th>RPATH</th><th>RUNPATH</th><th>FORTIFY</th><th>Symbols Stripped</th>' +
            f'</tr></thead><tbody>{body}</tbody></table></div>')

def _findings_table(findings: list[dict[str, Any]], root: Path | None) -> str:
    if not findings:
        return '<p class="muted">No evidence-backed correlation findings.</p>'
    rows = []
    for item in findings:
        severity = str(item.get("severity", "INFO")).upper()
        if severity not in SEVERITIES: severity = "INFO"
        refs = item.get("evidence_refs") if isinstance(item.get("evidence_refs"), list) else []
        trace = " ".join(f'<code class="trace">{_html(ref)}</code>' for ref in refs)
        rows.append(
            f'<tr><td><span class="indicator severity-{severity.lower()}">{_html(severity)}</span></td>'
            f'<td><strong>{_html(item.get("title"))}</strong><br><code>{_html(item.get("rule_id"))}</code></td>'
            f'<td>{_html(_display_path(item.get("affected_path"), root))}</td>'
            f'<td>{_html(item.get("classification"))}<br><span class="muted">{_html(item.get("confidence"))} confidence</span></td>'
            f'<td>{trace or "—"}</td></tr>'
        )
    return ('<div class="table-wrap"><table><thead><tr><th>Severity</th><th>Finding</th>'
            '<th>Affected path</th><th>Assessment</th><th>Trace</th></tr></thead><tbody>'
            + "".join(rows) + '</tbody></table></div>')


def _tool_coverage(records: list[dict[str, Any]], inventory: dict[str, Any]) -> str:
    grouped: dict[str, Counter[str]] = {}
    checks: dict[str, set[str]] = {}
    summaries: dict[str, Counter[str]] = {}
    def add_result(name: str, result: dict[str, Any]) -> None:
        grouped.setdefault(name, Counter())[str(result.get("status", "UNKNOWN"))] += 1
        checks.setdefault(name, set()).update(map(str, result.get("checks", [])))
        summary = result.get("summary")
        if isinstance(summary, dict):
            for key, value in summary.items():
                if isinstance(value, bool):
                    summaries.setdefault(name, Counter())[str(key)] += int(value)
                elif isinstance(value, int):
                    summaries.setdefault(name, Counter())[str(key)] += value
    for record in records:
        result_map = record.get("tool_results")
        if not isinstance(result_map, dict): continue
        for name, result in result_map.items():
            if not isinstance(result, dict): continue
            add_result(str(name), result)
    target_results = inventory.get("target_tool_results")
    if isinstance(target_results, dict):
        for name, result in target_results.items():
            if not isinstance(result, dict): continue
            add_result(str(name), result)
    if not grouped:
        return '<p class="muted">No optional tool coverage was recorded.</p>'
    rows = []
    for name in sorted(grouped):
        states = grouped[name]
        status = ", ".join(f"{key}: {states[key]}" for key in sorted(states))
        alert = any(key in states for key in ("ERROR", "TIMEOUT", "DATA_UNAVAILABLE", "TOOL_UNAVAILABLE"))
        css = "indicator-review" if alert else "indicator-good"
        compact_summary = summaries.get(name, Counter())
        result_text = ", ".join(
            f"{key.replace('_', ' ')}: {compact_summary[key]}"
            for key in sorted(compact_summary)
            if compact_summary[key] != 0 or key.endswith("count")
        ) or "—"
        rows.append(f'<tr><td><strong>{_html(name)}</strong></td><td>{_html(", ".join(sorted(checks[name])))}</td>'
                    f'<td><span class="indicator {css}">{_html(status)}</span></td><td>{_html(result_text)}</td></tr>')
    return ('<div class="table-wrap"><table><thead><tr><th>Tool</th><th>Checklist coverage</th>'
            '<th>Run status (count)</th><th>Compact result</th></tr></thead><tbody>' + "".join(rows) + '</tbody></table></div>')

def render_report(run: dict[str, Any], inventory: dict[str, Any], findings_document: dict[str, Any]) -> str:
    raw_records, raw_findings = inventory.get("records"), findings_document.get("findings")
    if not isinstance(raw_records,list) or not isinstance(raw_findings,list): raise ValueError("inventory records and findings must be arrays")
    all_records=[x for x in raw_records if isinstance(x,dict)]; findings=[x for x in raw_findings if isinstance(x,dict)]
    records=[x for x in all_records if x.get("type") in ELF_TYPES and x.get("status")=="SUCCESS"]
    executables=[x for x in records if x.get("type")=="elf_executable"]
    shared=[x for x in records if x.get("type")=="elf_shared_object"]
    root=_display_root(run,all_records); counts=Counter(str(x.get("severity","")).upper() for x in findings)
    metrics="".join(f'<div class="metric severity-{s.lower()}"><strong>{counts[s]}</strong><span>{s.title()}</span></div>' for s in SEVERITIES)
    metrics += f'<div class="metric"><strong>{len(findings)}</strong><span>Total findings</span></div><div class="metric"><strong>{len(executables)}</strong><span>ELF executables</span></div><div class="metric"><strong>{len(shared)}</strong><span>Shared objects</span></div><div class="metric"><strong>{len(all_records)-len(records)}</strong><span>Filtered non-ELF</span></div>'
    findings_section = _findings_table(findings, root)
    coverage_section = _tool_coverage(records, inventory)
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Linux ELF Security Report — {_html(run.get("run_id"))}</title><style>
:root{{--ink:#172033;--muted:#667085;--line:#d9dee8;--panel:#fff;--bg:#f4f6fa;--alert:#b42318;--alert-bg:#fef3f2;--review:#b54708;--review-bg:#fff7ed;--good:#067647;--good-bg:#ecfdf3}}*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 system-ui,sans-serif}}main{{max-width:1280px;margin:auto;padding:32px 20px 60px}}header,section{{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:24px;margin-bottom:20px}}h1,h2{{line-height:1.25}}h1{{margin-top:0}}h2{{border-bottom:1px solid var(--line);padding-bottom:10px}}.metrics{{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:10px}}.metric{{border:1px solid var(--line);border-radius:9px;padding:14px;display:flex;flex-direction:column}}.metric strong{{font-size:24px}}.metric span,.muted{{color:var(--muted)}}.metric.severity-critical,.metric.severity-high,.severity-critical,.severity-high{{color:var(--alert);background:var(--alert-bg);border-color:#fecdca}}.metric.severity-medium,.severity-medium{{color:var(--review);background:var(--review-bg);border-color:#fedf89}}.metric.severity-low,.severity-low{{color:#175cd3;background:#eff8ff;border-color:#b2ddff}}.metric.severity-info,.severity-info{{color:#475467;background:#f8f9fc}}.metric.severity-critical span,.metric.severity-high span,.metric.severity-medium span,.metric.severity-low span,.metric.severity-info span{{color:inherit}}.table-wrap{{overflow-x:auto}}table{{width:100%;border-collapse:collapse}}th,td{{border-bottom:1px solid var(--line);text-align:left;padding:8px;overflow-wrap:anywhere;vertical-align:top}}.overview{{white-space:nowrap}}a{{color:#175cd3}}code{{font-size:12px}}.indicator{{display:inline-block;border-radius:999px;padding:2px 8px;font-weight:700}}.indicator-alert{{color:var(--alert);background:var(--alert-bg)}}.indicator-review{{color:var(--review);background:var(--review-bg)}}.indicator-good{{color:var(--good);background:var(--good-bg)}}.indicator-neutral{{color:var(--muted);background:#f2f4f7}}.legend{{color:var(--muted);font-size:13px;margin:0 0 14px}}.review-cues{{margin-top:6px;display:flex;flex-direction:column;white-space:normal;color:var(--review);max-width:440px}}.review-cues code{{background:var(--review-bg);padding:2px 5px;margin-top:3px;overflow-wrap:anywhere}}.trace{{display:inline-block;background:#f2f4f7;padding:2px 5px;margin:1px}}@media(max-width:650px){{main{{padding-inline:10px}}}}
</style></head><body><main><header><h1>Linux ELF Security Report</h1><p>Focused static-analysis view for ELF executables and shared objects.</p></header><section><h2>Scan Summary</h2><div class="metrics">{metrics}</div></section><section><h2>ELF Executables</h2><p class="legend">Red and orange indicators require review; they are not confirmed vulnerabilities by themselves. Embedded path/URL strings appear only for files requiring review.</p>{_overview_table(executables,False)}</section><section><h2>Shared Objects</h2><p class="legend">Red and orange indicators require review; they are not confirmed vulnerabilities by themselves.</p>{_overview_table(shared,True)}</section><section><h2>Actionable Correlations</h2><p class="legend">Compact evidence-backed results only. Trace IDs map to directories under <code>raw/</code>.</p>{findings_section}</section><section><h2>Tool Coverage</h2>{coverage_section}</section></main></body></html>'''

def generate_report(run_root: Path, output_path: Path | None = None) -> Path:
    run_root=run_root.resolve(); run,inventory,findings=load_run(run_root)
    destination=output_path.resolve() if output_path else run_root/"report.html"
    report=render_report(run,inventory,findings); destination.parent.mkdir(parents=True,exist_ok=True)
    temporary=destination.with_name(f".{destination.name}.tmp"); temporary.write_text(report,encoding="utf-8"); temporary.replace(destination)
    return destination
