#!/usr/bin/env python3
"""Generate a deterministic, self-contained HTML report from normalized run data."""
from __future__ import annotations

import json
import os
from collections import Counter
from html import escape
from pathlib import Path, PurePath
from typing import Any, Iterable

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

def _definition_rows(rows: Iterable[tuple[str, Any]]) -> str:
    return "".join(f"<dt>{_html(k)}</dt><dd>{_html(v)}</dd>" for k, v in rows if v not in (None, "", [], {}))

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

def _anchor(record: dict[str, Any], index: int) -> str:
    raw = str(record.get("component_id", ""))
    safe = "".join(c for c in raw if c.isalnum() or c in "-_")
    return f"binary-{safe or index}"

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
    for index, record in enumerate(records, 1):
        cells = [("architecture", _architecture(record)),
                 ("nx", _short_status("nx", _status(record,"nx"))),
                 ("pie", _short_status("pie", _status(record,"pie"), shared)),
                 ("stack_canary", _short_status("stack_canary", _status(record,"stack_canary"))),
                 ("relro", _short_status("relro", _status(record,"relro"))),
                 ("rpath", _search_path(record,"rpath")),
                 ("runpath", _search_path(record,"runpath")),
                 ("fortify", _short_status("fortify", _status(record,"fortify"))),
                 ("stripped", "—")]
        rows.append(f'<tr><td>{_html(_basename(record))}</td>' +
                    "".join(f'<td><span class="indicator {_indicator_class(name, value)}">{_html(value)}</span></td>'
                            for name, value in cells) + "</tr>")
    body = "".join(rows) or '<tr><td colspan="10" class="muted">No matching ELF binaries.</td></tr>'
    first, pie = ("Shared Object", "PIE/PIC") if shared else ("Executable", "PIE")
    return ('<div class="table-wrap"><table class="overview"><thead><tr>' +
            f'<th>{first}</th><th>Architecture</th><th>NX</th><th>{pie}</th><th>Stack Canary</th>' +
            '<th>RELRO</th><th>RPATH</th><th>RUNPATH</th><th>FORTIFY</th><th>Symbols Stripped</th>' +
            f'</tr></thead><tbody>{body}</tbody></table></div>')

def _finding_html(item: dict[str, Any], index: int, root: Path | None) -> str:
    severity = str(item.get("severity", "INFO")).upper()
    if severity not in SEVERITIES: severity = "INFO"
    evidence = item.get("evidence_refs") if isinstance(item.get("evidence_refs"), list) else []
    extra = ""
    for heading, key in (("Description","description"),("Remediation","remediation")):
        if item.get(key): extra += f"<h4>{heading}</h4><p>{_html(item[key])}</p>"
    if evidence: extra += '<h4>Evidence references</h4><ul class="compact">' + "".join(f'<li><code>{_html(x)}</code></li>' for x in evidence) + '</ul>'
    rows = (("Rule ID",item.get("rule_id")),("Affected path",_display_path(item.get("affected_path"),root)),
            ("Confidence",item.get("confidence")),("Classification",item.get("classification")))
    return f'<article class="finding"><div class="finding-title"><span class="badge severity-{severity.lower()}">{_html(severity)}</span><h3>{_html(item.get("title",f"Finding {index}"))}</h3></div><dl>{_definition_rows(rows)}</dl>{extra}</article>'

def _capabilities_html(record: dict[str, Any]) -> str:
    capabilities = record.get("capabilities")
    if not isinstance(capabilities, dict): return ""
    groups = []
    for name, value in capabilities.items():
        if name.startswith("_") or not isinstance(value, dict) or value.get("detected") is not True: continue
        symbols = value.get("symbols")
        if not isinstance(symbols, list) or not symbols: continue
        groups.append(f'<h5>{_html(name.replace("_"," ").title())}</h5><ul class="compact symbols">' +
                      "".join(f'<li><code>{_html(x)}</code></li>' for x in symbols) + '</ul>')
    return '<h4>Security Capabilities</h4>' + "".join(groups) if groups else ""

def _dependencies_html(record: dict[str, Any], root: Path | None) -> str:
    dependencies = record.get("dependencies")
    if not isinstance(dependencies, list) or not dependencies: return ""
    rows=[]
    for dep in dependencies:
        if not isinstance(dep, dict): continue
        status=dep.get("resolution_status"); css=' class="warning-text"' if status != "RESOLVED" else ""
        rows.append(f'<tr><td>{_html(dep.get("dependency_name"))}</td><td{css}>{_html(status)}</td><td>{_html(_display_path(dep.get("resolved_path"),root))}</td></tr>')
    if not rows: return ""
    return '<h4>Dependencies</h4><div class="table-wrap"><table><thead><tr><th>Dependency</th><th>Status</th><th>Resolved Path</th></tr></thead><tbody>' + "".join(rows) + '</tbody></table></div>'

def _binary_detail(record: dict[str, Any], index: int, root: Path | None) -> str:
    strings = record.get("strings")
    strings_html = ('<h4>Strings</h4><ul class="compact">' + "".join(f'<li><code>{_html(x)}</code></li>' for x in strings) + '</ul>') if isinstance(strings,list) and strings else ""
    permissions = record.get("permissions") if isinstance(record.get("permissions"),dict) else {}
    file_data = permissions.get("file") if isinstance(permissions.get("file"),dict) else {}
    warning = '<div class="warning"><strong>Warning:</strong> writable by non-owner.</div>' if file_data.get("writable_by_non_owner") is True else ""
    content = strings_html + warning + _capabilities_html(record) + _dependencies_html(record,root)
    if not content: return ""
    return f'<article class="binary-detail" id="{_html(_anchor(record,index))}"><h3>{_html(_basename(record))}</h3><dl>{_definition_rows((("Path",_display_path(record.get("path"),root)),))}</dl>{content}</article>'

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
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Linux ELF Security Report — {_html(run.get("run_id"))}</title><style>
:root{{--ink:#172033;--muted:#667085;--line:#d9dee8;--panel:#fff;--bg:#f4f6fa;--alert:#b42318;--alert-bg:#fef3f2;--review:#b54708;--review-bg:#fff7ed;--good:#067647;--good-bg:#ecfdf3}}*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 system-ui,sans-serif}}main{{max-width:1280px;margin:auto;padding:32px 20px 60px}}header,section{{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:24px;margin-bottom:20px}}h1,h2{{line-height:1.25}}h1{{margin-top:0}}h2{{border-bottom:1px solid var(--line);padding-bottom:10px}}.metrics{{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:10px}}.metric{{border:1px solid var(--line);border-radius:9px;padding:14px;display:flex;flex-direction:column}}.metric strong{{font-size:24px}}.metric span,.muted{{color:var(--muted)}}.metric.severity-critical,.metric.severity-high{{color:var(--alert);background:var(--alert-bg);border-color:#fecdca}}.metric.severity-medium{{color:var(--review);background:var(--review-bg);border-color:#fedf89}}.metric.severity-low{{color:#175cd3;background:#eff8ff;border-color:#b2ddff}}.metric.severity-info{{color:#475467;background:#f8f9fc}}.metric.severity-critical span,.metric.severity-high span,.metric.severity-medium span,.metric.severity-low span,.metric.severity-info span{{color:inherit}}.table-wrap{{overflow-x:auto}}table{{width:100%;border-collapse:collapse}}th,td{{border-bottom:1px solid var(--line);text-align:left;padding:8px;overflow-wrap:anywhere;vertical-align:top}}.overview{{white-space:nowrap}}a{{color:#175cd3}}.indicator{{display:inline-block;border-radius:999px;padding:2px 8px;font-weight:700}}.indicator-alert{{color:var(--alert);background:var(--alert-bg)}}.indicator-review{{color:var(--review);background:var(--review-bg)}}.indicator-good{{color:var(--good);background:var(--good-bg)}}.indicator-neutral{{color:var(--muted);background:#f2f4f7}}.legend{{color:var(--muted);font-size:13px;margin:0 0 14px}}@media(max-width:650px){{main{{padding-inline:10px}}}}
</style></head><body><main><header><h1>Linux ELF Security Report</h1><p>Focused static-analysis view for ELF executables and shared objects.</p></header><section><h2>Scan Summary</h2><div class="metrics">{metrics}</div></section><section><h2>ELF Executables</h2><p class="legend">Red and orange indicators require review; they are not confirmed vulnerabilities by themselves.</p>{_overview_table(executables,False)}</section><section><h2>Shared Objects</h2><p class="legend">Red and orange indicators require review; they are not confirmed vulnerabilities by themselves.</p>{_overview_table(shared,True)}</section></main></body></html>'''

def generate_report(run_root: Path, output_path: Path | None = None) -> Path:
    run_root=run_root.resolve(); run,inventory,findings=load_run(run_root)
    destination=output_path.resolve() if output_path else run_root/"report.html"
    report=render_report(run,inventory,findings); destination.parent.mkdir(parents=True,exist_ok=True)
    temporary=destination.with_name(f".{destination.name}.tmp"); temporary.write_text(report,encoding="utf-8"); temporary.replace(destination)
    return destination
