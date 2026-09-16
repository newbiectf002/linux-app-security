#!/usr/bin/env python3
"""Convert normalized findings to DefectDojo Generic Findings Import JSON."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


SUPPORTED_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
REQUIRED_FINDING_FIELDS = {
    "title": str,
    "severity": str,
    "rule_id": str,
    "component_id": str,
    "affected_path": str,
    "confidence": str,
    "classification": str,
    "evidence_refs": list,
    "remediation": str,
}


def _require_nonempty_string(value: Any, field: str, index: int) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"finding {index} field '{field}' must be a non-empty string")
    return value


def validate_document(document: Any) -> dict[str, Any]:
    if not isinstance(document, dict):
        raise ValueError("normalized findings input must be a JSON object")
    findings = document.get("findings")
    if not isinstance(findings, list):
        raise ValueError("normalized findings input must contain a 'findings' array")
    source_run_id = document.get("source_run_id")
    if source_run_id is not None and not isinstance(source_run_id, str):
        raise ValueError("'source_run_id' must be a string or null")
    for index, item in enumerate(findings):
        if not isinstance(item, dict):
            raise ValueError(f"finding {index} must be a JSON object")
        for field, expected_type in REQUIRED_FINDING_FIELDS.items():
            if field not in item:
                raise ValueError(f"finding {index} is missing required field '{field}'")
            if not isinstance(item[field], expected_type):
                raise ValueError(
                    f"finding {index} field '{field}' must be {expected_type.__name__}"
                )
        for field in REQUIRED_FINDING_FIELDS:
            if field != "evidence_refs":
                _require_nonempty_string(item[field], field, index)
        severity = item["severity"].upper()
        if severity not in SUPPORTED_SEVERITIES:
            raise ValueError(f"finding {index} has unsupported severity '{item['severity']}'")
        if not all(isinstance(reference, str) and reference for reference in item["evidence_refs"]):
            raise ValueError(f"finding {index} field 'evidence_refs' must contain strings")
    return document


def _unique_id(item: dict[str, Any]) -> str:
    identity = "\0".join((item["rule_id"], item["component_id"], item["affected_path"]))
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()


def convert_document(document: Any) -> dict[str, Any]:
    source = validate_document(document)
    exported = []
    for item in source["findings"]:
        evidence = ", ".join(item["evidence_refs"]) or "None recorded"
        description = "\n".join([
            f"Rule ID: {item['rule_id']}",
            f"Component ID: {item['component_id']}",
            f"Affected path: {item['affected_path']}",
            f"Classification: {item['classification']}",
            f"Confidence: {item['confidence']}",
            f"Evidence references: {evidence}",
        ])
        exported.append({
            "component_name": item["component_id"],
            "description": description,
            "file_path": item["affected_path"],
            "mitigation": item["remediation"],
            "references": "\n".join(item["evidence_refs"]),
            "severity": item["severity"].title(),
            "static_finding": True,
            "title": item["title"],
            "unique_id_from_tool": _unique_id(item),
            "vuln_id_from_tool": item["rule_id"],
        })
    return {
        "findings": exported,
        "name": "Linux ELF Security Findings",
        "type": "Linux ELF Security",
    }


def default_output_path(input_path: Path) -> Path:
    parent = input_path.resolve().parent
    if parent.name == "normalized":
        parent = parent.parent
    return parent / "defectdojo-generic-findings.json"


def export_file(input_path: Path, output_path: Path | None = None) -> Path:
    input_path = input_path.resolve()
    destination = output_path.resolve() if output_path else default_output_path(input_path)
    with input_path.open(encoding="utf-8") as source_file:
        document = json.load(source_file)
    exported = convert_document(document)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.tmp")
    temporary.write_text(
        json.dumps(exported, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    temporary.replace(destination)
    return destination
