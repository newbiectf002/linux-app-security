#!/usr/bin/env python3
"""Minimal Step 6 correlation rules over normalized ELF records."""

from __future__ import annotations

from typing import Any, Iterable


EVALUATION_SCHEMA_VERSION = "1.0"


def unique_evidence(references: Iterable[str], valid_ids: set[str]) -> list[str]:
    return list(dict.fromkeys(reference for reference in references if reference in valid_ids))


def is_privileged(permissions: dict[str, Any]) -> bool:
    file_permissions = permissions.get("file") or {}
    capability_collection = permissions.get("capability_collection") or {}
    return bool(
        file_permissions.get("setuid") is True
        or file_permissions.get("setgid") is True
        or (
            capability_collection.get("status") == "PRESENT"
            and capability_collection.get("capabilities")
        )
    )


def finding(
    rule_id: str, component_id: str, title: str, severity: str,
    affected_path: str, evidence_refs: list[str], remediation: str,
) -> dict[str, Any]:
    return {
        "rule_id": rule_id,
        "component_id": component_id,
        "title": title,
        "severity": severity,
        "confidence": "HIGH",
        "classification": "LIKELY_TRUE_POSITIVE",
        "affected_path": affected_path,
        "evidence_refs": evidence_refs,
        "remediation": remediation,
    }


def evaluate_record(record: dict[str, Any]) -> list[dict[str, Any]]:
    component_type = record.get("type")
    if component_type not in {"elf_executable", "elf_shared_object"}:
        return []
    permissions = record.get("permissions") or {}
    file_permissions = permissions.get("file") or {}
    component_id = record.get("component_id")
    affected_path = record.get("path")
    if not component_id or not affected_path:
        return []
    valid_ids = {
        reference.get("evidence_id")
        for reference in record.get("raw_evidence", [])
        if reference.get("evidence_id")
    }
    file_refs = unique_evidence(
        (permissions.get("stat_cross_check") or {}).get("evidence_refs", []), valid_ids,
    )
    capability_refs = unique_evidence(
        (permissions.get("capability_collection") or {}).get("evidence_refs", []), valid_ids,
    )
    privileged = is_privileged(permissions)
    writable = file_permissions.get("writable_by_non_owner") is True
    findings: list[dict[str, Any]] = []

    if component_type == "elf_executable" and writable:
        if privileged:
            findings.append(finding(
                "ELF-PRIV-WRITABLE-EXEC", component_id,
                "Privileged executable is writable by a non-owner", "HIGH", affected_path,
                unique_evidence([*file_refs, *capability_refs], valid_ids),
                "Remove non-owner write access and review the privilege mechanism.",
            ))
        else:
            findings.append(finding(
                "ELF-WRITABLE-EXEC", component_id,
                "Executable is writable by a non-owner", "MEDIUM", affected_path,
                file_refs, "Remove group/world write access from the executable.",
            ))

    if component_type == "elf_shared_object" and writable:
        findings.append(finding(
            "ELF-WRITABLE-SHARED-OBJECT", component_id,
            "Shared object is writable by a non-owner", "MEDIUM", affected_path,
            file_refs, "Remove group/world write access from the shared object.",
        ))

    if component_type == "elf_executable" and privileged:
        dynamic_linking = record.get("dynamic_linking") or {}
        for directory in permissions.get("search_path_directories", []):
            directory_permissions = directory.get("permissions") or {}
            if (
                directory.get("resolution_status") != "RESOLVED"
                or directory_permissions.get("writable_by_non_owner") is not True
                or not directory.get("resolved")
            ):
                continue
            source = str(directory.get("source", "")).lower()
            path_refs = (dynamic_linking.get(source) or {}).get("evidence_refs", [])
            directory_refs = directory.get("evidence_refs", [])
            findings.append(finding(
                "ELF-PRIV-WRITABLE-LIB-SEARCH-PATH", component_id,
                "Privileged executable uses a non-owner-writable library search directory",
                "HIGH", directory["resolved"],
                unique_evidence([*capability_refs, *file_refs, *path_refs, *directory_refs], valid_ids),
                "Remove non-owner write access or remove the directory from RPATH/RUNPATH.",
            ))
    return findings


def evaluate_inventory(inventory: dict[str, Any]) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for record in inventory.get("records", []):
        for item in evaluate_record(record):
            identity = (item["rule_id"], item["component_id"], item["affected_path"])
            if identity not in seen:
                seen.add(identity)
                findings.append(item)
    findings.sort(key=lambda item: (item["rule_id"], item["component_id"], item["affected_path"]))
    return {
        "schema_version": EVALUATION_SCHEMA_VERSION,
        "source_schema_version": inventory.get("schema_version"),
        "source_run_id": inventory.get("run_id"),
        "evaluation_scope": "STEP_6_MINIMAL_ELF_CORRELATION",
        "findings": findings,
        "summary": {
            "total": len(findings),
            "high": sum(item["severity"] == "HIGH" for item in findings),
            "medium": sum(item["severity"] == "MEDIUM" for item in findings),
            "low": sum(item["severity"] == "LOW" for item in findings),
        },
    }
