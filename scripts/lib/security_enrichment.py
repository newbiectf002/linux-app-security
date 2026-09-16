#!/usr/bin/env python3
"""Optional P0/P1 static collectors with compact normalized results.

Raw stdout/stderr is always retained by EvidenceRunner.  This module only
keeps small summaries and review cues in inventory.json; tool hits are not
treated as confirmed vulnerabilities.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

from elf_inventory import EvidenceRunner, Invocation


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_YARA_RULES = REPOSITORY_ROOT / "rules" / "elf-review.yar"
MAX_REVIEW_ITEMS = 20
MAX_MATCH_NAMES = 25


def _status(invocation: Invocation, success_codes: set[int] | None = None) -> str:
    success_codes = success_codes or {0}
    if invocation.exit_code == 127:
        return "TOOL_UNAVAILABLE"
    if invocation.exit_code == 124:
        return "TIMEOUT"
    if invocation.exit_code in success_codes:
        return "SUCCESS"
    return "ERROR"


def _result(
    tier: str, checks: list[str], invocation: Invocation, summary: dict[str, Any] | None = None,
    status: str | None = None,
) -> dict[str, Any]:
    return {
        "tier": tier,
        "checks": checks,
        "status": status or _status(invocation),
        "summary": summary or {},
        "evidence_refs": [invocation.reference.evidence_id],
    }


def _json(stdout: str) -> Any | None:
    try:
        return json.loads(stdout)
    except (json.JSONDecodeError, TypeError):
        return None


def _string_review(stdout: str, evidence_id: str) -> list[dict[str, str]]:
    items: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    url = re.compile(r"http://[^\s\"'<>]{4,200}", re.I)
    path = re.compile(r"(?<![\w.])/(?:home|root|tmp|var/tmp|Users)/[^\s\"'<>]{2,180}")
    markers = ("-----BEGIN PRIVATE KEY-----", "-----BEGIN RSA PRIVATE KEY-----")
    for line in stdout.splitlines():
        value = line.strip()
        candidates: list[tuple[str, str, str]] = []
        candidates.extend(("url", hit, "Embedded URL requires contextual review") for hit in url.findall(value))
        candidates.extend(("path", hit, "Embedded absolute path may expose build/runtime context") for hit in path.findall(value))
        candidates.extend(("secret_marker", marker, "Private-key marker requires immediate review") for marker in markers if marker in value)
        for category, hit, reason in candidates:
            key = (category, hit)
            if key in seen:
                continue
            seen.add(key)
            items.append({
                "category": category, "value": hit, "reason": reason,
                "evidence_ref": evidence_id,
            })
            if len(items) >= MAX_REVIEW_ITEMS:
                return items
    return items


def _checksec_summary(stdout: str) -> dict[str, Any]:
    data = _json(stdout)
    if isinstance(data, list) and data and isinstance(data[0], dict):
        data = data[0].get("checks", data[0])
    if isinstance(data, dict):
        # Checksec releases use either the path as the key or a direct object.
        values = next(iter(data.values()), data) if len(data) == 1 else data
        if isinstance(values, dict):
            allow = ("relro", "canary", "nx", "pie", "rpath", "runpath", "fortify_source")
            return {key: values[key] for key in allow if key in values}
    return {}


def _rule_names(data: Any) -> list[str]:
    if not isinstance(data, dict):
        return []
    rules = data.get("rules")
    if isinstance(rules, dict):
        return sorted(str(name) for name in rules)[:MAX_MATCH_NAMES]
    if isinstance(rules, list):
        names = []
        for item in rules:
            if isinstance(item, dict):
                name = item.get("name") or item.get("rule") or item.get("id")
                if name:
                    names.append(str(name))
        return sorted(set(names))[:MAX_MATCH_NAMES]
    return []


def collect_binary_tools(
    path: Path, runner: EvidenceRunner, profile: str,
    yara_rules: Path | None = None,
) -> tuple[dict[str, Any], list[dict[str, str]]]:
    """Run static tools for one ELF without executing the target."""
    results: dict[str, Any] = {}
    review: list[dict[str, str]] = []

    strings = runner.run(["strings", "-a", "--", str(path)], path)
    string_items = _string_review(strings.stdout, strings.reference.evidence_id) if strings.exit_code == 0 else []
    results["strings"] = _result(
        "P0", ["CHK-08", "CHK-09", "CHK-13", "CHK-17"], strings,
        {"review_item_count": len(string_items)},
    )
    review.extend(string_items)

    checksec = runner.run(["checksec", "file", str(path), "--output=json"], path)
    results["checksec"] = _result(
        "P0", ["CHK-05"], checksec,
        _checksec_summary(checksec.stdout) if checksec.exit_code == 0 else {},
    )

    lddtree = runner.run(["lddtree", "-l", str(path)], path)
    libraries = [line.strip() for line in lddtree.stdout.splitlines() if line.strip()]
    results["lddtree"] = _result(
        "P0", ["CHK-12"], lddtree,
        {"resolved_path_count": len(libraries)},
    )

    getfacl = runner.run(["getfacl", "-cp", "--absolute-names", str(path)], path)
    acl_lines = [line for line in getfacl.stdout.splitlines() if line and not line.startswith("#")]
    extended_acl = any(line.startswith(("user:", "group:")) and not line.startswith(("user::", "group::")) for line in acl_lines)
    results["getfacl"] = _result(
        "P0", ["CHK-03"], getfacl,
        {"extended_acl_present": extended_acl} if getfacl.exit_code == 0 else {},
    )

    if profile != "p1":
        return results, review

    capa = runner.run(["capa", "-q", "-j", str(path)], path, timeout=300)
    capa_data = _json(capa.stdout) if capa.exit_code == 0 else None
    capa_rules = _rule_names(capa_data)
    results["capa"] = _result(
        "P1", ["CHK-06", "CHK-09", "CHK-13", "CHK-15", "CHK-16", "CHK-17"], capa,
        {"matched_rule_count": len(capa_rules), "matched_rules": capa_rules},
    )
    high_signal_capa = [
        name for name in capa_rules
        if any(marker in name.lower() for marker in (
            "anti-analysis", "credential", "download", "execute", "inject", "persistence", "shell",
        ))
    ]
    if high_signal_capa:
        review.append({
            "category": "capa", "value": ", ".join(high_signal_capa[:5]),
            "reason": "High-signal behavioral capability matches require analyst validation",
            "evidence_ref": capa.reference.evidence_id,
        })

    cwe = runner.run(["cwe_checker", str(path), "--json", "--quiet"], path, timeout=600)
    cwe_data = _json(cwe.stdout) if cwe.exit_code == 0 else None
    cwe_names = _rule_names(cwe_data)
    if not cwe_names and isinstance(cwe_data, list):
        cwe_names = sorted({str(item.get("name") or item.get("cwe") or item.get("id")) for item in cwe_data if isinstance(item, dict)})[:MAX_MATCH_NAMES]
        cwe_names = [name for name in cwe_names if name not in {"None", ""}]
    results["cwe_checker"] = _result(
        "P1", ["CHK-07"], cwe,
        {"reported_check_count": len(cwe_names), "reported_checks": cwe_names},
    )
    if cwe_names:
        review.append({
            "category": "cwe_checker", "value": f"{len(cwe_names)} candidate weakness check(s)",
            "reason": "Static-analysis candidates may contain false positives",
            "evidence_ref": cwe.reference.evidence_id,
        })

    rules = yara_rules or DEFAULT_YARA_RULES
    if not rules.is_file():
        yara = runner.run(["yara", str(rules), str(path)], path)
        results["yara"] = _result("P1", ["CHK-08", "CHK-09", "CHK-10", "CHK-13", "CHK-16", "CHK-17", "CHK-18"], yara, status="DATA_UNAVAILABLE")
    else:
        yara = runner.run(["yara", str(rules), str(path)], path, timeout=120)
        matches = sorted({line.split(maxsplit=1)[0] for line in yara.stdout.splitlines() if line.strip()})[:MAX_MATCH_NAMES]
        results["yara"] = _result(
            "P1", ["CHK-08", "CHK-09", "CHK-10", "CHK-13", "CHK-16", "CHK-17", "CHK-18"], yara,
            {"match_count": len(matches), "matches": matches},
        )
        if matches:
            review.append({
                "category": "yara", "value": ", ".join(matches),
                "reason": "Rule match requires analyst validation",
                "evidence_ref": yara.reference.evidence_id,
            })

    clam_database = os.environ.get("CLAMAV_DB_DIR")
    clam_command = ["clamscan", "--no-summary", "--infected"]
    if clam_database:
        clam_command.append(f"--database={clam_database}")
    clam = runner.run([*clam_command, str(path)], path, timeout=300)
    clam_status = _status(clam, {0, 1})
    if clam.exit_code == 2 and (
        (clam_database and not Path(clam_database).is_dir())
        or any(marker in clam.stderr.lower() for marker in ("database", "no supported database", "can't get file status"))
    ):
        clam_status = "DATA_UNAVAILABLE"
    detected = clam.exit_code == 1
    results["clamscan"] = _result(
        "P1", ["CHK-17"], clam,
        {"malware_detected": detected}, status=clam_status,
    )
    if detected:
        review.append({
            "category": "malware", "value": "ClamAV signature match",
            "reason": "Signature match requires quarantine and independent validation",
            "evidence_ref": clam.reference.evidence_id,
        })
    return results, review[:MAX_REVIEW_ITEMS]


def collect_target_tools(target: Path, runner: EvidenceRunner, profile: str) -> dict[str, Any]:
    """Run target-level SBOM, vulnerability, and secret collectors."""
    if profile != "p1":
        return {}
    results: dict[str, Any] = {}

    syft = runner.run(["syft", "scan", str(target), "-o", "syft-json"], target, timeout=900)
    syft_data = _json(syft.stdout) if syft.exit_code == 0 else None
    artifacts = syft_data.get("artifacts") if isinstance(syft_data, dict) else None
    results["syft"] = _result(
        "P1", ["CHK-12"], syft,
        {"package_count": len(artifacts)} if isinstance(artifacts, list) else {},
    )

    if syft.exit_code == 0:
        sbom_path = runner.run_root / syft.reference.path / "stdout.txt"
        grype_env = os.environ.copy()
        grype_env.update({"GRYPE_DB_AUTO_UPDATE": "false", "GRYPE_CHECK_FOR_APP_UPDATE": "false"})
        grype = runner.run(["grype", f"sbom:{sbom_path}", "-o", "json"], target, timeout=900, environment=grype_env)
        grype_data = _json(grype.stdout) if grype.exit_code == 0 else None
        matches = grype_data.get("matches") if isinstance(grype_data, dict) else None
        grype_status = _status(grype)
        if grype.exit_code not in {0, 127, 124} and "database" in grype.stderr.lower():
            grype_status = "DATA_UNAVAILABLE"
        results["grype"] = _result(
            "P1", ["CHK-12"], grype,
            {"candidate_vulnerability_count": len(matches)} if isinstance(matches, list) else {},
            status=grype_status,
        )
    else:
        results["grype"] = {
            "tier": "P1", "checks": ["CHK-12"], "status": "SKIPPED_PREREQUISITE",
            "summary": {}, "evidence_refs": [],
        }

    trivy_env = os.environ.copy()
    trivy_env.update({"TRIVY_SKIP_DB_UPDATE": "true", "TRIVY_DISABLE_VEX_NOTICE": "true"})
    trivy = runner.run(
        ["trivy", "filesystem", "--scanners", "secret", "--format", "json", "--quiet", str(target)],
        target, timeout=900, environment=trivy_env,
    )
    trivy_data = _json(trivy.stdout) if trivy.exit_code == 0 else None
    secrets = []
    if isinstance(trivy_data, dict):
        for result in trivy_data.get("Results", []) or []:
            if isinstance(result, dict):
                secrets.extend(result.get("Secrets", []) or [])
    results["trivy_secret"] = _result(
        "P1", ["CHK-08"], trivy,
        {"candidate_secret_count": len(secrets)},
    )
    return results
