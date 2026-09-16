from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from html.parser import HTMLParser
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts" / "lib"))

from html_report import generate_report  # noqa: E402


class Parser(HTMLParser):
    pass


def write_run(root: Path, findings: list[dict[str, object]], extra_records: list[dict[str, object]] | None = None) -> None:
    normalized = root / "normalized"
    normalized.mkdir(parents=True)
    run = {
        "run_id": "run-test",
        "target": "/workspace/linux-app-security/real_apps/abc_RealSample",
        "target_root": "/workspace/linux-app-security/real_apps/abc_RealSample",
        "started_at": "2026-01-01T00:00:00Z",
        "finished_at": "2026-01-01T00:00:01Z",
        "schema_version": "1.5",
    }
    inventory = {
        "schema_version": "1.5",
        "records": [{
            "component_id": "cmp-test",
            "path": "/workspace/linux-app-security/real_apps/abc_RealSample/bin/app",
            "type": "elf_executable",
            "status": "SUCCESS",
            "elf": {"class": "ELF64", "machine": "AArch64", "build_id": "build-test"},
            "permissions": {"file": {"mode": "0755", "writable_by_non_owner": False}},
            "dynamic_linking": {"linkage": "DYNAMIC", "custom_search_path": "RUNPATH",
                                "rpath": {"present": False, "original_values": []},
                                "runpath": {"present": True, "original_values": ["$ORIGIN/lib"]}},
            "hardening": {"nx": {"status": "ENABLED"}, "fortify": {"status": "UNKNOWN"}},
            "dependencies": [{
                "dependency_name": "libc.so.6",
                "resolution_status": "TARGET_ROOT_CONTEXT_REQUIRED",
                "resolved_path": None,
            }],
        }, *(extra_records or [])],
        "summary": {"total": 1 + len(extra_records or []), "elf_executable": 1,
                    "elf_shared_object": 0, "malformed_elf": 0, "unsupported": 0},
    }
    findings_document = {"schema_version": "1.0", "findings": findings}
    (root / "run.json").write_text(json.dumps(run), encoding="utf-8")
    (normalized / "inventory.json").write_text(json.dumps(inventory), encoding="utf-8")
    (normalized / "findings.json").write_text(json.dumps(findings_document), encoding="utf-8")


def medium_finding(title: str = "Writable loader path") -> dict[str, object]:
    return {
        "severity": "MEDIUM",
        "title": title,
        "rule_id": "ELF-WRITABLE-LIB-SEARCH-PATH",
        "affected_path": "/workspace/linux-app-security/real_apps/abc_RealSample/lib",
        "component_id": "cmp-test",
        "confidence": "HIGH",
        "classification": "LIKELY_TRUE_POSITIVE",
        "remediation": "Remove non-owner write access.",
        "evidence_refs": ["ev-000009-readelf", "ev-000020-python_os_stat"],
    }


class HtmlReportTests(unittest.TestCase):
    def test_summary_is_rendered_without_finding_details(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            run_root = Path(temporary) / "run"
            write_run(run_root, [medium_finding()])
            report = generate_report(run_root).read_text(encoding="utf-8")

        self.assertNotIn("Writable loader path", report)
        self.assertNotIn("ELF-WRITABLE-LIB-SEARCH-PATH", report)
        self.assertNotIn("Security Findings", report)
        self.assertNotIn("Binary Details", report)
        self.assertNotIn("Scan Metadata", report)
        self.assertIn("AArch64", report)
        self.assertIn("<strong>1</strong><span>Medium</span>", report)
        Parser().feed(report)

    def test_zero_findings_is_successful(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            run_root = Path(temporary) / "run"
            write_run(run_root, [])
            report = generate_report(run_root).read_text(encoding="utf-8")

        self.assertIn("<td>app</td>", report)
        self.assertIn("<strong>0</strong><span>Total findings</span>", report)

    def test_all_json_values_are_html_escaped(self) -> None:
        attack = '<img onerror="x">'
        with tempfile.TemporaryDirectory() as temporary:
            run_root = Path(temporary) / "run"
            write_run(run_root, [medium_finding(attack)])
            inventory_path = run_root / "normalized" / "inventory.json"
            inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
            inventory["records"][0]["path"] = f"/tmp/{attack}"
            inventory_path.write_text(json.dumps(inventory), encoding="utf-8")
            report = generate_report(run_root).read_text(encoding="utf-8")

        self.assertNotIn(attack, report)
        self.assertIn("&lt;img onerror=&quot;x&quot;&gt;", report)

    def test_missing_and_malformed_input_return_nonzero(self) -> None:
        cli = ROOT / "scripts" / "report" / "generate-html-report.py"
        missing = subprocess.run(
            [sys.executable, str(cli), "/definitely/not/a/run"],
            check=False, capture_output=True, text=True,
        )
        with tempfile.TemporaryDirectory() as temporary:
            run_root = Path(temporary) / "run"
            write_run(run_root, [])
            (run_root / "normalized" / "findings.json").write_text("{bad", encoding="utf-8")
            malformed = subprocess.run(
                [sys.executable, str(cli), str(run_root)],
                check=False, capture_output=True, text=True,
            )

        self.assertEqual(2, missing.returncode)
        self.assertIn("run directory does not exist", missing.stderr)
        self.assertEqual(2, malformed.returncode)
        self.assertIn("malformed JSON", malformed.stderr)

    def test_output_is_deterministic_and_has_no_external_assets(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            run_root = Path(temporary) / "run"
            write_run(run_root, [medium_finding()])
            first = generate_report(run_root).read_bytes()
            second = generate_report(run_root).read_bytes()

        self.assertEqual(first, second)
        lowered = first.lower()
        self.assertNotIn(b"http://", lowered)
        self.assertNotIn(b"https://", lowered)
        self.assertNotIn(b"<script", lowered)

    def test_filters_non_elf_and_normalizes_paths(self) -> None:
        unsupported = {
            "component_id": "cmp-qm", "path": "/workspace/linux-app-security/real_apps/abc_RealSample/translations/qt_ca.qm",
            "type": "unsupported", "status": "NOT_IMPLEMENTED_IN_CURRENT_MVP",
        }
        pak = {"component_id": "cmp-pak", "path": "/workspace/linux-app-security/real_apps/abc_RealSample/app_loader/locales/fi.pak",
               "type": "unsupported", "status": "NOT_IMPLEMENTED_IN_CURRENT_MVP"}
        dll = {"component_id": "cmp-dll", "path": "/workspace/linux-app-security/real_apps/abc_RealSample/App.dll",
               "type": "unsupported", "status": "NOT_IMPLEMENTED_IN_CURRENT_MVP"}
        shared = {
            "component_id": "cmp-so", "path": "/workspace/linux-app-security/real_apps/abc_RealSample/lib/libfoo.so",
            "type": "elf_shared_object", "status": "SUCCESS", "architecture": "x86_64",
            "elf": {"class": "ELF64", "machine": "x86-64", "elf_type": "DYN"},
            "hardening": {"nx": {"status": "ENABLED"}, "pie": {"status": "NOT_APPLICABLE"},
                          "stack_canary": {"status": "ENABLED"}, "relro": {"status": "FULL"},
                          "fortify": {"status": "ENABLED"}},
            "dynamic_linking": {"rpath": {"present": False, "original_values": []},
                                "runpath": {"present": False, "original_values": []}},
            "permissions": {"file": {"writable_by_non_owner": False}},
            "capabilities": {"dynamic_loading": {"detected": True, "symbols": ["dlopen"]}},
            "dependencies": [],
        }
        with tempfile.TemporaryDirectory() as temporary:
            run_root = Path(temporary) / "run"
            write_run(run_root, [], [unsupported, pak, dll, shared])
            report = generate_report(run_root).read_text(encoding="utf-8")
        self.assertNotIn("/workspace/linux-app-security/", report)
        self.assertNotIn("NOT_IMPLEMENTED_IN_CURRENT_MVP", report)
        self.assertNotIn("fi.pak", report)
        self.assertNotIn("qt_ca.qm", report)
        self.assertNotIn("App.dll", report)
        self.assertNotIn("Component ID", report)
        self.assertIn("<td>app</td>", report)
        self.assertIn("<td>libfoo.so</td>", report)
        self.assertIn("DSO / PIC", report)
        self.assertNotIn("No dependencies recorded", report)
        self.assertNotIn("writable by non-owner", report)

    def test_conditional_capabilities_dependencies_and_writable_warning(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            run_root = Path(temporary) / "run"
            write_run(run_root, [])
            path = run_root / "normalized" / "inventory.json"
            data = json.loads(path.read_text())
            record = data["records"][0]
            record["capabilities"] = {
                "network": {"detected": False, "symbols": []},
                "dynamic_loading": {"detected": True, "symbols": ["dlopen", "dlsym"]},
            }
            record["permissions"]["file"]["writable_by_non_owner"] = True
            path.write_text(json.dumps(data))
            report = generate_report(run_root).read_text(encoding="utf-8")
        self.assertIn("$ORIGIN/lib", report)
        self.assertNotIn("Dynamic Loading", report)
        self.assertNotIn("writable by non-owner", report)
        self.assertNotIn("TARGET_ROOT_CONTEXT_REQUIRED", report)

    def test_suspicious_summary_indicators_are_highlighted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            run_root = Path(temporary) / "run"
            write_run(run_root, [])
            path = run_root / "normalized" / "inventory.json"
            data = json.loads(path.read_text())
            data["records"][0]["hardening"].update({
                "nx": {"status": "DISABLED"},
                "pie": {"status": "DISABLED"},
                "stack_canary": {"status": "NOT_DETECTED"},
                "relro": {"status": "PARTIAL"},
                "fortify": {"status": "NOT_DETECTED"},
            })
            path.write_text(json.dumps(data))
            report = generate_report(run_root).read_text(encoding="utf-8")

        self.assertIn('class="indicator indicator-alert">Disabled</span>', report)
        self.assertIn('class="indicator indicator-alert">No PIE</span>', report)
        self.assertIn('class="indicator indicator-review">Partial</span>', report)
        self.assertIn('class="indicator indicator-review">$ORIGIN/lib</span>', report)
        self.assertIn("not confirmed vulnerabilities", report)


if __name__ == "__main__":
    unittest.main()
