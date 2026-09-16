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


def write_run(root: Path, findings: list[dict[str, object]]) -> None:
    normalized = root / "normalized"
    normalized.mkdir(parents=True)
    run = {
        "run_id": "run-test",
        "target": "/opt/product/app",
        "target_root": "/",
        "started_at": "2026-01-01T00:00:00Z",
        "finished_at": "2026-01-01T00:00:01Z",
        "schema_version": "1.5",
    }
    inventory = {
        "schema_version": "1.5",
        "records": [{
            "component_id": "cmp-test",
            "path": "/opt/product/app",
            "type": "elf_executable",
            "status": "SUCCESS",
            "elf": {"class": "ELF64", "machine": "AArch64", "build_id": "build-test"},
            "permissions": {"file": {"mode": "0755", "writable_by_non_owner": False}},
            "dynamic_linking": {"linkage": "DYNAMIC", "custom_search_path": "NONE"},
            "hardening": {"nx": {"status": "ENABLED"}, "fortify": {"status": "UNKNOWN"}},
            "dependencies": [{
                "dependency_name": "libc.so.6",
                "resolution_status": "TARGET_ROOT_CONTEXT_REQUIRED",
                "resolved_path": None,
            }],
        }],
        "summary": {"total": 1, "elf_executable": 1, "elf_shared_object": 0,
                    "malformed_elf": 0, "unsupported": 0},
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
        "affected_path": "/opt/product/lib",
        "component_id": "cmp-test",
        "confidence": "HIGH",
        "classification": "LIKELY_TRUE_POSITIVE",
        "remediation": "Remove non-owner write access.",
        "evidence_refs": ["ev-000009-readelf", "ev-000020-python_os_stat"],
    }


class HtmlReportTests(unittest.TestCase):
    def test_medium_finding_and_inventory_are_rendered(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            run_root = Path(temporary) / "run"
            write_run(run_root, [medium_finding()])
            report = generate_report(run_root).read_text(encoding="utf-8")

        self.assertIn("Writable loader path", report)
        self.assertIn("ELF-WRITABLE-LIB-SEARCH-PATH", report)
        self.assertIn("ev-000009-readelf", report)
        self.assertIn("AArch64", report)
        self.assertIn("TARGET_ROOT_CONTEXT_REQUIRED", report)
        self.assertIn("<strong>1</strong><span>Medium</span>", report)
        Parser().feed(report)

    def test_zero_findings_is_successful(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            run_root = Path(temporary) / "run"
            write_run(run_root, [])
            report = generate_report(run_root).read_text(encoding="utf-8")

        self.assertIn("0 security findings", report)
        self.assertIn("/opt/product/app", report)
        self.assertIn("<strong>0</strong><span>Total</span>", report)

    def test_all_json_values_are_html_escaped(self) -> None:
        attack = '<script>alert("x")</script>'
        with tempfile.TemporaryDirectory() as temporary:
            run_root = Path(temporary) / "run"
            finding = medium_finding(attack)
            finding["evidence_refs"] = [attack]
            write_run(run_root, [finding])
            run_path = run_root / "run.json"
            run = json.loads(run_path.read_text(encoding="utf-8"))
            run["target"] = attack
            run_path.write_text(json.dumps(run), encoding="utf-8")
            report = generate_report(run_root).read_text(encoding="utf-8")

        self.assertNotIn(attack, report)
        self.assertIn("&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;", report)

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


if __name__ == "__main__":
    unittest.main()
