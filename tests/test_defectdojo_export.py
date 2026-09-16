from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts" / "lib"))

from defectdojo_export import convert_document, export_file  # noqa: E402


def normalized_finding(severity: str = "MEDIUM") -> dict[str, object]:
    return {
        "affected_path": "/opt/product/lib",
        "classification": "LIKELY_TRUE_POSITIVE",
        "component_id": "cmp-example",
        "confidence": "HIGH",
        "evidence_refs": ["ev-000009-readelf", "ev-000020-python_os_stat"],
        "remediation": "Remove non-owner write access.",
        "rule_id": "ELF-WRITABLE-LIB-SEARCH-PATH",
        "severity": severity,
        "title": "Executable uses a non-owner-writable library search directory",
    }


def normalized_document(findings: list[dict[str, object]]) -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "source_run_id": "run-example",
        "findings": findings,
        "summary": {"total": len(findings)},
    }


class DefectDojoExportTests(unittest.TestCase):
    def test_medium_and_high_findings_are_mapped(self) -> None:
        medium = normalized_finding()
        high = normalized_finding("HIGH")
        high["rule_id"] = "ELF-PRIV-WRITABLE-LIB-SEARCH-PATH"
        high["title"] = "Privileged executable uses a writable search directory"

        exported = convert_document(normalized_document([medium, high]))

        self.assertEqual(["Medium", "High"], [item["severity"] for item in exported["findings"]])
        first = exported["findings"][0]
        self.assertEqual(medium["rule_id"], first["vuln_id_from_tool"])
        self.assertEqual(medium["affected_path"], first["file_path"])
        self.assertEqual(medium["component_id"], first["component_name"])
        self.assertIn("Confidence: HIGH", first["description"])
        self.assertIsInstance(first["references"], str)
        for reference in medium["evidence_refs"]:
            self.assertIn(reference, first["references"])
        for field in (
            "title", "severity", "description", "mitigation", "references", "file_path",
            "component_name", "unique_id_from_tool", "vuln_id_from_tool",
        ):
            self.assertIsInstance(first[field], str)
        self.assertIsInstance(first["static_finding"], bool)

    def test_zero_findings_is_valid(self) -> None:
        self.assertEqual([], convert_document(normalized_document([]))["findings"])

    def test_malformed_input_is_rejected_by_cli(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "findings.json"
            source.write_text('{"findings": [{"title": "incomplete"}]}\n', encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(ROOT / "scripts" / "export" / "export-defectdojo.py"), str(source)],
                check=False, capture_output=True, text=True,
            )
        self.assertEqual(2, result.returncode)
        self.assertIn("missing required field", result.stderr)

    def test_output_is_deterministic_and_omits_unsupported_claims(self) -> None:
        document = normalized_document([normalized_finding()])
        first = json.dumps(convert_document(document), sort_keys=True)
        second = json.dumps(convert_document(document), sort_keys=True)
        finding = convert_document(document)["findings"][0]
        reordered_finding = dict(reversed(list(normalized_finding().items())))
        alternate = normalized_document([reordered_finding])
        alternate["source_run_id"] = "run-different"
        alternate_id = convert_document(alternate)["findings"][0]["unique_id_from_tool"]

        self.assertEqual(first, second)
        self.assertEqual(finding["unique_id_from_tool"], alternate_id)
        for absent in ("cve", "cwe", "component_version", "verified", "false_p"):
            self.assertNotIn(absent, finding)

    def test_default_output_is_created_at_run_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            run_root = Path(temporary) / "runs" / "run-example"
            normalized = run_root / "normalized"
            normalized.mkdir(parents=True)
            source = normalized / "findings.json"
            source.write_text(json.dumps(normalized_document([])), encoding="utf-8")

            output = export_file(source)

            self.assertEqual(run_root / "defectdojo-generic-findings.json", output)
            self.assertTrue(output.is_file())


if __name__ == "__main__":
    unittest.main()
