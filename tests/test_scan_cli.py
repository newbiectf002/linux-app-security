from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "scripts" / "scan" / "scan-elf.py"
SPEC = importlib.util.spec_from_file_location("scan_elf_cli", CLI)
assert SPEC and SPEC.loader
SCAN_CLI = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SCAN_CLI)


def compile_target(root: Path) -> Path:
    source = root / "fixture.c"
    target = root / "app"
    source.write_text("int main(void) { return 0; }\n", encoding="utf-8")
    subprocess.run(["gcc", "-o", str(target), str(source)], check=True)
    return target


@unittest.skipUnless(
    shutil.which("gcc") and shutil.which("readelf"),
    "requires gcc and readelf",
)
class ScanCliTests(unittest.TestCase):
    def test_success_with_target_root_preserves_output_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = compile_target(root)
            output = root / "output"
            result = subprocess.run(
                [
                    sys.executable, str(CLI), str(target),
                    "--target-root", str(root), "--output-dir", str(output),
                ],
                check=False, capture_output=True, text=True,
            )

            self.assertEqual(0, result.returncode, result.stderr)
            report = json.loads(result.stdout)
            run_root = Path(report["run_root"])
            self.assertEqual(str(run_root / "run.json"), report["run_metadata"])
            self.assertTrue((run_root / "run.json").is_file())
            self.assertTrue((run_root / "normalized" / "inventory.json").is_file())
            self.assertTrue((run_root / "normalized" / "findings.json").is_file())
            self.assertTrue((run_root / "raw").is_dir())
            self.assertEqual(str(run_root / "report.html"), report["report_output"])
            self.assertTrue((run_root / "report.html").is_file())
            run = json.loads((run_root / "run.json").read_text(encoding="utf-8"))
            self.assertEqual(str(root), run["target_root"])

    def test_no_report_skips_html_generation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = compile_target(root)
            output = root / "output"
            result = subprocess.run(
                [
                    sys.executable, str(CLI), str(target), "--target-root", str(root),
                    "--output-dir", str(output), "--no-report",
                ],
                check=False, capture_output=True, text=True,
            )

            self.assertEqual(0, result.returncode, result.stderr)
            response = json.loads(result.stdout)
            run_root = Path(response["run_root"])
            self.assertNotIn("report_output", response)
            self.assertFalse((run_root / "report.html").exists())

    def test_report_failure_preserves_completed_scan_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = compile_target(root)
            output = root / "output"
            stderr = io.StringIO()
            argv = [str(CLI), str(target), "--target-root", str(root), "--output-dir", str(output)]
            with (
                mock.patch.object(sys, "argv", argv),
                mock.patch.object(SCAN_CLI, "generate_report", side_effect=ValueError("render failed")),
                contextlib.redirect_stderr(stderr),
            ):
                return_code = SCAN_CLI.main()

            run_roots = list((output / "runs").iterdir())
            self.assertEqual(1, return_code)
            self.assertEqual(1, len(run_roots))
            run_root = run_roots[0]
            self.assertTrue((run_root / "run.json").is_file())
            self.assertTrue((run_root / "normalized" / "inventory.json").is_file())
            self.assertTrue((run_root / "normalized" / "findings.json").is_file())
            self.assertTrue((run_root / "raw").is_dir())
            self.assertFalse((run_root / "report.html").exists())
            self.assertIn("scan output retained at", stderr.getvalue())

    def test_unsupported_single_file_returns_nonzero(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "plain.txt"
            target.write_text("not an ELF\n", encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(CLI), str(target), "--output-dir", str(root / "output")],
                check=False, capture_output=True, text=True,
            )

            self.assertEqual(2, result.returncode)
            self.assertIn("unsupported input", result.stderr)
            self.assertIn("inspection evidence retained at", result.stderr)

    def test_missing_target_returns_nonzero(self) -> None:
        result = subprocess.run(
            [sys.executable, str(CLI), "/definitely/not/a/scanner-target"],
            check=False, capture_output=True, text=True,
        )

        self.assertEqual(2, result.returncode)
        self.assertIn("target must be an existing file or directory", result.stderr)


if __name__ == "__main__":
    unittest.main()
