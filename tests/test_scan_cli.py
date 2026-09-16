from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "scripts" / "scan" / "scan-elf.py"


@unittest.skipUnless(
    shutil.which("gcc") and shutil.which("readelf"),
    "requires gcc and readelf",
)
class ScanCliTests(unittest.TestCase):
    def test_success_with_target_root_preserves_output_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "fixture.c"
            target = root / "app"
            output = root / "output"
            source.write_text("int main(void) { return 0; }\n", encoding="utf-8")
            subprocess.run(["gcc", "-o", str(target), str(source)], check=True)
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
            run = json.loads((run_root / "run.json").read_text(encoding="utf-8"))
            self.assertEqual(str(root), run["target_root"])

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
