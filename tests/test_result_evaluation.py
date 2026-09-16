from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts" / "lib"))

from elf_inventory import scan  # noqa: E402
from result_evaluation import is_privileged  # noqa: E402


@unittest.skipUnless(shutil.which("gcc") and shutil.which("readelf"), "requires gcc and readelf")
class ResultEvaluationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        source = self.root / "fixture.c"
        source.write_text("int main(void) { return 0; }\n", encoding="utf-8")
        shared_source = self.root / "shared.c"
        shared_source.write_text("int exported_fixture(void) { return 0; }\n", encoding="utf-8")
        base = self.root / "base"
        subprocess.run(["gcc", "-o", str(base), str(source)], check=True)

        self.writable_executable = self.root / "writable-executable"
        shutil.copy2(base, self.writable_executable)
        self.writable_executable.chmod(0o775)

        self.privileged_writable_executable = self.root / "privileged-writable-executable"
        shutil.copy2(base, self.privileged_writable_executable)
        self.privileged_writable_executable.chmod(0o4775)

        self.writable_shared_object = self.root / "writable.so"
        subprocess.run([
            "gcc", "-shared", "-fPIC", "-Wl,-soname,writable.so",
            "-o", str(self.writable_shared_object), str(shared_source),
        ], check=True)
        self.writable_shared_object.chmod(0o775)

        self.safe_root = self.root / "safe"
        safe_bin = self.safe_root / "bin"
        self.safe_lib = self.safe_root / "lib"
        safe_bin.mkdir(parents=True)
        self.safe_lib.mkdir()
        self.safe_executable = safe_bin / "app"
        subprocess.run([
            "gcc", "-o", str(self.safe_executable), str(source),
            "-Wl,--enable-new-dtags,-rpath,$ORIGIN/../lib",
        ], check=True)
        self.safe_executable.chmod(0o755)
        self.safe_lib.chmod(0o755)

        self.nonpriv_root = self.root / "nonpriv"
        nonpriv_bin = self.nonpriv_root / "bin"
        self.nonpriv_lib = self.nonpriv_root / "lib"
        nonpriv_bin.mkdir(parents=True)
        self.nonpriv_lib.mkdir()
        self.nonpriv_executable = nonpriv_bin / "app"
        subprocess.run([
            "gcc", "-o", str(self.nonpriv_executable), str(source),
            "-Wl,--enable-new-dtags,-rpath,$ORIGIN/../lib",
        ], check=True)
        self.nonpriv_executable.chmod(0o755)
        self.nonpriv_lib.chmod(0o775)

        self.rpath_root = self.root / "rpath"
        rpath_bin = self.rpath_root / "bin"
        self.rpath_lib = self.rpath_root / "lib"
        rpath_bin.mkdir(parents=True)
        self.rpath_lib.mkdir()
        self.rpath_executable = rpath_bin / "app"
        subprocess.run([
            "gcc", "-o", str(self.rpath_executable), str(source),
            "-Wl,--disable-new-dtags,-rpath,$ORIGIN/../lib",
        ], check=True)
        self.rpath_executable.chmod(0o755)
        self.rpath_lib.chmod(0o775)

        self.origin_root = self.root / "origin"
        self.origin_root.mkdir()
        self.origin_executable = self.origin_root / "app"
        subprocess.run([
            "gcc", "-o", str(self.origin_executable), str(source),
            "-Wl,--enable-new-dtags,-rpath,$ORIGIN",
        ], check=True)
        self.origin_executable.chmod(0o755)
        self.origin_root.chmod(0o775)

        self.stripped_root = self.root / "stripped"
        stripped_bin = self.stripped_root / "bin"
        self.stripped_lib = self.stripped_root / "lib"
        stripped_bin.mkdir(parents=True)
        self.stripped_lib.mkdir()
        self.stripped_executable = stripped_bin / "app"
        subprocess.run([
            "gcc", "-s", "-o", str(self.stripped_executable), str(source),
            "-Wl,--enable-new-dtags,-rpath,$ORIGIN/../lib",
        ], check=True)
        self.stripped_executable.chmod(0o755)
        self.stripped_lib.chmod(0o775)

        self.privileged_root = self.root / "privileged"
        privileged_bin = self.privileged_root / "bin"
        self.privileged_lib = self.privileged_root / "lib"
        privileged_bin.mkdir(parents=True)
        self.privileged_lib.mkdir()
        self.privileged_path_executable = privileged_bin / "app"
        subprocess.run([
            "gcc", "-o", str(self.privileged_path_executable), str(source),
            "-Wl,--enable-new-dtags,-rpath,$ORIGIN/../lib",
        ], check=True)
        self.privileged_path_executable.chmod(0o4755)
        self.privileged_lib.chmod(0o777)

        self.unresolved_executable = self.root / "unresolved"
        subprocess.run([
            "gcc", "-o", str(self.unresolved_executable), str(source),
            "-Wl,--enable-new-dtags,-rpath,relative/lib",
        ], check=True)
        self.unresolved_executable.chmod(0o4755)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def findings(self, target: Path, run_id: str) -> tuple[Path, dict[str, object], dict[str, object]]:
        run_root, inventory = scan(target, self.root / "output", run_id=run_id)
        evaluation = json.loads((run_root / "normalized" / "findings.json").read_text())
        return run_root, inventory, evaluation

    def test_writable_executable(self) -> None:
        _, _, evaluation = self.findings(self.writable_executable, "writable-exec")
        self.assertEqual(["ELF-WRITABLE-EXEC"], [item["rule_id"] for item in evaluation["findings"]])
        self.assertEqual("MEDIUM", evaluation["findings"][0]["severity"])

    def test_privileged_writable_executable_supersedes_generic_rule(self) -> None:
        _, _, evaluation = self.findings(self.privileged_writable_executable, "priv-writable")
        self.assertEqual(
            ["ELF-PRIV-WRITABLE-EXEC"],
            [item["rule_id"] for item in evaluation["findings"]],
        )
        self.assertEqual("HIGH", evaluation["findings"][0]["severity"])

    def test_writable_shared_object(self) -> None:
        _, _, evaluation = self.findings(self.writable_shared_object, "writable-so")
        self.assertEqual(
            ["ELF-WRITABLE-SHARED-OBJECT"],
            [item["rule_id"] for item in evaluation["findings"]],
        )

    def test_mode_775_runpath_directory_creates_medium_finding(self) -> None:
        _, _, evaluation = self.findings(self.nonpriv_executable, "nonpriv-path")
        self.assertEqual(1, len(evaluation["findings"]))
        finding = evaluation["findings"][0]
        self.assertEqual("ELF-WRITABLE-LIB-SEARCH-PATH", finding["rule_id"])
        self.assertEqual("MEDIUM", finding["severity"])
        self.assertEqual(str(self.nonpriv_lib), finding["affected_path"])

    def test_exact_origin_runpath_is_correlated_with_directory_permissions(self) -> None:
        _, inventory, evaluation = self.findings(self.origin_executable, "origin-path")
        record = inventory["records"][0]
        self.assertEqual(["$ORIGIN"], record["dynamic_linking"]["runpath"]["entries"])
        self.assertEqual(
            "0775",
            record["permissions"]["search_path_directories"][0]["permissions"]["mode"],
        )
        self.assertEqual(
            ["ELF-WRITABLE-LIB-SEARCH-PATH"],
            [item["rule_id"] for item in evaluation["findings"]],
        )

    def test_rpath_variant_creates_the_same_medium_rule(self) -> None:
        _, inventory, evaluation = self.findings(self.rpath_executable, "rpath")
        self.assertTrue(inventory["records"][0]["dynamic_linking"]["rpath"]["present"])
        self.assertEqual(
            ["ELF-WRITABLE-LIB-SEARCH-PATH"],
            [item["rule_id"] for item in evaluation["findings"]],
        )

    def test_stripped_elf_retains_search_path_correlation(self) -> None:
        _, inventory, evaluation = self.findings(self.stripped_executable, "stripped")
        metadata = inventory["records"][0]["capabilities"]["_metadata"]
        self.assertTrue(any("stripped" in item.lower() for item in metadata["limitations"]))
        self.assertEqual(
            ["ELF-WRITABLE-LIB-SEARCH-PATH"],
            [item["rule_id"] for item in evaluation["findings"]],
        )

    def test_privileged_writable_runpath_correlation_and_evidence(self) -> None:
        run_root, inventory, evaluation = self.findings(self.privileged_path_executable, "priv-path")
        findings = evaluation["findings"]
        self.assertEqual(1, len(findings))
        self.assertEqual("ELF-PRIV-WRITABLE-LIB-SEARCH-PATH", findings[0]["rule_id"])
        self.assertEqual(str(self.privileged_lib), findings[0]["affected_path"])
        self.assertTrue(findings[0]["evidence_refs"])
        record = inventory["records"][0]
        valid_ids = {item["evidence_id"] for item in record["raw_evidence"]}
        self.assertTrue(set(findings[0]["evidence_refs"]).issubset(valid_ids))
        evidence_paths = {item["evidence_id"]: item["path"] for item in record["raw_evidence"]}
        for evidence_id in findings[0]["evidence_refs"]:
            self.assertTrue((run_root / evidence_paths[evidence_id] / "metadata.json").is_file())

    def test_safe_and_unresolved_paths_do_not_create_false_findings(self) -> None:
        _, _, safe = self.findings(self.safe_executable, "safe")
        _, _, unresolved = self.findings(self.unresolved_executable, "unresolved")
        self.assertEqual([], safe["findings"])
        self.assertEqual([], unresolved["findings"])

    def test_finding_identities_are_unique(self) -> None:
        _, _, evaluation = self.findings(self.privileged_path_executable, "unique")
        identities = [
            (item["rule_id"], item["component_id"], item["affected_path"])
            for item in evaluation["findings"]
        ]
        self.assertEqual(len(identities), len(set(identities)))

    def test_linux_file_capability_is_a_privilege_signal(self) -> None:
        permissions = {
            "file": {"setuid": False, "setgid": False},
            "capability_collection": {
                "status": "PRESENT",
                "capabilities": [{"name": "cap_net_bind_service", "flags": "ep"}],
            },
        }
        self.assertTrue(is_privileged(permissions))


if __name__ == "__main__":
    unittest.main()
