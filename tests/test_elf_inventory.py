from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts" / "lib"))

from elf_inventory import parse_capabilities, parse_nm_symbols, scan  # noqa: E402


@unittest.skipUnless(shutil.which("gcc") and shutil.which("readelf"), "requires gcc and readelf")
class ElfInventoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.fixtures = self.root / "fixtures"
        self.fixtures.mkdir()
        source = self.fixtures / "fixture.c"
        source.write_text(
            "int exported_fixture(void) { return 7; }\n"
            "int main(void) { return exported_fixture(); }\n",
            encoding="utf-8",
        )
        subprocess.run(["gcc", "-o", str(self.fixtures / "app"), str(source)], check=True)
        subprocess.run([
            "gcc", "-shared", "-fPIC", "-Wl,-soname,libmilestone1.so.1",
            "-o", str(self.fixtures / "library-without-so-extension"), str(source),
        ], check=True)
        subprocess.run([
            "gcc", "-fPIE", "-pie", "-fstack-protector-all",
            "-Wl,-z,relro,-z,now", "-o", str(self.fixtures / "full"), str(source),
        ], check=True)
        subprocess.run([
            "gcc", "-fPIE", "-pie", "-fno-stack-protector",
            "-Wl,-z,relro,-z,lazy", "-o", str(self.fixtures / "partial"), str(source),
        ], check=True)
        subprocess.run([
            "gcc", "-no-pie", "-fno-stack-protector", "-Wl,-z,norelro,-z,execstack",
            "-o", str(self.fixtures / "weak"), str(source),
        ], check=True)
        subprocess.run([
            "gcc", "-Wl,--disable-new-dtags,-rpath,$ORIGIN/../lib:../legacy",
            "-o", str(self.fixtures / "with-rpath"), str(source),
        ], check=True)
        subprocess.run([
            "gcc", "-Wl,--enable-new-dtags,-rpath,$ORIGIN/../lib:./lib::/opt/product/lib",
            "-o", str(self.fixtures / "with-runpath"), str(source),
        ], check=True)
        subprocess.run([
            "gcc", "-shared", "-fPIC", "-Wl,-soname,libsearch.so.1",
            "-Wl,--enable-new-dtags,-rpath,$ORIGIN/plugins",
            "-o", str(self.fixtures / "shared-with-runpath"), str(source),
        ], check=True)
        subprocess.run([
            "gcc", "-static", "-o", str(self.fixtures / "static-app"), str(source),
        ], check=True)
        fortify_source = self.fixtures / "fortify.c"
        fortify_source.write_text(
            "#include <string.h>\n"
            "__attribute__((noinline)) int copy_value(const char *s) { char d[8]; strcpy(d, s); return d[0]; }\n"
            "int main(int argc, char **argv) { return copy_value(argc > 1 ? argv[1] : \"ok\"); }\n",
            encoding="utf-8",
        )
        subprocess.run([
            "gcc", "-O2", "-D_FORTIFY_SOURCE=2", "-fstack-protector-all",
            "-Wl,-z,relro,-z,now", "-o", str(self.fixtures / "fortify"), str(fortify_source),
        ], check=True)
        rwx_source = self.fixtures / "rwx.S"
        rwx_source.write_text(".global _start\n_start:\n    ret\n", encoding="utf-8")
        subprocess.run([
            "gcc", "-nostdlib", "-no-pie", "-Wl,-N",
            "-o", str(self.fixtures / "rwx"), str(rwx_source),
        ], check=True, capture_output=True)
        (self.fixtures / "malformed").write_bytes(b"\x7fELFbroken")
        (self.fixtures / "plain.txt").write_text("not an ELF\n", encoding="utf-8")
        capability_source = ROOT / "samples" / "elf" / "milestone5-capabilities.c"
        self.capability_executable = self.fixtures / "milestone5-executable"
        self.capability_shared = self.fixtures / "milestone5.so"
        subprocess.run(["gcc", "-fno-builtin", "-o", str(self.capability_executable),
                        str(capability_source), "-ldl"], check=True)
        subprocess.run(["gcc", "-shared", "-fPIC", "-fno-builtin", "-DMILESTONE5_SHARED",
                        "-Wl,-soname,milestone5.so", "-o", str(self.capability_shared),
                        str(capability_source), "-ldl"], check=True)
        self.capability_stripped = self.fixtures / "milestone5-stripped"
        shutil.copy2(self.capability_executable, self.capability_stripped)
        subprocess.run(["strip", "--strip-all", str(self.capability_stripped)], check=True)
        self.dependency_root = self.root / "dependency-root"
        dependency_bin = self.dependency_root / "opt" / "product" / "bin"
        dependency_lib = self.dependency_root / "opt" / "product" / "lib"
        dependency_bin.mkdir(parents=True)
        dependency_lib.mkdir(parents=True)
        dependency_source = ROOT / "samples" / "elf" / "milestone6-dependency.c"
        consumer_source = ROOT / "samples" / "elf" / "milestone6-consumer.c"
        self.dependency_library = dependency_lib / "libmilestone6.so.1"
        subprocess.run([
            "gcc", "-shared", "-fPIC", "-Wl,-soname,libmilestone6.so.1",
            "-o", str(self.dependency_library), str(dependency_source),
        ], check=True)
        self.bundled_consumer = dependency_bin / "bundled-consumer"
        subprocess.run([
            "gcc", "-o", str(self.bundled_consumer), str(consumer_source),
            f"-L{dependency_lib}", "-l:libmilestone6.so.1",
            "-Wl,--enable-new-dtags,-rpath,$ORIGIN/../lib",
        ], check=True)
        self.missing_consumer = dependency_bin / "missing-consumer"
        subprocess.run([
            "gcc", "-o", str(self.missing_consumer), str(consumer_source),
            f"-L{dependency_lib}", "-l:libmilestone6.so.1",
            "-Wl,--enable-new-dtags,-rpath,$ORIGIN/../missing",
        ], check=True)
        ambiguous_a = self.dependency_root / "opt" / "product" / "lib-a"
        ambiguous_b = self.dependency_root / "opt" / "product" / "lib-b"
        ambiguous_a.mkdir()
        ambiguous_b.mkdir()
        shutil.copy2(self.dependency_library, ambiguous_a / self.dependency_library.name)
        shutil.copy2(self.dependency_library, ambiguous_b / self.dependency_library.name)
        self.ambiguous_consumer = dependency_bin / "ambiguous-consumer"
        subprocess.run([
            "gcc", "-o", str(self.ambiguous_consumer), str(consumer_source),
            f"-L{ambiguous_a}", "-l:libmilestone6.so.1",
            "-Wl,--enable-new-dtags,-rpath,$ORIGIN/../lib-a:$ORIGIN/../lib-b",
        ], check=True)
        plugin_dir = self.dependency_root / "opt" / "product" / "plugins"
        plugin_dir.mkdir()
        self.dependency_plugin = plugin_dir / "milestone6-plugin.so"
        subprocess.run([
            "gcc", "-shared", "-fPIC", "-DMILESTONE6_SHARED",
            "-Wl,-soname,milestone6-plugin.so", "-o", str(self.dependency_plugin),
            str(consumer_source), f"-L{dependency_lib}", "-l:libmilestone6.so.1",
            "-Wl,--enable-new-dtags,-rpath,$ORIGIN/../lib",
        ], check=True)
        system_lib = self.dependency_root / "usr" / "lib"
        system_lib.mkdir(parents=True)
        system_dependency = system_lib / "libmilestone6system.so.1"
        subprocess.run([
            "gcc", "-shared", "-fPIC", "-Wl,-soname,libmilestone6system.so.1",
            "-o", str(system_dependency), str(dependency_source),
        ], check=True)
        self.system_consumer = dependency_bin / "system-consumer"
        subprocess.run([
            "gcc", "-o", str(self.system_consumer), str(consumer_source),
            f"-L{system_lib}", "-l:libmilestone6system.so.1",
        ], check=True)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_directory_covers_required_artifact_types(self) -> None:
        run_root, result = scan(self.fixtures, self.root / "output", run_id="required-cases")
        by_name = {Path(item["path"]).name: item for item in result["records"]}
        self.assertEqual("elf_executable", by_name["app"]["type"])
        self.assertIn("PT_INTERP is present", by_name["app"]["classification_evidence"])
        self.assertEqual("elf_shared_object", by_name["library-without-so-extension"]["type"])
        self.assertEqual("libmilestone1.so.1", by_name["library-without-so-extension"]["elf"]["soname"])
        self.assertIn("DT_SONAME is present", by_name["library-without-so-extension"]["classification_evidence"])
        self.assertEqual("malformed_elf", by_name["malformed"]["type"])
        self.assertEqual("unsupported", by_name["plain.txt"]["type"])
        self.assertEqual("NOT_IMPLEMENTED_IN_CURRENT_MVP", by_name["plain.txt"]["status"])
        self.assertTrue((run_root / "normalized" / "inventory.json").is_file())

    def test_single_file_and_traceable_raw_evidence(self) -> None:
        run_root, result = scan(self.fixtures / "app", self.root / "output", run_id="single-file")
        record = result["records"][0]
        self.assertRegex(record["sha256"], r"^[0-9a-f]{64}$")
        self.assertIsNotNone(record["elf"]["class"])
        self.assertIsNotNone(record["elf"]["machine"])
        self.assertTrue(record["raw_evidence"])
        for reference in record["raw_evidence"]:
            evidence_dir = run_root / reference["path"]
            self.assertTrue((evidence_dir / "metadata.json").is_file())
            metadata = json.loads((evidence_dir / "metadata.json").read_text())
            if "source" in metadata:
                self.assertTrue((evidence_dir / "result.json").is_file())
            else:
                self.assertTrue((evidence_dir / "stdout.txt").is_file())
                self.assertTrue((evidence_dir / "stderr.txt").is_file())
            self.assertEqual(reference["evidence_id"], metadata["evidence_id"])
            self.assertIn("target_file", metadata)

    def test_relro_canary_nx_pie_and_executable_stack(self) -> None:
        _, result = scan(self.fixtures, self.root / "hardening-output", run_id="hardening")
        by_name = {Path(item["path"]).name: item for item in result["records"]}
        full = by_name["full"]["hardening"]
        self.assertEqual("FULL", full["relro"]["status"])
        self.assertEqual("ENABLED", full["stack_canary"]["status"])
        self.assertEqual("ENABLED", full["nx"]["status"])
        self.assertEqual("ENABLED", full["pie"]["status"])
        self.assertEqual("DISABLED", full["executable_stack"]["status"])
        partial = by_name["partial"]["hardening"]
        self.assertEqual("PARTIAL", partial["relro"]["status"])
        self.assertEqual("NOT_DETECTED", partial["stack_canary"]["status"])
        weak = by_name["weak"]["hardening"]
        self.assertEqual("NONE", weak["relro"]["status"])
        self.assertEqual("DISABLED", weak["nx"]["status"])
        self.assertEqual("DISABLED", weak["pie"]["status"])
        self.assertEqual("ENABLED", weak["executable_stack"]["status"])

    def test_shared_object_pie_is_not_applicable(self) -> None:
        _, result = scan(
            self.fixtures / "library-without-so-extension",
            self.root / "shared-output", run_id="shared",
        )
        self.assertEqual("NOT_APPLICABLE", result["records"][0]["hardening"]["pie"]["status"])

    def test_fortify_positive_and_absence_remains_unknown(self) -> None:
        _, positive = scan(self.fixtures / "fortify", self.root / "fortify-output", run_id="positive")
        self.assertEqual("ENABLED", positive["records"][0]["hardening"]["fortify"]["status"])
        _, negative = scan(self.fixtures / "partial", self.root / "fortify-output", run_id="unknown")
        self.assertEqual("UNKNOWN", negative["records"][0]["hardening"]["fortify"]["status"])

    def test_rwx_load_segment(self) -> None:
        _, result = scan(self.fixtures / "rwx", self.root / "rwx-output", run_id="rwx")
        hardening = result["records"][0]["hardening"]
        self.assertEqual("PRESENT", hardening["rwx_segment"]["status"])
        self.assertEqual("UNKNOWN", hardening["nx"]["status"])

    def test_nm_failure_does_not_destroy_other_hardening_results(self) -> None:
        original_which = shutil.which

        def without_nm(tool: str) -> str | None:
            return None if Path(tool).name == "nm" else original_which(tool)

        with mock.patch("elf_inventory.shutil.which", side_effect=without_nm):
            _, result = scan(self.fixtures / "full", self.root / "failure-output", run_id="nm-missing")
        record = result["records"][0]
        self.assertEqual("SUCCESS", record["status"])
        self.assertEqual("FULL", record["hardening"]["relro"]["status"])
        self.assertEqual("ERROR", record["hardening"]["stack_canary"]["status"])
        self.assertEqual("ERROR", record["hardening"]["fortify"]["status"])

    def test_dynamic_needed_and_no_custom_search_path(self) -> None:
        _, result = scan(self.fixtures / "full", self.root / "dynamic-output", run_id="needed")
        linking = result["records"][0]["dynamic_linking"]
        self.assertEqual("DYNAMIC", linking["linkage"])
        self.assertIn("libc.so.6", [item["name"] for item in linking["needed"]])
        self.assertEqual("NONE", linking["custom_search_path"])
        self.assertFalse(linking["rpath"]["present"])
        self.assertFalse(linking["runpath"]["present"])
        self.assertEqual("AGREEMENT", linking["cross_check"]["status"])

    def test_rpath_is_separate_and_relative_is_an_indicator(self) -> None:
        _, result = scan(self.fixtures / "with-rpath", self.root / "rpath-output", run_id="rpath")
        linking = result["records"][0]["dynamic_linking"]
        self.assertTrue(linking["rpath"]["present"])
        self.assertFalse(linking["runpath"]["present"])
        self.assertEqual(["$ORIGIN/../lib", "../legacy"], linking["rpath"]["entries"])
        self.assertIn("USES_ORIGIN", linking["indicators"])
        self.assertIn("RELATIVE_SEARCH_PATH", linking["indicators"])

    def test_runpath_origin_relative_empty_and_absolute_entries(self) -> None:
        _, result = scan(self.fixtures / "with-runpath", self.root / "runpath-output", run_id="runpath")
        linking = result["records"][0]["dynamic_linking"]
        self.assertFalse(linking["rpath"]["present"])
        self.assertEqual(
            ["$ORIGIN/../lib", "./lib", "", "/opt/product/lib"],
            linking["runpath"]["entries"],
        )
        self.assertIn("USES_ORIGIN", linking["indicators"])
        self.assertIn("RELATIVE_SEARCH_PATH", linking["indicators"])
        self.assertIn("CURRENT_DIRECTORY_SEARCH_PATH", linking["indicators"])

    def test_static_elf_is_not_an_error(self) -> None:
        _, result = scan(self.fixtures / "static-app", self.root / "static-output", run_id="static")
        linking = result["records"][0]["dynamic_linking"]
        self.assertEqual("STATIC", linking["linkage"])
        self.assertEqual("ABSENT", linking["metadata_status"])
        self.assertEqual([], linking["needed"])

    def test_shared_object_dynamic_metadata_and_pie_distinction(self) -> None:
        _, result = scan(
            self.fixtures / "shared-with-runpath", self.root / "so-output", run_id="so",
        )
        record = result["records"][0]
        self.assertEqual("elf_shared_object", record["type"])
        self.assertEqual("DYNAMIC", record["dynamic_linking"]["linkage"])
        self.assertEqual(["$ORIGIN/plugins"], record["dynamic_linking"]["runpath"]["entries"])
        self.assertEqual("NOT_APPLICABLE", record["hardening"]["pie"]["status"])

    def test_component_id_is_content_stable_and_run_id_is_unique(self) -> None:
        copied = self.fixtures / "same-content-different-path"
        shutil.copy2(self.fixtures / "full", copied)
        _, first = scan(self.fixtures / "full", self.root / "identity-output")
        _, second = scan(copied, self.root / "identity-output")
        self.assertNotEqual(first["run_id"], second["run_id"])
        self.assertEqual(first["records"][0]["component_id"], second["records"][0]["component_id"])

    def test_objdump_failure_keeps_readelf_dynamic_metadata(self) -> None:
        original_which = shutil.which

        def without_objdump(tool: str) -> str | None:
            return None if Path(tool).name == "objdump" else original_which(tool)

        with mock.patch("elf_inventory.shutil.which", side_effect=without_objdump):
            _, result = scan(self.fixtures / "with-runpath", self.root / "objdump-output")
        record = result["records"][0]
        self.assertEqual("SUCCESS", record["status"])
        self.assertEqual("DYNAMIC", record["dynamic_linking"]["linkage"])
        self.assertEqual("TOOL_ERROR", record["dynamic_linking"]["cross_check"]["status"])

    def test_file_modes_setuid_setgid_and_writable_flags(self) -> None:
        cases = {
            "normal-mode": (0o755, False, False),
            "group-writable": (0o775, True, False),
            "world-writable": (0o777, True, True),
            "setuid-setgid": (0o6755, False, False),
        }
        for name, (mode, non_owner, world) in cases.items():
            destination = self.fixtures / name
            shutil.copy2(self.fixtures / "full", destination)
            destination.chmod(mode)
        _, result = scan(self.fixtures, self.root / "permission-output", run_id="modes")
        by_name = {Path(item["path"]).name: item for item in result["records"]}
        for name, (mode, non_owner, world) in cases.items():
            permissions = by_name[name]["permissions"]["file"]
            self.assertEqual(f"{mode:04o}", permissions["mode"])
            self.assertEqual(non_owner, permissions["writable_by_non_owner"])
            self.assertEqual(world, permissions["world_writable"])
        self.assertTrue(by_name["setuid-setgid"]["permissions"]["file"]["setuid"])
        self.assertTrue(by_name["setuid-setgid"]["permissions"]["file"]["setgid"])

    def test_parent_directory_permissions_are_separate(self) -> None:
        safe = self.root / "safe-parent"
        writable = self.root / "writable-parent"
        safe.mkdir(mode=0o755)
        writable.mkdir(mode=0o777)
        safe.chmod(0o755)
        writable.chmod(0o777)
        shutil.copy2(self.fixtures / "full", safe / "app")
        shutil.copy2(self.fixtures / "full", writable / "app")
        _, safe_result = scan(safe / "app", self.root / "parent-output", run_id="safe")
        _, writable_result = scan(writable / "app", self.root / "parent-output", run_id="writable")
        self.assertFalse(safe_result["records"][0]["permissions"]["parent_directory"]["metadata"]["writable_by_non_owner"])
        self.assertTrue(writable_result["records"][0]["permissions"]["parent_directory"]["metadata"]["writable_by_non_owner"])

    def test_origin_search_directory_resolves_from_artifact(self) -> None:
        app_root = self.root / "origin-app"
        binary_dir = app_root / "bin"
        library_dir = app_root / "lib"
        binary_dir.mkdir(parents=True)
        library_dir.mkdir()
        library_dir.chmod(0o777)
        app = binary_dir / "app"
        subprocess.run([
            "gcc", "-Wl,--enable-new-dtags,-rpath,$ORIGIN/../lib",
            "-o", str(app), str(self.fixtures / "fixture.c"),
        ], check=True)
        _, result = scan(app, self.root / "origin-output", run_id="origin")
        context = result["records"][0]["permissions"]["search_path_directories"][0]
        self.assertEqual("RESOLVED", context["resolution_status"])
        self.assertEqual(str(library_dir), context["resolved"])
        self.assertTrue(context["permissions"]["writable_by_non_owner"])

    def test_runtime_relative_paths_do_not_use_scanner_cwd(self) -> None:
        _, result = scan(self.fixtures / "with-runpath", self.root / "relative-output", run_id="relative")
        contexts = result["records"][0]["permissions"]["search_path_directories"]
        runtime_entries = [item for item in contexts if item["original"] in {"./lib", ""}]
        self.assertTrue(runtime_entries)
        for item in runtime_entries:
            self.assertEqual("RUNTIME_CONTEXT_REQUIRED", item["resolution_status"])
            self.assertIsNone(item["resolved"])
        absolute = next(item for item in contexts if item["original"] == "/opt/product/lib")
        self.assertEqual("TARGET_ROOT_CONTEXT_REQUIRED", absolute["resolution_status"])
        self.assertIsNone(absolute["exists"])

    def test_missing_getcap_does_not_lose_stat_metadata(self) -> None:
        original_which = shutil.which

        def without_getcap(tool: str) -> str | None:
            return None if Path(tool).name == "getcap" else original_which(tool)

        with mock.patch("elf_inventory.shutil.which", side_effect=without_getcap):
            _, result = scan(self.fixtures / "full", self.root / "getcap-output")
        permissions = result["records"][0]["permissions"]
        self.assertEqual("SUCCESS", permissions["status"])
        self.assertEqual("TOOL_UNAVAILABLE", permissions["capability_collection"]["status"])
        self.assertEqual("0755", permissions["file"]["mode"])

    def test_capability_parser_and_positive_xattr_when_supported(self) -> None:
        self.assertEqual(
            [
                {"name": "cap_net_bind_service", "flags": "ep"},
                {"name": "cap_sys_chroot", "flags": "ep"},
            ],
            parse_capabilities("/tmp/app cap_net_bind_service,cap_sys_chroot=ep\n"),
        )
        if not shutil.which("setcap") or not shutil.which("getcap"):
            self.skipTest("libcap tools unavailable")
        capable = self.fixtures / "capable"
        shutil.copy2(self.fixtures / "full", capable)
        applied = subprocess.run(
            ["setcap", "cap_net_bind_service=ep", str(capable)],
            capture_output=True, text=True, check=False,
        )
        if applied.returncode != 0:
            self.skipTest(f"filesystem does not support file capabilities: {applied.stderr}")
        _, result = scan(capable, self.root / "capability-output", run_id="capability")
        collection = result["records"][0]["permissions"]["capability_collection"]
        self.assertEqual("PRESENT", collection["status"])
        self.assertEqual("cap_net_bind_service", collection["capabilities"][0]["name"])

    def test_symlink_context_is_not_silently_lost(self) -> None:
        link = self.root / "linked-app"
        link.symlink_to(self.fixtures / "full")
        _, result = scan(link, self.root / "symlink-output", run_id="symlink")
        file_permissions = result["records"][0]["permissions"]["file"]
        self.assertTrue(file_permissions["is_symlink"])
        self.assertEqual(str((self.fixtures / "full").resolve()), file_permissions["final_resolved_path"])

    def test_run_directory_is_never_overwritten(self) -> None:
        scan(self.fixtures / "app", self.root / "output", run_id="immutable")
        with self.assertRaises(FileExistsError):
            scan(self.fixtures / "app", self.root / "output", run_id="immutable")


    def test_nm_parser_normalizes_versions_and_matches_exact_names(self) -> None:
        parsed = parse_nm_symbols("                 U system@GLIBC_2.2.5\n00000000 T my_system_helper\n")
        self.assertEqual("system", parsed[0]["name"])
        self.assertEqual("system@GLIBC_2.2.5", parsed[0]["raw_name"])
        self.assertEqual("my_system_helper", parsed[1]["name"])

    def test_capability_groups_for_executable(self) -> None:
        _, result = scan(self.capability_executable, self.root / "m5-output", run_id="executable")
        capabilities = result["records"][0]["capabilities"]
        for group in ("command_execution", "process_debug", "filesystem", "network",
                      "dynamic_loading", "privilege_memory"):
            self.assertTrue(capabilities[group]["detected"], group)
        self.assertIn("system", capabilities["command_execution"]["imported_symbols"])
        self.assertNotIn("my_system_helper", capabilities["command_execution"]["symbols"])
        self.assertEqual("COMPLETE_FOR_DYNAMIC_SYMBOLS", capabilities["_metadata"]["coverage"])

    def test_shared_object_imports_exports_and_scope(self) -> None:
        _, result = scan(self.capability_shared, self.root / "m5-output", run_id="shared")
        record = result["records"][0]
        self.assertEqual("elf_shared_object", record["type"])
        self.assertIn("dlopen", record["capabilities"]["dynamic_loading"]["imported_symbols"])
        self.assertIn("system", record["capabilities"]["command_execution"]["exported_symbols"])
        self.assertEqual("elf_shared_object", record["capabilities"]["_metadata"]["component_scope"])
        raw_commands = [reference["command"] for reference in record["raw_evidence"]]
        self.assertIn(["nm", "-D", "--defined-only", "--", str(self.capability_shared)], raw_commands)

    def test_stripped_binary_reports_partial_coverage(self) -> None:
        _, result = scan(self.capability_stripped, self.root / "m5-output", run_id="stripped")
        metadata = result["records"][0]["capabilities"]["_metadata"]
        self.assertEqual("PARTIAL", metadata["coverage"])
        self.assertTrue(any("stripped" in item.lower() for item in metadata["limitations"]))

    def test_static_binary_reports_unknown_coverage(self) -> None:
        _, result = scan(self.fixtures / "static-app", self.root / "m5-output", run_id="static-capability")
        self.assertEqual("UNKNOWN", result["records"][0]["capabilities"]["_metadata"]["coverage"])

    def test_missing_nm_uses_readelf_fallback_without_false_confidence(self) -> None:
        original_which = shutil.which

        def without_nm(tool: str) -> str | None:
            return None if Path(tool).name == "nm" else original_which(tool)

        with mock.patch("elf_inventory.shutil.which", side_effect=without_nm):
            _, result = scan(self.capability_executable, self.root / "m5-output", run_id="nm-missing")
        capabilities = result["records"][0]["capabilities"]
        self.assertEqual("PARTIAL", capabilities["_metadata"]["coverage"])
        self.assertIn("socket", capabilities["network"]["imported_symbols"])

    def dependency_record(
        self, binary: Path, run_id: str, dependency_name: str = "libmilestone6.so.1",
    ) -> tuple[Path, dict[str, object]]:
        run_root, result = scan(
            binary, self.root / "m6-output", run_id=run_id,
            target_root=self.dependency_root,
        )
        record = next(
            item for item in result["records"][0]["dependencies"]
            if item["dependency_name"] == dependency_name
        )
        return run_root, record

    def test_origin_bundled_dependency_resolves_with_evidence(self) -> None:
        run_root, dependency = self.dependency_record(self.bundled_consumer, "bundled")
        self.assertEqual("RESOLVED", dependency["resolution_status"])
        self.assertEqual("BUNDLED", dependency["bundled_or_system"])
        self.assertEqual(str(self.dependency_library), dependency["resolved_path"])
        self.assertIsNone(dependency["version"])
        evidence_id = dependency["evidence_refs"][-1]
        evidence = next((run_root / "raw").glob(f"{evidence_id}*"))
        self.assertTrue((evidence / "result.json").is_file())

    def test_system_like_dependency_classification_does_not_guess_version(self) -> None:
        _, dependency = self.dependency_record(
            self.system_consumer, "system-like", "libmilestone6system.so.1",
        )
        self.assertEqual("RESOLVED", dependency["resolution_status"])
        self.assertEqual("SYSTEM", dependency["bundled_or_system"])
        self.assertEqual("UNKNOWN", dependency["package_owner_status"])
        self.assertIsNone(dependency["version"])
        self.assertEqual("ABI_IDENTIFIER_NOT_PACKAGE_VERSION", dependency["soname_semantics"])

    def test_dependency_not_found_is_isolated(self) -> None:
        _, dependency = self.dependency_record(self.missing_consumer, "missing")
        self.assertEqual("NOT_FOUND", dependency["resolution_status"])
        self.assertIsNone(dependency["resolved_path"])

    def test_ambiguous_dependency_does_not_choose_first_candidate(self) -> None:
        _, dependency = self.dependency_record(self.ambiguous_consumer, "ambiguous")
        self.assertEqual("AMBIGUOUS", dependency["resolution_status"])
        self.assertIsNone(dependency["resolved_path"])

    def test_shared_object_dt_needed_resolves_like_executable(self) -> None:
        _, dependency = self.dependency_record(self.dependency_plugin, "shared-dependency")
        self.assertEqual("RESOLVED", dependency["resolution_status"])
        self.assertEqual("BUNDLED", dependency["bundled_or_system"])

    def test_missing_target_root_is_explicit(self) -> None:
        _, result = scan(self.system_consumer, self.root / "m6-output", run_id="no-root")
        dependency = next(
            item for item in result["records"][0]["dependencies"]
            if item["dependency_name"] == "libmilestone6system.so.1"
        )
        self.assertEqual("TARGET_ROOT_CONTEXT_REQUIRED", dependency["resolution_status"])

    def test_relative_search_path_requires_runtime_context(self) -> None:
        _, result = scan(
            self.fixtures / "with-runpath", self.root / "m6-output", run_id="runtime-context",
        )
        self.assertTrue(result["records"][0]["dependencies"])
        self.assertTrue(all(
            item["resolution_status"] == "RUNTIME_CONTEXT_REQUIRED"
            for item in result["records"][0]["dependencies"]
        ))

    def test_package_owner_when_host_database_supports_it(self) -> None:
        if not shutil.which("dpkg-query"):
            self.skipTest("dpkg-query unavailable")
        _, result = scan(Path("/bin/ls"), self.root / "m6-output", run_id="host-owner", target_root=Path("/"))
        resolved = [item for item in result["records"][0]["dependencies"] if item["package_owner_status"] == "RESOLVED"]
        if not resolved:
            self.skipTest("host package database does not own a resolved /bin/ls dependency path")
        self.assertTrue(resolved[0]["package_owner"])
        self.assertEqual("RESOLVED", resolved[0]["version_status"])

    def test_package_tool_unavailable_preserves_dependency_record(self) -> None:
        original_which = shutil.which

        def without_dpkg_query(tool: str) -> str | None:
            return None if Path(tool).name == "dpkg-query" else original_which(tool)

        with mock.patch("elf_inventory.shutil.which", side_effect=without_dpkg_query):
            _, result = scan(Path("/bin/ls"), self.root / "m6-output", run_id="no-package-tool", target_root=Path("/"))
        resolved = [item for item in result["records"][0]["dependencies"] if item["resolution_status"] == "RESOLVED"]
        self.assertTrue(resolved)
        self.assertTrue(all(item["package_owner_status"] == "TOOL_UNAVAILABLE" for item in resolved))


if __name__ == "__main__":
    unittest.main()
