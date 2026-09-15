#!/usr/bin/env python3
"""Milestone 1 ELF inventory, evidence capture, and normalization."""

from __future__ import annotations

import hashlib
import grp
import json
import os
import pwd
import re
import shutil
import stat as stat_module
import subprocess
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from result_evaluation import evaluate_inventory


ELF_MAGIC = b"\x7fELF"
SCHEMA_VERSION = "1.5"

CAPABILITY_SYMBOLS: dict[str, tuple[str, ...]] = {
    "command_execution": ("system", "popen", "execve", "execvp", "execl", "posix_spawn"),
    "process_debug": ("fork", "clone", "kill", "ptrace"),
    "filesystem": ("open", "openat", "fopen", "unlink", "chmod", "chown", "rename"),
    "network": ("socket", "connect", "bind", "listen", "accept", "send", "recv", "getaddrinfo"),
    "dynamic_loading": ("dlopen", "dlsym"),
    "privilege_memory": ("setuid", "setgid", "setresuid", "capset", "mmap", "mprotect"),
}


def tool_environment() -> dict[str, str]:
    environment = os.environ.copy()
    environment.update({"LC_ALL": "C", "LANG": "C"})
    return environment


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def new_run_id() -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    return f"run-{stamp}-{uuid.uuid4().hex[:10]}"


def atomic_json(path: Path, value: Any) -> None:
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, path)


@dataclass(frozen=True)
class EvidenceReference:
    evidence_id: str
    tool: str
    command: list[str]
    path: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "tool": self.tool,
            "command": self.command,
            "path": self.path,
        }


@dataclass(frozen=True)
class Invocation:
    reference: EvidenceReference
    stdout: str
    stderr: str
    exit_code: int


class EvidenceRunner:
    """Invoke read-only tools and preserve every invocation before parsing it."""

    def __init__(self, run_root: Path):
        self.run_root = run_root
        self.raw_root = run_root / "raw"
        self.raw_root.mkdir(parents=True, exist_ok=False)
        self._counter = 0
        self._versions: dict[str, str | None] = {}

    def _next_id(self, tool: str) -> str:
        self._counter += 1
        safe_tool = re.sub(r"[^a-zA-Z0-9_.-]", "_", tool)
        return f"ev-{self._counter:06d}-{safe_tool}"

    def _tool_version(self, tool: str) -> str | None:
        if tool in self._versions:
            return self._versions[tool]
        executable = shutil.which(tool)
        if not executable:
            self._versions[tool] = None
            return None
        if tool == "getcap":
            self._versions[tool] = None
            return None
        evidence_id = self._next_id(tool)
        evidence_dir = self.raw_root / evidence_id
        evidence_dir.mkdir(parents=False, exist_ok=False)
        command = [tool, "--version"]
        started = utc_now()
        try:
            result = subprocess.run(
                [executable, "--version"], capture_output=True, text=True,
                errors="replace", timeout=10, check=False, env=tool_environment(),
            )
            stdout, stderr, exit_code = result.stdout, result.stderr, result.returncode
            first_line = (result.stdout or result.stderr).splitlines()
            version = first_line[0].strip() if first_line else None
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout or ""
            stderr = (exc.stderr or "") + "tool version invocation timed out\n"
            exit_code = 124
            version = None
        except OSError as exc:
            stdout, stderr, exit_code = "", f"tool version invocation failed: {exc}\n", 126
            version = None
        (evidence_dir / "stdout.txt").write_text(stdout, encoding="utf-8")
        (evidence_dir / "stderr.txt").write_text(stderr, encoding="utf-8")
        atomic_json(evidence_dir / "metadata.json", {
            "schema_version": SCHEMA_VERSION,
            "evidence_id": evidence_id,
            "command": command,
            "tool": {"name": tool, "version": version},
            "target_file": None,
            "purpose": "tool_version",
            "started_at": started,
            "finished_at": utc_now(),
            "exit_code": exit_code,
            "stdout_path": "stdout.txt",
            "stderr_path": "stderr.txt",
        })
        self._versions[tool] = version
        return version

    def run(self, command: list[str], target: Path) -> Invocation:
        tool = Path(command[0]).name
        version = self._tool_version(tool)
        evidence_id = self._next_id(tool)
        evidence_dir = self.raw_root / evidence_id
        evidence_dir.mkdir(parents=False, exist_ok=False)
        started = utc_now()
        executable = shutil.which(command[0])
        if executable is None:
            stdout, stderr, exit_code = "", f"tool unavailable: {tool}\n", 127
        else:
            try:
                result = subprocess.run(
                    [executable, *command[1:]], capture_output=True, text=True,
                    errors="replace", timeout=60, check=False, env=tool_environment(),
                )
                stdout, stderr, exit_code = result.stdout, result.stderr, result.returncode
            except subprocess.TimeoutExpired as exc:
                stdout = exc.stdout or ""
                stderr = (exc.stderr or "") + "tool invocation timed out\n"
                exit_code = 124
            except OSError as exc:
                stdout, stderr, exit_code = "", f"tool invocation failed: {exc}\n", 126
        finished = utc_now()
        (evidence_dir / "stdout.txt").write_text(stdout, encoding="utf-8")
        (evidence_dir / "stderr.txt").write_text(stderr, encoding="utf-8")
        metadata = {
            "schema_version": SCHEMA_VERSION,
            "evidence_id": evidence_id,
            "command": command,
            "tool": {"name": tool, "version": version},
            "target_file": str(target.absolute()),
            "started_at": started,
            "finished_at": finished,
            "exit_code": exit_code,
            "stdout_path": "stdout.txt",
            "stderr_path": "stderr.txt",
        }
        atomic_json(evidence_dir / "metadata.json", metadata)
        relative = evidence_dir.relative_to(self.run_root).as_posix()
        reference = EvidenceReference(evidence_id, tool, command, relative)
        return Invocation(reference, stdout, stderr, exit_code)

    def record_structured(
        self, source: str, target: Path, result: dict[str, Any],
        status: str = "SUCCESS", error: str | None = None,
    ) -> EvidenceReference:
        evidence_id = self._next_id(source)
        evidence_dir = self.raw_root / evidence_id
        evidence_dir.mkdir(parents=False, exist_ok=False)
        timestamp = utc_now()
        atomic_json(evidence_dir / "result.json", result)
        atomic_json(evidence_dir / "metadata.json", {
            "schema_version": SCHEMA_VERSION,
            "evidence_id": evidence_id,
            "source": source,
            "target_file": str(target.absolute()),
            "timestamp": timestamp,
            "status": status,
            "error": error,
            "result_path": "result.json",
        })
        relative = evidence_dir.relative_to(self.run_root).as_posix()
        return EvidenceReference(evidence_id, source, [], relative)


def has_elf_magic(path: Path) -> bool:
    try:
        with path.open("rb") as stream:
            return stream.read(4) == ELF_MAGIC
    except OSError:
        return False


def parse_header(text: str) -> dict[str, str | None]:
    fields: dict[str, str | None] = {
        "elf_class": None,
        "endianness": None,
        "elf_type": None,
        "elf_type_description": None,
        "machine": None,
        "entry_point": None,
    }
    for line in text.splitlines():
        match = re.match(r"\s*Class:\s*(.+?)\s*$", line)
        if match:
            fields["elf_class"] = match.group(1)
        match = re.match(r"\s*Data:\s*(.+?)\s*$", line)
        if match:
            data = match.group(1).lower()
            fields["endianness"] = "little" if "little endian" in data else "big" if "big endian" in data else data
        match = re.match(r"\s*Type:\s*(\S+)(?:\s+\((.*?)\))?", line)
        if match:
            fields["elf_type"] = match.group(1)
            fields["elf_type_description"] = match.group(2)
        match = re.match(r"\s*Machine:\s*(.+?)\s*$", line)
        if match:
            fields["machine"] = match.group(1)
        match = re.match(r"\s*Entry point address:\s*(\S+)", line)
        if match:
            fields["entry_point"] = match.group(1)
    return fields


def normalize_architecture(machine: str | None) -> str | None:
    if not machine:
        return None
    mappings = (
        ("x86-64", "x86_64"), ("advanced micro devices x86-64", "x86_64"),
        ("intel 80386", "x86"), ("aarch64", "aarch64"),
        ("arm", "arm"), ("risc-v", "riscv"),
    )
    lowered = machine.lower()
    for marker, normalized in mappings:
        if marker in lowered:
            return normalized
    return machine


def parse_interpreter(text: str) -> str | None:
    match = re.search(r"Requesting program interpreter:\s*([^\]]+)\]", text)
    return match.group(1).strip() if match else None


def parse_build_id(text: str) -> str | None:
    match = re.search(r"Build ID:\s*([0-9a-fA-F]+)", text)
    return match.group(1).lower() if match else None


def parse_soname(text: str) -> str | None:
    match = re.search(r"\(SONAME\).*?\[([^\]]+)\]", text)
    return match.group(1) if match else None


def parse_program_headers(text: str) -> list[dict[str, str]]:
    """Parse one-line (`readelf -W -l`) program-header records."""
    headers: list[dict[str, str]] = []
    pattern = re.compile(
        r"^\s*(?P<type>\S+)\s+"
        r"(?:0x[0-9a-fA-F]+\s+){5}"
        r"(?P<flags>[RWE ]+?)\s+0x[0-9a-fA-F]+\s*$"
    )
    for line in text.splitlines():
        match = pattern.match(line)
        if match:
            headers.append({
                "type": match.group("type"),
                "flags": "".join(match.group("flags").split()),
                "raw": line.strip(),
            })
    return headers


def check_result(
    status: str, evidence: Iterable[EvidenceReference], confidence: str,
    details: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "status": status,
        "confidence": confidence,
        "evidence_refs": [item.evidence_id for item in evidence],
        "details": details or [],
        "tool_disagreement": None,
        "cross_check_status": "NOT_PERFORMED",
    }


def component_id(component_type: str, sha256: str | None) -> str | None:
    if not sha256:
        return None
    digest = hashlib.sha256(f"{component_type}\0{sha256}".encode("utf-8")).hexdigest()
    return f"cmp-{digest}"


def parse_dynamic_section(text: str) -> dict[str, Any]:
    return {
        "section_present": "Dynamic section at offset" in text,
        "explicitly_absent": "There is no dynamic section" in text,
        "needed": re.findall(r"\(NEEDED\).*?\[([^\]]+)\]", text),
        "rpath_values": re.findall(r"\(RPATH\).*?\[([^\]]*)\]", text),
        "runpath_values": re.findall(r"\(RUNPATH\).*?\[([^\]]*)\]", text),
    }


def parse_objdump_private_headers(text: str) -> dict[str, list[str]]:
    result = {"needed": [], "rpath_values": [], "runpath_values": []}
    mapping = {"NEEDED": "needed", "RPATH": "rpath_values", "RUNPATH": "runpath_values"}
    for line in text.splitlines():
        match = re.match(r"\s*(NEEDED|RPATH|RUNPATH)\s+(.*?)\s*$", line)
        if match:
            result[mapping[match.group(1)]].append(match.group(2))
    return result


def normalize_symbol_name(name: str) -> str:
    """Remove a symbol version for exact capability matching."""
    return name.split("@", 1)[0]


def parse_nm_symbols(text: str) -> list[dict[str, str]]:
    """Parse GNU nm output without substring matching."""
    parsed: list[dict[str, str]] = []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 2:
            continue
        symbol_type, raw_name = fields[-2:]
        if len(symbol_type) != 1 or not symbol_type.isalpha():
            continue
        parsed.append({
            "name": normalize_symbol_name(raw_name),
            "raw_name": raw_name,
            "symbol_type": symbol_type,
        })
    return parsed


def parse_readelf_dynsyms(text: str) -> tuple[set[str], set[str]]:
    imported: set[str] = set()
    exported: set[str] = set()
    for line in text.splitlines():
        match = re.match(
            r"\s*\d+:\s+\S+\s+\d+\s+\S+\s+\S+\s+\S+\s+(\S+)\s+(.+?)\s*$",
            line,
        )
        if not match:
            continue
        section_index, raw_name = match.groups()
        raw_name = re.sub(r"\s+\(\d+\)$", "", raw_name)
        name = normalize_symbol_name(raw_name)
        if name:
            (imported if section_index == "UND" else exported).add(name)
    return imported, exported


def evaluate_capabilities(
    component_type: str, file_text: str, linkage: str,
    imported_nm: Invocation, exported_nm: Invocation, readelf_dynsyms: Invocation,
) -> dict[str, Any]:
    """Normalize CHK-06 indicators; never create a finding or severity."""
    nm_available = imported_nm.exit_code == 0 and exported_nm.exit_code == 0
    nm_imported = {item["name"] for item in parse_nm_symbols(imported_nm.stdout)} if imported_nm.exit_code == 0 else set()
    nm_exported = {item["name"] for item in parse_nm_symbols(exported_nm.stdout)} if exported_nm.exit_code == 0 else set()
    if readelf_dynsyms.exit_code == 0:
        readelf_imported, readelf_exported = parse_readelf_dynsyms(readelf_dynsyms.stdout)
    else:
        readelf_imported, readelf_exported = set(), set()
    imported = nm_imported if imported_nm.exit_code == 0 else readelf_imported
    exported = nm_exported if exported_nm.exit_code == 0 else readelf_exported
    stripped = "stripped" in file_text.lower() and "not stripped" not in file_text.lower()
    limitations = [
        "Capability presence is an indicator, not proof of a vulnerability or reachable behavior.",
        "Absence from the dynamic symbol table is not proof that a capability is absent.",
    ]
    if linkage == "STATIC":
        coverage = "UNKNOWN"
        limitations.append("Static linkage can hide API use from dynamic-symbol inspection.")
    elif stripped:
        coverage = "PARTIAL"
        limitations.append("The ELF is stripped; available dynamic symbols provide partial coverage only.")
    elif not nm_available and readelf_dynsyms.exit_code == 0:
        coverage = "PARTIAL"
        limitations.append("nm was unavailable or failed; readelf dynamic symbols were used as fallback.")
    elif not nm_available:
        coverage = "UNKNOWN"
        limitations.append("nm and the readelf fallback did not provide complete dynamic-symbol evidence.")
    else:
        coverage = "COMPLETE_FOR_DYNAMIC_SYMBOLS"
    nm_refs = [imported_nm.reference.evidence_id, exported_nm.reference.evidence_id]
    readelf_refs = [readelf_dynsyms.reference.evidence_id]
    groups: dict[str, Any] = {}
    for group, candidates in CAPABILITY_SYMBOLS.items():
        matched_imports = sorted(imported.intersection(candidates))
        matched_exports = sorted(exported.intersection(candidates))
        groups[group] = {
            "detected": bool(matched_imports or matched_exports),
            "symbols": sorted(set(matched_imports + matched_exports)),
            "imported_symbols": matched_imports,
            "exported_symbols": matched_exports,
            "evidence_refs": nm_refs + readelf_refs,
        }
    groups["_metadata"] = {
        "coverage": coverage,
        "component_scope": component_type,
        "source": "dynamic_symbols",
        "nm_status": "SUCCESS" if nm_available else "UNAVAILABLE_OR_ERROR",
        "readelf_fallback_status": "SUCCESS" if readelf_dynsyms.exit_code == 0 else "UNAVAILABLE_OR_ERROR",
        "cross_check": (
            "AGREEMENT"
            if nm_available and readelf_dynsyms.exit_code == 0
            and nm_imported == readelf_imported and nm_exported == readelf_exported
            else "DISAGREEMENT"
            if nm_available and readelf_dynsyms.exit_code == 0
            else "NOT_PERFORMED"
        ),
        "limitations": limitations,
        "evidence_refs": nm_refs + readelf_refs,
    }
    return groups


def split_search_paths(values: list[str]) -> list[str]:
    return [entry for value in values for entry in value.split(":")]


def system_library_directories(architecture: str | None) -> list[str]:
    triplets = {
        "x86_64": "x86_64-linux-gnu", "x86": "i386-linux-gnu",
        "aarch64": "aarch64-linux-gnu", "arm": "arm-linux-gnueabihf",
    }
    directories = ["/lib", "/usr/lib", "/lib64", "/usr/lib64"]
    if architecture in triplets:
        triplet = triplets[architecture]
        directories = [f"/lib/{triplet}", f"/usr/lib/{triplet}", *directories]
    return directories


def dependency_candidate(
    directory: str, dependency_name: str, artifact: Path, target_root: Path | None,
) -> tuple[Path | None, str | None]:
    origin_pattern = re.compile(r"\$(?:ORIGIN|\{ORIGIN\})")
    if origin_pattern.search(directory):
        expanded = origin_pattern.sub(str(artifact.parent.resolve()), directory)
        return Path(expanded) / dependency_name, None
    if directory in {"", "."} or not directory.startswith("/"):
        return None, "RUNTIME_CONTEXT_REQUIRED"
    if target_root is None:
        return None, "TARGET_ROOT_CONTEXT_REQUIRED"
    return target_root / directory.lstrip("/") / dependency_name, None


def classify_dependency_path(path: Path, target_root: Path | None) -> str:
    if target_root is None:
        return "UNKNOWN"
    try:
        relative = path.resolve().relative_to(target_root.resolve())
    except (OSError, ValueError):
        return "UNKNOWN"
    if relative.parts[:1] == ("lib",) or relative.parts[:2] == ("usr", "lib"):
        return "SYSTEM"
    return "BUNDLED"


def parse_dpkg_owner(text: str, resolved_path: Path) -> str | None:
    expected = str(resolved_path)
    owners = []
    for line in text.splitlines():
        if ": " in line:
            owner, path = line.split(": ", 1)
            if path == expected:
                owners.append(owner)
    return sorted(set(owners))[0] if len(set(owners)) == 1 else None


def parse_dpkg_version(text: str, package_owner: str) -> str | None:
    for line in text.splitlines():
        fields = line.split("\t", 1)
        if len(fields) == 2 and fields[0] == package_owner and fields[1]:
            return fields[1]
    return None


def package_provenance(
    resolved_path: Path, bundling: str, target_root: Path | None, runner: EvidenceRunner,
) -> tuple[dict[str, Any], list[EvidenceReference]]:
    if bundling != "SYSTEM" or target_root is None or target_root.resolve() != Path("/"):
        return {
            "package_owner": None,
            "package_owner_status": "UNKNOWN",
            "version": None,
            "version_status": "UNKNOWN",
        }, []
    owner_query = runner.run(["dpkg-query", "-S", str(resolved_path)], resolved_path)
    references = [owner_query.reference]
    if owner_query.exit_code == 127:
        status, owner = "TOOL_UNAVAILABLE", None
    elif owner_query.exit_code != 0:
        status, owner = "PACKAGE_DATABASE_UNAVAILABLE", None
    else:
        owner = parse_dpkg_owner(owner_query.stdout, resolved_path)
        status = "RESOLVED" if owner else "UNKNOWN"
    if not owner:
        return {
            "package_owner": None, "package_owner_status": status,
            "version": None, "version_status": "UNKNOWN",
        }, references
    version_query = runner.run(
        ["dpkg-query", "-W", "-f=${binary:Package}\\t${Version}\\n", owner], resolved_path,
    )
    references.append(version_query.reference)
    version = parse_dpkg_version(version_query.stdout, owner) if version_query.exit_code == 0 else None
    return {
        "package_owner": owner, "package_owner_status": "RESOLVED",
        "version": version, "version_status": "RESOLVED" if version else "UNKNOWN",
    }, references


def evaluate_dependencies(
    artifact: Path, component_id_value: str | None, architecture: str | None,
    dynamic_linking: dict[str, Any], target_root: Path | None, runner: EvidenceRunner,
) -> tuple[list[dict[str, Any]], list[EvidenceReference]]:
    records: list[dict[str, Any]] = []
    all_references: list[EvidenceReference] = []
    search_entries = [*dynamic_linking["rpath"]["entries"], *dynamic_linking["runpath"]["entries"]]
    if target_root is not None:
        search_entries.extend(system_library_directories(architecture))
    for needed in dynamic_linking["needed"]:
        name = needed["name"]
        candidates: list[Path] = []
        deferred: set[str] = {"TARGET_ROOT_CONTEXT_REQUIRED"} if target_root is None else set()
        inspected: list[dict[str, Any]] = []
        for directory in search_entries:
            candidate, deferred_status = dependency_candidate(directory, name, artifact, target_root)
            if deferred_status:
                deferred.add(deferred_status)
                inspected.append({"directory": directory, "candidate": None, "status": deferred_status})
                continue
            assert candidate is not None
            try:
                exists = candidate.is_file()
                inspected.append({"directory": directory, "candidate": str(candidate), "status": "FOUND" if exists else "NOT_FOUND"})
                if exists:
                    candidates.append(candidate.resolve())
            except OSError as exc:
                inspected.append({"directory": directory, "candidate": str(candidate), "status": "ERROR", "error": str(exc)})
                deferred.add("ERROR")
        unique_candidates = sorted(set(candidates), key=str)
        if len(unique_candidates) > 1:
            resolution_status, resolved = "AMBIGUOUS", None
        elif len(unique_candidates) == 1:
            resolution_status, resolved = "RESOLVED", unique_candidates[0]
        elif "ERROR" in deferred:
            resolution_status, resolved = "ERROR", None
        elif "RUNTIME_CONTEXT_REQUIRED" in deferred:
            resolution_status, resolved = "RUNTIME_CONTEXT_REQUIRED", None
        elif "TARGET_ROOT_CONTEXT_REQUIRED" in deferred:
            resolution_status, resolved = "TARGET_ROOT_CONTEXT_REQUIRED", None
        else:
            resolution_status, resolved = "NOT_FOUND", None
        resolution_ref = runner.record_structured("dependency_resolution", artifact, {
            "component_id": component_id_value, "dependency_name": name,
            "target_root": str(target_root) if target_root is not None else None,
            "search_entries": search_entries, "inspected_candidates": inspected,
            "resolution_status": resolution_status,
            "matching_candidates": [str(item) for item in unique_candidates],
        })
        references = [resolution_ref]
        bundling = classify_dependency_path(resolved, target_root) if resolved else "UNKNOWN"
        package = {
            "package_owner": None, "package_owner_status": "UNKNOWN",
            "version": None, "version_status": "UNKNOWN",
        }
        if resolved:
            package, package_refs = package_provenance(resolved, bundling, target_root, runner)
            references.extend(package_refs)
        records.append({
            "dependency_name": name, "resolved_path": str(resolved) if resolved else None,
            "resolution_status": resolution_status, "bundled_or_system": bundling,
            **package, "soname": name,
            "soname_semantics": "ABI_IDENTIFIER_NOT_PACKAGE_VERSION",
            "origin": "DT_NEEDED",
            "evidence_refs": [*needed["evidence_refs"], *[item.evidence_id for item in references]],
        })
        all_references.extend(references)
    return records, all_references


def search_path_indicators(entries: list[str]) -> list[str]:
    indicators: set[str] = set()
    origin = re.compile(r"\$(?:ORIGIN|\{ORIGIN\})")
    for entry in entries:
        if origin.search(entry):
            indicators.add("USES_ORIGIN")
            continue
        if entry in {"", "."}:
            indicators.update({"CURRENT_DIRECTORY_SEARCH_PATH", "RELATIVE_SEARCH_PATH"})
        elif not entry.startswith("/"):
            indicators.add("RELATIVE_SEARCH_PATH")
    return sorted(indicators)


def evaluate_dynamic_linking(
    component_type: str,
    header: dict[str, str | None],
    interpreter: str | None,
    program: Invocation,
    dynamic: Invocation,
    objdump: Invocation,
) -> dict[str, Any]:
    readelf_data = parse_dynamic_section(dynamic.stdout) if dynamic.exit_code == 0 else {
        "section_present": False, "explicitly_absent": False,
        "needed": [], "rpath_values": [], "runpath_values": [],
    }
    program_headers = parse_program_headers(program.stdout) if program.exit_code == 0 else []
    has_dynamic_segment = any(item["type"] == "DYNAMIC" for item in program_headers)
    if dynamic.exit_code in {124, 126, 127}:
        linkage, metadata_status = "ERROR", "TOOL_ERROR"
    elif dynamic.exit_code != 0:
        linkage, metadata_status = "UNKNOWN", "PARSE_ERROR"
    elif readelf_data["section_present"] or has_dynamic_segment or readelf_data["needed"] or interpreter:
        linkage, metadata_status = "DYNAMIC", "PRESENT"
    elif readelf_data["explicitly_absent"] and header["elf_type"] == "EXEC" and not interpreter:
        linkage, metadata_status = "STATIC", "ABSENT"
    elif readelf_data["explicitly_absent"]:
        linkage, metadata_status = "UNKNOWN", "ABSENT_AMBIGUOUS"
    else:
        linkage, metadata_status = "UNKNOWN", "UNKNOWN"

    objdump_data = parse_objdump_private_headers(objdump.stdout) if objdump.exit_code == 0 else None
    if objdump_data is None:
        cross_check_status = "TOOL_ERROR" if objdump.exit_code in {124, 126, 127} else "NOT_AVAILABLE"
        disagreement = None
    elif dynamic.exit_code != 0:
        cross_check_status, disagreement = "READ_ELF_UNAVAILABLE", None
    else:
        disagreement = any(
            readelf_data[key] != objdump_data[key]
            for key in ("needed", "rpath_values", "runpath_values")
        )
        cross_check_status = "DISAGREEMENT" if disagreement else "AGREEMENT"

    all_refs = [dynamic.reference.evidence_id, program.reference.evidence_id, objdump.reference.evidence_id]
    field_refs = [dynamic.reference.evidence_id]
    if objdump.exit_code == 0:
        field_refs.append(objdump.reference.evidence_id)
    rpath_entries = split_search_paths(readelf_data["rpath_values"])
    runpath_entries = split_search_paths(readelf_data["runpath_values"])
    return {
        "linkage": linkage,
        "metadata_status": metadata_status,
        "interpreter": {"value": interpreter, "evidence_refs": [program.reference.evidence_id]},
        "needed": [{"name": name, "evidence_refs": field_refs} for name in readelf_data["needed"]],
        "rpath": {
            "present": bool(readelf_data["rpath_values"]),
            "original_values": readelf_data["rpath_values"],
            "entries": rpath_entries,
            "evidence_refs": field_refs,
        },
        "runpath": {
            "present": bool(readelf_data["runpath_values"]),
            "original_values": readelf_data["runpath_values"],
            "entries": runpath_entries,
            "evidence_refs": field_refs,
        },
        "custom_search_path": (
            "BOTH" if readelf_data["rpath_values"] and readelf_data["runpath_values"]
            else "RPATH" if readelf_data["rpath_values"]
            else "RUNPATH" if readelf_data["runpath_values"]
            else "NONE"
        ),
        "indicators": search_path_indicators(rpath_entries + runpath_entries),
        "cross_check": {
            "authority": "readelf",
            "secondary_tool": "objdump",
            "status": cross_check_status,
            "tool_disagreement": disagreement,
        },
        "evidence_refs": all_refs,
        "dlopen_dlsym": "DEFERRED_TO_SYMBOL_CAPABILITY_MILESTONE",
        "runtime_environment": "NOT_EVALUATED",
        "component_scope": component_type,
    }


def permission_triplet(mode: int, read: int, write: int, execute: int) -> dict[str, bool]:
    return {
        "read": bool(mode & read),
        "write": bool(mode & write),
        "execute": bool(mode & execute),
    }


def lookup_owner(uid: int) -> tuple[str | None, str]:
    try:
        return pwd.getpwuid(uid).pw_name, "RESOLVED"
    except KeyError:
        return None, "NOT_FOUND"
    except OSError:
        return None, "ERROR"


def lookup_group(gid: int) -> tuple[str | None, str]:
    try:
        return grp.getgrgid(gid).gr_name, "RESOLVED"
    except KeyError:
        return None, "NOT_FOUND"
    except OSError:
        return None, "ERROR"


def stat_result(path: Path) -> dict[str, Any]:
    link_stat = path.lstat()
    is_symlink = stat_module.S_ISLNK(link_stat.st_mode)
    effective_path = path.resolve(strict=True)
    effective = effective_path.stat()
    mode = stat_module.S_IMODE(effective.st_mode)
    owner_name, owner_status = lookup_owner(effective.st_uid)
    group_name, group_status = lookup_group(effective.st_gid)
    group_writable = bool(mode & stat_module.S_IWGRP)
    world_writable = bool(mode & stat_module.S_IWOTH)
    return {
        "input_path": str(path.absolute()),
        "is_symlink": is_symlink,
        "symlink_target": os.readlink(path) if is_symlink else None,
        "final_resolved_path": str(effective_path),
        "file_type": (
            "directory" if stat_module.S_ISDIR(effective.st_mode)
            else "regular_file" if stat_module.S_ISREG(effective.st_mode)
            else "other"
        ),
        "owner": {"uid": effective.st_uid, "name": owner_name, "lookup_status": owner_status},
        "group": {"gid": effective.st_gid, "name": group_name, "lookup_status": group_status},
        "mode": f"{mode:04o}",
        "setuid": bool(mode & stat_module.S_ISUID),
        "setgid": bool(mode & stat_module.S_ISGID),
        "sticky": bool(mode & stat_module.S_ISVTX),
        "user": permission_triplet(mode, stat_module.S_IRUSR, stat_module.S_IWUSR, stat_module.S_IXUSR),
        "group_permissions": permission_triplet(mode, stat_module.S_IRGRP, stat_module.S_IWGRP, stat_module.S_IXGRP),
        "other": permission_triplet(mode, stat_module.S_IROTH, stat_module.S_IWOTH, stat_module.S_IXOTH),
        "world_writable": world_writable,
        "group_writable": group_writable,
        "writable_by_non_owner": group_writable or world_writable,
    }


def collect_structured_stat(
    path: Path, runner: EvidenceRunner,
) -> tuple[dict[str, Any] | None, EvidenceReference, str, str | None]:
    try:
        result = stat_result(path)
        reference = runner.record_structured("python_os_stat", path, result)
        return result, reference, "SUCCESS", None
    except FileNotFoundError as exc:
        result = {"path": str(path.absolute())}
        reference = runner.record_structured("python_os_stat", path, result, "PATH_NOT_FOUND", str(exc))
        return None, reference, "PATH_NOT_FOUND", str(exc)
    except PermissionError as exc:
        result = {"path": str(path.absolute())}
        reference = runner.record_structured("python_os_stat", path, result, "PERMISSION_DENIED", str(exc))
        return None, reference, "PERMISSION_DENIED", str(exc)
    except OSError as exc:
        result = {"path": str(path.absolute())}
        reference = runner.record_structured("python_os_stat", path, result, "ERROR", str(exc))
        return None, reference, "ERROR", str(exc)


def parse_capabilities(text: str) -> list[dict[str, str]]:
    capabilities: list[dict[str, str]] = []
    for names, flags in re.findall(r"((?:cap_[a-z0-9_]+,?)+)=([eip]+)", text.lower()):
        for name in names.rstrip(",").split(","):
            capabilities.append({"name": name, "flags": flags})
    return capabilities


def resolve_search_directory(
    entry: str, artifact: Path, runner: EvidenceRunner,
) -> tuple[dict[str, Any], list[EvidenceReference]]:
    origin_pattern = re.compile(r"\$(?:ORIGIN|\{ORIGIN\})")
    references: list[EvidenceReference] = []
    if entry in {"", "."} or (not entry.startswith("/") and not origin_pattern.search(entry)):
        return {
            "original": entry,
            "resolution_status": "RUNTIME_CONTEXT_REQUIRED",
            "resolved": None,
            "exists": None,
            "permissions": None,
            "evidence_refs": [],
        }, references
    if entry.startswith("/"):
        return {
            "original": entry,
            "resolution_status": "TARGET_ROOT_CONTEXT_REQUIRED",
            "resolved": os.path.normpath(entry),
            "exists": None,
            "permissions": None,
            "evidence_refs": [],
        }, references
    expanded = origin_pattern.sub(str(artifact.parent.resolve()), entry)
    if "$" in expanded:
        return {
            "original": entry,
            "resolution_status": "UNRESOLVED_LOADER_TOKEN",
            "resolved": os.path.normpath(expanded),
            "exists": None,
            "permissions": None,
            "evidence_refs": [],
        }, references
    resolved = Path(os.path.normpath(expanded))
    permissions, reference, status, error = collect_structured_stat(resolved, runner)
    references.append(reference)
    return {
        "original": entry,
        "resolution_status": "RESOLVED" if status == "SUCCESS" else status,
        "resolved": str(resolved),
        "exists": status == "SUCCESS",
        "final_resolved_path": permissions["final_resolved_path"] if permissions else None,
        "is_symlink": permissions["is_symlink"] if permissions else None,
        "permissions": permissions,
        "error": error,
        "evidence_refs": [reference.evidence_id],
    }, references


def evaluate_permissions(
    path: Path, component: str, component_type: str,
    dynamic_linking: dict[str, Any], runner: EvidenceRunner,
) -> tuple[dict[str, Any], list[EvidenceReference]]:
    references: list[EvidenceReference] = []
    target_stat, target_ref, target_status, target_error = collect_structured_stat(path, runner)
    references.append(target_ref)
    stat_cli = runner.run(["stat", "--printf=%u|%g|%a|%A|%F\n", "--", str(path)], path)
    references.append(stat_cli.reference)

    parent = path.absolute().parent
    parent_stat, parent_ref, parent_status, parent_error = collect_structured_stat(parent, runner)
    references.append(parent_ref)
    parent_cli = runner.run(["stat", "--printf=%u|%g|%a|%A|%F\n", "--", str(parent)], parent)
    references.append(parent_cli.reference)

    getcap = runner.run(["getcap", "-n", str(path.resolve())], path)
    references.append(getcap.reference)
    if getcap.exit_code == 127:
        capabilities, capability_status = [], "TOOL_UNAVAILABLE"
    elif getcap.exit_code == 0:
        capabilities = parse_capabilities(getcap.stdout)
        capability_status = "PRESENT" if capabilities else "NONE"
    elif "permission denied" in getcap.stderr.lower():
        capabilities, capability_status = [], "PERMISSION_DENIED"
    else:
        capabilities, capability_status = [], "EXECUTION_ERROR"

    cross_check = (
        "TOOL_UNAVAILABLE" if stat_cli.exit_code == 127
        else "EXECUTION_ERROR" if stat_cli.exit_code != 0
        else "NOT_AVAILABLE"
    )
    if target_stat and stat_cli.exit_code == 0:
        expected = f"{target_stat['owner']['uid']}|{target_stat['group']['gid']}|{int(target_stat['mode'], 8):o}"
        cross_check = "AGREEMENT" if stat_cli.stdout.startswith(expected + "|") else "DISAGREEMENT"

    search_directories: list[dict[str, Any]] = []
    for source in ("rpath", "runpath"):
        for entry in dynamic_linking[source]["entries"]:
            resolved, new_references = resolve_search_directory(entry, path, runner)
            resolved["source"] = source.upper()
            search_directories.append(resolved)
            references.extend(new_references)

    return {
        "status": target_status,
        "component_id": component,
        "file": target_stat,
        "file_error": target_error,
        "capability_collection": {
            "status": capability_status,
            "capabilities": capabilities,
            "evidence_refs": [getcap.reference.evidence_id],
        },
        "parent_directory": {
            "status": parent_status,
            "path": str(parent),
            "metadata": parent_stat,
            "error": parent_error,
            "evidence_refs": [parent_ref.evidence_id, parent_cli.reference.evidence_id],
        },
        "search_path_directories": search_directories,
        "stat_cross_check": {
            "source": "python_os_stat",
            "secondary_tool": "stat",
            "status": cross_check,
            "evidence_refs": [target_ref.evidence_id, stat_cli.reference.evidence_id],
        },
        "acl": "NOT_EVALUATED",
        "runtime_execution_identity": "NOT_EVALUATED",
        "shared_object_runtime_privilege": (
            "NOT_EVALUATED" if component_type == "elf_shared_object" else "NOT_APPLICABLE"
        ),
        "evidence_refs": [reference.evidence_id for reference in references],
    }, references


def evaluate_hardening(
    component_type: str,
    header: dict[str, str | None],
    file_evidence: EvidenceReference,
    header_evidence: EvidenceReference,
    program: Invocation,
    dynamic: Invocation,
    symbols: Invocation,
) -> dict[str, Any]:
    """Normalize CHK-05 states without creating findings or severity."""
    program_headers = parse_program_headers(program.stdout) if program.exit_code == 0 else []
    program_refs = [program.reference]
    dynamic_refs = [dynamic.reference]
    symbol_refs = [symbols.reference]

    if program.exit_code != 0:
        relro = check_result("ERROR", program_refs + dynamic_refs, "NONE", ["program headers unavailable"])
        nx = check_result("ERROR", program_refs, "NONE", ["program headers unavailable"])
        executable_stack = check_result("ERROR", program_refs, "NONE", ["program headers unavailable"])
        rwx = check_result("ERROR", program_refs, "NONE", ["program headers unavailable"])
    else:
        has_relro = any(item["type"] == "GNU_RELRO" for item in program_headers)
        if not has_relro:
            relro = check_result("NONE", program_refs + dynamic_refs, "HIGH", ["PT_GNU_RELRO is absent"])
        elif dynamic.exit_code != 0:
            relro = check_result("UNKNOWN", program_refs + dynamic_refs, "LOW", ["PT_GNU_RELRO is present", "dynamic section unavailable"])
        else:
            bind_now = bool(re.search(r"\bBIND_NOW\b|Flags:\s*.*\bNOW\b", dynamic.stdout))
            relro = check_result(
                "FULL" if bind_now else "PARTIAL", program_refs + dynamic_refs, "HIGH",
                ["PT_GNU_RELRO is present", "immediate binding is present" if bind_now else "immediate binding is absent"],
            )

        stack_headers = [item for item in program_headers if item["type"] == "GNU_STACK"]
        if not stack_headers:
            nx = check_result("UNKNOWN", program_refs, "LOW", ["PT_GNU_STACK is absent"])
            executable_stack = check_result("UNKNOWN", program_refs, "LOW", ["PT_GNU_STACK is absent"])
        else:
            stack_executable = any("E" in item["flags"] for item in stack_headers)
            stack_lines = [item["raw"] for item in stack_headers]
            nx = check_result("DISABLED" if stack_executable else "ENABLED", program_refs, "HIGH", stack_lines)
            executable_stack = check_result("ENABLED" if stack_executable else "DISABLED", program_refs, "HIGH", stack_lines)

        rwx_headers = [
            item for item in program_headers
            if item["type"] == "LOAD" and all(flag in item["flags"] for flag in "RWE")
        ]
        rwx = check_result(
            "PRESENT" if rwx_headers else "ABSENT", program_refs, "HIGH",
            [item["raw"] for item in rwx_headers],
        )

    if component_type == "elf_shared_object":
        pie = check_result("NOT_APPLICABLE", [header_evidence], "HIGH", ["component is a shared object"])
    elif component_type == "elf_executable":
        if header["elf_type"] == "EXEC":
            pie = check_result("DISABLED", [header_evidence, file_evidence], "HIGH", ["executable ELF type is ET_EXEC"])
        elif header["elf_type"] == "DYN" and parse_interpreter(program.stdout):
            pie = check_result(
                "ENABLED", [header_evidence, program.reference, file_evidence], "HIGH",
                ["executable ELF type is ET_DYN", "PT_INTERP is present"],
            )
        else:
            pie = check_result("UNKNOWN", [header_evidence, program.reference, file_evidence], "LOW", ["PIE evidence is ambiguous"])
    else:
        pie = check_result("NOT_APPLICABLE", [header_evidence], "HIGH")

    if symbols.exit_code == 0:
        canary_symbols = sorted(set(re.findall(r"\b(__stack_chk_(?:fail|guard))(?:@\S+)?", symbols.stdout)))
        canary = check_result(
            "ENABLED" if canary_symbols else "NOT_DETECTED", symbol_refs,
            "HIGH" if canary_symbols else "MEDIUM",
            canary_symbols or ["no dynamic stack-protector symbol was detected; this is not proof of source-wide absence"],
        )
        imported_names = {
            line.split()[-1].split("@", 1)[0]
            for line in symbols.stdout.splitlines() if line.split()
        }
        fortify_symbols = sorted(
            name for name in imported_names
            if name.startswith("__") and name.endswith("_chk") and not name.startswith("__stack_chk")
        )
        fortify = check_result(
            "ENABLED" if fortify_symbols else "UNKNOWN", symbol_refs,
            "HIGH" if fortify_symbols else "LOW",
            fortify_symbols or ["no fortified libc wrapper was detected; eligible calls or independent compiler evidence are unknown"],
        )
    else:
        tool_failed = symbols.exit_code in {124, 126, 127}
        status = "ERROR" if tool_failed else "UNKNOWN"
        confidence = "NONE" if tool_failed else "LOW"
        detail = "nm execution failed" if tool_failed else "dynamic symbol evidence is unavailable or absent"
        canary = check_result(status, symbol_refs, confidence, [detail])
        fortify = check_result(status, symbol_refs, confidence, [detail])

    return {
        "relro": relro,
        "stack_canary": canary,
        "nx": nx,
        "pie": pie,
        "fortify": fortify,
        "executable_stack": executable_stack,
        "rwx_segment": rwx,
    }


def classify_elf(
    header: dict[str, str | None], interpreter: str | None,
    soname: str | None, file_text: str, mode: int,
) -> tuple[str, list[str]]:
    elf_type = header["elf_type"]
    description = (header["elf_type_description"] or "").lower()
    file_lower = file_text.lower()
    reasons = [f"ELF header type is {elf_type}"]
    if elf_type == "EXEC":
        return "elf_executable", reasons
    if elf_type != "DYN":
        return "unsupported", reasons + ["ELF object type is outside the current MVP"]
    if interpreter:
        return "elf_executable", reasons + ["PT_INTERP is present"]
    if soname:
        return "elf_shared_object", reasons + ["DT_SONAME is present", "PT_INTERP is absent"]
    if "position-independent executable" in description or "pie executable" in file_lower:
        return "elf_executable", reasons + ["tool semantics identify a PIE executable", f"executable mode is {bool(mode & 0o111)}"]
    if "shared object" in file_lower:
        return "elf_shared_object", reasons + ["file magic identifies a shared object", "PT_INTERP is absent"]
    return "unsupported", reasons + ["ET_DYN role is ambiguous without executable or shared-object evidence"]


def iter_targets(target: Path, excluded_root: Path | None = None) -> Iterable[Path]:
    if target.is_file():
        yield target
        return
    for root, directories, files in os.walk(target, followlinks=False):
        root_path = Path(root).resolve()
        if excluded_root and (root_path == excluded_root or excluded_root in root_path.parents):
            directories[:] = []
            continue
        directories.sort()
        if excluded_root:
            directories[:] = [
                name for name in directories
                if (Path(root) / name).resolve() != excluded_root
            ]
        for name in sorted(files):
            path = Path(root) / name
            if path.is_file() and not path.is_symlink():
                yield path


def analyze_file(path: Path, runner: EvidenceRunner, target_root: Path | None = None) -> dict[str, Any]:
    evidence: list[EvidenceReference] = []
    sha = runner.run(["sha256sum", "--", str(path)], path)
    evidence.append(sha.reference)
    sha256 = sha.stdout.split()[0] if sha.exit_code == 0 and sha.stdout.split() else None
    file_result = runner.run(["file", "-b", "--", str(path)], path)
    evidence.append(file_result.reference)
    base: dict[str, Any] = {
        "path": str(path.absolute()),
        "sha256": sha256,
        "component_id": component_id("unsupported", sha256),
        "type": "unsupported",
        "status": "NOT_IMPLEMENTED_IN_CURRENT_MVP",
        "elf": None,
        "hardening": None,
        "dynamic_linking": None,
        "permissions": None,
        "capabilities": None,
        "dependencies": None,
        "classification_evidence": [],
        "raw_evidence": [item.as_dict() for item in evidence],
    }
    if not has_elf_magic(path):
        base["classification_evidence"] = ["ELF magic is absent"]
        return base

    header_result = runner.run(["readelf", "-W", "-h", "--", str(path)], path)
    evidence.append(header_result.reference)
    if header_result.exit_code != 0:
        tool_failure = header_result.exit_code in {124, 126, 127}
        base.update({
            "type": "unsupported" if tool_failure else "malformed_elf",
            "status": "ERROR",
            "classification_evidence": [
                "ELF magic is present",
                "readelf execution failed" if tool_failure else "readelf could not parse the ELF header",
            ],
            "raw_evidence": [item.as_dict() for item in evidence],
        })
        base["component_id"] = component_id(base["type"], sha256)
        return base
    header = parse_header(header_result.stdout)
    if not all(header[key] for key in ("elf_class", "endianness", "elf_type", "machine")):
        base.update({
            "type": "malformed_elf",
            "status": "ERROR",
            "classification_evidence": ["ELF header output is incomplete"],
            "raw_evidence": [item.as_dict() for item in evidence],
        })
        base["component_id"] = component_id("malformed_elf", sha256)
        return base

    program = runner.run(["readelf", "-W", "-l", "--", str(path)], path)
    notes = runner.run(["readelf", "-W", "-n", "--", str(path)], path)
    dynamic = runner.run(["readelf", "-W", "-d", "--", str(path)], path)
    symbols = runner.run(["nm", "-D", "--undefined-only", "--", str(path)], path)
    evidence.extend((program.reference, notes.reference, dynamic.reference, symbols.reference))
    interpreter = parse_interpreter(program.stdout) if program.exit_code == 0 else None
    build_id = parse_build_id(notes.stdout) if notes.exit_code == 0 else None
    soname = parse_soname(dynamic.stdout) if dynamic.exit_code == 0 else None
    component_type, reasons = classify_elf(
        header, interpreter, soname, file_result.stdout, path.stat().st_mode,
    )
    status = "SUCCESS" if component_type != "unsupported" else "NOT_IMPLEMENTED_IN_CURRENT_MVP"
    base.update({
        "component_id": component_id(component_type, sha256),
        "type": component_type,
        "status": status,
        "architecture": normalize_architecture(header["machine"]),
        "elf": {
            "class": header["elf_class"],
            "endianness": header["endianness"],
            "machine": header["machine"],
            "elf_type": header["elf_type"],
            "build_id": build_id,
            "interpreter": interpreter,
            "soname": soname,
        },
        "classification_evidence": reasons,
        "raw_evidence": [item.as_dict() for item in evidence],
    })
    if component_type in {"elf_executable", "elf_shared_object"}:
        base["hardening"] = evaluate_hardening(
            component_type, header, file_result.reference, header_result.reference,
            program, dynamic, symbols,
        )
        objdump = runner.run(["objdump", "-p", "--", str(path)], path)
        evidence.append(objdump.reference)
        base["raw_evidence"] = [item.as_dict() for item in evidence]
        base["dynamic_linking"] = evaluate_dynamic_linking(
            component_type, header, interpreter, program, dynamic, objdump,
        )
        permissions, permission_evidence = evaluate_permissions(
            path, base["component_id"], component_type, base["dynamic_linking"], runner,
        )
        evidence.extend(permission_evidence)
        base["raw_evidence"] = [item.as_dict() for item in evidence]
        base["permissions"] = permissions
        exported_symbols = runner.run(["nm", "-D", "--defined-only", "--", str(path)], path)
        readelf_dynsyms = runner.run(["readelf", "-W", "--dyn-syms", "--", str(path)], path)
        evidence.extend((exported_symbols.reference, readelf_dynsyms.reference))
        base["raw_evidence"] = [item.as_dict() for item in evidence]
        base["capabilities"] = evaluate_capabilities(
            component_type, file_result.stdout, base["dynamic_linking"]["linkage"],
            symbols, exported_symbols, readelf_dynsyms,
        )
        dependencies, dependency_evidence = evaluate_dependencies(
            path, base["component_id"], base["architecture"], base["dynamic_linking"],
            target_root, runner,
        )
        evidence.extend(dependency_evidence)
        base["raw_evidence"] = [item.as_dict() for item in evidence]
        base["dependencies"] = dependencies
    else:
        base["hardening"] = None
        base["dynamic_linking"] = None
        base["permissions"] = None
        base["capabilities"] = None
        base["dependencies"] = None
    return base


def scan(
    target: Path, output_root: Path, run_id: str | None = None,
    target_root: Path | None = None,
) -> tuple[Path, dict[str, Any]]:
    target = target.absolute()
    output_root = output_root.resolve()
    if not target.exists() or not (target.is_file() or target.is_dir()):
        raise ValueError(f"target must be an existing file or directory: {target}")
    if target_root is not None:
        target_root = target_root.resolve()
        if not target_root.is_dir():
            raise ValueError(f"target root must be an existing directory: {target_root}")
        try:
            target.resolve().relative_to(target_root)
        except ValueError as exc:
            raise ValueError(f"target must be inside the explicit target root: {target}") from exc
    actual_run_id = run_id or new_run_id()
    targets = list(iter_targets(target, excluded_root=output_root))
    run_root = output_root / "runs" / actual_run_id
    run_root.mkdir(parents=True, exist_ok=False)
    runner = EvidenceRunner(run_root)
    started = utc_now()
    records = [analyze_file(path, runner, target_root) for path in targets]
    normalized = {
        "schema_version": SCHEMA_VERSION,
        "run_id": actual_run_id,
        "milestone": "6-elf-dependency-provenance",
        "started_at": started,
        "finished_at": utc_now(),
        "target": str(target),
        "target_root": str(target_root) if target_root is not None else None,
        "records": records,
        "summary": {
            "total": len(records),
            "elf_executable": sum(item["type"] == "elf_executable" for item in records),
            "elf_shared_object": sum(item["type"] == "elf_shared_object" for item in records),
            "malformed_elf": sum(item["type"] == "malformed_elf" for item in records),
            "unsupported": sum(item["type"] == "unsupported" for item in records),
        },
    }
    normalized_dir = run_root / "normalized"
    normalized_dir.mkdir()
    atomic_json(normalized_dir / "inventory.json", normalized)
    evaluation = evaluate_inventory(normalized)
    atomic_json(normalized_dir / "findings.json", evaluation)
    atomic_json(run_root / "run.json", {
        "schema_version": SCHEMA_VERSION,
        "run_id": actual_run_id,
        "target": str(target),
        "target_root": str(target_root) if target_root is not None else None,
        "started_at": started,
        "finished_at": normalized["finished_at"],
        "normalized_output": "normalized/inventory.json",
        "findings_output": "normalized/findings.json",
    })
    return run_root, normalized
