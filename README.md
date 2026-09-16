# Linux Application Security Analysis

This repository holds the approved research baseline and a portable development environment for static and artifact-based analysis of Linux desktop applications.

## Current status

Steps 1–4: research baseline completed.

Step 5 Batch 1 (CHK-01–CHK-06): completed and retained for reuse.

Milestone 1: ELF executable/shared-object inventory and metadata implemented.

Milestone 2: ELF executable/shared-object binary-hardening normalization implemented.

Milestone 3: ELF dynamic-linking metadata and search-path indicators implemented.

Milestone 4: ELF filesystem permission, capability, parent-directory, and safe
search-path directory context implemented.
Milestone 5: ELF dynamic-symbol API capability indicators implemented for ELF executables and shared objects.

Milestone 6: deterministic ELF dependency resolution and provenance evidence
implemented with explicit target-root context.

Step 6 core: five minimal ELF permission/privilege correlation rules implemented
and validated; findings remain reviewable evidence-based classifications rather
than confirmed vulnerabilities.

The static ELF/`.so` MVP now includes the CLI workflow, real-ELF validation,
DefectDojo Generic Findings export, automatic offline HTML reports, and a
regression test suite. It is not a complete production scanner. Normalized
hardening, dynamic-linking, permission, and API capability states are evidence
and indicators, not findings.

Deferred work includes deeper dependency/provenance analysis, ACL evaluation,
runtime identity and group membership, richer runtime context, and advanced UI.

## Project structure

- `docs/`: approved Step 1–4 baseline documents
- `research/raw/`: preserved raw research evidence
- `samples/`: samples grouped by artifact type
- `scripts/`: future install, scan, parser, and shared helper scripts
- `config/`: machine-readable configuration
- `output/`, `cache/`, `tmp/`: generated working data

## Reading order

Read `AGENTS.md`, then `PROJECT_CONTEXT.md`, followed by the four approved documents in `docs/` in numeric order.

Operational scan commands for ELF executables and shared objects are documented
in [`docs/SCAN_GUIDE.md`](docs/SCAN_GUIDE.md).

## Baseline container

Build and open an interactive shell with:

```sh
docker compose build
docker compose run --rm research
```

The current repository is mounted at `/workspace`. A local `.env` is optional; copy `.env.example` to `.env` only when overrides are needed.

For scanner-heavy workloads, a copy/clone under the native WSL filesystem such as:

```text
~/projects/linux-app-security
```

may provide better Linux filesystem behavior and performance.

## Milestone 1 scan

Inside the project container, inspect a single file or a directory without
executing the target:

```sh
python3 scripts/scan/scan-elf.py <file-or-directory>
```

For deterministic dependency resolution, provide an explicit extracted or live
filesystem root. For a target on the live system:

```sh
python3 scripts/scan/scan-elf.py <target> --target-root /
```

For an extracted application tree, replace `/` with that explicit root. Host
package ownership is queried only when the root is `/`.

Each execution creates a unique directory under `output/runs/` containing
immutable per-invocation raw evidence, `run.json`, `normalized/inventory.json`,
the minimal evaluation output `normalized/findings.json`, and an offline
`report.html`. The command prints the exact paths after a successful run; use
`--no-report` to skip HTML generation.

Export normalized findings for DefectDojo's `Generic Findings Import` parser:

```sh
python3 scripts/export/export-defectdojo.py \
  output/runs/<run-id>/normalized/findings.json
```

The export is written to
`output/runs/<run-id>/defectdojo-generic-findings.json`.

Generate a self-contained offline HTML report:

```sh
python3 scripts/report/generate-html-report.py output/runs/<run-id>
```

The report is written to `output/runs/<run-id>/report.html`.
The standalone command remains available to regenerate reports for older runs.

## Data flow

```text
Target / App
    ↓
ELF discovery → raw/ evidence
    ↓
normalized/inventory.json
    ↓
Correlation / finding rules
    ↓
normalized/findings.json
    ↓
run.json
    ├── report.html
    └── defectdojo-generic-findings.json (on explicit export)
```

`inventory.json` records what the scanner observed; `findings.json` contains
evidence-backed security conclusions; `run.json` is the scan manifest;
`report.html` is for offline human review; and the DefectDojo JSON is the
machine-import artifact. Small sanitized examples are under
[`docs/examples/`](docs/examples/).

## Current limitations

This is static ELF analysis. `UNKNOWN`, `NOT_EVALUATED`,
`TARGET_ROOT_CONTEXT_REQUIRED`, and `RUNTIME_CONTEXT_REQUIRED` describe missing
or deferred context and are not vulnerabilities by themselves.
`writable_by_non_owner` includes group-writable paths, but the scanner does not
prove that the runtime process belongs to that group. ACLs and runtime identity
or group membership are not evaluated deeply.
