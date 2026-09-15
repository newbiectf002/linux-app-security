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

The current implementation is an ELF/`.so` MVP foundation, not a complete
production scanner. Symbol/API capability, dependency provenance, correlation,
export, and reporting milestones are not implemented yet. Normalized hardening,
dynamic-linking, and permission states are evidence and indicators, not findings.

## Project structure

- `docs/`: approved Step 1–4 baseline documents
- `research/raw/`: preserved raw research evidence
- `samples/`: samples grouped by artifact type
- `scripts/`: future install, scan, parser, and shared helper scripts
- `config/`: machine-readable configuration
- `output/`, `cache/`, `tmp/`: generated working data

## Reading order

Read `AGENTS.md`, then `PROJECT_CONTEXT.md`, followed by the four approved documents in `docs/` in numeric order.

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

Each execution creates a unique directory under `output/runs/` containing
immutable per-invocation raw evidence and `normalized/inventory.json`.
