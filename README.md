# Linux Application Security Analysis

This repository holds the approved research baseline and a portable development environment for static and artifact-based analysis of Linux desktop applications.

## Current status

Steps 1–4: research baseline completed.  
Step 5: pending.

No scanner has been selected or installed by this setup.

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
