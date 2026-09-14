# Portability Report

## Git branch

Current branch: `step5-tool-research`

Batch 1 and portability work were committed locally. No merge, remote creation,
or push was performed.

## Files created/modified

Created for this task:

- `docs/PORTABILITY.md`
- `scripts/export-project.sh`
- `scripts/import-project.sh`
- `PORTABILITY_REPORT.md`

Modified for this task:

- `.gitignore` — added `exports/`

The approved Step 1–4 baseline and Batch 1 research results were not modified by
the portability work. Pre-existing Batch 1 work was committed separately.

## Export archive

- Path: `exports/linux-app-security-evidence-20260913-175249.tar.gz`
- Absolute path: `/mnt/c/Users/acer/Downloads/codex_scanLinux/linux-app-security/exports/linux-app-security-evidence-20260913-175249.tar.gz`
- Size: 3,440,193 bytes (approximately 3.3 MiB)
- SHA-256: `3a65ca381274532e4298997e7d38d92758896ab741e5d3eeb92bcef6a8bb61b2`
- Sidecar: `exports/linux-app-security-evidence-20260913-175249.tar.gz.sha256`
- Archive members: 64

## SHA256 verification result

PASS — `sha256sum -c` verified the generated archive successfully.

## Import test result

PASS — import was tested in the isolated ignored directory
`tmp/portability-import-test/`, not over the active repository. It restored 52
files with zero existing-file conflicts. Expected raw evidence, generated ELF,
DEB, RPM, Snap, and output placeholder files were present. `.git`, `AGENTS.md`,
`PROJECT_CONTEXT.md`, Dockerfile, and baseline documents were not restored or
overwritten.

Both scripts passed `bash -n`. The importer also preflighted all members before
extraction and accepted no absolute paths, traversal, links, special members, or
paths outside the approved restore locations.

## Docker rebuild instructions

Verified:

```bash
docker compose build
docker compose run --rm research bash
```

The build completed successfully and the research container opened with
`/workspace` as its working directory.

## Data intentionally excluded

- `.git/`
- `.env` and `.env.*`
- common credential/key filenames and `.aws`/`.ssh` directories
- `cache/` and `tmp/`
- virtual environments and `node_modules/`
- Docker images, layers, containers, networks, and volumes
- files outside the explicit evidence/output/generated-artifact allowlist

The `exports/` directory is ignored by Git, so evidence archives are not
committed by default.

## Git status

The branch remains `step5-tool-research`, and the worktree is clean. Generated
artifacts, raw evidence, exports, cache, and temporary files remain intentionally
ignored. No baseline document under `docs/01-*` through `docs/04-*` is modified.

Portable project setup completed.

Step 5 Batch 2 has NOT been started.
