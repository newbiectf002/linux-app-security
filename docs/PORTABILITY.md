# Project Portability

This project is designed to be cloned on another Ubuntu/WSL host and rebuilt
without copying Docker image layers.

## What Git contains

Git should contain the project instructions and context, approved Step 1–4
baseline, Batch 1 research report and matrix, configuration, Docker/Compose
definitions, reproducible sample source/metadata, and scripts.

## What Git does not contain

The following are ignored or intentionally kept outside Git:

- `.env` and credentials;
- `exports/` archives;
- cache, temporary files, virtual environments, and `node_modules/`;
- generated scanner output under `output/`;
- generated ELF binaries and package artifacts (`.deb`, `.rpm`, `.snap`, etc.);
- the locally built checksec executable;
- Docker images, layers, containers, networks, and volumes.

Use the evidence export archive when ignored research evidence or generated
artifacts must move with the project. Never place real credentials in evidence.

## Clone and rebuild on a new machine

Use a private repository:

```bash
git clone <PRIVATE_REPO_URL>
cd linux-app-security

git switch step5-tool-research

cp .env.example .env

docker compose build
docker compose run --rm research bash
```

The `.env` file is optional and must not contain committed credentials. The
Compose build uses host networking only while constructing the image to work
around the documented WSL Docker bridge issue; runtime remains on its normal
Compose network.

## Restore an evidence archive

Copy both the archive and its `.sha256` sidecar to the new machine, then run:

```bash
./scripts/import-project.sh /path/to/linux-app-security-evidence-YYYYMMDD-HHMMSS.tar.gz
```

The importer verifies the sidecar when present, validates every archive member,
rejects links and unsafe paths, and will not overwrite existing project files.
It restores only approved evidence/output/generated-artifact locations.

## Create an evidence archive

```bash
./scripts/export-project.sh
```

The default destination is
`exports/linux-app-security-evidence-YYYYMMDD-HHMMSS.tar.gz`, with a matching
`.sha256` file. Source data is never deleted. Cache, temporary data, `.git`,
`.env`, common credential files, and Docker storage are excluded.

## Optional private Git remote

Do not publish this repository. If the user has provisioned a private remote:

```bash
git remote add origin <PRIVATE_REPO_URL>
git push -u origin master
git push -u origin step5-tool-research
```

Review `git status`, ignored artifacts, and raw evidence before pushing. Raw
evidence stays outside Git and moves via the evidence archive. No remote is
required for local archive portability.
