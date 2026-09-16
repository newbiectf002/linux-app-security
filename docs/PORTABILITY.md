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

git switch main

cp .env.example .env

docker compose build
docker compose run --rm research bash
```

## Move the built images without rebuilding

On the source machine:

```bash
docker save \
  linux-app-security-research:latest \
  linux-app-security-codex:local \
  | gzip > linux-app-security-images.tar.gz
```

Copy the archive and repository to the target Linux machine, then load it:

```bash
gzip -dc linux-app-security-images.tar.gz | docker load
docker compose run --rm research bash
```

The scanner image can continue fully offline after the Grype and ClamAV caches
are copied. Cache data lives in the ignored repository `cache/` directory and
is not part of `docker save`; copy it separately when offline operation matters.
Set `LOCAL_UID` and `LOCAL_GID` in `.env` to the target Linux user IDs so scan
outputs remain editable by that user.

The optional Codex image does not contain credentials. Start it with:

```bash
docker compose --profile codex run --rm codex
```

On first use, sign in interactively. The Compose file stores Codex state in the
`codex-home` volume; do not bake or commit that volume, API keys, or auth files.
Codex itself still requires network access to authenticate and use models.

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
git push -u origin main
```

Review `git status`, ignored artifacts, and raw evidence before pushing. Raw
evidence stays outside Git and moves via the evidence archive. No remote is
required for local archive portability.
