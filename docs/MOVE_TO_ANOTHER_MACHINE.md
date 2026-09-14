# Move to Another Machine

Clone the private repository and switch to the current research branch:

```bash
git clone <PRIVATE_REPO_URL>
cd linux-app-security
git switch step5-tool-research

cp .env.example .env

docker compose build
```

Copy the latest evidence archive and its matching `.sha256` sidecar to the new
machine. From the cloned repository, restore the evidence without overwriting
existing project files:

```bash
./scripts/import-project.sh /path/to/linux-app-security-evidence-....tar.gz
```

Open the research environment:

```bash
docker compose run --rm research bash
```

To continue with Codex, use this instruction:

```text
Read AGENTS.md and PROJECT_CONTEXT.md, inspect the current git branch and Step 5 research state, then continue only from the currently authorized task.
```

Step 5 Batch 2 must not begin without explicit authorization.
