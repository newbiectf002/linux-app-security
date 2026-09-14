#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <archive.tar.gz>" >&2
    exit 2
fi

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
project_root=$(cd -- "$script_dir/.." && pwd -P)
archive_input=$1

if [[ ! -f "$archive_input" ]]; then
    echo "Archive not found: $archive_input" >&2
    exit 1
fi

archive_dir=$(cd -- "$(dirname -- "$archive_input")" && pwd -P)
archive="$archive_dir/$(basename -- "$archive_input")"
checksum="$archive.sha256"

if [[ -f "$checksum" ]]; then
    (
        cd -- "$archive_dir"
        sha256sum -c -- "$(basename -- "$checksum")"
    )
    echo "Checksum verification: PASS"
else
    echo "Checksum sidecar not found; continuing without checksum verification." >&2
fi

staging=$(mktemp -d)
member_list=$(mktemp)
trap 'rm -rf -- "$staging"; rm -f -- "$member_list"' EXIT

python3 - "$archive" "$member_list" <<'PY'
import pathlib
import sys
import tarfile

archive, output = sys.argv[1:]
protected = {
    ".git", "AGENTS.md", "PROJECT_CONTEXT.md", "Dockerfile",
    "docs/01-identification.md", "docs/02-extraction.md",
    "docs/03-component-classification.md", "docs/04-security-checklist.md",
}
generated_suffixes = (
    ".AppImage", ".deb", ".rpm", ".snap", ".flatpak", ".zip", ".7z",
    ".tar", ".tar.gz", ".tgz",
)

def allowed(name: str, is_dir: bool) -> bool:
    if name in {"research", "research/raw", "output", "samples", "samples/elf", "samples/elf/generated"}:
        return is_dir
    if name.startswith("research/raw/") or name.startswith("output/"):
        return True
    if name.startswith("samples/elf/generated/"):
        return True
    return name.startswith("samples/") and name.endswith(generated_suffixes)

with tarfile.open(archive, "r:gz") as tf, open(output, "w", encoding="utf-8") as out:
    for member in tf.getmembers():
        name = member.name
        path = pathlib.PurePosixPath(name)
        if not name or name.startswith("/") or ".." in path.parts or "\\" in name:
            raise SystemExit(f"Unsafe archive path: {name!r}")
        if name in protected or name.startswith(".git/"):
            raise SystemExit(f"Protected project path in archive: {name}")
        if member.issym() or member.islnk() or not (member.isfile() or member.isdir()):
            raise SystemExit(f"Unsupported archive member type: {name}")
        if not allowed(name, member.isdir()):
            raise SystemExit(f"Path outside approved restore locations: {name}")
        out.write(name + "\n")
PY

tar -xzf "$archive" -C "$staging" --no-same-owner --no-same-permissions

restored=0
skipped=0
while IFS= read -r relative; do
    [[ -n "$relative" ]] || continue
    source_path="$staging/$relative"
    destination="$project_root/$relative"
    if [[ -d "$source_path" ]]; then
        mkdir -p -- "$destination"
        continue
    fi
    if [[ -e "$destination" ]]; then
        echo "Skipped existing: $relative"
        skipped=$((skipped + 1))
        continue
    fi
    mkdir -p -- "$(dirname -- "$destination")"
    cp -p -- "$source_path" "$destination"
    echo "Restored: $relative"
    restored=$((restored + 1))
done <"$member_list"

echo "Restore completed: $restored file(s) restored, $skipped existing file(s) skipped."
