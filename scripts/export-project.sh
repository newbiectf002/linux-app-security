#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
project_root=$(cd -- "$script_dir/.." && pwd -P)
timestamp=$(date -u +%Y%m%d-%H%M%S)
export_dir="$project_root/exports"
archive="$export_dir/linux-app-security-evidence-$timestamp.tar.gz"
checksum="$archive.sha256"

mkdir -p -- "$export_dir"
file_list=$(mktemp)
trap 'rm -f -- "$file_list"' EXIT

cd -- "$project_root"

add_tree() {
    local root=$1
    [[ -e "$root" ]] || return 0
    find "$root" \
        \( -name .env -o -name '.env.*' -o -name credentials -o -name 'credentials.*' \
           -o -name .aws -o -name .ssh -o -name id_rsa -o -name id_ed25519 \
           -o -name '*.key' -o -name '*.p12' -o -name '*.pfx' \) -prune \
        -o -print0 >>"$file_list"
}

add_tree research/raw
add_tree output
add_tree samples/elf/generated

if [[ -d samples ]]; then
    find samples -type f \
        \( -name '*.AppImage' -o -name '*.deb' -o -name '*.rpm' \
           -o -name '*.snap' -o -name '*.flatpak' -o -name '*.zip' \
           -o -name '*.7z' -o -name '*.tar' -o -name '*.tar.gz' \
           -o -name '*.tgz' \) \
        ! -name .env ! -name '.env.*' ! -name '*.key' ! -name '*.p12' \
        ! -name '*.pfx' -print0 >>"$file_list"
fi

if [[ ! -s "$file_list" ]]; then
    echo "No eligible evidence or generated artifacts were found." >&2
    exit 1
fi

LC_ALL=C sort -zu "$file_list" -o "$file_list"
tar --no-recursion --null --files-from="$file_list" -czf "$archive"

(
    cd -- "$export_dir"
    sha256sum "$(basename -- "$archive")" >"$(basename -- "$checksum")"
)

echo "Archive created: $archive"
echo "Checksum created: $checksum"
