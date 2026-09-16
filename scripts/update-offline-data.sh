#!/usr/bin/env bash
set -euo pipefail

# This is the only scanner workflow that intentionally needs Internet access.
# Scans themselves use the persisted databases and disable automatic updates.
clamav_data_dir="${CLAMAV_DB_DIR:-/workspace/cache/clamav}"
mkdir -p "$clamav_data_dir" "${GRYPE_DB_CACHE_DIR:-/workspace/cache/grype/db}"
freshclam --stdout --no-warnings --datadir="$clamav_data_dir"
GRYPE_DB_CACHE_DIR="${GRYPE_DB_CACHE_DIR:-/workspace/cache/grype/db}" \
  GRYPE_CHECK_FOR_APP_UPDATE=false grype db update

echo "ClamAV and Grype data refreshed. P0/P1 scans can now run offline."
