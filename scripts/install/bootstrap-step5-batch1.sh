#!/usr/bin/env bash
# RESEARCH PROTOTYPE – NOT PRODUCTION INSTALLER
set -euo pipefail

apt-get update
apt-get install -y --no-install-recommends \
  build-essential desktop-file-utils libcap2-bin libssl-dev
rm -rf /var/lib/apt/lists/*
