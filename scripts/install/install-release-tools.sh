#!/usr/bin/env bash
set -euo pipefail

# Pinned standalone tools used by the P0/P1 image. Checksums published by
# Anchore/Aqua are verified; projects without checksum assets use reviewed,
# pinned SHA-256 values recorded below.
CHECKSEC_VERSION="${CHECKSEC_VERSION:-3.2.0}"
CAPA_VERSION="${CAPA_VERSION:-9.4.0}"
SYFT_VERSION="${SYFT_VERSION:-1.51.1}"
GRYPE_VERSION="${GRYPE_VERSION:-0.118.0}"
TRIVY_VERSION="${TRIVY_VERSION:-0.73.0}"

install_root="${INSTALL_ROOT:-/usr/local/bin}"
download_dir="$(mktemp -d)"
trap 'rm -rf -- "$download_dir"' EXIT

case "$(dpkg --print-architecture)" in
  amd64)
    go_arch="amd64"
    trivy_arch="64bit"
    ;;
  arm64)
    go_arch="arm64"
    trivy_arch="ARM64"
    ;;
  *)
    echo "unsupported architecture: $(dpkg --print-architecture)" >&2
    exit 2
    ;;
esac

download() {
  curl --fail --location --retry 3 --silent --show-error "$1" --output "$2"
}

verify_from_release() {
  local checksum_url="$1" asset_path="$2"
  local checksum_file="$download_dir/checksums-$(basename "$asset_path").txt"
  download "$checksum_url" "$checksum_file"
  local expected
  expected="$(awk -v name="$(basename "$asset_path")" '$2 == name || $2 == "*" name {print $1; exit}' "$checksum_file")"
  test -n "$expected"
  printf '%s  %s\n' "$expected" "$asset_path" | sha256sum --check --status
}

install_tar_binary() {
  local asset="$1" binary="$2"
  local extract_dir="$download_dir/extract-$binary"
  mkdir -p "$extract_dir"
  tar -xzf "$asset" -C "$extract_dir"
  install -m 0755 "$(find "$extract_dir" -type f -name "$binary" -print -quit)" "$install_root/$binary"
}

checksec_asset="$download_dir/checksec_${CHECKSEC_VERSION}_linux_${go_arch}.tar.gz"
download "https://github.com/slimm609/checksec/releases/download/${CHECKSEC_VERSION}/$(basename "$checksec_asset")" "$checksec_asset"
case "$go_arch" in
  amd64) checksec_sha='921afb5e348b9fbca99cc201bbe5f779199a61efb8f7c91b266c4b1a8eec8185' ;;
  arm64) checksec_sha='18d395eb0f9829fcf5e448384de409ee24e4137aea1727be531d8eb96fdc41fd' ;;
esac
printf '%s  %s\n' "$checksec_sha" "$checksec_asset" | sha256sum --check --status
install_tar_binary "$checksec_asset" checksec

syft_asset="$download_dir/syft_${SYFT_VERSION}_linux_${go_arch}.tar.gz"
download "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/$(basename "$syft_asset")" "$syft_asset"
verify_from_release "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_checksums.txt" "$syft_asset"
install_tar_binary "$syft_asset" syft

grype_asset="$download_dir/grype_${GRYPE_VERSION}_linux_${go_arch}.tar.gz"
download "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/$(basename "$grype_asset")" "$grype_asset"
verify_from_release "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_checksums.txt" "$grype_asset"
install_tar_binary "$grype_asset" grype

trivy_asset="$download_dir/trivy_${TRIVY_VERSION}_Linux-${trivy_arch}.tar.gz"
download "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/$(basename "$trivy_asset")" "$trivy_asset"
verify_from_release "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_checksums.txt" "$trivy_asset"
install_tar_binary "$trivy_asset" trivy

# capa's standalone Linux archive is currently x86-64 only.
if [ "$go_arch" = "amd64" ]; then
  capa_asset="$download_dir/capa-v${CAPA_VERSION}-linux.zip"
  download "https://github.com/mandiant/capa/releases/download/v${CAPA_VERSION}/$(basename "$capa_asset")" "$capa_asset"
  printf '%s  %s\n' '07800a1d20a21eb18fc98716e2ae81b668e0c9a04defd588c8aa17ea3d3281e4' "$capa_asset" | sha256sum --check --status
  unzip -q "$capa_asset" -d "$download_dir/capa"
  install -m 0755 "$(find "$download_dir/capa" -type f -name capa -print -quit)" "$install_root/capa"
fi
