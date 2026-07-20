#!/bin/sh
set -eu
repo="homelab-doctor/homelab-doctor"
version="${HOMELAB_DOCTOR_VERSION:-latest}"
arch="$(uname -m)"
case "$arch" in x86_64) arch=amd64 ;; aarch64|arm64) arch=arm64 ;; *) echo "unsupported architecture: $arch" >&2; exit 1 ;; esac
os="$(uname -s | tr '[:upper:]' '[:lower:]')"
[ "$os" = linux ] || { echo "Linux is required" >&2; exit 1; }
base="https://github.com/$repo/releases"
if [ "$version" = latest ]; then version="$(curl -fsSL "$base/latest" -o /dev/null -w '%{url_effective}' | sed 's#.*/##')"; fi
archive="homelab-doctor_${version#v}_linux_${arch}.tar.gz"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
curl -fsSL "$base/download/$version/$archive" -o "$tmp/$archive"
tar -xzf "$tmp/$archive" -C "$tmp"
install -m 0755 "$tmp/homelab-doctor" "${HOMELAB_DOCTOR_INSTALL_DIR:-/usr/local/bin}/homelab-doctor"
echo "Installed homelab-doctor $version"
