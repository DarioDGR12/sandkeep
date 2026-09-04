#!/usr/bin/env bash
# Download Firecracker + a CI guest kernel into ./assets.
# Rootfs is built separately by scripts/build-rootfs.sh (it includes guest-agent).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ASSETS="$ROOT/assets"
mkdir -p "$ASSETS"

ARCH="$(uname -m)"
S3="https://s3.amazonaws.com/spec.ccfc.min"

echo ">> latest Firecracker release"
latest="$(basename "$(curl -fsSLI -o /dev/null -w '%{url_effective}' https://github.com/firecracker-microvm/firecracker/releases/latest)")"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
curl -fsSL "https://github.com/firecracker-microvm/firecracker/releases/download/${latest}/firecracker-${latest}-${ARCH}.tgz" \
  | tar -xz -C "$tmp"
fc="$(find "$tmp" -type f -name "firecracker-${latest}-${ARCH}" | head -1)"
jailer="$(find "$tmp" -type f -name "jailer-${latest}-${ARCH}" | head -1)"
install -m 0755 "$fc" "$ASSETS/firecracker"
if [[ -n "$jailer" ]]; then
  install -m 0755 "$jailer" "$ASSETS/jailer"
fi
"$ASSETS/firecracker" --version

echo ">> latest CI kernel (x86_64 vmlinux-6.1.* preferred)"
prefix="$(curl -fsSL "$S3?list-type=2&prefix=firecracker-ci/&delimiter=/" \
  | grep -oE 'firecracker-ci/[0-9]{8}-[^/<]+/' \
  | sort \
  | tail -1)"
kernel_key="$(curl -fsSL "$S3?list-type=2&prefix=${prefix}${ARCH}/vmlinux-6.1." \
  | grep -oE "${prefix}${ARCH}/vmlinux-6\.[0-9]+\.[0-9]+" \
  | sort -V \
  | tail -1)"
if [[ -z "$kernel_key" ]]; then
  echo "could not resolve CI kernel key" >&2
  exit 1
fi
echo "   $S3/$kernel_key"
curl -fsSL -o "$ASSETS/vmlinux" "$S3/$kernel_key"
echo ">> assets ready in $ASSETS"
ls -lh "$ASSETS/firecracker" "$ASSETS/vmlinux"
