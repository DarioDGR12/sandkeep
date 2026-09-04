#!/usr/bin/env bash
# Build a minimal Alpine ext4 rootfs with python3, nodejs, and guest-agent as PID 1.
# Needs: curl, tar, mkfs.ext4, sudo (for apk in chroot), Go toolchain.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ASSETS="$ROOT/assets"
WORK="$(mktemp -d)"
trap 'sudo rm -rf "$WORK"' EXIT

ALPINE_VER="${ALPINE_VER:-3.20.3}"
ALPINE_REL="${ALPINE_REL:-v3.20}"
IMG_SIZE_MB="${IMG_SIZE_MB:-384}"

echo ">> build static guest-agent"
mkdir -p "$ROOT/bin"
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "$ROOT/bin/guest-agent" "$ROOT/cmd/guest-agent"

echo ">> alpine minirootfs $ALPINE_VER"
curl -fsSL -o "$WORK/alpine.tar.gz" \
  "https://dl-cdn.alpinelinux.org/alpine/${ALPINE_REL}/releases/x86_64/alpine-minirootfs-${ALPINE_VER}-x86_64.tar.gz"
mkdir -p "$WORK/rootfs"
tar -xzf "$WORK/alpine.tar.gz" -C "$WORK/rootfs"

echo ">> apk add python3 nodejs (chroot)"
cp /etc/resolv.conf "$WORK/rootfs/etc/resolv.conf"
sudo chroot "$WORK/rootfs" /sbin/apk add --no-cache python3 nodejs

echo ">> install guest-agent as /usr/local/bin/guest-agent"
sudo mkdir -p "$WORK/rootfs/usr/local/bin"
sudo install -m 0755 "$ROOT/bin/guest-agent" "$WORK/rootfs/usr/local/bin/guest-agent"

# Tiny fallback init if someone boots without our boot_args.
cat > "$WORK/init" <<'EOF'
#!/bin/sh
exec /usr/local/bin/guest-agent
EOF
sudo install -m 0755 "$WORK/init" "$WORK/rootfs/init"

echo ">> mkfs.ext4 ${IMG_SIZE_MB}MiB"
mkdir -p "$ASSETS"
IMG="$ASSETS/rootfs.ext4"
rm -f "$IMG"
dd if=/dev/zero of="$IMG" bs=1M count="$IMG_SIZE_MB" status=none
sudo mkfs.ext4 -q -F -d "$WORK/rootfs" "$IMG"
sudo chown "$USER:$USER" "$IMG"
echo ">> rootfs $IMG"
ls -lh "$IMG"
