#!/usr/bin/env bash
# Grant the current user /dev/kvm access for local Firecracker runs.
set -euo pipefail
if [[ ! -e /dev/kvm ]]; then
  echo "/dev/kvm is missing; this host cannot run Firecracker" >&2
  exit 1
fi
if [[ -r /dev/kvm && -w /dev/kvm ]]; then
  echo "KVM already writable"
  exit 0
fi
if command -v setfacl >/dev/null 2>&1; then
  sudo setfacl -m "u:${USER}:rw" /dev/kvm
else
  sudo chmod a+rw /dev/kvm
fi
echo "KVM access granted for $USER"
