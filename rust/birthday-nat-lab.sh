#!/usr/bin/env bash
set -euo pipefail
conwu_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
if ((EUID != 0)); then
  echo 'Run this isolated lab as Linux root.' >&2
  exit 1
fi
mkdir -p "$conwu_root/out/lab"
runtime="$(mktemp -d "$conwu_root/out/lab/.birthday-runtime-XXXXXXXX")"
trap 'rmdir "$runtime/netns" "$runtime" 2>/dev/null || true' EXIT
unshare --mount --propagation private /bin/bash -c '
set -euo pipefail
mount --bind "$1" /run
mkdir -p /run/netns
export PYTHONDONTWRITEBYTECODE=1
conwu_root="$2"
shift 2
exec python3 "$conwu_root/rust/birthday-nat-lab.py" "$@"
' conwu-private-birthday "$runtime" "$conwu_root" "$@"
