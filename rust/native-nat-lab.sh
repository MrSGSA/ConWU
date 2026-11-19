#!/usr/bin/env bash
set -euo pipefail
conwu_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
if ((EUID != 0)); then
  echo 'Run this isolated network/mount namespace lab as Linux root.' >&2
  exit 1
fi
mkdir -p "$conwu_root/out/lab" "$conwu_root/out/tmp-linux"
runtime="$(mktemp -d "$conwu_root/out/lab/.nat-runtime-XXXXXXXX")"
# Namespace handles are workspace files, and cleanup only removes empty dirs.
trap 'rmdir "$runtime/netns" "$runtime" 2>/dev/null || true' EXIT
if (($# == 0)); then
  set -- tcp https phantun mimic tcpraw faketcp
fi
strategy=--assisted
if [[ ${1:-} == --host-igd ]]; then
  strategy=--host-igd
  shift
fi
unshare --mount --propagation private /bin/bash -c '
set -euo pipefail
mount --bind "$1" /run
mkdir -p /run/netns
# WSL DrvFs cannot host AF_UNIX socket files. The private tmpfs keeps their
# pathname inside this repository without modifying another process mount.
mount -t tmpfs -o mode=0700,size=64m conwu-native-ipc "$2/out/tmp-linux"
export TMPDIR="$2/out/tmp-linux"
export PYTHONDONTWRITEBYTECODE=1
conwu_root="$2"
shift 2
exec python3 "$conwu_root/rust/native-lab.py" --nat "$@"
' conwu-private-nat "$runtime" "$conwu_root" "$strategy" "$@"
