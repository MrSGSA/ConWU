#!/usr/bin/env bash
set -euo pipefail
conwu_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
export PATH="${CONWU_LINUX_TOOLCHAIN_ROOT:-/mnt/d/Codex/cache/rust-linux-1.95/toolchain}/bin:$PATH"
export CARGO_HOME="${CONWU_LINUX_CARGO_HOME:-$conwu_root/out/cargo-home}"
export CARGO_TARGET_DIR="${CONWU_LINUX_TARGET_DIR:-$conwu_root/out/rust-target-linux}"
export TMPDIR="${CONWU_LINUX_TMPDIR:-$conwu_root/out/tmp-linux}"
export CONWU_LINK_NO_MMAP=1
mkdir -p "$TMPDIR"
cd "$conwu_root"
exec cargo "$@"
