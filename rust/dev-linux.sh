#!/usr/bin/env bash
set -euo pipefail
conwu_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
export PATH="/mnt/d/Codex/cache/rust-linux-1.95/toolchain/bin:$PATH"
export CARGO_HOME=/mnt/d/Codex/cache/cargo-rust-rewrite
export CARGO_TARGET_DIR="$conwu_root/out/rust-target-linux"
export TMPDIR="$conwu_root/out/tmp-linux"
mkdir -p "$TMPDIR"
cd "$conwu_root"
exec cargo "$@"
