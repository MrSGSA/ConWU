#!/usr/bin/env bash
# Local development build only. Does not install or start the program.
set -euo pipefail
conwu_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
export PATH="/mnt/d/Codex/cache/rust-linux-1.95/toolchain/bin:$PATH"
export CARGO_HOME=/mnt/d/Codex/cache/cargo-rust-rewrite
export CARGO_TARGET_DIR="$conwu_root/out/rust-target-linux"
export TMPDIR="$conwu_root/out/tmp-linux"
mkdir -p "$TMPDIR"
cd "$conwu_root"
cargo build --offline --locked --release --message-format=short --manifest-path rust/Cargo.toml --workspace >out/linux-release-build.log 2>&1
{
    rustc -Vv
    uname -m
    getconf GNU_LIBC_VERSION
    ldd out/rust-target-linux/release/conwu
    out/rust-target-linux/release/conwu version
} >out/linux-build-info.txt 2>&1
