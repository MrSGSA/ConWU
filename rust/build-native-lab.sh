#!/usr/bin/env bash
set -euo pipefail
conwu_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
export PATH="/mnt/d/Codex/cache/rust-linux-1.95/toolchain/bin:$PATH"
export CARGO_HOME=/mnt/d/Codex/cache/cargo-rust-rewrite
export CARGO_TARGET_DIR="$conwu_root/out/rust-target-linux"
export TMPDIR="$conwu_root/out/tmp-linux"
export CONWU_LINK_NO_MMAP=1
mkdir -p "$TMPDIR" "$conwu_root/out/rust-components-linux"
cd "$conwu_root"
cargo build --offline --message-format=short --manifest-path rust/Cargo.toml --package conwu --features lab-api
cargo build --offline --release --manifest-path transport/phantun/Cargo.toml --workspace
cp "$CARGO_TARGET_DIR/release/conwu-raw" "$CARGO_TARGET_DIR/release/conwu-phantun" out/rust-components-linux/
cmake -S . -B out/native-linux -DCMAKE_BUILD_TYPE=Release -DSTREAMLINK_LINUX_STATIC=OFF
cmake --build out/native-linux --target udp2raw-native --parallel 4
cp out/native-linux/udp2raw-native out/rust-components-linux/
python3 rust/native-lab.py
