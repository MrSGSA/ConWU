#!/usr/bin/env bash
set -euo pipefail
conwu_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
conwu_toolchain="${CONWU_LINUX_TOOLCHAIN_ROOT:-/mnt/d/Codex/cache/rust-linux-1.95/toolchain}"
export PATH="$conwu_toolchain/bin:$PATH"
export CARGO_HOME="${CONWU_LINUX_CARGO_HOME:-$conwu_root/out/cargo-home}"
export CARGO_TARGET_DIR="${CONWU_LINUX_TARGET_DIR:-$conwu_root/out/rust-target-linux}"
export TMPDIR="${CONWU_LINUX_TMPDIR:-$conwu_root/out/tmp-linux}"
export CONWU_LINK_NO_MMAP=1
export CARGO_BUILD_JOBS="${CONWU_BUILD_JOBS:-2}"
export CC_x86_64_unknown_linux_musl=musl-gcc
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER="$conwu_toolchain/lib/rustlib/x86_64-unknown-linux-gnu/bin/rust-lld"
export RUSTFLAGS='-C target-feature=+crt-static -C link-self-contained=yes'
mkdir -p "$TMPDIR" "$conwu_root/out/rust-components-linux-musl"
cd "$conwu_root"
cargo build --release --locked --offline --message-format=short --target x86_64-unknown-linux-musl --manifest-path rust/Cargo.toml --package conwu --features "${CONWU_LINUX_FEATURES:-local-install}"
cargo build --release --locked --offline --message-format=short --target x86_64-unknown-linux-musl --manifest-path transport/phantun/Cargo.toml --workspace
cp "$CARGO_TARGET_DIR/x86_64-unknown-linux-musl/release/conwu-raw" "$CARGO_TARGET_DIR/x86_64-unknown-linux-musl/release/conwu-phantun" out/rust-components-linux-musl/
cmake -S . -B out/native-linux-static -DCMAKE_BUILD_TYPE=Release -DSTREAMLINK_LINUX_STATIC=ON
cmake --build out/native-linux-static --target udp2raw-native --parallel "$CARGO_BUILD_JOBS"
cp out/native-linux-static/udp2raw-native out/rust-components-linux-musl/
file "$CARGO_TARGET_DIR/x86_64-unknown-linux-musl/release/conwu" out/rust-components-linux-musl/*
python3 rust/verify-linux-static.py "$CARGO_TARGET_DIR/x86_64-unknown-linux-musl/release/conwu" out/rust-components-linux-musl/*
"$CARGO_TARGET_DIR/x86_64-unknown-linux-musl/release/conwu" version
