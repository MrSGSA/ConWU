#!/usr/bin/env bash
# Local WSL laboratory only; no service/driver installation or publication.
set -euo pipefail
conwu_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
export PATH="/mnt/d/Codex/cache/rust-linux-1.95/toolchain/bin:$PATH"
export CARGO_HOME=/mnt/d/Codex/cache/cargo-rust-rewrite
export CARGO_TARGET_DIR="$conwu_root/out/rust-target-linux"
export TMPDIR="$conwu_root/out/tmp-linux"
mkdir -p "$TMPDIR"
cd "$conwu_root"
bash rust/test-linux.sh >out/linux-test.log 2>&1
bash rust/build-native-lab.sh >out/native-lab.log 2>&1
python3 rust/native-lab.py --tun >out/tun-lab.log 2>&1
# Never package the preceding lab-api executable. Release has default features.
bash rust/build-linux.sh
