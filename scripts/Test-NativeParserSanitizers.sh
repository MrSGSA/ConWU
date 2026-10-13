#!/usr/bin/env bash
set -euo pipefail
root=$(cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"
output=${1:-artifacts/rc1-sec02/linux-sanitizers}
mkdir -p -- "$output"
compiler=${CXX:-g++}
sources=(main common network connection client server misc fd_manager encrypt log my_ev)
files=()
for name in "${sources[@]}"; do files+=("transport/udp2raw/$name.cpp"); done
files+=(transport/udp2raw/lib/md5.cpp transport/udp2raw/lib/pbkdf2-sha1.cpp transport/udp2raw/lib/pbkdf2-sha256.cpp
  transport/udp2raw/lib/aes_faster_c/aes.cpp transport/udp2raw/lib/aes_faster_c/wrapper.cpp tests/native_parser_test.cpp)
printf 'const char *gitversion="offline-parser-sanitizer";\n' > "$output/git_version.h"
"$compiler" -std=c++17 -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer -pthread \
  -DUDP2RAW_PARSER_TEST -Itransport/udp2raw -Itransport/udp2raw/libev -I"$output" "${files[@]}" -o "$output/native-parser-asan"
"$compiler" --version > "$output/compiler.txt"
# This compiles the full upstream Linux entry and common production parser.
# It neither opens raw sockets nor substitutes for Windows capture validation.
ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1 "$output/native-parser-asan"
