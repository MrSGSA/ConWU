#!/usr/bin/env bash
set -euo pipefail
command -v python3 >/dev/null || { echo '安装需要 Python 3，请先安装 python3。'; exit 1; }
conwu_bundle="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
exec python3 "$conwu_bundle/install.py" "$@"
