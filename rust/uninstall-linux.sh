#!/usr/bin/env bash
set -euo pipefail
conwu_bundle="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
exec "$conwu_bundle/install.sh" --uninstall "$@"
