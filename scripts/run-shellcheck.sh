#!/usr/bin/env bash

set -euo pipefail

readonly VERSION=0.9.0

command -v shellcheck >/dev/null
test "$(shellcheck --version | sed -n 's/^version: //p')" = "$VERSION"
exec shellcheck scripts/publish.sh scripts/run-actionlint.sh scripts/run-shellcheck.sh
