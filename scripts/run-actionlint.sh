#!/usr/bin/env bash

set -euo pipefail

readonly VERSION=1.7.12
readonly ARCHIVE=actionlint_1.7.12_linux_amd64.tar.gz
readonly SHA256=8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8

if command -v actionlint >/dev/null 2>&1 && \
  test "$(actionlint -version | head -1)" = "$VERSION"; then
  exec actionlint -color
fi

temporary=$(mktemp -d)
trap 'rm -rf -- "$temporary"' EXIT
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
  "https://github.com/rhysd/actionlint/releases/download/v$VERSION/$ARCHIVE" \
  --output "$temporary/$ARCHIVE"
test "$(sha256sum "$temporary/$ARCHIVE" | awk '{print $1}')" = "$SHA256"
tar -xzf "$temporary/$ARCHIVE" -C "$temporary" actionlint
test "$("$temporary/actionlint" -version | head -1)" = "$VERSION"
"$temporary/actionlint" -color
