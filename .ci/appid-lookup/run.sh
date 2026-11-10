#!/bin/bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="$(mktemp -d)"
trap 'rm -rf "$OUT"' EXIT
python3 "$ROOT/.ci/appid-lookup/test_source.py"
swiftc -swift-version 6 "$ROOT/Sources/Models/AppID.swift" \
  "$ROOT/Sources/DeveloperPortal/AppIDLookupResponse.swift" \
  "$ROOT/.ci/appid-lookup/RuntimeTests.swift" -o "$OUT/appid-lookup-tests"
"$OUT/appid-lookup-tests"
