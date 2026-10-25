#!/bin/bash
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
swiftc -swift-version 6 -parse-as-library "$root/Sources/Anisette/OwnedODAAuthenticationContext.swift" "$root/.ci/owned-oda/Fixture.swift" -o "$tmp/owned-oda"
python3 - "$tmp/owned-oda" <<'PY'
import subprocess,sys
for attempt in range(10):
    subprocess.run([sys.argv[1]],check=True,timeout=20)
PY
