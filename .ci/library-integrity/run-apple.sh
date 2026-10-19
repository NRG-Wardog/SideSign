#!/bin/bash
# Local-only synthetic fixture. The caller supplies reviewed genuine libdeflate
# build outputs. No downloads, dependency resolution, provider or guest code.
set -euo pipefail
if [[ $# != 3 ]]; then
  echo 'usage: run-apple.sh NEW_OUTPUT_DIRECTORY LIBDEFLATE_INCLUDE_DIRECTORY LIBDEFLATE_STATIC_ARCHIVE' >&2
  exit 2
fi
if [[ "$(uname -s)" != Darwin ]]; then
  echo 'Apple Swift/CryptoKit required; no Swift runtime test was run.' >&2
  exit 2
fi
here="$(cd "$(dirname "$0")" && pwd)"
out="$1"
include="$2"
archive="$3"
[[ ! -e "$out" && -f "$include/libdeflate.h" && -f "$archive" && "$archive" == *.a ]]
python3 -B "$here/generate.py" "$out"
mkdir "$out/libdeflate-module"
cp "$include/libdeflate.h" "$out/libdeflate-module/libdeflate.h"
printf 'module libdeflate { header "libdeflate.h" export * }\n' > "$out/libdeflate-module/module.modulemap"
xcrun swiftc --version > "$out/swift-version.txt" 2>&1
uname -a > "$out/host.txt"
shasum -a 256 "$include/libdeflate.h" "$archive" > "$out/libdeflate-input-sha256.txt"
set +e
xcrun swiftc -swift-version 6 -parse-as-library -O \
  -module-name SideSignLibraryIntegrityFixture -I "$out/libdeflate-module" \
  "$out/ProductionDownload.swift" "$out/Archive.swift" "$out/ProductionUnzip.swift" \
  "$out/BoundaryDoubles.swift" "$out/FixtureData.swift" "$out/RuntimeTests.swift" \
  "$archive" -o "$out/library-integrity-tests" > "$out/compile.stdout" 2> "$out/compile.stderr"
compile_status=$?
printf '%s\n' "$compile_status" > "$out/compile.exit-code"
set -e
[[ "$compile_status" == 0 ]] || exit "$compile_status"
set +e
"$out/library-integrity-tests" > "$out/runtime.stdout" 2> "$out/runtime.stderr"
runtime_status=$?
printf '%s\n' "$runtime_status" > "$out/runtime.exit-code"
set -e
cat "$out/runtime.stdout"
exit "$runtime_status"
