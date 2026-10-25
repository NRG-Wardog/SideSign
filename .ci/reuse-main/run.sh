#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/../.."
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
python3 .ci/reuse-main/test_source.py
swiftc -swift-version 6 Sources/CodeSigning/ExtensionSigningPolicy.swift .ci/reuse-main/Cases.swift -o "$work/policy"
"$work/policy"
# Compile the production signer with isolated synthetic boundary doubles. Only
# the CodeSignKit import is replaced; signer and policy bodies are unmodified.
sed '/^import CodeSignKit$/d' Sources/CodeSigning/CodeSignerAPI.swift > "$work/CodeSignerAPI.swift"
swiftc -swift-version 6 Sources/CodeSigning/ExtensionSigningPolicy.swift "$work/CodeSignerAPI.swift" .ci/reuse-main/SignerDoubles.swift .ci/reuse-main/SignerCases.swift -o "$work/signer"
"$work/signer"
