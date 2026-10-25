# ILoader opt-in authentication source-owned fixture

This package tests the isolated ILoader-style remote-v3 authentication branch. The existing `auth-request-diagnostics` suite remains the baseline/nil-context runtime gate; this package does not replace it. `authentication-projection.json` reverses only the explicitly scoped opt-in edits, then the original diagnostics projection must still restore the exact embedded baseline.

## Source-only checks and generation

```
python3 -B .ci/iloader-auth-parity/test_source.py
python3 -B .ci/iloader-auth-parity/generate.py --output-dir DIR
```

Generation does not run Swift. `source-evidence.json` binds each source input, fixture file, and the exact output closure. The immutable official reference is `fc7a81a6de678aa707e05399ffafb8be0ad56921`; `official-reference.json` pins the five reviewed source files and their request/lifecycle contract. It is not a claim that Rust and Swift crypto implementations are equivalent.

## Authorized fake-only execution

Compile exactly the seven files listed in `source-evidence.json` → `output_closure`, using `swiftc -swift-version 5 -parse-as-library`. Run the resulting executable once with `DIR/cases.json` as argv1. The expected marker is `ILOADER_AUTH_PARITY_FIXTURE_PASS`, followed by a dynamic case-count JSON object.

All Apple/provider HTTP and websocket boundaries are in-memory scripted doubles. The entire production Authentication.swift extension and production ILoader context/policy bodies are retained; only unavailable imports and transport/native-crypto boundaries are replaced. Request/body/header expectations are independent literal values tied to reviewed official source. No credentials, real provider data, native library, network, or Apple service are used. Synthetic crypto is not cryptographic validation, and a pass does not demonstrate Apple acceptance.

Coverage includes full parsed body dictionaries and primitive types, exact complete header maps, the distinct URL-bag profile, metadata/header acquisition and endpoint boundaries, strict 60 whole-second cache TTL, current acquisition at 2FA/app-token stages, one status-434 init resync using the same A2k and original complete CPD, and negative cases for fallback and special -80045 retry. Existing diagnostic runtime tests separately prove nil-context request bytes/headers/results/errors remain equivalent to the original baseline.


## Bounded HTTP collector coverage

The same seven-file closure also includes the complete production
`ILoaderRemoteHTTPTransport.swift` body. Its Foundation session, task, delegate
and challenge types are replaced by dedicated in-memory callback boundaries.
Existing authentication vectors are unchanged. Parked task callbacks exercise
2xx compatibility, exact-cap success, chunk overflow before append, declared
oversize, changed response URLs, redirects, HTTP-auth refusal, platform TLS
handling, cancellation and late callbacks. The owner's actual registry is tested
for in-flight cancellation and permanent invalidation. No real session or task is
constructed. Source receipts include the new production transport file.

This only hardens provider/provisioning HTTP; GrandSlam/2FA transport, WebSocket,
Mac identity/profile and authentication policy are unchanged. Generated fixtures
are not production-platform networking integration tests or proof of live Apple
acceptance. Run the existing normal build/CI gates too.
