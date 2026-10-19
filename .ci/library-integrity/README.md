# Archive-digest rejection: synthetic source fixture

The production patch replaces one proceed-on-mismatch log with the existing
`AnisetteError.sha256Mismatch(expected:actual:)` throw. The declared expected hash,
case-insensitive comparison, missing/empty-hash policy, and existing `isCaching`
defer are unchanged. Directory creation still happens before verification.

## Portable checks

Run `python3 -B .ci/library-integrity/test_source.py` and
`python3 -B .ci/test_login_trace_source.py` from the repository root.
These check source identity, the exact one-line production delta, ordered source
statements, mutation rejection, deterministic generation, and inert fixture ZIPs.
They do **not** compile or execute Swift. The historic login-trace core digest is
retained via an exact one-occurrence inverse normalization of the reviewed throw.

`generate.py NEW_OUTPUT_DIRECTORY` copies byte-bound complete production
`downloadAndCacheLibs`, `resolveZipData`, and `computeSHA256` methods; the complete
ODAInfo and AnisetteError declarations; their state fields; the HTTP response
extension; the complete unzip method and helper constants; and all of Archive.swift.
`source-spans.json` records entire-file and exact byte-span SHA-256 values and
offsets. Every genuine source byte must match before generation is permitted.
No production seam or fixture conditional is added to shipped code.

## Apple runtime stage, separately required

After independent review, run:

`bash .ci/library-integrity/run-apple.sh NEW_OUTPUT_DIRECTORY LIBDEFLATE_INCLUDE_DIRECTORY LIBDEFLATE_STATIC_ARCHIVE`

Use reviewed genuine libdeflate build outputs from the separately sealed build
graph. The runner does not download, resolve, build dependencies, publish, or
dispatch anything. Its inputs and compile/runtime exit codes are recorded. The
generated fixture compiles with Apple Swift 6 and CryptoKit. Production imports
the Swift Crypto package; substituting CryptoKit is an explicit standalone-test
boundary, not evidence that the full production dependency graph built.

Runtime cases exercise exact production acquisition and extraction source with
ordinary inert text in the required filenames:

1. Matching lowercase SHA succeeds and extracts both fixture entries.
2. Matching uppercase SHA succeeds, preserving case-insensitive behavior.
3. Missing SHA remains accepted (compatibility, not an authenticity claim).
4. Empty SHA remains accepted (same limitation).
5. Mismatch with no prior pair throws exact expected/actual digests.
6. Mismatch with an existing synthetic valid pair preserves both bytes and the
   previous inert provider object.
7. A mismatching malformed archive throws the digest error before ZIP parsing.
8. Malformed nonempty expected-hash text also throws the digest error, preserving
   that exact expected text and the previous synthetic pair.

Each mismatch asserts no temporary-directory getter (hence no later temp-ZIP
construction/write in the bound method), no genuine unzip-entry log, no provider
validation/construction call, no asset changes, exactly the two existing
pre-verification directory-creation calls, and `isCaching == false`. A subsequent
matching call on that same fixture manager must succeed. Successful calls check
temporary ZIP cleanup and both extracted bytes. The pre-existing valid pair means
a complete pair of inert synthetic files accepted by the test provider boundary,
not actual Apple shared-library validity.

## Explicit test boundaries and limits

- Foundation filesystem operations are forwarded through a recording FileManager
  facade, with an isolated temporary root. The genuine unzip method and all of
  Archive.swift run against it. Extraction entry is observed through the existing
  genuine first log; no production instrumentation is inserted.
- AnisetteClient is an inert existence-check/constructor boundary. No AnisetteKit,
  native loader, Unicorn, guest code, provisioning, or proprietary assets are
  linked or run. This does not test real provider construction.
- URLSession is a deny-only boundary. All intended cases use exact production
  Base64 decoding with inline synthetic bytes; remote transport is not tested.
- Constants and wrapper construction are test-only. No user identifiers,
  credentials, or metadata downloads are used.
- Source tests and successful generation are not runtime passes. Apple compilation
  and execution were unavailable during Linux preparation and must pass on the
  final reviewed composition before any runtime claim.
- Existing cache reuse remains existence-only. This correction rejects extraction
  only when a supplied nonempty expected hash mismatches. Absent/empty optional
  hashes retain their previous contract. It does not retroactively authenticate
  an existing pair, make two-file publication atomic, authenticate metadata,
  repair an existing mixed cache, or prove the cause of the reported initializer
  failure. See ATOMIC_PAIR_DESIGN.md.
