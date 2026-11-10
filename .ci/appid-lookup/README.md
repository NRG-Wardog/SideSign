# Strict App ID preservation lookup

`fetchAppIDsPreservingIdentity(for:session:)` is a read-only, opt-in API. It only
returns a list after an HTTP 2xx response, explicit zero resultCode, an actual
appIds array and valid nonempty identity fields. Empty arrays are authoritative;
missing or null arrays are not. JSON, XML and binary plists are accepted. Provider
errors and contradictory opaque-ID/bundle mappings fail closed. Exact duplicate
rows remain duplicates so callers can reject ambiguous identity matches. Identity
strings are never case-folded or rewritten. Opaque IDs use the preservation
origin's ASCII letters/digits/hyphen grammar with a 256-byte limit; bundle IDs use
ASCII letters/digits/dot/hyphen with a 512-byte limit, also allowing unrelated
`*` and `com.example.*` inventory entries without wildcard expansion. Responses
are capped at 4 MiB and 4096 records; exceeding a limit fails closed.

All response failures use finite `AppIDLookupError` values without payloads.
Transport errors retain existing transport semantics. This is deliberately not a
change to legacy list/create/update/remove behavior. Existing protocol conformers
must implement the strict API; the default throws rather than reusing unvalidated
legacy results. Proxies must forward the new method explicitly.

Run `bash .ci/appid-lookup/run.sh` with Swift 6. It compiles the production parser
and AppID decoder unchanged, with only unrelated Feature metadata doubled. The
fixtures cover valid/empty lists, all wire formats, HTTP errors and missing HTTP,
missing/null/wrong status and lists, malformed rows, conflicting mappings,
duplicate preservation and case preservation. Python contracts check the actual
strict call wiring precedes legacy fallbacks. Both the existing macOS build
workflow and the dedicated validation workflow run these tests; the dedicated
workflow also compiles the full SideSign target against locked dependencies.

Passing these tests does not establish a physical-device root cause or confirm
refresh success on a device.
