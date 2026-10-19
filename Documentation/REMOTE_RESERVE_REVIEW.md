# Strict remote-v3 reserve: source-review candidate

This is an explicit API, not an enabled fallback or production-readiness claim. It
has not contacted an Anisette provider or Apple with identity/provisioning data.
No guest libraries were run. Existing manager modes and legacy remote source are
unchanged. Dependency pins intentionally still reference the review base; the
new API requires the accompanying reviewed AnisetteKit change before compilation.

## Entry and ownership

`AnisetteDataManager.fetchRemoteReserveAnisetteData(server:identifier:existingAdiBlob:profileGeneration:expectedDescriptor:)`
returns `(data: AnisetteData, newAdiBlob: Data?, descriptor: RemoteReserveDescriptor)`.

The caller obtains explicit consent, supplies a remote-only UUID/generation, and
owns atomic profile persistence and stale-generation checks. Existing blobs must
have an expected descriptor. The descriptor includes normalized origin, protocol
version 3, client info and user agent. A mismatch fails before identity traffic.
The API never changes the manager mode, rotates hosts, retries legacy v1, resets
an identity, re-provisions an existing blob, or caches OTPs/descriptors.

Origins are HTTPS only, hostname case-normalized, default port removed, and
restricted to origin/root syntax. Credentials, query, fragment, paths, Unicode
host spellings and trailing-dot aliases are refused. IPv6 literal syntax remains
subject to Foundation URL validation. A normalized origin has no trailing slash.

## Maintained flow, isolated storage

The new SideSign provider reuses AnisetteKit's maintained Apple lookup/start/finish
sequence with a new `.ephemeral` storage case. That case returns before constructing
provisioning file paths, never reads disk routing info, and disables routing-file
writes. It rejects native providers. The per-call client receives an explicit
remote provider and no library resolver. Its synthetic provisioning path is never
accessed. Existing `.disk` and `.memory` semantics remain unchanged.

The provider uses the v3 reference format: base64 of 16 UUID bytes and SHA256 of
those same bytes for MD-LU. It validates the descriptor and uses its client info
and user agent for Apple provisioning. The returned AnisetteData carries those
values and provider routing info; GrandSlam authentication uses its client info
and identity while preserving the historical `h.grandSlam.userAgent`. This reserve
API accepts no custom/local header overrides. Descriptor fields are printable
ASCII, bounded and CR/LF-free. Server messages are never copied into errors/logs.

Protocol reference (format only):
https://github.com/SideStore/apple-private-apis/blob/master/omnisette/src/remote_anisette_v3.rs
The reference's invalid-certificate/retry behavior is deliberately not used.

## Transport limits

- Private ephemeral URLSessions; no cookie, credential or URL cache stores.
- Standard TLS trust; no certificate bypass or automatic HTTP authentication.
- All HTTP redirects refused, including same-origin; WebSocket redirects refused
  and current URL rechecked before using received provisioning instructions.
- Apple targets must be HTTPS `gsa.apple.com`, default port, under `/grandslam/`,
  without userinfo/query/fragment, checked before each request is transmitted.
- HTTP bodies capped while streaming, before append; advertised oversize rejected.
- 16 KiB descriptor, 64 KiB OTP response, 3,000,000-byte protocol/Apple responses,
  1 MiB decoded blobs/SPIM/CPIM/PTM/TK. Base64 must be canonical and nonempty.
- Four exact provisioning messages: GiveIdentifier, GiveStartProvisioningData,
  GiveEndProvisioningData, ProvisioningSuccess. Repeats/out-of-order steps fail.
- HTTP 30-second request / 60-second resource limits; each WebSocket send/receive
  has a cancellable 30-second deadline and size cap.
- Cancellation invalidates owned HTTP sessions, closes the socket, and propagates;
  Apple finish failure also closes the outstanding provider session.

Remote diagnostics append stages 57–60 (`remoteDescriptor`, `remoteStart`,
`remoteEnd`, `remoteHeaders`) without renumbering existing stages. No payloads,
identity data, origin URLs or descriptor strings are included in traces.

## Verification and limitations

Locally runnable, passed:

- `python3 -B .ci/test_remote_reserve_source.py`: 7 source-invariant checks.
- `python3 -B .ci/test_login_trace_source.py`: 10 historical trace/core regressions.
- `python3 -B .ci/test_diagnostic_dependencies.py`: 36 dependency-gate regression
  checks against synthetic local repository fixtures (not approval of new pins).
- In AnisetteKit: `python3 -B .ci/native-tests/run_tests.py`: 8 synthetic host-native
  tests passed, 1 Swift decoder test skipped because Swift is absent. These use
  maintained boundaries with synthetic VM/I/O doubles, not proprietary execution.

Added but NOT compiled/run here:

- `RemoteReserveTests`: synthetic HTTP/WebSocket orchestration, descriptor binding,
  exact UUID/MD-LU fixtures, fresh/existing state, no downgrade/rotation/cache,
  cancellation, malformed and reordered input, Apple-origin rejection, tracing.
- `RemoteReserveHTTPDelegateTests`: real bounded delegate/state implementation with
  parked URLSession tasks that are never resumed; redirect refusal, streaming and
  advertised size caps, response-origin mismatch, and cancellation/late callbacks.
- `RemoteReserveWebSocketDelegateTests`: actual redirect callback and bounded
  operation wrapper with parked, never-resumed tasks; handshake cancellation,
  deadline cancellation and parent-cancellation propagation.
- `EphemeralAnisetteTests` in AnisetteKit: sentinel-file preservation, native-provider
  rejection and cancellation. All bytes and headers are synthetic.

After reviewed dependency integration, run ONLY these named Swift suites on an
approved Swift host: in SideSign, run `swift test --filter RemoteReserveTests`,
`swift test --filter RemoteReserveHTTPDelegateTests`, and
`swift test --filter RemoteReserveWebSocketDelegateTests`; in AnisetteKit, run
`swift test --filter EphemeralAnisetteTests`. Capture the test list and require
nonzero matching synthetic tests for each selection. Do not run the existing unfiltered
AnisetteKit tests: a historical test makes real provisioning/native calls.

The source-invariant checks do not prove Swift type correctness or live protocol
compatibility. No successful real login, endpoint availability, or device behavior
is claimed. Live activation, identity transmission and production publication are
separate approval/review steps.
