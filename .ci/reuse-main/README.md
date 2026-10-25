# Experimental ReuseMain preflight

Issue: https://github.com/NRG-Wardog/sidestore-auto-refresh/issues/50

The existing `CodeSignerAPI` entry point retains its old per-extension behavior.
The concrete `AppBundleSigner` overload requires explicit
`extensionStrategy: .reuseMainWhenCompatible`. It returns per-extension decisions
with stable reason codes, and uses the exact main signing entitlement dictionary
and main profile only for compatible candidates. A fallback needs a profile
matching that extension, rather than silently using `profiles.first`.

Preflight admits only nested extension bundle identifiers, a concrete main
application/team identity, consistent declared source extension identifiers, and
identical non-identity capability maps. Keychain and app-group mismatches require
separate provisioning. It does not rewrite bundle identifiers, remove extensions,
or discard entitlement requirements to make a candidate pass.

This is an experimental signing primitive, not a claim of iOS installation or
extension compatibility. Reusing the main application identifier for an extension
is deliberate and requires device qualification. Upstream reference inspected:
isideload `fc7a81a6de678aa707e05399ffafb8be0ad56921`, `sideloader.rs` lines 188-201.
It does not provide runtime proof for this product.

## SideStore integration

The paired SideStore candidate checks compatibility before skipping extension
provisioning. Any incompatible extension produces reason codes and asks whether
to keep all extensions using separate profiles. This conservative first version
falls back as a group, not a mixed main/separate profile set. Cancel or a headless
caller cannot consume additional extension App IDs. An incompatible explicit
profile override fails rather than pretending to have separate profiles.

A distinct `keepAllValidatedReuseMain` choice selects the new signer overload.
The legacy `useMainProfile` boolean alone does not enable stricter behavior.
A versioned registry binds explicit new consent to the original/resigned bundle
IDs, installed profile UUID, and a per-sign nonce sealed in the main Info.plist.
It is activated only after ordinary-app installation returns success. Failed
opt-ins and opt-outs cannot mutate it. A cached-payload mismatch for an already
validated app fails explicitly rather than silently taking the legacy route.
Validated ReuseMain is not available for host self-install/self-refresh; those
operations retain the pre-existing legacy or separate-profile strategy.
Ordinary and legacy signing stay on the old entry point. User-edited entitlements
require separate profiles until that mapping is qualified. A final-to-original extension ID map explicitly carries pre-rewrite identity into
the signer. Existing ReuseMain refresh accepts the main identity only with a
matching persisted installed-app association, identical embedded profiles, and
complete main/extension entitlement equality. Untrusted imported copies fail
closed. Previously opted-in reused profiles with different entitlement maps require an
interactive fallback; legacy profiles remain on the unchanged legacy path.

## Tests

- `python3 .ci/reuse-main/test_source.py`: source contract only.
- `swiftc Sources/CodeSigning/ExtensionSigningPolicy.swift .ci/reuse-main/Cases.swift -o /tmp/reuse-main-policy && /tmp/reuse-main-policy`: 24 policy checks, no real signing.
- `bash .ci/reuse-main/run.sh` also compiles the production signer body with synthetic CodeSignKit boundary doubles. These do not prove real cryptographic signing.
- Full SideSign compilation is still required.
- Device checks must cover installation, launch, refresh, actual extension
  execution, incompatible-capability fallback, and observed App ID counts.

Never include real certificates, profile payloads, credentials, or entitlement
values in test logs or public diagnostics.

Strict experimental/fallback signing binds profile and entitlement teams to the
selected team and certificate organizational unit, and require the actual signing
leaf DER to appear in the selected profile. Required capabilities must
survive the selected fallback profile; a matching bundle ID alone is insufficient.
