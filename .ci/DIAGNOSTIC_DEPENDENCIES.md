# Explicit ADI diagnostic dependency proof

The diagnostic candidate changes only SideSign's AnisetteKit manifest revision
from `62ce85c8798d8eab8e29752aba7dc9f1f6a5b80d` to
`e530b84687ebea2e7d1115119e1a6d18372de14b`, plus this document, the diagnostic
tests, and the existing dependency verifier. Every runtime, license, historical
parity proof, and accepted receipt remains byte-for-byte unchanged from accepted
SideSign `06351a87d44ff8faa7d5a2e8c7ed3096fff73d2c`, tree
`a773b5461f43b4a28d0d34f7c1acd8728a9f8c6f`.

The initial `Package.resolved` is deliberately the exact accepted lock, still
pinning the old AnisetteKit revision. This is a pending-resolution source
candidate, not a resolved graph or native success. Never edit the lock by hand
to make the manifest and lock agree. Only genuine target-macOS resolver output
may supply its eventual replacement.

## Source-only external basis

The original default gate and `.ci/production-dependencies.json` retain their
accepted behavior. The default gate rejects this diagnostic candidate. Select
the diagnostic proof explicitly:

```sh
python3 -B .ci/production-dependencies.py --root /clean/SideSign \
  --diagnostic-basis /reviewed/sidesign-diagnostic-transition.json \
  --diagnostic-basis-sha256 APPROVED_BASIS_SHA256
```

The reviewer must supply an independently approved SHA256; calculating a new
hash of unreviewed input does not constitute approval. Both external files must
be ordinary non-executable files outside the owner checkout. The gate reads
them without modifying anything or using the network. Its source registry
identity is `97c9d0b81e9b59c8271ae1155393b2fcb534dc97ea367095d3adfcde8a3783ad`.

The strict JSON schema contains exactly these keys:

```json
{
  "schema_version": 1,
  "owner": "SideSign",
  "purpose": "diagnostic_dependency_source_transition",
  "source_registry_sha256": "97c9d0b81e9b59c8271ae1155393b2fcb534dc97ea367095d3adfcde8a3783ad",
  "accepted": {
    "commit": "06351a87d44ff8faa7d5a2e8c7ed3096fff73d2c",
    "tree": "a773b5461f43b4a28d0d34f7c1acd8728a9f8c6f"
  },
  "candidate": {"commit": "EXACT_COMMIT", "tree": "EXACT_TREE"},
  "anisette": {
    "repository": "https://github.com/NRG-Wardog/AnisetteKit.git",
    "accepted_commit": "62ce85c8798d8eab8e29752aba7dc9f1f6a5b80d",
    "diagnostic_commit": "e530b84687ebea2e7d1115119e1a6d18372de14b"
  },
  "changes": {
    "Package.swift": {
      "before": {"mode": "100644", "blob": "OLD_GIT_BLOB", "sha256": "OLD_SHA256"},
      "after": {"mode": "100644", "blob": "NEW_GIT_BLOB", "sha256": "NEW_SHA256"}
    }
  }
}
```

The abbreviated `changes` example must also contain exact before/after rows for
`.ci/production-dependencies.py`, `.ci/test_diagnostic_dependencies.py`, and
`.ci/DIAGNOSTIC_DEPENDENCIES.md`. A newly added file has `before: null`. Include
`Package.resolved` only when it actually changed through reviewed resolution.
No other changed paths are accepted, even if added to an approved basis. All
rows bind Git blob IDs, modes, and SHA256 of bytes. The candidate commit/tree
must be recorded externally after committing the candidate, avoiding a
self-referential owner manifest. Do not embed the basis in the owner tree.

This basis describes immutable source identity. It must not contain build
status, tests, readiness, or native/resolver outcome receipts. Future source
changes require a new reviewed basis; never add outcomes to an existing one.

## Genuine resolver output and a separate reviewed receipt

After resolving the pending candidate on the actual macOS/Xcode runner, capture
the lock exactly as written, including whether `originHash` exists and its
exact value. Preserve five unrelated package pins, including every URL and
branch/version/revision field. Only AnisetteKit may move to the diagnostic
revision. An absent origin hash is `{ "present": false, "value": null }`; an
observed present hash is `{ "present": true, "value": "ACTUAL_HASH" }`.
Do not invent a hash, insert a null `originHash` key, or remove one that was
actually emitted.

Commit only the captured lock, review a new source basis binding that exact
candidate, and supply a separate approved receipt:

```sh
python3 -B .ci/production-dependencies.py --root /clean/SideSign \
  --diagnostic-basis /reviewed/sidesign-resolved-transition.json \
  --diagnostic-basis-sha256 APPROVED_RESOLVED_BASIS_SHA256 \
  --diagnostic-resolver-receipt /reviewed/diagnostic-resolver-receipt.json \
  --diagnostic-resolver-receipt-sha256 APPROVED_RECEIPT_SHA256
```

The receipt contains exactly:

- `schema_version: 1`, `owner: "SideSign"`, and
  `purpose: "diagnostic_swiftpm_resolution"`;
- the actual NRG-Wardog GitHub Actions `run_url` and positive `run_attempt`;
- `resolver_tested_commit` and `resolver_tested_tree` identifying the pending
  candidate before resolution;
- `lock_sha256` of the exact resolver-produced bytes, and `origin_hash` with
  the observed `present` and `value` fields;
- `toolchain: { "xcode": "ACTUAL_VERSION", "swift": "ACTUAL_VERSION" }`;
- `command`, the actual resolver argument vector;
- `evidence_sha256`, with digests named `resolver_log`, `resolution_before`,
  and `resolution_after` for the preserved run artifacts.

Receipt approval must independently check those run artifacts. A hash match
alone cannot establish that a command ran. The verifier additionally requires
the resolver-tested commit to be an ancestor of the final candidate, its
starting lock to equal the accepted lock, and its entire source inventory to
match the final candidate except for the exact captured lock. Synthetic unit
test receipts deliberately exercise this shape; they are never native evidence.

## Results and regression checks

Both pending and resolved modes report `diagnostic_dependency_transition_pass`
and `production_ready: false`. Pending mode reports
`accepted_lock_retained_pending_resolution`; reviewed resolved mode reports
`reviewed_resolver_observed_lock`. Both keep native validation
`not_established_for_candidate`. `historical_receipts_only` refers to the
unchanged accepted receipts in `.ci/production-dependencies.json`, which cannot
supply diagnostic readiness. A separate new native receipt bound to the actual
diagnostic graph is required by the integration's later acceptance gate.

Run `python3 -B .ci/test_diagnostic_dependencies.py` for exact source, metadata,
pin, hash, origin-state, fake-readiness, working-tree, and index adversarial
checks. To test default compatibility without changing frozen assertions, run
the unchanged `.ci/test_production_dependencies.py` from an independent accepted
checkout loading the updated verifier. Its fixture clones stay on the accepted
commit. Run historical source parity at its original checkpoint, and corrected
source parity plus `.ci/test-source-parity.py` at
`ed30d3989ea0f80bcb91466d6d5ca043f4366df0`. Neither old whole-tree gate should be
reported as passing against the intentionally changed diagnostic candidate.

These Python checks do not invoke Swift, resolve packages, compile iOS code,
build an IPA, publish a ref, or establish device behavior.
