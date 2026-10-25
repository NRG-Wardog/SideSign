# Owned ODA authentication controls

`python3 .ci/owned-oda/test_sources.py` checks exact pre-integration authentication and developer-portal bytes after reversing only the reviewed transport wrappers. This deliberately preserves SRP, 2FA and certificate-mutation retention semantics; it is not wire/network proof.

`bash .ci/owned-oda/run.sh` compiles the actual production context with a minimal `AnisetteData` double and runs its deterministic concurrency fixture ten times under a watchdog. It covers repeated/2FA-style header fetch staging, pre-cancel, stale identity, joined noncooperative cancellation, no overlapping provider admission, immutable existing blob, task-local nil shadowing, conflicting RemoteMac selection, and commit/invalidation lock linearization. It does not execute ADI or contact Apple.

Production native preparation uses the separately qualified AnisetteKit owned attempt. Each fetch snapshots the two built-in libraries and validates those exact bytes against the existing pinned Apple Music manifest before native staging. Custom metadata remains a separate trust boundary: the owned diagnostic path requires HTTPS, an explicit archive SHA-256, bounded downloads and bounded exact archive entries. A metadata author's hash establishes integrity, not independent source authenticity. Legacy manually selected custom providers are unchanged. No custom executable is run by these fixtures.

The context keeps a revoked task-local sentinel. It never falls back to a shared session/VM after cancellation, and `finish` joins the admitted native child before the next provider can start. Blob publication is separate from header production; SideStore supplies a synchronous reserved-identity and Keychain snapshot-CAS commit gate. Failed native cleanup preserves retained files and prevents successful provider completion; outer cleanup removes only the matching empty directory inode, never recursively.

Full SideSign/SideStore compilation, trusted native ADI qualification, and device sign-in/2FA/cancellation still require their corresponding exact-pinned CI/device evidence.
