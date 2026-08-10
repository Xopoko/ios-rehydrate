# Threat Model

## Scope

This model covers the Windows-first v0.1 CLI, its local files, Python dependencies, USB device
protocol boundary, and the single InstallationProxy `Upgrade` action. Apple services, the
device operating system, host administrators, malware with equivalent privileges, and legal
authorization decisions are outside the trusted computing base.

## Assets and trust boundaries

Assets include the operator-supplied IPA, encrypted backup and password, existing app data,
device/app identity, pairing state, receipts, and the integrity of the host filesystem. Trust
boundaries exist at CLI input, local archive parsing, filesystem writes, Python dependencies,
USB/device responses, backup parsing, and the final mutation request.

Assumptions:

- the operator controls the host and is authorized to use the device and IPA;
- the host's Python runtime, trust store, USB stack, and filesystem are not already compromised;
- the device may disconnect or return malformed/incomplete responses; and
- the IPA and backup are untrusted parser inputs even when their provenance is believed.

## Threats, controls, and residual risk

| Threat | v0.1 control | Verification | Residual risk |
| --- | --- | --- | --- |
| Wrong or ambiguous device | Explicit selector; exact resolution; strict mux-serial grammar; redacted stable reference | Synthetic zero/one/many-device and malformed-record tests | A valid full identifier supplied by the operator can still select the wrong owned device |
| Wrong app or destructive operation | Exact bundle match; require `User` plus placeholder/demoted; only `Upgrade`; no force/fallback | Policy-matrix tests and adapter call assertions | Device-reported metadata can be stale or misleading |
| Time-of-check/time-of-use change | Early policy check plus a second bounded inspection after staging and immediately before `Upgrade`; literal confirmation | Eligible-to-ineligible and eligible-to-eligible staging-change tests | State can still change after the final check |
| Malformed or hostile IPA | Read-only input; pre-constructor EOCD/ZIP64/central-directory bounds; stored/deflated-only; safe paths/types; bounded expansion; duplicate/collision and single-root checks; strict metadata parsing | Synthetic standard/ZIP64, malformed-central-directory, unsupported-method, traversal, duplicate, bomb, ambiguity, and metadata tests | Parser/library vulnerabilities remain possible; nonstandard ZIP forms are refused |
| Artifact substitution | Retain the exact validated local bytes and bind evidence to their digest before staging | Retained-byte, digest, and immutable-input tests | A compromised host can subvert both checking and staging |
| Command injection | Runtime device and IPA operations use direct library calls, not constructed shell command strings | Tests assert adapter calls and treat values as data | A compromised dependency still executes in-process |
| Unsafe overwrite or path escape | New backup/receipt destinations; receipt reserved before work; every MobileBackup2 filesystem handler confined to a fresh identity-checked root; strict relative paths and no-follow ancestor/target checks | Pinned-handler parity, traversal/alias, root-replacement, nested-link/reparse, pre-truncate identity, and existing-target tests | Same-user filesystem races or privileged interference remain possible |
| Forged or stale receipt | Exact schema/tool version, timezone-aware age bound, chained create/verify digests, full-request flag, strict aggregate types, device/app references, encrypted/completed state, and nonempty app domain are checked | Synthetic stale/future/version/type/digest/aggregate mismatch tests | Receipts are not signed and remain under operator/host control |
| Backup disclosure | Encryption required; hidden prompt fails closed instead of echo fallback; password never logged; redacted outputs | Warning-injected password/redaction tests and receipt inspection | Backup files remain sensitive and operator-managed |
| Host resource exhaustion from backup input | Bound required plists, encrypted/decrypted manifest size, keybag TLV/iterations, DeviceLink control/transfer frames, directory responses, streamed filesystem scans, hashed payload count, per-entry metadata, domain entry count, and logical total at first-party boundaries | Synthetic oversized plist/database/keybag/iteration/frame/directory/filesystem/blob/count/total tests | Before DeviceLink, pinned backup factory-info code materializes device app metadata/icons/AFC files without a project aggregate cap; allowed maxima also remain substantial |
| Secret or identity leakage | Opaque references; bounded sanitized errors; dependency warning/logger suppression at known secret-bearing boundaries; minimal receipts; no telemetry | Seeded warning/logger, scanner, and snapshot tests | Hashes, timing, counts, and context can still correlate a user; other dependency diagnostics remain outside a universal no-log proof |
| Device/protocol failure after mutation | Record the boundary; time-bound calls; classify ambiguous outcomes; no automatic retry; persist requested redacted unknown-outcome evidence; report session cleanup separately from known app/backup/encryption outcome | Injected timeout, cancellation, interrupt, postflight, unknown-receipt, disconnect, and cleanup-only failures | Manual inspection can still be inconclusive |
| Device staging residue | Random per-run path; one shielded exact-file cleanup; report cleanup status separately | Cleanup success, exception, timeout, cancellation, and false-return tests | A full or partial IPA can remain on the device after cleanup failure |
| Dependency compromise | Exact pins for device/backup libraries; review/update gates | Lock/metadata review and CI | Pins preserve known vulnerable code until updated and do not prove provenance |
| Unauthorized acquisition or DRM bypass | No Apple auth/download/acquisition, decrypt, dump, re-sign, or jailbreak path | Public-surface and call-path tests | Operator can use unrelated tools outside this project |
| Network or telemetry surprise | No project service client or telemetry; explicit platform-local usbmux address ignores environment-selected remote mux endpoints | Adapter tests with hostile mux environment plus source/dependency review | Package install, host, device, and dependencies may have independent network behavior |

## Safety invariants

1. The source IPA is immutable from the CLI's perspective.
2. Backups and receipts use new destinations; failure does not silently replace prior evidence.
   Receipt finalization failure does not erase a known operation result.
3. Backup encryption is never disabled or rotated by v0.1.
4. App mutation means exactly InstallationProxy `Upgrade` for an eligible existing target.
5. Any unknown eligibility fact fails closed before mutation.
6. Any unknown outcome after mutation is reported as unknown and is not retried automatically.
7. Sensitive identifiers and paths are absent from normal persistent evidence.

## Claims not established

Passing controls and tests does not prove the tool secure, the backup restorable, the IPA
authorized, the app compatible, or app data preserved. This repository contains no real-device
compatibility evidence. Independent security review is still required before any non-local
`ArtifactProvider` is considered.
