# Architecture

## Purpose

iOS Rehydrate separates inspection, evidence gathering, policy, and the single permitted
mutation. “Rehydrate” has a narrow technical meaning here: stage the exact locally supplied,
validated IPA bytes and invoke InstallationProxy `Upgrade` for an existing `User` placeholder
or demoted target. It does not mean source recovery, backup restore, a new install, guaranteed
launchability, or guaranteed data preservation.

## Data flow

```text
operator inputs
    |
    v
CLI and redacted presentation
    |---------------------> receipt writer (new files only)
    |
    +--> device selector --> app inspector ---------+
    |                                                |
    +--> backup encryption/create/verify adapters    +--> policy gate
    |                                                |
    +--> local-file IPA reader --> structural verifier
                                                     |
                                                     v
                                      explicit `rehydrate` confirmation
                                                     |
                                                     v
                               exact-byte staging --> InstallationProxy Upgrade
                                                     |
                                                     v
                                           bounded post-inspection/result
```

## Components

### CLI and privacy boundary

The Typer CLI parses explicit selectors, maps expected failures to stable exit behavior, and
renders bounded pretty or compact-JSON success output plus sanitized line-oriented failures. Raw device identifiers, app identifiers, account data,
full paths, unrelated app inventory, and raw lower-level errors do not belong in normal output
or receipts.

### Device adapter

`pymobiledevice3==10.7.1` provides local USB device discovery, lockdown services, app inspection,
staging, and InstallationProxy access. Device-bound commands never choose a sole connected
device implicitly: the operator supplies a redacted device reference or full UDID, and the
selector must resolve exactly. Untrusted mux serials must match a bounded legacy or modern UDID
grammar before they can reach pairing-record lookup. Discovery and connection calls receive an
explicit platform-local mux address, ignoring environment-selected remote mux endpoints.
Automatic pairing is disabled. The adapter supplies an ephemeral pairing-cache directory so the
dependency does not create its normal persistent project cache; the dependency may still read an
existing pairing record from usbmux/iTunes. Session-close failure is reported separately and
cannot erase an already determined operation result or classified body failure.

### Backup subsystem

The subsystem reads the device's backup-encryption state, can enable encryption through a
hidden double-entry password prompt, requests a fresh full backup in a new directory, and
verifies the resulting metadata, device binding, encrypted state, completion state, manifest
structure, and nonempty hashed payload. It records the full-backup request separately from the
observed final status. It never disables encryption, changes an existing encryption password,
recovers a password, or restores a backup.

The pinned MobileBackup2 dependency's generic `DeviceLink` filesystem handlers are replaced for
this workflow by a first-party boundary with an asserted handler table. Every device-controlled
path must be one bounded, unambiguous relative path beneath a fresh root. Before create, open,
truncate, read, copy, move, remove, or enumerate, the boundary rechecks root identity and all
existing components with no-follow metadata and rejects links/reparse points. Encryption changes
receive their own fresh private scratch root instead of the operator's existing parent. Generic
bounded errors replace dependency warnings containing device-controlled names or text. Incoming
DeviceLink control plists are length-prefixed, bounded before read/parse, and restricted to the
known pinned command set. Case/short-name aliases and Windows DOS device components fail closed;
directory responses and direct handler iterables are capped. A changed or nonempty scratch is
preserved instead of recursively deleted, and that cleanup result is exposed separately from
the proved encryption state.

`pyiosbackup==0.2.4` and the device adapters provide the encrypted-backup mechanics. Backup
content and passwords stay outside public output. Before decrypting, v0.1 caps the encrypted
manifest database at 512 MiB; it also bounds plist sizes, per-entry metadata, app-domain entry
count, and declared logical size. Before prompting for a password or invoking PBKDF, a first-party
parser bounds and validates the keybag TLV, required root/class fields, salts, wrapped keys,
manifest-key/class match, and iteration counts. The exact dependency logger that can reveal
derived key material at debug level is suppressed and restored under a lock around keybag
construction. Directory validation streams entries and caps both inspected entries and hashed
payload count. These are fail-closed safety limits, not compatibility claims.

`pymobiledevice3` still constructs initial backup factory information before the bounded
DeviceLink loop by materializing InstallationProxy app metadata/icons and AFC iTunes/iBooks
files. v0.1 does not replace that dependency path and therefore does not establish aggregate
memory isolation from a compromised device. This residual is kept explicit rather than hidden
behind the later `Info.plist` size check.

### IPA verifier

The verifier opens the source local file read-only, computes bounded evidence, rejects unsafe
or ambiguous ZIP structure, requires one root app bundle, parses its metadata, and checks the
workflow-required metadata plus any requested identity/store constraints. It does not
authenticate provenance, cryptographic signature validity, or Mach-O encryption state. It
neither decrypts nor rewrites the archive. Before constructing `ZipFile`, a first-party preflight
validates the bounded EOCD or ZIP64 records, exact single-disk central-directory placement,
physical header count, declared entry count, directory size, and compression methods. It then
cross-checks every central entry against its local header and bounded raw payload range. Only
stored and deflated members pass; raw decoding must reach exact EOF with the declared size and
CRC, without trailing compressed bytes. Path, namespace/member-type, expansion, ratio,
duplicate, and canonical-collision checks remain in the post-construction verifier.

### Policy gate and rehydrate executor

The executor checks that the bundle match is exact and that a fresh matching
encrypted-backup/app-domain receipt is present. That receipt is itself bound to a fresh
`backup create` receipt from the same CLI version, including the original full-backup request
and current backup aggregates. It then requires `ApplicationType` `User`, a placeholder or
demoted app, and the literal confirmation `rehydrate` before staging the exact validated bytes.
Because app
state can change during a long upload, the executor performs a second bounded inspection after
staging and immediately before the mutation boundary. Only another exact eligible result permits
the single InstallationProxy `Upgrade` verb. The final pre-send snapshot is the one recorded as
the operation's `before` evidence. The receipt is a local guardrail, not a signed attestation.
There is no `Install`, `Uninstall`, force, automatic retry, or fallback path.

A terminal response and bounded-attempt, bounded-time post-inspection distinguish known success,
known failure, and unknown outcome. After the mutation boundary, a disconnect, cancellation,
interrupt, or timeout is not treated as safe failure and is never retried automatically. The
executor makes one shielded, bounded attempt to remove only its randomly named staged IPA. The
result records whether cleanup was confirmed; failure can leave a full or partial staged copy
on the device without changing the separately determined app outcome.

Backup operations apply the same truth rule to their inner protocol sessions. A completed backup
is structurally validated even when MobileBackup2 disconnect/close cannot be confirmed; the
report carries `mobilebackup_connection_closed` separately. Encryption-enable cleanup status is
reported separately when that operation ran.

### Evidence writer

Optional JSON receipts contain redacted, minimal facts. Their paths are atomically reserved with
no-overwrite semantics before device access or other operation work. A pre-operation failure
removes only an unchanged reservation. Once the Upgrade send boundary is crossed, an unknown
outcome is finalized as explicit redacted evidence when possible instead of leaving a pristine
empty reservation. A finalization failure cannot turn a known successful operation into a false
operation failure. Read safety-gate receipts require the current schema/tool version, a valid
timezone-aware timestamp, and a maximum age of 24 hours. Timestamps, opaque references, hashes,
aggregate counts/sizes, and platform
responses can vary across runs; policy decisions and normalized synthetic-test expectations are
intended to be deterministic for the same inputs.

## Read and write surfaces

The CLI reads the selected IPA, device protocol responses, an existing system/usbmux pairing
record, and an operator-selected backup when verifying. It writes only a new backup directory,
explicitly requested new receipt files, an ephemeral pairing-cache directory, and bounded
staging required by the device protocol. Ephemeral cache and staging removal are best-effort;
their residual data risks are documented in the privacy and threat-model documents. The CLI
does not modify the source IPA. Backup creation routes device-requested filesystem work through
the contained MobileBackup2 boundary; no-follow checks and identity rechecks fail closed on
known link/reparse/root-replacement cases, but cannot make host-level concurrent filesystem
interference impossible.

The implementation has no Apple account, store, acquisition, telemetry, or project-hosted
service client. Its adapter supplies an explicit platform-local usbmux address rather than an
environment-selected remote endpoint. Source checkout, dependency installation, the host, or
the device can still have separate network behavior; the architecture therefore makes no
blanket offline claim.

The runtime workflow uses Python library APIs directly; it does not construct shell command
strings or delegate the device/IPA operation to an external executable.

## Extension seam

The architecture may retain an internal `ArtifactProvider` seam whose v0.1 implementation is
local-file-only. No external or acquiring provider is part of v0.1. Any future provider requires
an independent security review before implementation or activation and must not receive device
mutation privileges, bypass the verifier/policy gate, or weaken the anti-scope.

## Dependency and license boundary

Both pinned device/backup dependencies, `pymobiledevice3` and `pyiosbackup`, are GPL-licensed.
The project is consequently distributed under GPL-3.0-or-later; see [../NOTICE.md](../NOTICE.md).
