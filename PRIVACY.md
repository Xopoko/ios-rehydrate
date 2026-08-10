# Privacy

iOS Rehydrate is designed to minimize what it reveals, not to make device work nonsensitive.
An encrypted full backup can contain highly personal data, and an IPA can be proprietary.
The operator controls where those files are stored, retained, and deleted.

## Data handled

| Data | Why it is used | Persistent output |
| --- | --- | --- |
| Device identifiers and properties | Select exactly one device and bind checks to it | Redacted/opaque references only |
| Existing pairing records | Establish the already-trusted USB session through usbmux/iTunes | Read by the pinned device library; no project receipt or log |
| App identity and state | Decide whether the target is eligible | Redacted app reference and minimal state |
| Backup password | Enable or open encrypted backup material | Never written to output or receipts |
| Backup contents | Create and validate a full encrypted backup | The operator-selected backup directory |
| Local IPA and metadata | Structural and identity verification, then exact-byte staging | The source file remains operator-controlled; receipts contain bounded evidence |
| Command results and errors | Operator feedback and reproducibility | Console output and optional new JSON receipt |

Normal output and receipts omit raw device identifiers, names, account information, full
paths, bundle identifiers, and unrelated app inventory. Errors are bounded and sanitized.
`--json` changes successful output to compact JSON; failures remain sanitized stderr lines. It
does not change the privacy policy.

Redaction reduces accidental disclosure; it is not anonymization. Repeated opaque references,
timestamps, hashes, sizes, and workflow facts can still be identifying when combined with
other information.

## Storage and retention

- The CLI writes only operator-requested backups, new receipts, and bounded working data
  needed for the selected operation.
- Device sessions use an ephemeral pairing-cache directory under the operating-system temporary
  area. Automatic pairing is disabled; the directory is removed after the session on a
  best-effort basis. The device library can still read existing usbmux/iTunes pairing records.
  Discovery and session creation use the platform's explicit local mux endpoint; an
  environment-supplied remote endpoint is ignored.
- Receipt files are created without overwrite. Backup creation requires a new output
  directory and preserves incomplete output on failure for diagnosis.
- MobileBackup2 device-controlled filesystem requests pass through a first-party containment
  adapter rooted at the newly reserved directory. Backup-encryption changes use a separate
  fresh private scratch directory. An unchanged empty scratch is removed; a changed or nonempty
  scratch is preserved rather than recursively deleted and should be treated as sensitive.
  `encryption_scratch_removed` reports whether absence was confirmed for that run. Inner
  MobileBackup2 connection cleanup is reported separately from backup/encryption outcome, so a
  close failure cannot erase already established evidence.
- The CLI does not send backups, IPAs, receipts, or diagnostics to a project-operated or
  acquisition service. The rehydrate operation intentionally stages the validated IPA bytes to
  the selected USB-connected device.
- Rehydration makes one bounded, best-effort attempt to remove its randomly named staged file.
  The result reports whether removal was confirmed. A disconnect, timeout, or device-side
  deletion failure can leave a full or partial IPA copy in the project's device staging
  directory; the CLI does not automatically retry either cleanup or mutation.
- When rehydration has crossed the send boundary but its final state is unknown, an explicitly
  requested result receipt records only redacted unknown-outcome and cleanup evidence. It does
  not record raw device/app identifiers or paths.
- There is no telemetry, analytics SDK, hosted crash reporter, or project-operated account
  service.
- The CLI does not manage a retention schedule. Remove local backups, receipts, and incomplete
  working data yourself when they are no longer needed, using your normal secure-deletion and
  backup policies.

Filesystem permissions, disk encryption, endpoint protection, cloud-sync software, backup
software, shell history, and administrator access remain outside the CLI's control. Choose a
private output location and avoid placing sensitive material in a synced or shared folder.
The project rejects known symlink/reparse ancestors and rechecks root/target identity around
filesystem operations, but a same-user or privileged process racing those checks remains outside
the guarantee.
Device selectors, bundle identifiers, and local source/output paths are command-line arguments
and may be retained by shell history or visible to privileged process-inspection tools. Output
redaction cannot remove those host-level records.

## Network boundary

Version 0.1 implements no Apple authentication, store lookup/download, acquisition service,
telemetry, or project-operated network endpoint. Its device adapter pins discovery and session
creation to the platform's local usbmux endpoint and does not honor a remote mux address from
the environment. This is not an “offline” guarantee: source hosting and dependency installation
can require a network, and the operating system, device, or third-party tooling may communicate
independently.

The pinned backup dependency gathers device-provided app metadata, icons, and AFC files for
`Info.plist` before the first-party bounded DeviceLink loop begins. Aggregate memory use for that
initial dependency response is not project-bounded; do not treat v0.1 as isolation from a
compromised device.

## Sharing diagnostics

Never attach an IPA, backup, pairing record, password, receipt containing sensitive context,
raw log, device screenshot, or unredacted command output to a public issue. Reproduce with
synthetic data where possible. Send security-sensitive reports only through the private route
described in [SECURITY.md](SECURITY.md).

## Credentials and legal data

Backup passwords are accepted through an interactive hidden prompt, not a command-line value,
environment variable, receipt, or log. A runtime warning that hidden input is unavailable is
treated as a refusal; the CLI does not fall back to echoed input. Version 0.1 does not request
Apple credentials. Before calling the encrypted-backup dependency, the project validates the
keybag's bounded shape and iteration counts. The dependency logger that can otherwise emit
derived key material at debug level is disabled and restored around that call.

Enabling backup encryption changes device state. An interruption can make that state uncertain;
the CLI performs a bounded reconciliation and reports an unknown outcome when it cannot prove
the resulting state. It never disables encryption or rotates an existing backup password.

Use only material you are legally entitled and authorized to process. The tool cannot verify
ownership or resolve retention, privacy, employment, contractual, or jurisdictional duties for
you.
