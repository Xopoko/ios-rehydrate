# iOS Rehydrate

`ios-rehydrate` is an experimental, Windows-first Python CLI for one narrow recovery
workflow: inspect an app already represented on a connected iOS device, create and verify a
fresh encrypted backup after requesting a full backup, validate a locally supplied IPA and its
workflow-required App Store metadata, and ask InstallationProxy to `Upgrade` an eligible
placeholder or demoted app.

> **Evidence boundary:** this repository publishes synthetic and mocked evidence only. It
> contains no real device data, IPA, backup, log, identifier, screenshot, or private result.
> Passing the public tests does not establish real-device compatibility, reliability,
> security, or data preservation.

## Scope and safety boundary

Version 0.1 can:

- list USB-connected devices using redacted references;
- inspect one explicitly selected app;
- report backup-encryption state and, with explicit consent, enable encryption;
- request a new full backup and verify the resulting backup's encrypted, completed structure
  and nonempty payload;
- structurally verify a local IPA without rewriting, decrypting, or re-signing it; and
- invoke only InstallationProxy `Upgrade`, and only when the live target is a `User` app in
  placeholder or demoted state.

Version 0.1 does **not** authenticate to Apple, acquire or download apps, bypass DRM, decrypt
or dump executables, re-sign packages, support jailbreaks, install an absent app, uninstall
an app, delete app or user data, or restore a backup. It has no telemetry or crash-reporting
service. There is no force flag and no fallback from `Upgrade` to `Install` or `Uninstall`.

Use only an IPA that you obtained lawfully and are authorized to use with the selected
device/account context. Structural verification cannot prove provenance, ownership,
authorization, cryptographic signature validity, Mach-O encryption state, future App Store
acceptance, or legal compliance.

## Requirements

- Windows and Python 3.11, 3.12, or 3.13
- a working local Apple mobile-device USB driver/usbmux provider (`doctor` reports readiness;
  remote or environment-selected mux endpoints are not used)
- a physical iOS device connected over USB, paired, trusted, and unlocked when requested
- enough local storage for a new full encrypted backup
- a compatible IPA already present on the local filesystem and lawfully available to you

The device workflow is local, but the project does not claim to be universally offline.
Cloning the source and installing Python dependencies can require network access, and the
host platform or device may have independent network behavior.

Version 0.1 intentionally refuses an encrypted `Manifest.db` larger than 512 MiB, an app-domain
metadata blob larger than 8 MiB, more than 1,000,000 entries in one app domain, or more than
4 TiB of declared logical app-domain data. Before asking for a backup password or running
PBKDF, it also bounds and validates the keybag, including iteration ceilings of 1,000,000 for
`ITER` and 20,000,000 for `DPIC`. These fail-closed limits can reject a legitimate future or
nonstandard backup; there is no override flag. Structural backup scans stop at 2,000,000
filesystem entries or 1,000,000 hashed payload files. DeviceLink control plists are capped at
16 MiB and a single directory response at 50,000 entries.

IPA parsing is also fail-closed: the file is capped at 2 GiB, declared entries at 50,000, the
ZIP central directory at 64 MiB, expanded content at 8 GiB, and compression ratio at 200:1.
Only stored and deflated ZIP members are accepted. The preflight reads and validates the bounded
EOCD/ZIP64 and central-directory structure before Python's `ZipFile` constructor materializes it.
These limits intentionally reject SFX/prefixed archives, central-directory trailers, and other
nonstandard forms; there is no override flag.

## Quickstart

From a clean checkout, use the locked `uv` path for reproducible project and release
verification. The `pip` path is a convenience setup only; its resolved toolchain can drift.

### With uv

```powershell
uv sync --locked --dev
uv run ios-rehydrate --help
uv run pytest
```

### With pip (convenience, not reproducible release evidence)

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\python.exe -m pip install "pytest>=8.3,<10" "pytest-cov>=6,<8" "pytest-mock>=3.14,<4" "ruff>=0.11,<1" "mypy>=1.15,<2"
.\.venv\Scripts\python.exe -m pytest
```

The default public test suite uses synthetic inputs and adapters. Passing it does not prove
that any particular device/app/IPA combination will work or that app data will be preserved.

## Operator workflow

Start with diagnostics and discover the redacted device reference:

```powershell
ios-rehydrate doctor
ios-rehydrate device list
ios-rehydrate app inspect --device <device-ref-or-full-udid> --bundle-id <bundle-id>
```

Check encryption, then create a **new** backup directory. If encryption is disabled,
`--enable-encryption` prompts securely for a new password and leaves encryption enabled on
the device after the command completes. An interruption while changing encryption can leave
the new state uncertain; the CLI reconciles it when possible and otherwise reports an unknown
outcome. If the runtime cannot guarantee a hidden prompt, it refuses to read the password.
An interrupted backup keeps its incomplete new directory for operator inspection.

```powershell
ios-rehydrate backup encryption-status --device <device-ref-or-full-udid>
ios-rehydrate backup create --device <device-ref-or-full-udid> --output <new-backup-dir> --enable-encryption --receipt <new-backup-receipt.json>
ios-rehydrate backup verify --device <device-ref-or-full-udid> --backup <backup-dir> --bundle-id <bundle-id> --creation-receipt <new-backup-receipt.json> --receipt <new-verification-receipt.json>
```

Verify the locally supplied IPA:

```powershell
ios-rehydrate ipa verify <path-to-app.ipa> --bundle-id <bundle-id> --receipt <new-ipa-receipt.json>
```

Only after reviewing the inspection, backup, and IPA results should you cross the mutation
boundary:

```powershell
ios-rehydrate app rehydrate --device <device-ref-or-full-udid> --bundle-id <bundle-id> --ipa <path-to-app.ipa> --backup-receipt <new-verification-receipt.json> --receipt <new-result-receipt.json>
```

The app-domain verification step requires the fresh `backup create` receipt and binds its
full-backup request evidence to the backup's current structure and aggregate payload values.
The last command requires that fresh matching verification receipt, refuses anything except a
`User` placeholder or demoted app, and requires the operator to type `rehydrate`. After
staging, it performs a second bounded eligibility check immediately before sending `Upgrade`;
an ineligible or ambiguous change fails closed without sending the mutation. Receipts are
guardrails rather than signatures and remain operator-controlled. A disconnect or timeout after
the `Upgrade` request can leave the outcome unknown; the CLI does not retry automatically. The
command stages one randomly named IPA copy on the selected device and makes one bounded cleanup
attempt. Check `cleanup.staging_removed` in a successful result. If cleanup cannot be confirmed,
a full or partial staged copy may remain under the project's device staging directory; do not
repeat the mutation merely to clean it up. If the final app outcome is unknown after the send
boundary, a requested result receipt is finalized with `status: unknown` and the available
redacted cleanup evidence rather than being left as an empty file. Device-bound results also report
`connection_closed`; a failed local-session close does not replace an already known operation
result.

Backup creation separately reports `mobilebackup_connection_closed`; when encryption was
enabled in the same command, `encryption_mobilebackup_connection_closed` reports that inner
session and `encryption_scratch_removed` reports whether the per-run private scratch was proved
absent after cleanup. Both are `null` when no enable operation ran. A `false` value does not
erase a structurally validated backup or proved encryption state; preserved scratch must be
treated as sensitive.

Add `--json` to commands for successful structured, redacted output. Failures remain one
sanitized `error[REASON]` line on stderr with a stable exit code. Receipt paths must be new files;
the CLI reserves an optional receipt before opening the device or starting other work and
refuses to overwrite it. If an operation succeeds but receipt finalization fails, the command
still reports the operation result with `receipt_written: false` and preserves the reserved
file for diagnosis. Treat backup directories and receipts as sensitive even when identifiers
are redacted. Safety-gate receipts must come from the same CLI version, contain timezone-aware
creation times, and be no more than 24 hours old. They remain unsigned local guardrails, not
attestations against a compromised host.

## What IPA verification means

The verifier treats the IPA as untrusted input. It checks archive structure and safety,
requires one root app bundle, reads its metadata, checks requested identity/store constraints
when supplied, and requires the metadata, SINF, and CodeResources shape expected by this
workflow. It does not authenticate the package's provenance, signature, or executable
encryption state. The IPA is not modified.

A pass means that the implemented structural checks passed. It is not a guarantee that Apple
will authorize the package, that the device will accept it, that the app will launch, or that
its existing data will remain compatible.

## Dependency resource residual

The first-party MobileBackup2 boundary caps DeviceLink control frames, transfers, paths, and
filesystem enumeration. Before that boundary starts, pinned `pymobiledevice3` builds the initial
backup `Info.plist` by materializing app metadata, icons, and AFC files returned by the device.
That dependency path has no project-enforced aggregate response cap. A compromised or severely
malformed device can therefore still cause high memory use before the bounded backup loop.
Version 0.1 documents this residual rather than claiming hostile-device resource isolation.

## Documentation

- [Privacy](PRIVACY.md)
- [Security policy](SECURITY.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Public experiment](docs/EXPERIMENT.md)
- [Evidence-gated roadmap](docs/ROADMAP.md)
- [Source and evidence provenance](docs/PROVENANCE.md)
- [Contributing](CONTRIBUTING.md)
- [Third-party notices](NOTICE.md)

## License

iOS Rehydrate is licensed under GPL-3.0-or-later. Its pinned device/backup dependencies
include GPL-licensed software; see [NOTICE.md](NOTICE.md).
