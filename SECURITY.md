# Security Policy

iOS Rehydrate crosses a sensitive device-mutation boundary and parses untrusted archives.
Treat it as experimental software, keep a verified backup, and review the exact command before
confirming `rehydrate`.

## Supported versions

Security fixes are made only on the current public v0.1 development/release line. There is no
long-term-support branch or response-time guarantee.

## Reporting a vulnerability

Use GitHub's **Report a vulnerability** button in the repository's Security tab. Repository
maintainers must enable private vulnerability reporting before the first public push. If that
button is absent, do not disclose the report publicly; wait for the project to publish a private
channel.

Never put an IPA, backup, pairing record, password, device/account identifier, private path,
raw log, or other sensitive artifact in a GitHub issue, discussion, pull request, or public
proof of concept. A minimal synthetic reproducer and redacted description are preferred.

Public issues are appropriate for nonsensitive bugs only.

## Security boundary

Version 0.1 is intended to:

- select one device explicitly and redact its identity;
- reject an absent, system, ambiguous, or otherwise ineligible app;
- write backups and receipts only to new operator-selected destinations;
- parse an IPA defensively without modifying it;
- send only InstallationProxy `Upgrade` after an exact confirmation; and
- fail closed when preconditions cannot be established.

It is not a sandbox, malware scanner, legal-rights verifier, Apple authorization emulator, or
backup-restorability proof. It cannot make a compromised host, dependency, USB stack, device,
or maliciously privileged process safe.

## High-risk inputs and residual risks

- A malformed IPA can target archive and parser bugs despite pre-constructor EOCD/ZIP64 and
  central-directory bounds, compression-method restrictions, size, path, type, collision,
  duplicate-entry, expansion, and structural checks.
- Backup metadata is bounded before parsing, but manifest verification can still hold multiple
  copies of up to 512 MiB in memory and cause substantial memory pressure.
- Keybag shape and PBKDF iteration counts are bounded before the password prompt and expensive
  derivation. The fail-closed ceilings can reject a legitimate future or nonstandard backup.
- A full backup contains sensitive data and can be exposed by weak filesystem permissions,
  cloud sync, malware, or password mishandling.
- A cable loss, device reboot, or protocol timeout after `Upgrade` begins can make the outcome
  unknown. The CLI does not retry automatically.
- A full or partial IPA copy can remain in the project's device staging directory when bounded
  cleanup cannot be confirmed. A known app outcome does not by itself prove staging cleanup.
- An interruption while enabling backup encryption can leave the device state uncertain; a
  partial backup directory or changed/nonempty private scratch is deliberately preserved when
  the project cannot prove it safe to remove. Successful enable results separately report
  whether that per-run scratch was proved absent.
- Device-controlled MobileBackup2 paths are constrained beneath a fresh root with no-follow and
  identity checks, but same-user filesystem races and privileged interference cannot be made
  impossible by the process.
- Pinned `pymobiledevice3` materializes initial device app metadata/icons and AFC files before
  the first-party bounded DeviceLink loop. A compromised device can still cause high memory use
  in that dependency path; v0.1 does not claim hostile-device resource isolation.
- Platform authorization and DRM decisions are controlled by Apple and can reject a
  structurally valid package.
- App version/schema changes can make existing app data incompatible; no preservation claim
  is made.
- Pinned dependencies reduce accidental drift but do not eliminate supply-chain risk.

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for the detailed controls and remaining risk.

## Release and dependency policy

The project is GPL-3.0-or-later. The pinned runtime includes `pymobiledevice3==10.7.1` and
`pyiosbackup==0.2.4`, both GPL-licensed; see [NOTICE.md](NOTICE.md). A public release should be
built from a reviewed commit, pass the synthetic test/lint/type-check gates, and include
dependency metadata. These gates are quality evidence, not a security audit.
