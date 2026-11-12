# iOS Rehydrate

[![CI](https://github.com/Xopoko/ios-rehydrate/actions/workflows/ci.yml/badge.svg)](https://github.com/Xopoko/ios-rehydrate/actions/workflows/ci.yml)

Reinstall an **offloaded** iOS app from an IPA you already have.

When iOS offloads an app it leaves a placeholder and keeps the app's data. If the app is no
longer downloadable, the placeholder is stuck. `ios-rehydrate` takes a local IPA, checks it,
and sends InstallationProxy `Upgrade` for that placeholder, so the app is upgraded in place
instead of installed fresh. Before it does that, it makes you take a fresh encrypted backup.

It is a Windows-first Python CLI, version 0.1, alpha. It has only been tested with synthetic
inputs and mocked devices in CI, so keep the backup.

## What it will and won't do

The only thing it changes on the phone is one `Upgrade` call, for an app that is a `User`
placeholder or demoted app, after you type `rehydrate`. It also stages the IPA in
`/PublicStaging/ios-rehydrate/` and tries once to delete it afterwards. Enabling backup
encryption, if you ask for it, is the only other change to the device.

It does not install apps that aren't already there, uninstall or delete anything, restore
backups, download from the App Store, sign in to Apple, decrypt or re-sign IPAs, or fall back to
`Install` if `Upgrade` fails. There is no `--force`, no automatic retry, and no telemetry.

Only use IPAs you are entitled to use. The IPA check is structural: it can't tell whether Apple
will accept the package or whether the app will still read its old data.

## Requirements

- Windows with Python 3.11–3.13 (Linux works for development)
- Apple's mobile device USB driver (installed with iTunes or the Apple Devices app)
- An iPhone/iPad connected over USB, already paired and trusted
- Disk space for a full encrypted backup
- The app's IPA, including `iTunesMetadata.plist` and `SC_Info/*.sinf`

## Install

```powershell
uv sync --locked
uv run ios-rehydrate --help
```

Or, with pip: `pip install .`

## Usage

```powershell
# 1. Check the environment and find the device. References are hashes, not UDIDs.
ios-rehydrate doctor
ios-rehydrate device list
ios-rehydrate app inspect --device <device-ref> --bundle-id com.example.app

# 2. Back up. --enable-encryption prompts for a new backup password if encryption is off.
ios-rehydrate backup create --device <device-ref> --output .\backup-new --enable-encryption --receipt create.json
ios-rehydrate backup verify --device <device-ref> --backup .\backup-new --bundle-id com.example.app --creation-receipt create.json --receipt verify.json

# 3. Check the IPA.
ios-rehydrate ipa verify .\App.ipa --bundle-id com.example.app

# 4. Rehydrate. Asks you to type "rehydrate".
ios-rehydrate app rehydrate --device <device-ref> --bundle-id com.example.app --ipa .\App.ipa --backup-receipt verify.json --receipt result.json
```

`--device` takes either the reference from `device list` or the full UDID. Add `--json` to any
command for compact output.

### Receipts

Each step can write a JSON receipt, and the next step requires it. `backup verify --bundle-id`
needs the `create` receipt, and `app rehydrate` needs the `verify` receipt. A receipt must be
from the same tool version, under 24 hours old, and for the same device and app. Receipt paths
must be new files. They are reserved before any work starts and never overwritten. Receipts
aren't signed. They stop you from making a mistake, but they don't protect against a
compromised machine.

If the operation succeeds but the receipt can't be written, the output says
`receipt_written: false` and the reserved file is left in place.

### Errors and unknown outcomes

Failures print one line, `error[REASON]: message`, to stderr and exit with a stable code:

| Code | Meaning |
| ---- | ------- |
| 2 | bad arguments |
| 10 / 11 | device not found or ambiguous / device unavailable |
| 20 / 21 | backup creation / backup verification failed |
| 30 | IPA rejected |
| 40 / 42 | refused by policy / not confirmed or interrupted |
| 51 | `Upgrade` could not be sent |
| 52 | **outcome unknown**: the request may have reached the device |
| 53 | `Upgrade` returned but the app didn't end up in the expected state |
| 70 / 74 | dependency or internal error / filesystem error |

On exit code 52, check the phone before doing anything else. Do not rerun the command just to
clean up. If you asked for a receipt, it is written with `status: unknown`. Results also report
`cleanup.staging_removed` and `connection_closed`. If `staging_removed` is `false`, a copy of
the IPA may still be in the device's staging directory.

## Limits

Inputs larger than these are rejected, and there is no override:

- **IPA:** 2 GiB file, 50,000 entries, 64 MiB central directory, 8 GiB expanded, 200:1
  compression ratio. Only stored and deflate members are allowed. Self-extracting or
  prefixed ZIPs are refused.
- **Backup:** 512 MiB `Manifest.db`, 1,000,000 entries or 4 TiB declared size in the app
  domain, 8 MiB per manifest entry, 2,000,000 directory entries or 1,000,000 payload files
  scanned. Keybag PBKDF iterations are capped at 1,000,000 (`ITER`) and 20,000,000 (`DPIC`).
- **MobileBackup2 protocol:** 16 MiB control messages, 50,000 entries per directory listing.

Before the bounded backup loop starts, `pymobiledevice3` loads app metadata, icons, and some
files from the device into memory without a cap. A malicious device could use that to exhaust
memory.

## Privacy

- Output and receipts use hashed references (`device_…`, `app_…`) instead of UDIDs, bundle
  IDs, or paths. Hashes and sizes can still be correlated, so treat backups and receipts as
  sensitive.
- The backup password is read only from a hidden prompt. If the terminal can't hide input,
  the command refuses rather than echoing it. The password is never written anywhere.
- Device connections use only the local usbmux socket. Remote endpoints set in the environment
  are ignored, and automatic pairing is off. Existing pairing records are read normally.
- Nothing is sent anywhere except the IPA bytes staged to the selected device.
- Device selectors, bundle IDs, and paths are command-line arguments, so they end up in shell
  history.

## Development

```powershell
uv sync --locked --dev
uv run ruff check . ; uv run ruff format --check . ; uv run mypy ; uv run pytest
```

Tests use synthetic data and mocked device adapters only. See [CONTRIBUTING.md](CONTRIBUTING.md)
and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## License

GPL-3.0-or-later. `pymobiledevice3` and `pyiosbackup` are GPL-licensed, and
`safe_mobilebackup.py` is adapted from `pymobiledevice3`. See [NOTICE.md](NOTICE.md).
Report vulnerabilities as described in [SECURITY.md](SECURITY.md).
