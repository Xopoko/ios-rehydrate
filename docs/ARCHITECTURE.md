# Architecture

## Modules

| Module | Role |
| ------ | ---- |
| `cli.py` | Typer commands, receipt gates, the `rehydrate` confirmation, error → exit-code mapping |
| `device.py` | USB-only device discovery and lockdown sessions (local usbmux, no autopair, throwaway pairing cache) |
| `apps.py` | InstallationProxy lookup of one bundle ID → `AppSnapshot`; `is_rehydratable()` |
| `backup.py` | Read/enable backup encryption, run a full backup into a new directory, structurally validate it |
| `safe_mobilebackup.py` | `DeviceLink` subclass that confines every device-requested file operation to the backup root |
| `manifest.py` | Validate the keybag, decrypt `Manifest.db` in memory, count the app's domain entries |
| `ipa.py` | Parse and validate the IPA (raw ZIP preflight, then `zipfile`), extract metadata and SINF |
| `upgrade.py` | Stage the IPA over AFC, re-check eligibility, send `Upgrade`, post-check, clean up staging |
| `receipts.py` | Exclusive-create JSON receipts and the reader that enforces version, kind, and age |
| `privacy.py` | Hashed references (`device_…`, `app_…`) and scrubbing of paths/UDIDs/emails from error text |
| `fs.py` | Shared no-follow helpers: link/reparse detection, safe directory chains, reserved Windows names |

## Rehydrate flow

1. The IPA is validated with the same checks as `ipa verify`. The validated bytes are kept in
   memory, and those exact bytes are what get staged.
2. The device is opened and the `backup-verification` receipt is checked against the device
   and app. That receipt in turn embeds the SHA-256 of the `backup-create` receipt it was checked
   against.
3. The app must be `User` + placeholder/demoted. The operator types `rehydrate`.
4. The IPA is written to `/PublicStaging/ios-rehydrate/<random>.ipa`.
5. The app is inspected again (staging can take a while); it must still be eligible. The backup
   receipt is re-read and must be byte-identical.
6. `Upgrade` is sent. From here on any error, timeout, or interrupt is reported as
   *outcome unknown* (exit 52) and never retried.
7. One shielded, time-limited attempt removes the staged file.
8. Up to three post-checks confirm the app is installed with the IPA's version and build.

## Invariants

- The source IPA is never modified.
- Backups and receipts only go to new paths; nothing is overwritten. A partial backup is kept.
- Backup encryption is never disabled and its password never changed.
- The only mutation is `Upgrade` for an eligible existing app. No `Install`, `Uninstall`,
  force flag, or retry.
- Anything uncertain before `Upgrade` is a refusal; anything uncertain after it is "unknown".
- Normal output and receipts contain no raw UDIDs, bundle IDs, or paths.
- A failure while closing a connection or writing a receipt is reported separately and never
  hides an already-known result.

## Untrusted inputs and how they are handled

| Input | Handling | What remains |
| ----- | -------- | ------------ |
| IPA | Size/entry/ratio caps; EOCD, ZIP64, and every central/local header are cross-checked before `zipfile` sees the data so both parsers agree; traversal, duplicate, case-collision, and link entries rejected | Parser bugs; Apple can still reject a structurally valid package |
| Device file requests during backup | Strict relative paths, no aliases or DOS device names, root identity re-checked and no-follow `lstat` of every component before each operation | Same-user or privileged processes racing the checks |
| DeviceLink protocol | Length-prefixed messages capped before parsing; only known commands accepted | `pymobiledevice3` builds the initial `Info.plist` without a size cap |
| Backup on disk | Plist and `Manifest.db` size caps; keybag TLV shape and PBKDF iteration counts validated *before* asking for the password; SQLite opened read-only from memory | Up to 512 MiB held in memory, possibly more than once |
| Receipts | Exact schema/version, timezone-aware timestamp under 24 h old, device/app/digest chain checked | Not signed; anyone with write access to the files can forge them |
| Device app state | Checked before confirmation, again before staging, and again right before `Upgrade` | Can still change after the final check |

`pyiosbackup` logs derived key material at DEBUG level. Its logger is disabled, under a lock,
around keybag construction.

## Dependencies

`pymobiledevice3` and `pyiosbackup` are pinned exactly because `safe_mobilebackup.py` overrides
`DeviceLink` internals and `manifest.py` relies on `pyiosbackup`'s behavior. When bumping
`pymobiledevice3`, diff `services/device_link.py` and `services/mobilebackup2.py` against the
previous version, and update the handler-parity tests in `tests/test_safe_mobilebackup.py`.
