# Notices

iOS Rehydrate is licensed under the GNU General Public License v3.0 or later. See `LICENSE`.

## GPL dependencies

- [`pymobiledevice3`](https://github.com/doronz88/pymobiledevice3) (GPL-3.0-or-later), pinned
  to 11.1.6
- [`pyiosbackup`](https://github.com/matan1008/pyiosbackup) (GPL-3.0-or-later), pinned to 0.2.4

Exact versions and hashes are in `uv.lock`.

## Adapted code

`src/ios_rehydrate/safe_mobilebackup.py` is a modified derivative of `services/device_link.py`
and `services/mobilebackup2.py` from `pymobiledevice3`, by doronz88, matan, and the
pymobiledevice3 contributors. It was first adapted from 10.7.1, at
[`6965e0d`](https://github.com/doronz88/pymobiledevice3/tree/6965e0d3fc24ea058f6da3bfb3fdc05eacb7ba6c).
It was then re-reviewed against 11.1.6, at
[`a6bd794`](https://github.com/doronz88/pymobiledevice3/tree/a6bd794e0d8a202e74e5b533ec914cdb67b07889).
In 11.1.6, upstream started logging the backup root in the free-space reply and continuing after
purge requests. The local subclass keeps the earlier behavior and doesn't log either.

The wire protocol and MobileBackup2 orchestration come from upstream. The local filesystem
handlers, the control-message parser, and the error handling were rewritten to confine and
bound device-controlled requests. The modified file is distributed under GPL-3.0-or-later.

[`ideviceinstaller`](https://github.com/libimobiledevice/ideviceinstaller) was used as a
reference for the App Store metadata that InstallationProxy expects. No code was copied from it.

## Trademarks

Apple, App Store, and iOS are trademarks of Apple Inc. This project is not affiliated with or
endorsed by Apple.
