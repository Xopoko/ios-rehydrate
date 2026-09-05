# Provenance

iOS Rehydrate's project-specific CLI, policies, parsers, documentation, and synthetic tests
were authored for this repository. No IPA, device backup, pairing record, log, screenshot,
account data, or device/app identifier is part of the source tree or test suite.

One source module is deliberately adapted rather than clean-room authored:

- [`src/ios_rehydrate/safe_mobilebackup.py`](../src/ios_rehydrate/safe_mobilebackup.py) is a
  modified derivative of the pinned `pymobiledevice3` implementations in
  [`services/device_link.py`](https://github.com/doronz88/pymobiledevice3/blob/6965e0d3fc24ea058f6da3bfb3fdc05eacb7ba6c/pymobiledevice3/services/device_link.py)
  and
  [`services/mobilebackup2.py`](https://github.com/doronz88/pymobiledevice3/blob/6965e0d3fc24ea058f6da3bfb3fdc05eacb7ba6c/pymobiledevice3/services/mobilebackup2.py).
  The adaptation retains the upstream wire framing and MobileBackup2 orchestration while
  replacing the local filesystem handlers and control-message boundary. Changes made on
  2026-08-09 add fail-closed path confinement, bounded parsing/transfers/enumeration, generic
  redacted errors, explicit cleanup evidence, and pinned handler-parity tests. Upstream and
  modified portions are GPL-3.0-or-later; attribution is retained in the file header and
  [`NOTICE.md`](../NOTICE.md).

Other interoperability work is based on public interfaces and independently written behavioral
requirements, with these exact references:

- [`pymobiledevice3` 10.7.1](https://github.com/doronz88/pymobiledevice3/tree/6965e0d3fc24ea058f6da3bfb3fdc05eacb7ba6c)
  for USB lockdown, MobileBackup2, AFC, and InstallationProxy access.
- [`pyiosbackup` 0.2.4](https://github.com/matan1008/pyiosbackup/tree/83b3606a295b0722771e4558bbbaa4e489e58b77)
  for encrypted-backup keybag and manifest structures.
- [`ideviceinstaller` 1.2.0](https://github.com/libimobiledevice/ideviceinstaller/tree/1762d5f12fc590b48877aac644ba3bccb72f33f9)
  as a public interoperability reference for App Store package metadata sent
  to InstallationProxy.

The project depends on the first two packages. Apart from the explicitly disclosed adapted
boundary above, it does not copy their source into this tree. Their GPL licenses are compatible
with this repository's GPL-3.0-or-later license. See [`NOTICE.md`](../NOTICE.md) and the
hash-locked `uv.lock` for dependency details.

## Reviewed dependency update

The current `pymobiledevice3` pin is
[`11.1.6`](https://github.com/doronz88/pymobiledevice3/tree/a6bd794e0d8a202e74e5b533ec914cdb67b07889).
The 2026-09-05 compatibility review compared its DeviceLink, MobileBackup2, InstallationProxy,
lockdown, AFC, usbmux, and service-connection implementations against 10.7.1. MobileBackup2,
InstallationProxy, and lockdown were unchanged. The existing synthetic protocol tests exercise
the AFC and connection callers; no live-device compatibility is claimed.

DeviceLink added raw backup-root logging to the free-space reply and changed purge requests
from a terminal exception to a logged response that continues serving. The local boundary now
owns both handlers. It preserves the prior capacity calculation and terminal purge exception,
without logging the root or device-controlled purge details. Regression tests check the wire
reply, macOS capacity fallback, untouched sentinel data, exception, log redaction, and that all
filesystem handlers resolve to the local implementation. The original adaptation provenance
above remains applicable.

## Evidence boundary

Public tests generate synthetic structures from scratch. They validate parser, policy,
redaction, and mocked protocol mechanics only. This repository publishes no private run or
real-device evidence. Compatibility must be reported separately without publishing private
artifacts.
