# Notices

## Project license

iOS Rehydrate is distributed under the GNU General Public License, version 3 or (at your
option) any later version (`GPL-3.0-or-later`). See `LICENSE` for the complete terms.

## GPL runtime dependencies

The v0.1 runtime pins these GPL-3.0-or-later projects:

- [`pymobiledevice3` 10.7.1](https://github.com/doronz88/pymobiledevice3/tree/6965e0d3fc24ea058f6da3bfb3fdc05eacb7ba6c),
  wheel SHA-256 `07120388a88010f3185afc79abc8c4b43a492b119684e576866886eac4f01d52`.
- [`pyiosbackup` 0.2.4](https://github.com/matan1008/pyiosbackup/tree/83b3606a295b0722771e4558bbbaa4e489e58b77),
  wheel SHA-256 `c71ae67d012c13e01a5139687eb5bfaaa4e7722e6519c3f0a246a87e015f1b9e`.

Their copyright notices and license texts remain those of their respective authors and
distributions. This notice is a concise dependency disclosure, not a replacement for the
complete license metadata shipped with a release or its dependency environment.

## Adapted pymobiledevice3 code

`src/ios_rehydrate/safe_mobilebackup.py` is a modified derivative of the `DeviceLink` and
`Mobilebackup2Service` implementations in `pymobiledevice3` 10.7.1 at commit
[`upstream pin`](https://github.com/doronz88/pymobiledevice3/tree/6965e0d3fc24ea058f6da3bfb3fdc05eacb7ba6c).
The upstream package metadata identifies `doronz88`, `matan`, and pymobiledevice3 contributors
as its authors/contributors and licenses the code under GPL-3.0-or-later. The 2026-08-09
iOS Rehydrate adaptation adds local path confinement, parser/resource bounds, redacted failure
handling, explicit cleanup evidence, and pinned protocol/handler tests. The modified source is
distributed under this repository's GPL-3.0-or-later license; see the file header and
[`docs/PROVENANCE.md`](docs/PROVENANCE.md) for exact source-file links and changes.

Other dependencies retain their own licenses. Release builders should preserve the complete
dependency metadata and notices produced for the released environment.

## No bundled third-party artifacts

The project does not distribute an IPA, device backup, device/account data, Apple credential,
pairing material, or private experiment artifact. Operators must supply their own IPA and must
be legally entitled and authorized to use it.

## Trademarks

Apple, App Store, iOS, and related marks belong to their respective owners. This independent
project is not affiliated with, endorsed by, or supported by Apple. Product names are used only
to describe interoperability.
