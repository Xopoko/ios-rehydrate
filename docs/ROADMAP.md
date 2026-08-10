# Evidence-Gated Roadmap

The roadmap uses evidence gates rather than dates. A stage is complete only when its evidence
is public, redacted, reproducible, and linked from this document; no stage is complete merely
because an implementation exists.

## Gate 1: Public v0.1 mechanics

- Clean installation with the declared Python versions.
- Synthetic tests cover every public command and stable failure class.
- Lint, type checking, and public-surface scanning pass.
- Documentation, packaging metadata, dependency pins, and GPL notices agree.
- A clean checkout passes one synthetic suite run and the two-run comparison inside
  [EXPERIMENT.md](EXPERIMENT.md).

**Current status:** public clean-checkout CI evidence is pending.

## Gate 2: Negative paths and mutation-boundary faults

- Fault injection before and after the `Upgrade` request.
- Explicit tests for disconnect, timeout, changed device/app state, wrong identity, malformed
  archives, filesystem escape/overwrite, redaction failure, and partial backup output.
- Assertions prove that `Install`, `Uninstall`, automatic retry, and force paths are absent.

## Gate 3: Rights-cleared compatibility evidence

- A predeclared compatibility matrix using multiple independently rights-cleared inputs.
- Repeated Windows/device runs with the denominator and failures retained.
- Separate results for structural validation, platform acceptance, launch, and app-data
  compatibility; none is used as a proxy for another.

No success-rate or preservation claim is allowed before this gate has public evidence.

## Gate 4: Independent review

- Independent reproduction of the public synthetic experiment.
- Focused review of archive parsing, redaction, backup handling, filesystem containment,
  dependency provenance, and the mutation boundary.
- Published remediation status without exposing private artifacts.

Only after this gate may the project consider a beta designation.

## Future ArtifactProvider decision

Version 0.1 has a local-file-only artifact boundary. A future `ArtifactProvider` is not an
acquisition promise and is not automatically accepted into scope. Before any additional provider
is designed or enabled, it requires an independent security, privacy, licensing, and platform-
policy review. It must remain isolated from device mutation and cannot bypass validation or
policy gates.

## v0.1 anti-scope

The following do not enter v0.1: Apple authentication, purchasing, lookup/download or other
acquisition; DRM bypass, decryption, dumping, or re-signing; jailbreak support; installing an
absent app; uninstalling or deleting app/user data; backup restore; password recovery, rotation,
or encryption disable; batch/device-fleet automation; telemetry; and automatic retry after an
ambiguous mutation outcome.

Any proposal that changes this boundary must be treated as a new security design, not a routine
feature request.
