# Contributing

Thank you for helping keep iOS Rehydrate narrow, inspectable, and fail-closed.

## Set up the project

For the reproducible, lock-backed development path, use `uv`:

```powershell
uv sync --locked --dev
uv run pytest
uv run ruff check .
uv run mypy
```

For convenience only, use `pip`. This does not reproduce the exact locked release toolchain:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\python.exe -m pip install "pytest>=8.3,<10" "pytest-cov>=6,<8" "pytest-mock>=3.14,<4" "ruff>=0.11,<1" "mypy>=1.15,<2"
.\.venv\Scripts\python.exe -m pytest
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m mypy
```

## Contribution rules

- Keep v0.1 inside the documented anti-scope. Do not add Apple authentication, acquisition or
  download, DRM bypass/decryption, dumping, re-signing, jailbreak support, generic
  install/uninstall/delete, backup restore, or telemetry.
- Preserve the mutation invariant: only InstallationProxy `Upgrade`, only for a live `User`
  placeholder or demoted target, after explicit confirmation.
- Make target selection explicit and fail closed on missing, ambiguous, or changed state.
- Add negative-path tests for archive handling, identity mismatch, unsafe filesystem targets,
  redaction, confirmation, and protocol failures around the mutation boundary.
- Keep normal output and fixtures free of identifiers, full paths, account data, unrelated app
  inventory, and raw lower-level exceptions.
- Prefer small, typed components with injectable device adapters so the default suite stays
  synthetic and deterministic.

## Test data and public artifacts

Use generated synthetic fixtures or material with clear redistribution rights. Do not commit
commercial IPAs, device backups/dumps, provisioning profiles, certificates, signing identities,
pairing records, credentials, passwords, private logs, device identifiers, account identifiers,
or identifying screenshots.

Hardware observations may inform a change, but a public test must reproduce the software
mechanic without requiring the private artifact. Describe hardware evidence only in aggregate
and preserve the `n` and limitations.

## Pull requests

A pull request should:

1. explain the safety invariant or bug it addresses;
2. include synthetic tests for success and failure paths;
3. update public documentation when behavior changes;
4. pass `pytest`, `ruff`, and `mypy`; and
5. confirm that no private artifact or identifier is included.

Do not weaken a guard merely to make a real-device case pass. Record unsupported cases as
failures and propose a separately reviewable policy change.

## Security and licensing

Report vulnerabilities through [SECURITY.md](SECURITY.md), not a public issue. By submitting a
contribution, you agree that it is licensed under the project's GPL-3.0-or-later terms and that
you have the right to contribute it. Third-party code and fixtures must retain provenance and
compatible licensing; do not copy from an unknown or incompatible source.

For a local prepublication check against known private values, keep the newline-delimited
denylist outside the repository and run, for example:

```powershell
uv run python scripts/check_public_surface.py . --denylist ..\private-values.txt
```
