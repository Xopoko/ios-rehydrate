# Public Synthetic Experiment

## Question and falsifiable hypothesis

Can a clean checkout exercise iOS Rehydrate's public mechanics without a physical device,
private IPA, backup, account, identifier, path, or network service?

**Hypothesis:** on a supported Python version, the default synthetic suite passes from the same
commit, while the public smoke runner executes its deterministic fixture twice, does not mutate
that generated input, and produces the preregistered normalized result. The suite invokes
neither Apple authentication/acquisition nor Install/Uninstall paths, writes only inside
test-owned temporary roots, and emits no seeded identifiers, credentials, or absolute user
paths.

The hypothesis fails if any required command fails, a prohibited call occurs, an input digest
changes, output escapes its temporary root, seeded sensitive text appears, or the two normalized
results disagree. Record the failure; do not change the threshold after seeing it.

## Reproduction

Record the commit first:

```powershell
git rev-parse HEAD
```

For reproducible release evidence, use the locked `uv` path:

```powershell
uv sync --locked --dev
uv run pytest
uv run python scripts/run_public_experiment.py
uv run ruff check .
uv run mypy
uv run python scripts/check_public_surface.py .
if (git status --porcelain=v1 --untracked-files=all) { throw "release snapshot is not clean" }
uv build --no-build-isolation
uv run python scripts/check_distributions.py . --smoke-install --rebuild-compare
if (git status --porcelain=v1 --untracked-files=all) { throw "release snapshot changed" }
```

`--rebuild-compare` performs a second build in a fresh external temporary directory and
requires byte-for-byte equality with both candidate artifacts. This proves repeatability inside
one pinned job; the project does not yet claim identical hashes across different operating
systems.

For a convenience-only local check, use `pip`. This path is not reproducible release evidence:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\python.exe -m pip install "pytest>=8.3,<10" "pytest-cov>=6,<8" "pytest-mock>=3.14,<4" "ruff>=0.11,<1" "mypy>=1.15,<2"
.\.venv\Scripts\python.exe -m pytest
.\.venv\Scripts\python.exe scripts\run_public_experiment.py
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m mypy
.\.venv\Scripts\python.exe scripts\check_public_surface.py .
```

Record the Windows version, Python version, package-lock state, commit SHA, and pass/fail result.
Do not publish a username, machine name, absolute path, device information, or raw environment
dump. Dependency installation and source hosting may use the network; the experiment does not
claim an offline bootstrap.

## Acceptance criteria

- The synthetic suite passes without an attached-device requirement.
- The public smoke runner's two internal executions produce the same normalized result.
- The deterministic public-smoke result exactly matches its preregistered JSON result.
- Archive, identity, redaction, filesystem, backup, confirmation, and device-protocol failure
  paths are represented by generated fixtures or mocks.
- Safety tests assert that only the `Upgrade` adapter call is reachable and only for a `User`
  placeholder/demoted target.
- Generated input digests are unchanged after the run.
- Persistent test output remains inside test-owned temporary roots and contains no seeded
  secret, identifier, or absolute user path.
- `ruff` and strict `mypy` pass for the tested commit.

Stop at the first invariant violation. Keep the failing result and diagnosis; do not reinterpret
a partial pass as success.

## What this experiment does not establish

Synthetic tests validate mechanics and policy wiring. They do not establish compatibility with
arbitrary apps, IPA variants, devices, Windows configurations, Apple policy, or future iOS
versions. They do not prove restorability, successful launch, behavioral fidelity, security,
reliability, legal authorization, or preservation of existing app data.
