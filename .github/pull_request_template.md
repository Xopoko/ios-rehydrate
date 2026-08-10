## Summary

Describe the change and its user-visible effect.

## Synthetic reproduction and provenance

List the synthetic reproduction or test inputs used, how they were generated, and why they contain no real app, device, backup, account, or user data.

## Validation

- [ ] `uv sync --locked --dev`
- [ ] `uv run ruff check .`
- [ ] `uv run ruff format --check .`
- [ ] `uv run mypy`
- [ ] `uv run pytest`
- [ ] `uv run python scripts/check_public_surface.py .`
- [ ] `uv run python scripts/check_public_surface.py --git-index .`
- [ ] `git status --porcelain=v1 --untracked-files=all` prints nothing
- [ ] `uv build --no-build-isolation`
- [ ] `uv run python scripts/check_distributions.py . --smoke-install --rebuild-compare`

## Privacy and repository safety

**Never attach, paste, commit, or link IPA files, device backups, logs, device identifiers, account names or details, credentials, secrets, authentication material, or screenshots.**

- [ ] The change and discussion contain only synthetic, self-created reproduction data with provenance documented above.
- [ ] No private, proprietary, device-derived, account-derived, or identifying material is included.
- [ ] No generated build distributions or other raw artifacts are committed.
