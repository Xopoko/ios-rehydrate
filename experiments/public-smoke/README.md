# Public smoke fixture

Run from the repository root:

```powershell
uv run python scripts/run_public_experiment.py
```

The script creates a deterministic synthetic IPA inside a temporary directory, validates the
same immutable bytes twice, checks the input digest after validation, compares the normalized
result with `expected-result.json`, and removes the temporary directory.

No real executable, signature, authorization record, IPA, device, account, or backup material
is used or committed. A pass validates only the implemented parser and redaction mechanics; it
does not show that a physical device would accept the synthetic archive.
