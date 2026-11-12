# Contributing

```powershell
uv sync --locked --dev
uv run ruff check . ; uv run ruff format --check . ; uv run mypy ; uv run pytest
```

## Ground rules

- **Keep the scope.** No Apple sign-in or downloading, no decryption or re-signing, no generic
  install/uninstall, no backup restore, no telemetry. The only mutation is `Upgrade` on an
  eligible placeholder, after confirmation. Don't add a fallback or a force flag.
- **Fail closed.** If a device, app, or file state is missing, ambiguous, or changed, refuse.
  Don't loosen a check to make one real device work. Open an issue that describes the case
  instead.
- **Test both paths.** Add tests for the success path and the failure path. Device code is
  tested through injected or mocked adapters.
- **Use only synthetic test data.** Never commit real IPAs, backups, provisioning profiles,
  certificates, pairing records, logs, or device/account identifiers.
- **Keep output clean.** Output and receipts must not contain raw identifiers, paths, or
  exception text. Use `privacy.opaque_ref` and stable `error[REASON]` codes.

Contributions are accepted under GPL-3.0-or-later. Third-party code needs compatible licensing
and a note in `NOTICE.md`.
