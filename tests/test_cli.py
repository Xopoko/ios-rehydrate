# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 iOS Rehydrate contributors

from __future__ import annotations

import importlib.metadata
import json
import platform
import sys
import warnings
from contextlib import asynccontextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from typer.testing import CliRunner

from ios_rehydrate import cli, receipts
from ios_rehydrate.apps import AppSnapshot, AppState
from ios_rehydrate.backup import BackupReport, EncryptionEnableReport
from ios_rehydrate.device import DeviceCloseStatus
from ios_rehydrate.errors import ExitCode, OutcomeUnknownError, RehydrateError
from ios_rehydrate.privacy import device_reference, opaque_ref
from ios_rehydrate.receipts import envelope, write_new_receipt

runner = CliRunner()
_BUNDLE_ID = "test.invalid.cli"
_DEVICE_ID = "00000000" + "-" + "2" * 16


async def _async_value(value: Any) -> Any:
    return value


def _assert_compact_json(result: Any, expected: dict[str, Any]) -> None:
    assert result.exit_code == 0, result.exception
    assert result.stdout == (
        json.dumps(expected, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n"
    )


def _assert_private_values_absent(output: str, *values: str) -> None:
    for value in values:
        assert value not in output
        assert json.dumps(value, ensure_ascii=True)[1:-1] not in output


def test_root_help_and_version() -> None:
    help_result = runner.invoke(cli.app, ["--help"])
    version_result = runner.invoke(cli.app, ["--version"])

    assert help_result.exit_code == 0
    assert "rehydrat" in help_result.stdout.casefold()
    assert "install-completion" not in help_result.stdout
    assert version_result.exit_code == 0
    assert version_result.stdout.strip() == "0.1.0"


def test_doctor_success_emits_compact_redacted_json(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package_versions = {
        "pymobiledevice3": "10.7.1-test",
        "pyiosbackup": "0.2.4-test",
        "typer": "0.27.1-test",
    }

    async def fake_list_devices() -> list[dict[str, str]]:
        return [{"device_ref": _DEVICE_ID, "connection_type": "USB"}]

    monkeypatch.setattr(importlib.metadata, "version", package_versions.__getitem__)
    monkeypatch.setattr(platform, "system", lambda: "Windows")
    monkeypatch.setattr(platform, "python_version", lambda: "3.13.7-test")
    monkeypatch.setattr(cli, "list_devices", fake_list_devices)

    result = runner.invoke(cli.app, ["doctor", "--json"])

    _assert_compact_json(
        result,
        {
            "ok": True,
            "host": {
                "system": "Windows",
                "python": "3.13.7-test",
                "windows_first_supported": True,
            },
            "dependencies": package_versions,
            "usbmux_available": True,
            "usb_device_count": 1,
        },
    )
    _assert_private_values_absent(result.stdout, _DEVICE_ID)


def test_licenses_success_emits_compact_json_schema() -> None:
    result = runner.invoke(cli.app, ["licenses", "--json"])

    _assert_compact_json(
        result,
        {
            "ok": True,
            "project_license": "GPL-3.0-or-later",
            "notice": "This program comes with absolutely no warranty.",
            "gpl_runtime_dependencies": {
                "pymobiledevice3": "GPL-3.0-or-later",
                "pyiosbackup": "GPL-3.0-or-later",
            },
        },
    )


def test_app_inspect_success_emits_compact_redacted_json(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lockdown = SimpleNamespace(udid=_DEVICE_ID)
    calls: list[str] = []

    @asynccontextmanager
    async def fake_open(selector: str, *, close_status: DeviceCloseStatus | None = None) -> Any:
        calls.append(f"open:{selector}")
        try:
            yield lockdown
        finally:
            if close_status is not None:
                close_status.closed = True

    async def fake_inspect(lockdown_arg: object, bundle_id: str) -> AppSnapshot:
        assert lockdown_arg is lockdown
        calls.append(f"inspect:{bundle_id}")
        return AppSnapshot(
            app_ref=opaque_ref(bundle_id, namespace="app"),
            state=AppState.PLACEHOLDER,
            version="1.2.3",
            build="45",
            placeholder=True,
            demoted=False,
            sizes={"static": 0, "dynamic": 2048},
        )

    monkeypatch.setattr(cli, "open_device", fake_open)
    monkeypatch.setattr(cli, "inspect_app", fake_inspect)

    result = runner.invoke(
        cli.app,
        [
            "app",
            "inspect",
            "--device",
            _DEVICE_ID,
            "--bundle-id",
            _BUNDLE_ID,
            "--json",
        ],
    )

    _assert_compact_json(
        result,
        {
            "ok": True,
            "app": {
                "app_ref": opaque_ref(_BUNDLE_ID, namespace="app"),
                "state": "PLACEHOLDER",
                "version": "1.2.3",
                "build": "45",
                "placeholder": True,
                "demoted": False,
                "sizes": {"static": 0, "dynamic": 2048},
                "connection_closed": True,
            },
        },
    )
    assert calls == [f"open:{_DEVICE_ID}", f"inspect:{_BUNDLE_ID}"]
    _assert_private_values_absent(result.stdout, _DEVICE_ID, _BUNDLE_ID)


def test_backup_encryption_status_success_emits_compact_redacted_json(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lockdown = SimpleNamespace(udid=_DEVICE_ID)
    calls: list[str] = []

    @asynccontextmanager
    async def fake_open(selector: str, *, close_status: DeviceCloseStatus | None = None) -> Any:
        calls.append(f"open:{selector}")
        try:
            yield lockdown
        finally:
            if close_status is not None:
                close_status.closed = True

    async def fake_encryption_status(lockdown_arg: object) -> bool:
        assert lockdown_arg is lockdown
        calls.append("encryption-status")
        return True

    monkeypatch.setattr(cli, "open_device", fake_open)
    monkeypatch.setattr(cli, "encryption_status", fake_encryption_status)

    result = runner.invoke(
        cli.app,
        ["backup", "encryption-status", "--device", _DEVICE_ID, "--json"],
    )

    _assert_compact_json(
        result,
        {
            "ok": True,
            "backup_encryption": {
                "device_ref": device_reference(_DEVICE_ID),
                "enabled": True,
                "connection_closed": True,
            },
        },
    )
    assert calls == [f"open:{_DEVICE_ID}", "encryption-status"]
    _assert_private_values_absent(result.stdout, _DEVICE_ID)


def test_ipa_verify_success_emits_compact_path_free_json(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ipa_path = tmp_path / "synthetic-private" / "sensitive-app.ipa"
    store_id = "123456789"
    payload = SimpleNamespace(
        sha256="a" * 64,
        size=4096,
        bundle_identifier=_BUNDLE_ID,
        version="1.2.3",
        build="45",
        minimum_os="16.0",
        metadata=b"metadata",
        sinf=b"sinf",
        has_code_resources=True,
        store_id=store_id,
    )

    def fake_validate_ipa(
        path: Path,
        *,
        expected_bundle_id: str | None,
        expected_store_id: str | None,
    ) -> SimpleNamespace:
        assert path == ipa_path
        assert expected_bundle_id == _BUNDLE_ID
        assert expected_store_id == store_id
        return payload

    monkeypatch.setattr(cli, "validate_ipa", fake_validate_ipa)
    assert not ipa_path.exists()

    result = runner.invoke(
        cli.app,
        [
            "ipa",
            "verify",
            str(ipa_path),
            "--bundle-id",
            _BUNDLE_ID,
            "--store-id",
            store_id,
            "--json",
        ],
    )

    _assert_compact_json(
        result,
        {
            "ok": True,
            "ipa": {
                "sha256": "a" * 64,
                "size": 4096,
                "version": "1.2.3",
                "build": "45",
                "minimum_os": "16.0",
                "bundle_ref": opaque_ref(_BUNDLE_ID, namespace="bundle"),
                "store_ref": opaque_ref(store_id, namespace="store"),
                "has_metadata": True,
                "has_sinf": True,
                "has_code_resources": True,
            },
            "receipt_written": False,
        },
    )
    _assert_private_values_absent(result.stdout, str(ipa_path), _BUNDLE_ID, store_id)


def test_plain_backup_verify_success_emits_compact_path_free_json(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backup_root = tmp_path / "synthetic-private" / "sensitive-backup"
    report = BackupReport(
        backup_ref="backup_123456789abc",
        device_ref=device_reference(_DEVICE_ID),
        payload_count=7,
        payload_bytes=8192,
        encrypted=True,
        completed=True,
        requested_full=False,
        observed_is_full_backup=False,
    )
    lockdown = SimpleNamespace(udid=_DEVICE_ID)
    calls: list[str] = []

    @asynccontextmanager
    async def fake_open(selector: str, *, close_status: DeviceCloseStatus | None = None) -> Any:
        calls.append(f"open:{selector}")
        try:
            yield lockdown
        finally:
            if close_status is not None:
                close_status.closed = True

    def fake_validate_backup(path: Path, udid: str) -> BackupReport:
        assert path == backup_root
        assert udid == _DEVICE_ID
        calls.append("validate-backup")
        return report

    def forbidden_app_domain(*args: Any, **kwargs: Any) -> object:
        del args, kwargs
        raise AssertionError("plain backup verification must not probe an app domain")

    monkeypatch.setattr(cli, "open_device", fake_open)
    monkeypatch.setattr(cli, "validate_backup", fake_validate_backup)
    monkeypatch.setattr(cli, "probe_app_domain", forbidden_app_domain)
    assert not backup_root.exists()

    result = runner.invoke(
        cli.app,
        ["backup", "verify", "--device", _DEVICE_ID, "--backup", str(backup_root), "--json"],
    )

    _assert_compact_json(
        result,
        {
            "ok": True,
            "backup": {
                "backup_ref": "backup_123456789abc",
                "device_ref": device_reference(_DEVICE_ID),
                "payload_count": 7,
                "payload_bytes": 8192,
                "encrypted": True,
                "completed": True,
                "requested_full": False,
                "observed_is_full_backup": False,
                "mobilebackup_connection_closed": None,
                "connection_closed": True,
            },
            "receipt_written": False,
        },
    )
    assert calls == [f"open:{_DEVICE_ID}", "validate-backup"]
    assert "app_ref" not in result.stdout
    assert "manifest" not in result.stdout
    _assert_private_values_absent(result.stdout, _DEVICE_ID, str(backup_root))


def test_console_parser_error_never_echoes_invalid_argument(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    private_argument = "C:" + "\\Users" + "\\synthetic-private" + "\\sensitive.ipa"
    monkeypatch.setattr(sys, "argv", ["ios-rehydrate", "doctor", private_argument])

    with pytest.raises(SystemExit) as caught:
        cli.main()

    captured = capsys.readouterr()
    assert caught.value.code == 2
    assert "CLI_USAGE" in captured.err
    assert private_argument not in captured.err
    assert private_argument not in captured.out


def test_console_abort_maps_to_interrupted_operation(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def aborted_app(*, standalone_mode: bool) -> None:
        assert standalone_mode is False
        raise cli.typer.Abort()

    monkeypatch.setattr(cli, "app", aborted_app)

    with pytest.raises(SystemExit) as caught:
        cli.main()

    captured = capsys.readouterr()
    assert caught.value.code == ExitCode.CONFIRMATION
    assert "OPERATION_INTERRUPTED" in captured.err


def test_console_cancelled_task_maps_to_interrupted_operation(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def cancelled_app(*, standalone_mode: bool) -> None:
        assert standalone_mode is False
        raise cli.asyncio.CancelledError

    monkeypatch.setattr(cli, "app", cancelled_app)

    with pytest.raises(SystemExit) as caught:
        cli.main()

    captured = capsys.readouterr()
    assert caught.value.code == ExitCode.CONFIRMATION
    assert "OPERATION_INTERRUPTED" in captured.err


def test_device_list_emits_only_redacted_records(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_list() -> list[dict[str, str]]:
        return [{"device_ref": "device_123456789abc", "connection_type": "USB"}]

    monkeypatch.setattr(cli, "list_devices", fake_list)
    result = runner.invoke(cli.app, ["device", "list", "--json"])

    assert result.exit_code == 0
    assert '"count":1' in result.stdout
    assert "device_123456789abc" in result.stdout


def test_json_output_ascii_escapes_terminal_and_bidi_controls(
    capsys: pytest.CaptureFixture[str],
) -> None:
    hostile = "visible\u009b31m\u202ereversed"

    cli._emit({"value": hostile}, compact=True)

    output = capsys.readouterr().out
    assert "\u009b" not in output
    assert "\u202e" not in output
    assert r"\u009b" in output
    assert r"\u202e" in output


@pytest.mark.parametrize("reader", [cli._backup_password, cli._new_backup_password])
def test_password_prompt_refuses_echoed_getpass_fallback(
    reader: object,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    seeded_input = "synthetic-do-not-echo"
    monkeypatch.setattr(cli, "_require_interactive_terminal", lambda: None)

    def unsafe_getpass(prompt: str) -> str:
        del prompt
        warnings.warn("echo control unavailable", cli.getpass.GetPassWarning, stacklevel=2)
        return seeded_input

    monkeypatch.setattr(cli.getpass, "getpass", unsafe_getpass)

    with pytest.raises(RehydrateError) as caught:
        reader()  # type: ignore[operator]

    captured = capsys.readouterr()
    assert caught.value.reason == "BACKUP_PASSWORD_UNAVAILABLE"
    assert seeded_input not in captured.out
    assert seeded_input not in captured.err
    assert seeded_input not in str(caught.value)


@pytest.mark.parametrize(
    "command",
    ["backup-create", "backup-verify", "ipa-verify", "app-rehydrate"],
)
def test_existing_optional_receipt_blocks_all_work(
    command: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    receipt = tmp_path / "existing.json"
    receipt.write_text("operator evidence", encoding="utf-8")
    calls: list[str] = []

    def forbidden_open(selector: str) -> object:
        calls.append(f"open:{selector}")
        raise AssertionError("device must not be opened")

    def forbidden_validate(*args: Any, **kwargs: Any) -> object:
        calls.append("validate")
        raise AssertionError("IPA validation must not run")

    async def forbidden_rehydrate(*args: Any, **kwargs: Any) -> dict[str, object]:
        calls.append("Upgrade")
        raise AssertionError("Upgrade must not run")

    monkeypatch.setattr(cli, "open_device", forbidden_open)
    monkeypatch.setattr(cli, "validate_ipa", forbidden_validate)
    monkeypatch.setattr(cli, "rehydrate_app", forbidden_rehydrate)
    commands = {
        "backup-create": [
            "backup",
            "create",
            "--device",
            "device_synthetic",
            "--output",
            str(tmp_path / "backup"),
        ],
        "backup-verify": [
            "backup",
            "verify",
            "--device",
            "device_synthetic",
            "--backup",
            str(tmp_path / "backup"),
        ],
        "ipa-verify": ["ipa", "verify", str(tmp_path / "synthetic.ipa")],
        "app-rehydrate": [
            "app",
            "rehydrate",
            "--device",
            "device_synthetic",
            "--bundle-id",
            _BUNDLE_ID,
            "--ipa",
            str(tmp_path / "synthetic.ipa"),
            "--backup-receipt",
            str(tmp_path / "backup-receipt.json"),
        ],
    }

    result = runner.invoke(cli.app, [*commands[command], "--receipt", str(receipt)])

    assert result.exit_code != 0
    assert isinstance(result.exception, RehydrateError)
    assert result.exception.reason == "RECEIPT_EXISTS"
    assert calls == []
    assert receipt.read_text(encoding="utf-8") == "operator evidence"


def test_pre_operation_failure_aborts_receipt_reservation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    receipt = tmp_path / "result.json"
    calls: list[str] = []

    def failed_preflight(output: Path) -> Path:
        calls.append(f"preflight:{output.name}")
        raise RehydrateError(
            "synthetic preflight failure",
            code=ExitCode.IO,
            reason="BACKUP_OUTPUT_INVALID",
        )

    def forbidden_open(selector: str) -> object:
        calls.append(f"open:{selector}")
        raise AssertionError("device must not be opened")

    monkeypatch.setattr(cli, "preflight_backup_output", failed_preflight)
    monkeypatch.setattr(cli, "open_device", forbidden_open)

    result = runner.invoke(
        cli.app,
        [
            "backup",
            "create",
            "--device",
            "device_synthetic",
            "--output",
            str(tmp_path / "backup"),
            "--receipt",
            str(receipt),
        ],
    )

    assert result.exit_code != 0
    assert calls == ["preflight:backup"]
    assert not receipt.exists()


def test_backup_create_reports_encryption_scratch_residue_separately(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lockdown = SimpleNamespace(udid=_DEVICE_ID)
    report = BackupReport(
        backup_ref="backup_123456789abc",
        device_ref=opaque_ref(_DEVICE_ID, namespace="device"),
        payload_count=10,
        payload_bytes=100,
        encrypted=True,
        completed=True,
        requested_full=True,
        observed_is_full_backup=False,
        mobilebackup_connection_closed=True,
    )

    @asynccontextmanager
    async def fake_open(selector: str, *, close_status: cli.DeviceCloseStatus | None = None) -> Any:
        del selector
        try:
            yield lockdown
        finally:
            if close_status is not None:
                close_status.closed = True

    async def fake_enable(*args: object, **kwargs: object) -> EncryptionEnableReport:
        del args, kwargs
        return EncryptionEnableReport(
            mobilebackup_connection_closed=True,
            scratch_removed=False,
        )

    async def fake_create(*args: object, **kwargs: object) -> BackupReport:
        del args, kwargs
        return report

    monkeypatch.setattr(cli, "preflight_backup_output", lambda output: output)
    monkeypatch.setattr(cli, "open_device", fake_open)
    monkeypatch.setattr(cli, "encryption_status", lambda lockdown_arg: _async_value(False))
    monkeypatch.setattr(cli, "enable_encryption", fake_enable)
    monkeypatch.setattr(cli, "create_backup", fake_create)
    monkeypatch.setattr(cli, "_require_interactive_terminal", lambda: None)
    monkeypatch.setattr(cli, "_new_backup_password", lambda: ("secret", "secret"))

    result = runner.invoke(
        cli.app,
        [
            "backup",
            "create",
            "--device",
            "device_synthetic",
            "--output",
            str(tmp_path / "backup"),
            "--enable-encryption",
            "--json",
        ],
        input="y\n",
    )

    assert result.exit_code == 0, result.exception
    assert '"encryption_mobilebackup_connection_closed":true' in result.stdout
    assert '"encryption_scratch_removed":false' in result.stdout


def test_unsafe_receipt_parent_blocks_device_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []

    def forbidden_open(selector: str) -> object:
        calls.append(f"open:{selector}")
        raise AssertionError("device must not be opened")

    monkeypatch.setattr(cli, "open_device", forbidden_open)
    receipt = tmp_path / "missing-parent" / "result.json"
    result = runner.invoke(
        cli.app,
        [
            "backup",
            "create",
            "--device",
            "device_synthetic",
            "--output",
            str(tmp_path / "backup"),
            "--receipt",
            str(receipt),
        ],
    )

    assert result.exit_code != 0
    assert isinstance(result.exception, RehydrateError)
    assert result.exception.reason == "RECEIPT_PARENT_INVALID"
    assert calls == []


def _backup_gate_receipt(path: Path) -> None:
    evidence = {
        "backup": {
            "backup_ref": "backup_123456789abc",
            "device_ref": opaque_ref(_DEVICE_ID, namespace="device"),
            "encrypted": True,
            "completed": True,
            "payload_count": 10,
            "payload_bytes": 100,
            "requested_full": True,
            "observed_is_full_backup": False,
        },
        "app_ref": opaque_ref(_BUNDLE_ID, namespace="app"),
        "manifest": {"entry_count": 2, "logical_bytes_total": 20},
        "creation_receipt_sha256": "a" * 64,
    }
    write_new_receipt(path, envelope("backup-verification", evidence))


def _backup_create_receipt(path: Path, report: BackupReport) -> None:
    write_new_receipt(
        path,
        envelope(
            "backup-create",
            {
                "backup": {
                    **report.as_public_dict(),
                    "connection_closed": True,
                }
            },
        ),
    )


def test_backup_gate_rejects_another_app(tmp_path: Path) -> None:
    receipt = tmp_path / "backup-receipt.json"
    _backup_gate_receipt(receipt)

    with pytest.raises(RehydrateError) as caught:
        cli._validate_backup_gate(
            receipt,
            device_ref=opaque_ref(_DEVICE_ID, namespace="device"),
            app_ref=opaque_ref("test.invalid.other", namespace="app"),
        )
    assert caught.value.reason == "BACKUP_RECEIPT_MISMATCH"


def test_backup_gate_rejects_boolean_count_even_though_bool_is_an_int(tmp_path: Path) -> None:
    receipt = tmp_path / "backup-receipt.json"
    _backup_gate_receipt(receipt)
    payload = receipts.read_receipt(receipt, expected_kind="backup-verification")[0]
    receipt.unlink()
    payload["evidence"]["backup"]["payload_count"] = True
    write_new_receipt(receipt, payload)

    with pytest.raises(RehydrateError) as caught:
        cli._validate_backup_gate(
            receipt,
            device_ref=opaque_ref(_DEVICE_ID, namespace="device"),
            app_ref=opaque_ref(_BUNDLE_ID, namespace="app"),
        )

    assert caught.value.reason == "BACKUP_RECEIPT_MISMATCH"


def test_creation_receipt_must_match_current_backup_aggregates(tmp_path: Path) -> None:
    report = BackupReport(
        backup_ref="backup_123456789abc",
        device_ref=opaque_ref(_DEVICE_ID, namespace="device"),
        payload_count=10,
        payload_bytes=100,
        encrypted=True,
        completed=True,
        requested_full=False,
        observed_is_full_backup=False,
    )
    receipt = tmp_path / "creation.json"
    created_report = BackupReport(
        **{**report.as_public_dict(), "requested_full": True}  # type: ignore[arg-type]
    )
    _backup_create_receipt(receipt, created_report)

    digest = cli._validate_backup_creation_receipt(receipt, report=report)

    assert len(digest) == 64
    payload = receipts.read_receipt(receipt, expected_kind="backup-create")[0]
    receipt.unlink()
    payload["evidence"]["backup"]["payload_bytes"] = 101
    write_new_receipt(receipt, payload)
    with pytest.raises(RehydrateError) as caught:
        cli._validate_backup_creation_receipt(receipt, report=report)
    assert caught.value.reason == "BACKUP_CREATION_RECEIPT_MISMATCH"


@pytest.mark.parametrize("receipt_changes_during_probe", [False, True])
def test_backup_verify_with_app_binds_fresh_creation_receipt(
    receipt_changes_during_probe: bool,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    creation_receipt = tmp_path / "creation.json"
    verification_receipt = tmp_path / "verification.json"
    device_ref = opaque_ref(_DEVICE_ID, namespace="device")
    report = BackupReport(
        backup_ref="backup_123456789abc",
        device_ref=device_ref,
        payload_count=10,
        payload_bytes=100,
        encrypted=True,
        completed=True,
        requested_full=False,
        observed_is_full_backup=False,
    )
    created_report = BackupReport(
        backup_ref=report.backup_ref,
        device_ref=report.device_ref,
        payload_count=report.payload_count,
        payload_bytes=report.payload_bytes,
        encrypted=True,
        completed=True,
        requested_full=True,
        observed_is_full_backup=False,
    )
    _backup_create_receipt(creation_receipt, created_report)
    lockdown = SimpleNamespace(udid=_DEVICE_ID)
    backup_root = tmp_path / "backup"
    (backup_root / _DEVICE_ID).mkdir(parents=True)

    @asynccontextmanager
    async def fake_open(selector: str, *, close_status: cli.DeviceCloseStatus | None = None) -> Any:
        del selector
        try:
            yield lockdown
        finally:
            if close_status is not None:
                close_status.closed = True

    class Manifest:
        def as_public_dict(self) -> dict[str, int]:
            return {"entry_count": 2, "logical_bytes_total": 20}

    real_creation_gate = cli._validate_backup_creation_receipt
    creation_gate_calls = 0

    def changing_creation_gate(*args: Any, **kwargs: Any) -> str:
        nonlocal creation_gate_calls
        creation_gate_calls += 1
        digest = real_creation_gate(*args, **kwargs)
        if receipt_changes_during_probe and creation_gate_calls == 2:
            return "d" * 64
        return digest

    monkeypatch.setattr(cli, "open_device", fake_open)
    monkeypatch.setattr(cli, "validate_backup", lambda *args, **kwargs: report)
    monkeypatch.setattr(cli, "probe_app_domain", lambda *args, **kwargs: Manifest())
    monkeypatch.setattr(cli, "_validate_backup_creation_receipt", changing_creation_gate)

    result = runner.invoke(
        cli.app,
        [
            "backup",
            "verify",
            "--device",
            "device_synthetic",
            "--backup",
            str(backup_root),
            "--bundle-id",
            _BUNDLE_ID,
            "--creation-receipt",
            str(creation_receipt),
            "--receipt",
            str(verification_receipt),
            "--json",
        ],
    )

    if receipt_changes_during_probe:
        assert result.exit_code != 0
        assert isinstance(result.exception, RehydrateError)
        assert result.exception.reason == "BACKUP_CREATION_RECEIPT_CHANGED"
        assert creation_gate_calls == 2
        assert not verification_receipt.exists()
        return

    assert result.exit_code == 0, result.exception
    assert '"requested_full":true' in result.stdout
    receipt_payload = json.loads(verification_receipt.read_text(encoding="utf-8"))
    evidence = receipt_payload["evidence"]
    assert receipt_payload["kind"] == "backup-verification"
    assert len(evidence["creation_receipt_sha256"]) == 64
    cli._validate_backup_gate(
        verification_receipt,
        device_ref=device_ref,
        app_ref=opaque_ref(_BUNDLE_ID, namespace="app"),
    )


def test_backup_verify_requires_creation_receipt_before_device_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    opened = False

    def forbidden_open(*args: object, **kwargs: object) -> object:
        nonlocal opened
        opened = True
        raise AssertionError("device must not be opened")

    monkeypatch.setattr(cli, "open_device", forbidden_open)
    result = runner.invoke(
        cli.app,
        [
            "backup",
            "verify",
            "--device",
            "device_synthetic",
            "--backup",
            str(tmp_path / "backup"),
            "--bundle-id",
            _BUNDLE_ID,
        ],
    )

    assert result.exit_code != 0
    assert isinstance(result.exception, RehydrateError)
    assert result.exception.reason == "BACKUP_CREATION_RECEIPT_REQUIRED"
    assert opened is False


def test_backup_verify_rejects_unused_creation_receipt_before_device_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    opened = False

    def forbidden_open(*args: object, **kwargs: object) -> object:
        nonlocal opened
        opened = True
        raise AssertionError("device must not be opened")

    monkeypatch.setattr(cli, "open_device", forbidden_open)
    result = runner.invoke(
        cli.app,
        [
            "backup",
            "verify",
            "--device",
            "device_synthetic",
            "--backup",
            str(tmp_path / "backup"),
            "--creation-receipt",
            str(tmp_path / "creation-receipt.json"),
        ],
    )

    assert result.exit_code != 0
    assert isinstance(result.exception, RehydrateError)
    assert result.exception.reason == "BACKUP_CREATION_RECEIPT_UNUSED"
    assert opened is False


@pytest.mark.parametrize("receipt_finalization_fails", [False, True])
def test_rehydrate_requires_matching_backup_and_exact_confirmation(
    receipt_finalization_fails: bool,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backup_receipt = tmp_path / "backup-receipt.json"
    result_receipt = tmp_path / "result-receipt.json"
    _backup_gate_receipt(backup_receipt)
    payload = SimpleNamespace(
        archive_bytes=b"synthetic archive",
        sha256="a" * 64,
        size=17,
        bundle_identifier=_BUNDLE_ID,
        version="1.0",
        build="1",
        minimum_os="16.0",
        metadata=b"metadata",
        sinf=b"sinf",
        has_code_resources=True,
        store_id=None,
    )
    lockdown = SimpleNamespace(udid=_DEVICE_ID)
    calls: list[str] = []

    @asynccontextmanager
    async def fake_open(selector: str, *, close_status: cli.DeviceCloseStatus | None = None) -> Any:
        calls.append(f"open:{selector}")
        try:
            yield lockdown
        finally:
            if close_status is not None:
                close_status.closed = False

    async def fake_inspect(lockdown_arg: object, bundle_id: str) -> AppSnapshot:
        assert lockdown_arg is lockdown
        assert bundle_id == _BUNDLE_ID
        return AppSnapshot(
            app_ref=opaque_ref(bundle_id, namespace="app"),
            state=AppState.PLACEHOLDER,
            version="1.0",
            build="1",
            placeholder=True,
            demoted=False,
            sizes={"static": 0, "dynamic": 20},
        )

    async def fake_rehydrate(
        lockdown_arg: object,
        payload_arg: object,
        *,
        on_mutation_boundary: object = None,
    ) -> dict[str, object]:
        assert lockdown_arg is lockdown
        assert payload_arg is payload
        assert callable(on_mutation_boundary)
        on_mutation_boundary()
        calls.append("Upgrade")
        return {"operation": "Upgrade", "before": {}, "after": {}}

    monkeypatch.setattr(cli, "open_device", fake_open)
    monkeypatch.setattr(cli, "inspect_app", fake_inspect)
    monkeypatch.setattr(cli, "rehydrate_app", fake_rehydrate)
    monkeypatch.setattr(cli, "validate_ipa", lambda *args, **kwargs: payload)
    monkeypatch.setattr(cli, "_require_interactive_terminal", lambda: None)
    if receipt_finalization_fails:

        def failed_fsync(descriptor: int) -> None:
            del descriptor
            raise OSError("synthetic receipt finalization failure")

        monkeypatch.setattr(receipts.os, "fsync", failed_fsync)

    result = runner.invoke(
        cli.app,
        [
            "app",
            "rehydrate",
            "--device",
            "device_synthetic",
            "--bundle-id",
            _BUNDLE_ID,
            "--ipa",
            str(tmp_path / "synthetic.ipa"),
            "--backup-receipt",
            str(backup_receipt),
            "--receipt",
            str(result_receipt),
            "--json",
        ],
        input="rehydrate\n",
    )

    assert result.exit_code == 0, result.exception
    assert calls == ["open:device_synthetic", "Upgrade"]
    assert result.stdout.strip().startswith("{")
    assert "Type 'rehydrate'" not in result.stdout
    assert "Type 'rehydrate'" in result.stderr
    assert '"operation":"Upgrade"' in result.stdout
    assert '"connection_closed":false' in result.stdout
    assert _DEVICE_ID not in result.stdout
    assert _BUNDLE_ID not in result.stdout
    assert result_receipt.is_file()
    if receipt_finalization_fails:
        assert '"receipt_written":false' in result.stdout
        assert '"receipt_warning":"RECEIPT_FINALIZE_FAILED"' in result.stdout
        assert "warning[RECEIPT_FINALIZE_FAILED]" in result.stderr
        assert "synthetic receipt finalization failure" not in result.stderr
    else:
        assert '"receipt_written":true' in result.stdout


def test_rehydrate_unknown_outcome_commits_nonempty_redacted_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backup_receipt = tmp_path / "backup-receipt.json"
    result_receipt = tmp_path / "result-receipt.json"
    _backup_gate_receipt(backup_receipt)
    payload = SimpleNamespace(
        archive_bytes=b"synthetic archive",
        sha256="b" * 64,
        size=17,
        bundle_identifier=_BUNDLE_ID,
        version="1.0",
        build="1",
        minimum_os="16.0",
        metadata=b"metadata",
        sinf=b"sinf",
        has_code_resources=True,
        store_id=None,
    )
    lockdown = SimpleNamespace(udid=_DEVICE_ID)

    @asynccontextmanager
    async def fake_open(selector: str, *, close_status: cli.DeviceCloseStatus | None = None) -> Any:
        del selector
        try:
            yield lockdown
        finally:
            if close_status is not None:
                close_status.closed = False

    async def fake_inspect(lockdown_arg: object, bundle_id: str) -> AppSnapshot:
        del lockdown_arg
        return AppSnapshot(
            app_ref=opaque_ref(bundle_id, namespace="app"),
            state=AppState.PLACEHOLDER,
            version="1.0",
            build="1",
            placeholder=True,
            demoted=False,
            sizes={"static": 0, "dynamic": 20},
        )

    async def fake_rehydrate(
        lockdown_arg: object,
        payload_arg: object,
        *,
        on_mutation_boundary: object = None,
    ) -> dict[str, object]:
        del lockdown_arg, payload_arg
        assert callable(on_mutation_boundary)
        on_mutation_boundary()
        raise OutcomeUnknownError(staging_removed=False)

    monkeypatch.setattr(cli, "open_device", fake_open)
    monkeypatch.setattr(cli, "inspect_app", fake_inspect)
    monkeypatch.setattr(cli, "rehydrate_app", fake_rehydrate)
    monkeypatch.setattr(cli, "validate_ipa", lambda *args, **kwargs: payload)
    monkeypatch.setattr(cli, "_require_interactive_terminal", lambda: None)

    result = runner.invoke(
        cli.app,
        [
            "app",
            "rehydrate",
            "--device",
            "device_synthetic",
            "--bundle-id",
            _BUNDLE_ID,
            "--ipa",
            str(tmp_path / "synthetic.ipa"),
            "--backup-receipt",
            str(backup_receipt),
            "--receipt",
            str(result_receipt),
            "--json",
        ],
        input="rehydrate\n",
    )

    assert result.exit_code != 0
    assert isinstance(result.exception, OutcomeUnknownError)
    assert result_receipt.stat().st_size > 0
    written = json.loads(result_receipt.read_text(encoding="utf-8"))
    rehydration = written["evidence"]["rehydration"]
    assert written["kind"] == "rehydration-result"
    assert rehydration["status"] == "unknown"
    assert rehydration["cleanup"] == {"staging_removed": False}
    assert rehydration["connection_closed"] is False
    serialized = json.dumps(written)
    assert _DEVICE_ID not in serialized
    assert _BUNDLE_ID not in serialized


def test_rehydrate_pre_send_failure_removes_reserved_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backup_receipt = tmp_path / "backup-receipt.json"
    result_receipt = tmp_path / "result-receipt.json"
    _backup_gate_receipt(backup_receipt)
    payload = SimpleNamespace(
        archive_bytes=b"synthetic archive",
        sha256="b" * 64,
        size=17,
        bundle_identifier=_BUNDLE_ID,
        version="1.0",
        build="1",
        minimum_os="16.0",
        metadata=b"metadata",
        sinf=b"sinf",
        has_code_resources=True,
        store_id=None,
    )
    lockdown = SimpleNamespace(udid=_DEVICE_ID)

    @asynccontextmanager
    async def fake_open(selector: str, *, close_status: cli.DeviceCloseStatus | None = None) -> Any:
        del selector, close_status
        yield lockdown

    async def fake_inspect(lockdown_arg: object, bundle_id: str) -> AppSnapshot:
        del lockdown_arg
        return AppSnapshot(
            app_ref=opaque_ref(bundle_id, namespace="app"),
            state=AppState.PLACEHOLDER,
            version="1.0",
            build="1",
            placeholder=True,
            demoted=False,
            sizes={"static": 0, "dynamic": 20},
        )

    async def fake_rehydrate(
        lockdown_arg: object,
        payload_arg: object,
        *,
        on_mutation_boundary: object = None,
    ) -> dict[str, object]:
        del lockdown_arg, payload_arg, on_mutation_boundary
        raise RehydrateError(
            "synthetic safe pre-send failure",
            code=ExitCode.UPGRADE_FAILED,
            reason="UPGRADE_START_FAILED",
        )

    monkeypatch.setattr(cli, "open_device", fake_open)
    monkeypatch.setattr(cli, "inspect_app", fake_inspect)
    monkeypatch.setattr(cli, "rehydrate_app", fake_rehydrate)
    monkeypatch.setattr(cli, "validate_ipa", lambda *args, **kwargs: payload)
    monkeypatch.setattr(cli, "_require_interactive_terminal", lambda: None)

    result = runner.invoke(
        cli.app,
        [
            "app",
            "rehydrate",
            "--device",
            "device_synthetic",
            "--bundle-id",
            _BUNDLE_ID,
            "--ipa",
            str(tmp_path / "synthetic.ipa"),
            "--backup-receipt",
            str(backup_receipt),
            "--receipt",
            str(result_receipt),
            "--json",
        ],
        input="rehydrate\n",
    )

    assert result.exit_code != 0
    assert isinstance(result.exception, RehydrateError)
    assert not result_receipt.exists()


@pytest.mark.parametrize(
    ("boundary_change", "expected_reason"),
    [
        ("stale", "BACKUP_RECEIPT_STALE"),
        ("digest", "BACKUP_RECEIPT_CHANGED"),
    ],
)
def test_rehydrate_revalidates_backup_receipt_at_send_boundary(
    boundary_change: str,
    expected_reason: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backup_receipt = tmp_path / "backup-receipt.json"
    result_receipt = tmp_path / "result-receipt.json"
    _backup_gate_receipt(backup_receipt)
    payload = SimpleNamespace(
        archive_bytes=b"synthetic archive",
        sha256="c" * 64,
        size=17,
        bundle_identifier=_BUNDLE_ID,
        version="1.0",
        build="1",
        minimum_os="16.0",
        metadata=b"metadata",
        sinf=b"sinf",
        has_code_resources=True,
        store_id=None,
    )
    lockdown = SimpleNamespace(udid=_DEVICE_ID)
    gate_calls = 0
    mutation_sent = False
    real_gate = cli._validate_backup_gate

    @asynccontextmanager
    async def fake_open(selector: str, *, close_status: cli.DeviceCloseStatus | None = None) -> Any:
        del selector, close_status
        yield lockdown

    async def fake_inspect(lockdown_arg: object, bundle_id: str) -> AppSnapshot:
        del lockdown_arg
        return AppSnapshot(
            app_ref=opaque_ref(bundle_id, namespace="app"),
            state=AppState.PLACEHOLDER,
            version="1.0",
            build="1",
            placeholder=True,
            demoted=False,
            sizes={"static": 0, "dynamic": 20},
        )

    def expiring_gate(*args: Any, **kwargs: Any) -> tuple[str, dict[str, Any]]:
        nonlocal gate_calls
        gate_calls += 1
        if gate_calls == 2:
            if boundary_change == "stale":
                raise RehydrateError(
                    "synthetic receipt expired",
                    code=ExitCode.POLICY_REFUSED,
                    reason="BACKUP_RECEIPT_STALE",
                )
            _, evidence = real_gate(*args, **kwargs)
            return "d" * 64, evidence
        return real_gate(*args, **kwargs)

    async def fake_rehydrate(
        lockdown_arg: object,
        payload_arg: object,
        *,
        on_mutation_boundary: object = None,
    ) -> dict[str, object]:
        nonlocal mutation_sent
        del lockdown_arg, payload_arg
        assert callable(on_mutation_boundary)
        on_mutation_boundary()
        mutation_sent = True
        return {"operation": "Upgrade"}

    monkeypatch.setattr(cli, "open_device", fake_open)
    monkeypatch.setattr(cli, "inspect_app", fake_inspect)
    monkeypatch.setattr(cli, "_validate_backup_gate", expiring_gate)
    monkeypatch.setattr(cli, "rehydrate_app", fake_rehydrate)
    monkeypatch.setattr(cli, "validate_ipa", lambda *args, **kwargs: payload)
    monkeypatch.setattr(cli, "_require_interactive_terminal", lambda: None)

    result = runner.invoke(
        cli.app,
        [
            "app",
            "rehydrate",
            "--device",
            "device_synthetic",
            "--bundle-id",
            _BUNDLE_ID,
            "--ipa",
            str(tmp_path / "synthetic.ipa"),
            "--backup-receipt",
            str(backup_receipt),
            "--receipt",
            str(result_receipt),
            "--json",
        ],
        input="rehydrate\n",
    )

    assert result.exit_code != 0
    assert isinstance(result.exception, RehydrateError)
    assert result.exception.reason == expected_reason
    assert gate_calls == 2
    assert mutation_sent is False
    assert not result_receipt.exists()
