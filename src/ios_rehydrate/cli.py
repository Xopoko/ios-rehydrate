# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 iOS Rehydrate contributors
"""Public command-line interface for the guarded rehydration workflow."""

from __future__ import annotations

import asyncio
import getpass
import importlib.metadata
import json
import platform
import re
import sys
import warnings
from dataclasses import replace
from pathlib import Path
from typing import Annotated, Any, NoReturn

import typer

# Typer 0.27.1 vendors Click; the exact runtime pin makes this exception boundary explicit.
from typer._click.exceptions import ClickException as TyperClickException
from typer._click.exceptions import Exit as TyperClickExit

from ios_rehydrate import __version__
from ios_rehydrate.apps import AppState, inspect_app
from ios_rehydrate.backup import (
    BackupReport,
    create_backup,
    enable_encryption,
    encryption_status,
    preflight_backup_output,
    validate_backup,
)
from ios_rehydrate.device import DeviceCloseStatus, list_devices, open_device
from ios_rehydrate.errors import ExitCode, OutcomeUnknownError, RehydrateError
from ios_rehydrate.ipa import public_summary, validate_ipa
from ios_rehydrate.manifest import probe_app_domain
from ios_rehydrate.privacy import device_reference, opaque_ref, sanitize_text
from ios_rehydrate.receipts import (
    MAX_RECEIPT_AGE,
    ReceiptReservation,
    envelope,
    read_receipt,
    reserve_receipt,
)
from ios_rehydrate.upgrade import rehydrate_app

app = typer.Typer(
    name="ios-rehydrate",
    help="Guarded rehydration of an existing iOS placeholder from a local IPA.",
    no_args_is_help=True,
    pretty_exceptions_enable=False,
    add_completion=False,
)
device_app = typer.Typer(help="Discover explicitly selected USB devices.", no_args_is_help=True)
target_app = typer.Typer(help="Inspect or rehydrate one existing app.", no_args_is_help=True)
backup_app = typer.Typer(help="Create and verify encrypted backups.", no_args_is_help=True)
ipa_app = typer.Typer(
    help="Validate a local IPA and the App Store metadata required by this workflow.",
    no_args_is_help=True,
)

app.add_typer(device_app, name="device")
app.add_typer(target_app, name="app")
app.add_typer(backup_app, name="backup")
app.add_typer(ipa_app, name="ipa")

_BUNDLE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,254}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")

DeviceOption = Annotated[
    str,
    typer.Option("--device", help="Exact redacted device reference or full UDID."),
]
BundleOption = Annotated[
    str,
    typer.Option("--bundle-id", help="Exact target bundle identifier."),
]
JsonOption = Annotated[
    bool,
    typer.Option("--json", help="Emit successful output as one compact JSON object."),
]
ReceiptOption = Annotated[
    Path | None,
    typer.Option("--receipt", help="Write a new redacted JSON receipt; never overwrites."),
]


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(__version__)
        raise typer.Exit()


@app.callback()
def root_callback(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            help="Show the version and exit.",
            callback=_version_callback,
            is_eager=True,
        ),
    ] = False,
) -> None:
    del version


def _run(awaitable: Any) -> Any:
    return asyncio.run(awaitable)


def _emit(payload: dict[str, Any], *, compact: bool) -> None:
    typer.echo(
        json.dumps(
            {"ok": True, **payload},
            # ASCII escaping prevents untrusted device/IPA text from emitting C1,
            # bidi, or other terminal-control code points directly.
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":") if compact else None,
            indent=None if compact else 2,
        )
    )


def _reserve_optional_receipt(path: Path | None) -> ReceiptReservation | None:
    return None if path is None else reserve_receipt(path)


def _abort_failed_optional_receipt(reservation: ReceiptReservation | None) -> None:
    if reservation is not None:
        reservation.abort_on_pre_operation_failure()


def _finalize_optional_receipt(
    reservation: ReceiptReservation | None, *, kind: str, evidence: dict[str, Any]
) -> dict[str, object]:
    if reservation is None:
        return {"receipt_written": False}
    try:
        reservation.commit(envelope(kind, evidence))
    except BaseException:
        reservation.preserve()
        typer.echo(
            "warning[RECEIPT_FINALIZE_FAILED]: operation succeeded; "
            "reserved receipt evidence could not be finalized",
            err=True,
        )
        return {
            "receipt_written": False,
            "receipt_warning": "RECEIPT_FINALIZE_FAILED",
        }
    return {"receipt_written": True}


def _require_bundle_identifier(bundle_id: str) -> str:
    if _BUNDLE_IDENTIFIER.fullmatch(bundle_id) is None:
        raise RehydrateError(
            "bundle identifier is invalid",
            code=ExitCode.USAGE,
            reason="BUNDLE_IDENTIFIER_INVALID",
        )
    return bundle_id


def _require_store_identifier(store_id: str | None) -> str | None:
    if store_id is not None and (not store_id.isascii() or not store_id.isdecimal()):
        raise RehydrateError(
            "store identifier must contain decimal digits only",
            code=ExitCode.USAGE,
            reason="STORE_IDENTIFIER_INVALID",
        )
    return store_id


def _require_device_identifier(lockdown: Any) -> str:
    udid = getattr(lockdown, "udid", None)
    if not isinstance(udid, str) or not udid:
        raise RehydrateError(
            "selected device did not provide an identifier",
            code=ExitCode.DEVICE_UNAVAILABLE,
            reason="DEVICE_IDENTIFIER_INVALID",
        )
    return udid


def _require_interactive_terminal() -> None:
    if not sys.stdin.isatty():
        raise RehydrateError(
            "an interactive terminal is required for confirmation",
            code=ExitCode.CONFIRMATION,
            reason="INTERACTIVE_TERMINAL_REQUIRED",
        )


def _new_backup_password() -> tuple[str, str]:
    _require_interactive_terminal()
    first = _hidden_password("New encrypted-backup password: ")
    second = _hidden_password("Repeat encrypted-backup password: ")
    return first, second


def _backup_password() -> str:
    _require_interactive_terminal()
    return _hidden_password("Encrypted-backup password: ")


def _hidden_password(prompt: str) -> str:
    """Refuse getpass's echoed-input fallback when terminal echo control is unavailable."""
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            return getpass.getpass(prompt)
    except getpass.GetPassWarning as exc:
        raise RehydrateError(
            "hidden backup-password entry is unavailable",
            code=ExitCode.CONFIRMATION,
            reason="BACKUP_PASSWORD_UNAVAILABLE",
        ) from exc


def _validate_backup_gate(
    receipt_path: Path, *, device_ref: str, app_ref: str
) -> tuple[str, dict[str, Any]]:
    receipt, digest = read_receipt(
        receipt_path,
        expected_kind="backup-verification",
        max_age=MAX_RECEIPT_AGE,
    )
    evidence = receipt["evidence"]
    backup = evidence.get("backup")
    manifest = evidence.get("manifest")
    valid = (
        isinstance(backup, dict)
        and backup.get("device_ref") == device_ref
        and backup.get("encrypted") is True
        and backup.get("completed") is True
        and backup.get("requested_full") is True
        and backup.get("observed_is_full_backup") is False
        and type(backup.get("payload_count")) is int
        and backup["payload_count"] > 0
        and type(backup.get("payload_bytes")) is int
        and backup["payload_bytes"] > 0
        and evidence.get("app_ref") == app_ref
        and isinstance(evidence.get("creation_receipt_sha256"), str)
        and _SHA256.fullmatch(evidence["creation_receipt_sha256"]) is not None
        and isinstance(manifest, dict)
        and type(manifest.get("entry_count")) is int
        and manifest["entry_count"] > 0
        and type(manifest.get("logical_bytes_total")) is int
        and manifest["logical_bytes_total"] >= 0
    )
    if not valid:
        raise RehydrateError(
            "backup receipt does not match the selected device and app",
            code=ExitCode.POLICY_REFUSED,
            reason="BACKUP_RECEIPT_MISMATCH",
        )
    return digest, evidence


def _validate_backup_creation_receipt(
    receipt_path: Path,
    *,
    report: BackupReport,
) -> str:
    """Bind a current structural verification to one fresh full-backup request."""
    receipt, digest = read_receipt(
        receipt_path,
        expected_kind="backup-create",
        max_age=MAX_RECEIPT_AGE,
    )
    backup = receipt["evidence"].get("backup")
    valid = (
        isinstance(backup, dict)
        and backup.get("backup_ref") == report.backup_ref
        and backup.get("device_ref") == report.device_ref
        and type(backup.get("payload_count")) is int
        and backup["payload_count"] == report.payload_count
        and type(backup.get("payload_bytes")) is int
        and backup["payload_bytes"] == report.payload_bytes
        and backup.get("encrypted") is True
        and backup.get("completed") is True
        and backup.get("requested_full") is True
        and backup.get("observed_is_full_backup") is False
    )
    if not valid:
        raise RehydrateError(
            "backup creation receipt does not match the verified backup",
            code=ExitCode.POLICY_REFUSED,
            reason="BACKUP_CREATION_RECEIPT_MISMATCH",
        )
    return digest


@app.command("doctor")
def doctor(json_output: JsonOption = False) -> None:
    """Report a redacted runtime/dependency readiness snapshot."""
    package_names = ("pymobiledevice3", "pyiosbackup", "typer")
    packages = {name: importlib.metadata.version(name) for name in package_names}
    usbmux_available = True
    try:
        connected = len(_run(list_devices()))
    except RehydrateError:
        usbmux_available = False
        connected = 0
    _emit(
        {
            "host": {
                "system": platform.system(),
                "python": platform.python_version(),
                "windows_first_supported": platform.system() == "Windows",
            },
            "dependencies": packages,
            "usbmux_available": usbmux_available,
            "usb_device_count": connected,
        },
        compact=json_output,
    )


@app.command("licenses")
def licenses(json_output: JsonOption = False) -> None:
    """Show the concise license and no-warranty notice."""
    _emit(
        {
            "project_license": "GPL-3.0-or-later",
            "notice": "This program comes with absolutely no warranty.",
            "gpl_runtime_dependencies": {
                "pymobiledevice3": "GPL-3.0-or-later",
                "pyiosbackup": "GPL-3.0-or-later",
            },
        },
        compact=json_output,
    )


@device_app.command("list")
def device_list(json_output: JsonOption = False) -> None:
    """List connected USB devices without printing raw identifiers or names."""
    devices = _run(list_devices())
    _emit({"devices": devices, "count": len(devices)}, compact=json_output)


@target_app.command("inspect")
def app_inspect(
    device: DeviceOption,
    bundle_id: BundleOption,
    json_output: JsonOption = False,
) -> None:
    """Inspect one exact app, including placeholder state."""
    bundle_id = _require_bundle_identifier(bundle_id)

    async def operation() -> dict[str, object]:
        close_status = DeviceCloseStatus()
        async with open_device(device, close_status=close_status) as lockdown:
            evidence = (await inspect_app(lockdown, bundle_id)).to_evidence()
        return {**evidence, "connection_closed": close_status.closed}

    _emit({"app": _run(operation())}, compact=json_output)


@backup_app.command("encryption-status")
def backup_encryption_status(
    device: DeviceOption,
    json_output: JsonOption = False,
) -> None:
    """Read the authoritative backup-encryption state."""

    async def operation() -> dict[str, object]:
        close_status = DeviceCloseStatus()
        async with open_device(device, close_status=close_status) as lockdown:
            udid = _require_device_identifier(lockdown)
            evidence = {
                "device_ref": device_reference(udid),
                "enabled": await encryption_status(lockdown),
            }
        return {**evidence, "connection_closed": close_status.closed}

    _emit({"backup_encryption": _run(operation())}, compact=json_output)


@backup_app.command("create")
def backup_create(
    device: DeviceOption,
    output: Annotated[Path, typer.Option("--output", help="New backup root directory.")],
    enable: Annotated[
        bool,
        typer.Option(
            "--enable-encryption",
            help="Enable persistent backup encryption if currently disabled.",
        ),
    ] = False,
    receipt: ReceiptOption = None,
    json_output: JsonOption = False,
) -> None:
    """Request a fresh full backup and verify the resulting encrypted backup."""
    reservation = _reserve_optional_receipt(receipt)

    async def operation() -> dict[str, Any]:
        preflight_backup_output(output)
        close_status = DeviceCloseStatus()
        encryption_mobilebackup_connection_closed: bool | None = None
        encryption_scratch_removed: bool | None = None
        async with open_device(device, close_status=close_status) as lockdown:
            encrypted = await encryption_status(lockdown)
            if not encrypted:
                if not enable:
                    raise RehydrateError(
                        "backup encryption is disabled; rerun with --enable-encryption",
                        code=ExitCode.POLICY_REFUSED,
                        reason="BACKUP_ENCRYPTION_REQUIRED",
                    )
                _require_interactive_terminal()
                if not typer.confirm(
                    "Backup encryption will remain enabled on the device. Continue?",
                    default=False,
                    err=True,
                ):
                    raise RehydrateError(
                        "backup encryption enable was not confirmed",
                        code=ExitCode.CONFIRMATION,
                        reason="BACKUP_ENCRYPTION_NOT_CONFIRMED",
                    )
                password = _new_backup_password()
                if reservation is not None:
                    reservation.mark_operation_started()
                encryption_report = await enable_encryption(
                    lockdown, output.parent, lambda: password
                )
                if encryption_report is not None:
                    encryption_mobilebackup_connection_closed = (
                        encryption_report.mobilebackup_connection_closed
                    )
                    encryption_scratch_removed = encryption_report.scratch_removed
            if reservation is not None and not reservation.operation_started:
                reservation.mark_operation_started()
            report = await create_backup(lockdown, output)
        return {
            **report.as_public_dict(),
            "encryption_mobilebackup_connection_closed": (
                encryption_mobilebackup_connection_closed
            ),
            "encryption_scratch_removed": encryption_scratch_removed,
            "connection_closed": close_status.closed,
        }

    try:
        evidence = {"backup": _run(operation())}
    except BaseException:
        _abort_failed_optional_receipt(reservation)
        raise
    receipt_status = _finalize_optional_receipt(
        reservation, kind="backup-create", evidence=evidence
    )
    _emit({**evidence, **receipt_status}, compact=json_output)


@backup_app.command("verify")
def backup_verify(
    device: DeviceOption,
    backup_root: Annotated[
        Path,
        typer.Option("--backup", help="Existing backup root containing one device directory."),
    ],
    bundle_id: Annotated[
        str | None,
        typer.Option("--bundle-id", help="Also verify this app's encrypted backup domain."),
    ] = None,
    creation_receipt: Annotated[
        Path | None,
        typer.Option(
            "--creation-receipt",
            help="Fresh receipt from `backup create`; required with --bundle-id.",
        ),
    ] = None,
    receipt: ReceiptOption = None,
    json_output: JsonOption = False,
) -> None:
    """Verify an encrypted backup and optionally its app domain."""
    if bundle_id is not None:
        bundle_id = _require_bundle_identifier(bundle_id)
        if creation_receipt is None:
            raise RehydrateError(
                "a fresh backup-create receipt is required with --bundle-id",
                code=ExitCode.USAGE,
                reason="BACKUP_CREATION_RECEIPT_REQUIRED",
            )
    elif creation_receipt is not None:
        raise RehydrateError(
            "a backup-create receipt is only used with --bundle-id",
            code=ExitCode.USAGE,
            reason="BACKUP_CREATION_RECEIPT_UNUSED",
        )
    reservation = _reserve_optional_receipt(receipt)

    async def selected_identity() -> tuple[str, str, bool]:
        close_status = DeviceCloseStatus()
        async with open_device(device, close_status=close_status) as lockdown:
            udid = _require_device_identifier(lockdown)
            device_ref = device_reference(udid)
        return udid, device_ref, close_status.closed

    try:
        udid, device_ref, connection_closed = _run(selected_identity())
        report = validate_backup(backup_root, udid)
        if report.device_ref != device_ref:
            raise RehydrateError(
                "backup does not match the selected device",
                code=ExitCode.BACKUP_VERIFY,
                reason="BACKUP_IDENTIFIER_MISMATCH",
            )
        evidence: dict[str, Any] = {
            "backup": {
                **report.as_public_dict(),
                "connection_closed": connection_closed,
            }
        }
        kind = "backup-structure"
        if bundle_id is not None:
            assert creation_receipt is not None
            creation_digest = _validate_backup_creation_receipt(
                creation_receipt,
                report=report,
            )
            report = replace(report, requested_full=True)
            evidence["backup"] = {
                **report.as_public_dict(),
                "connection_closed": connection_closed,
            }
            manifest_report = probe_app_domain(
                backup_root.resolve(strict=True) / udid,
                bundle_id,
                _backup_password,
            )
            final_creation_digest = _validate_backup_creation_receipt(
                creation_receipt,
                report=report,
            )
            if final_creation_digest != creation_digest:
                raise RehydrateError(
                    "backup creation receipt changed during verification",
                    code=ExitCode.POLICY_REFUSED,
                    reason="BACKUP_CREATION_RECEIPT_CHANGED",
                )
            evidence["app_ref"] = opaque_ref(bundle_id, namespace="app")
            evidence["manifest"] = manifest_report.as_public_dict()
            evidence["creation_receipt_sha256"] = creation_digest
            kind = "backup-verification"
    except BaseException:
        _abort_failed_optional_receipt(reservation)
        raise
    receipt_status = _finalize_optional_receipt(reservation, kind=kind, evidence=evidence)
    _emit({**evidence, **receipt_status}, compact=json_output)


@ipa_app.command("verify")
def ipa_verify(
    ipa_path: Annotated[Path, typer.Argument(help="Local operator-supplied IPA.")],
    bundle_id: Annotated[
        str | None,
        typer.Option("--bundle-id", help="Expected exact bundle identifier."),
    ] = None,
    store_id: Annotated[
        str | None,
        typer.Option("--store-id", help="Expected decimal App Store identifier."),
    ] = None,
    receipt: ReceiptOption = None,
    json_output: JsonOption = False,
) -> None:
    """Structurally validate an exact, retained local IPA."""
    if bundle_id is not None:
        bundle_id = _require_bundle_identifier(bundle_id)
    store_id = _require_store_identifier(store_id)
    reservation = _reserve_optional_receipt(receipt)
    try:
        payload = validate_ipa(
            ipa_path,
            expected_bundle_id=bundle_id,
            expected_store_id=store_id,
        )
        evidence = {"ipa": public_summary(payload)}
    except BaseException:
        _abort_failed_optional_receipt(reservation)
        raise
    receipt_status = _finalize_optional_receipt(
        reservation, kind="ipa-verification", evidence=evidence
    )
    _emit({**evidence, **receipt_status}, compact=json_output)


@target_app.command("rehydrate")
def app_rehydrate(
    device: DeviceOption,
    bundle_id: BundleOption,
    ipa_path: Annotated[Path, typer.Option("--ipa", help="Local operator-supplied IPA.")],
    backup_receipt: Annotated[
        Path,
        typer.Option(
            "--backup-receipt",
            help="Receipt from `backup verify --bundle-id`; required safety gate.",
        ),
    ],
    store_id: Annotated[
        str | None,
        typer.Option("--store-id", help="Expected decimal App Store identifier."),
    ] = None,
    receipt: ReceiptOption = None,
    json_output: JsonOption = False,
) -> None:
    """Rehydrate an eligible placeholder using exactly InstallationProxy Upgrade."""
    bundle_id = _require_bundle_identifier(bundle_id)
    store_id = _require_store_identifier(store_id)
    reservation = _reserve_optional_receipt(receipt)
    close_status = DeviceCloseStatus()
    unknown_evidence: dict[str, Any] | None = None

    async def operation() -> dict[str, Any]:
        nonlocal unknown_evidence
        async with open_device(device, close_status=close_status) as lockdown:
            udid = _require_device_identifier(lockdown)
            device_ref = device_reference(udid)
            app_ref = opaque_ref(bundle_id, namespace="app")
            backup_digest, _ = _validate_backup_gate(
                backup_receipt,
                device_ref=device_ref,
                app_ref=app_ref,
            )
            snapshot = await inspect_app(lockdown, bundle_id)
            if snapshot.state is not AppState.PLACEHOLDER or not (
                snapshot.placeholder or snapshot.demoted
            ):
                raise RehydrateError(
                    "target is not an exact User placeholder or demoted app",
                    code=ExitCode.POLICY_REFUSED,
                    reason="TARGET_NOT_REHYDRATABLE",
                )
            _require_interactive_terminal()
            confirmation = typer.prompt(
                "Type 'rehydrate' after reviewing the verified backup and lawful-use notice",
                err=True,
                hide_input=json_output,
            )
            if confirmation != "rehydrate":
                raise RehydrateError(
                    "rehydration confirmation did not match",
                    code=ExitCode.CONFIRMATION,
                    reason="REHYDRATE_NOT_CONFIRMED",
                )

            def mutation_boundary() -> None:
                final_digest, _ = _validate_backup_gate(
                    backup_receipt,
                    device_ref=device_ref,
                    app_ref=app_ref,
                )
                if final_digest != backup_digest:
                    raise RehydrateError(
                        "backup verification receipt changed before mutation",
                        code=ExitCode.POLICY_REFUSED,
                        reason="BACKUP_RECEIPT_CHANGED",
                    )
                if reservation is not None:
                    reservation.mark_operation_started()

            try:
                result = await rehydrate_app(
                    lockdown,
                    payload,
                    on_mutation_boundary=mutation_boundary,
                )
            except OutcomeUnknownError as error:
                unknown_evidence = {
                    "status": "unknown",
                    "operation": "Upgrade",
                    "ipa": {"sha256": payload.sha256, "size": payload.size},
                    "backup_receipt_sha256": backup_digest,
                    "device_ref": device_ref,
                    "app_ref": app_ref,
                    "cleanup": {"staging_removed": error.staging_removed},
                }
                raise
            evidence = {
                **result,
                "backup_receipt_sha256": backup_digest,
                "device_ref": device_ref,
                "app_ref": app_ref,
            }
        return {**evidence, "connection_closed": close_status.closed}

    try:
        payload = validate_ipa(
            ipa_path,
            expected_bundle_id=bundle_id,
            expected_store_id=store_id,
        )
        evidence = {"rehydration": _run(operation())}
    except OutcomeUnknownError:
        if unknown_evidence is not None:
            unknown_evidence["connection_closed"] = close_status.closed
            if reservation is not None:
                try:
                    reservation.commit(
                        envelope(
                            "rehydration-result",
                            {"rehydration": unknown_evidence},
                        )
                    )
                except BaseException:
                    reservation.preserve()
                    typer.echo(
                        "warning[RECEIPT_FINALIZE_FAILED]: outcome is unknown; "
                        "reserved receipt evidence could not be finalized",
                        err=True,
                    )
        else:
            _abort_failed_optional_receipt(reservation)
        raise
    except BaseException:
        _abort_failed_optional_receipt(reservation)
        raise
    receipt_status = _finalize_optional_receipt(
        reservation, kind="rehydration-result", evidence=evidence
    )
    _emit({**evidence, **receipt_status}, compact=json_output)


def _fail(error: RehydrateError) -> NoReturn:
    message = sanitize_text(error)
    typer.echo(f"error[{error.reason}]: {message}", err=True)
    raise SystemExit(int(error.code))


def main() -> None:
    try:
        app(standalone_mode=False)
    except TyperClickException as error:
        typer.echo(
            "error[CLI_USAGE]: invalid command-line arguments; run `ios-rehydrate --help`",
            err=True,
        )
        raise SystemExit(error.exit_code) from None
    except TyperClickExit as error:
        raise SystemExit(error.exit_code) from None
    except RehydrateError as error:
        _fail(error)
    except (asyncio.CancelledError, EOFError, KeyboardInterrupt, typer.Abort):
        _fail(
            RehydrateError(
                "operation interrupted",
                code=ExitCode.CONFIRMATION,
                reason="OPERATION_INTERRUPTED",
            )
        )
    except SystemExit:
        raise
    except Exception:
        _fail(
            RehydrateError(
                "unexpected internal error; no mutation retry was attempted",
                code=ExitCode.DEPENDENCY,
                reason="INTERNAL_ERROR",
            )
        )
