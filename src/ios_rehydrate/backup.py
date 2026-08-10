# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 iOS Rehydrate contributors
"""Create and structurally verify encrypted MobileBackup2 backups.

Only opaque references and aggregate values leave this module.  In particular,
``BackupReport`` never contains the backup path or a device identifier.
"""

from __future__ import annotations

import asyncio
import os
import plistlib
import re
import stat
import tempfile
from collections.abc import Awaitable, Callable
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Any

from ios_rehydrate.errors import ExitCode, RehydrateError
from ios_rehydrate.privacy import device_reference, opaque_ref
from ios_rehydrate.safe_mobilebackup import SafeMobilebackup2Service as Mobilebackup2Service

_BACKUP_DOMAIN = "com.apple.mobile.backup"
_WILL_ENCRYPT_KEY = "WillEncrypt"
_HASHED_PAYLOAD = re.compile(r"^[0-9a-fA-F]{40}$")
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
ENCRYPTION_REQUEST_TIMEOUT_SECONDS = 120.0
ENCRYPTION_RECONCILE_TIMEOUT_SECONDS = 10.0
MOBILEBACKUP_CLEANUP_TIMEOUT_SECONDS = 5.0

# These are intentionally generous compared with ordinary plist metadata while
# still bounding parser memory for an untrusted backup.  Info.plist contains app
# metadata and icons, so it receives the largest plist allowance.
MAX_INFO_PLIST_BYTES = 64 * 1024 * 1024
MAX_MANIFEST_PLIST_BYTES = 4 * 1024 * 1024
MAX_STATUS_PLIST_BYTES = 1024 * 1024

# Manifest.db is only structurally sized here (never loaded); the same ceiling
# bounds the in-memory encrypted-manifest probe in manifest.py.
MAX_MANIFEST_DB_BYTES = 512 * 1024 * 1024
MAX_INSPECTED_DIRECTORY_ENTRIES = 2_000_000
MAX_HASHED_PAYLOAD_COUNT = 1_000_000
_PLIST_LIMITS = {
    "Info.plist": MAX_INFO_PLIST_BYTES,
    "Manifest.plist": MAX_MANIFEST_PLIST_BYTES,
    "Status.plist": MAX_STATUS_PLIST_BYTES,
}


@dataclass(slots=True)
class _DirectoryEntryBudget:
    limit: int
    inspected: int = 0

    def consume(self) -> None:
        self.inspected += 1
        if self.inspected > self.limit:
            raise _verify_error(
                "backup contains too many directory entries",
                "BACKUP_DIRECTORY_ENTRY_LIMIT",
            )


@dataclass(frozen=True, slots=True)
class _PrivateScratch:
    path: Path
    identity: tuple[int, int]


@dataclass(frozen=True, slots=True)
class BackupReport:
    """Privacy-safe evidence that a backup passed structural validation."""

    backup_ref: str
    device_ref: str
    payload_count: int
    payload_bytes: int
    encrypted: bool
    completed: bool
    requested_full: bool
    observed_is_full_backup: bool
    mobilebackup_connection_closed: bool | None = None

    def as_public_dict(self) -> dict[str, str | int | bool | None]:
        """Return the complete report as a JSON-safe, privacy-safe mapping."""
        return asdict(self)


@dataclass(frozen=True, slots=True)
class EncryptionEnableReport:
    """Truthful cleanup evidence for one successful enable request."""

    mobilebackup_connection_closed: bool
    scratch_removed: bool


async def encryption_status(lockdown: Any) -> bool:
    """Read the authoritative backup-encryption boolean from lockdownd.

    pymobiledevice3's convenience method intentionally maps read failures to
    ``False``.  That is unsafe for an enable-only flow, so this function queries
    the canonical domain/key directly and refuses absent or non-boolean values.
    """
    try:
        value = await lockdown.get_value(_BACKUP_DOMAIN, _WILL_ENCRYPT_KEY)
    except Exception as exc:
        raise RehydrateError(
            "could not determine the device backup-encryption state",
            code=ExitCode.DEVICE_UNAVAILABLE,
            reason="BACKUP_ENCRYPTION_STATUS_UNAVAILABLE",
        ) from exc
    if type(value) is not bool:
        raise RehydrateError(
            "the device returned an invalid backup-encryption state",
            code=ExitCode.DEVICE_UNAVAILABLE,
            reason="BACKUP_ENCRYPTION_STATUS_INVALID",
        )
    return value


async def enable_encryption(
    lockdown: Any,
    backup_root: Path,
    password_provider: Callable[[], tuple[str, str]],
) -> EncryptionEnableReport | None:
    """Enable backup encryption without ever disabling or changing a password.

    ``password_provider`` is injected by the caller so a CLI can use hidden
    double-entry prompts.  It is deliberately not invoked when encryption is
    already enabled.  The state is queried again immediately before mutation;
    if it changed while the password was being collected, the operation is
    refused.
    """
    if await encryption_status(lockdown):
        return None

    root = _safe_existing_directory(backup_root, reason="BACKUP_PARENT_INVALID")
    try:
        supplied = password_provider()
    except Exception as exc:
        raise RehydrateError(
            "backup password entry did not complete",
            code=ExitCode.CONFIRMATION,
            reason="BACKUP_PASSWORD_UNAVAILABLE",
        ) from exc
    if (
        not isinstance(supplied, tuple)
        or len(supplied) != 2
        or type(supplied[0]) is not str
        or type(supplied[1]) is not str
        or not supplied[0]
        or supplied[0] != supplied[1]
    ):
        raise RehydrateError(
            "backup password entries must be nonempty and identical",
            code=ExitCode.CONFIRMATION,
            reason="BACKUP_PASSWORD_MISMATCH",
        )

    password = supplied[0]
    if await encryption_status(lockdown):
        raise RehydrateError(
            "backup encryption changed while confirmation was in progress",
            code=ExitCode.POLICY_REFUSED,
            reason="BACKUP_ENCRYPTION_STATE_CHANGED",
        )

    scratch = _reserve_private_scratch(root)

    async def request_change(service: Any) -> None:
        async with asyncio.timeout(ENCRYPTION_REQUEST_TIMEOUT_SECONDS):
            await service.change_password(backup_directory=scratch.path, old="", new=password)

    service_closed = False
    reconciled_after_request_error = False
    scratch_removed = False
    try:
        service_closed = await _run_mobilebackup_service(lockdown, request_change)
    except (Exception, asyncio.CancelledError, KeyboardInterrupt):
        enabled = await _reconcile_encryption_enable(lockdown)
        if enabled:
            reconciled_after_request_error = True
        else:
            raise RehydrateError(
                "backup-encryption enable outcome is unknown; inspect the device",
                code=ExitCode.OUTCOME_UNKNOWN,
                reason="BACKUP_ENCRYPTION_OUTCOME_UNKNOWN",
            ) from None
    finally:
        scratch_removed = _remove_empty_private_scratch(scratch)

    if reconciled_after_request_error:
        return EncryptionEnableReport(
            mobilebackup_connection_closed=False,
            scratch_removed=scratch_removed,
        )

    try:
        async with asyncio.timeout(ENCRYPTION_RECONCILE_TIMEOUT_SECONDS):
            enabled = await encryption_status(lockdown)
    except (Exception, asyncio.CancelledError, KeyboardInterrupt):
        raise RehydrateError(
            "backup-encryption enable outcome is unknown; inspect the device",
            code=ExitCode.OUTCOME_UNKNOWN,
            reason="BACKUP_ENCRYPTION_OUTCOME_UNKNOWN",
        ) from None
    if not enabled:
        raise RehydrateError(
            "backup encryption could not be confirmed after the request",
            code=ExitCode.BACKUP_CREATE,
            reason="BACKUP_ENCRYPTION_ENABLE_UNCONFIRMED",
        )
    return EncryptionEnableReport(
        mobilebackup_connection_closed=service_closed,
        scratch_removed=scratch_removed,
    )


async def create_backup(
    lockdown: Any,
    output_root: Path,
    progress: Callable[[float], None] | None = None,
) -> BackupReport:
    """Request a fresh full backup, preserve failures, and validate the result.

    The existing parent directory is checked first and ``output_root`` is then
    reserved with one non-recursive ``mkdir`` call.  No failure path deletes or
    truncates the reserved directory, so partial evidence remains available for
    recovery or diagnosis.
    """
    expected_udid = getattr(lockdown, "udid", None)
    if not isinstance(expected_udid, str) or not _is_single_component(expected_udid):
        raise RehydrateError(
            "the connected device did not provide a valid identifier",
            code=ExitCode.DEVICE_SELECTION,
            reason="BACKUP_DEVICE_IDENTIFIER_INVALID",
        )
    if not await encryption_status(lockdown):
        raise RehydrateError(
            "encrypted device backups must be enabled before backup creation",
            code=ExitCode.POLICY_REFUSED,
            reason="BACKUP_ENCRYPTION_REQUIRED",
        )
    target = _reserve_output_root(output_root)

    callback = progress if progress is not None else _ignore_progress

    async def request_backup(service: Any) -> None:
        await service.backup(
            full=True,
            backup_directory=target,
            progress_callback=callback,
        )

    try:
        service_closed = await _run_mobilebackup_service(lockdown, request_backup)
    except (Exception, asyncio.CancelledError, KeyboardInterrupt):
        raise RehydrateError(
            "backup creation failed; incomplete data was preserved",
            code=ExitCode.BACKUP_CREATE,
            reason="BACKUP_CREATE_INCOMPLETE",
        ) from None

    try:
        report = validate_backup(target, expected_udid, requested_full=True)
        return replace(report, mobilebackup_connection_closed=service_closed)
    except RehydrateError as exc:
        raise RehydrateError(
            "backup verification failed; incomplete data was preserved",
            code=ExitCode.BACKUP_VERIFY,
            reason=exc.reason,
        ) from exc


def validate_backup(
    output_root: Path, expected_udid: str, *, requested_full: bool = False
) -> BackupReport:
    """Validate the exact encrypted, completed backup rooted at ``output_root``.

    ``Status.plist``'s final ``IsFullBackup`` value is observed as ``False`` for
    the completed MobileBackup2 format.  That Apple status field does not mean
    this function requested an incremental backup: ``create_backup`` always
    invokes ``backup(full=True)`` and records that separately as
    ``requested_full``.
    """
    if not isinstance(expected_udid, str) or not _is_single_component(expected_udid):
        raise _verify_error("backup device identifier is invalid", "BACKUP_IDENTIFIER_INVALID")

    root = _safe_existing_directory(output_root, reason="BACKUP_LAYOUT_INVALID")
    entry_budget = _DirectoryEntryBudget(MAX_INSPECTED_DIRECTORY_ENTRIES)
    device_root = _exact_device_directory(root, expected_udid, entry_budget)

    blobs: dict[str, bytes] = {}
    for name, size_limit in _PLIST_LIMITS.items():
        path = device_root / name
        metadata = _regular_file_metadata(path)
        if metadata is None:
            raise _verify_error("required backup metadata is missing", "BACKUP_METADATA_MISSING")
        if metadata.st_size <= 0:
            raise _verify_error("required backup metadata is empty", "BACKUP_METADATA_EMPTY")
        if metadata.st_size > size_limit:
            raise _verify_error("backup plist metadata is too large", "BACKUP_METADATA_TOO_LARGE")
        blobs[name] = _read_bounded_metadata(path, size_limit)

    # Structural validation must not load an attacker-sized Manifest.db.  Its
    # content is handled separately by the bounded, in-memory manifest probe.
    database_metadata = _regular_file_metadata(device_root / "Manifest.db")
    if database_metadata is None:
        raise _verify_error("required backup metadata is missing", "BACKUP_METADATA_MISSING")
    if database_metadata.st_size <= 0:
        raise _verify_error("required backup metadata is empty", "BACKUP_METADATA_EMPTY")
    if database_metadata.st_size > MAX_MANIFEST_DB_BYTES:
        raise _verify_error(
            "encrypted manifest database is too large",
            "BACKUP_MANIFEST_DB_TOO_LARGE",
        )

    info = _load_plist(blobs["Info.plist"])
    manifest = _load_plist(blobs["Manifest.plist"])
    status = _load_plist(blobs["Status.plist"])

    if manifest.get("IsEncrypted") is not True:
        raise _verify_error("backup is not encrypted", "BACKUP_NOT_ENCRYPTED")
    _validate_identifiers(info, manifest, expected_udid)

    if status.get("SnapshotState") != "finished" or status.get("BackupState") != "new":
        raise _verify_error("backup did not reach its completed state", "BACKUP_STATE_INCOMPLETE")
    if status.get("IsFullBackup") is not False:
        raise _verify_error("backup final-state metadata is unexpected", "BACKUP_STATE_INVALID")

    payload_count, payload_bytes = _hashed_payload_totals(device_root, entry_budget)
    if payload_count <= 0 or payload_bytes <= 0:
        raise _verify_error("backup has no nonempty hashed payload", "BACKUP_PAYLOAD_EMPTY")

    return BackupReport(
        backup_ref=opaque_ref(str(root), namespace="backup"),
        device_ref=device_reference(expected_udid),
        payload_count=payload_count,
        payload_bytes=payload_bytes,
        encrypted=True,
        completed=True,
        requested_full=requested_full,
        observed_is_full_backup=False,
    )


def _ignore_progress(_: float) -> None:
    return None


async def _run_mobilebackup_service(
    lockdown: Any, operation: Callable[[Any], Awaitable[None]]
) -> bool:
    """Run one service operation without allowing exit cleanup to replace it."""
    manager = Mobilebackup2Service(lockdown)
    entered = False
    service: Any = None
    primary: BaseException | None = None
    cleanup_closed = True
    operation_connection_closed = True
    try:
        service = await manager.__aenter__()
        entered = True
        await operation(service)
        operation_connection_closed = (
            getattr(service, "device_link_connection_closed", True) is True
        )
    except BaseException as exc:
        primary = exc
        raise
    finally:
        if entered:
            try:
                async with asyncio.timeout(MOBILEBACKUP_CLEANUP_TIMEOUT_SECONDS):
                    await manager.__aexit__(
                        type(primary) if primary is not None else None,
                        primary,
                        primary.__traceback__ if primary is not None else None,
                    )
            except BaseException:
                if primary is None:
                    cleanup_closed = False
    return cleanup_closed and operation_connection_closed


def _reserve_private_scratch(parent: Path) -> _PrivateScratch:
    """Create a fresh root for ChangePassword without reusing operator storage."""
    try:
        before = os.lstat(parent)
        scratch = Path(tempfile.mkdtemp(prefix=".ios-rehydrate-device-link-", dir=parent))
        after = os.lstat(parent)
        scratch_metadata = os.lstat(scratch)
    except OSError as exc:
        raise RehydrateError(
            "private backup scratch space could not be reserved",
            code=ExitCode.IO,
            reason="BACKUP_SCRATCH_CREATE_FAILED",
        ) from exc
    if (
        _is_reparse(before)
        or _is_reparse(after)
        or _is_reparse(scratch_metadata)
        or not stat.S_ISDIR(before.st_mode)
        or not stat.S_ISDIR(after.st_mode)
        or not stat.S_ISDIR(scratch_metadata.st_mode)
        or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
        or scratch.parent != parent
    ):
        raise RehydrateError(
            "private backup scratch space is unsafe",
            code=ExitCode.POLICY_REFUSED,
            reason="BACKUP_SCRATCH_UNSAFE",
        )
    return _PrivateScratch(scratch, (scratch_metadata.st_dev, scratch_metadata.st_ino))


def _remove_empty_private_scratch(scratch: _PrivateScratch) -> bool:
    """Remove only the unchanged empty directory that this process reserved."""
    try:
        metadata = os.lstat(scratch.path)
        if (
            stat.S_ISDIR(metadata.st_mode)
            and not _is_reparse(metadata)
            and (metadata.st_dev, metadata.st_ino) == scratch.identity
        ):
            scratch.path.rmdir()
        else:
            return False
    except FileNotFoundError:
        return True
    except OSError:
        # A nonempty or changed scratch directory is preserved; recursive cleanup
        # could delete operator data and must never replace the primary outcome.
        return False
    try:
        os.lstat(scratch.path)
    except FileNotFoundError:
        return True
    except OSError:
        return False
    return False


async def _reconcile_encryption_enable(lockdown: Any) -> bool:
    """Bound a post-request state check after an interrupted operation."""

    try:
        async with asyncio.timeout(ENCRYPTION_RECONCILE_TIMEOUT_SECONDS):
            return await encryption_status(lockdown)
    except (Exception, asyncio.CancelledError, KeyboardInterrupt):
        raise RehydrateError(
            "backup-encryption enable outcome is unknown; inspect the device",
            code=ExitCode.OUTCOME_UNKNOWN,
            reason="BACKUP_ENCRYPTION_OUTCOME_UNKNOWN",
        ) from None


def preflight_backup_output(output_root: Path) -> Path:
    """Validate a new backup destination without creating or mutating it."""
    raw = Path(output_root)
    if not raw.name or raw.name in {".", ".."}:
        raise RehydrateError(
            "backup output name is invalid",
            code=ExitCode.IO,
            reason="BACKUP_OUTPUT_INVALID",
        )
    parent = _safe_existing_directory(raw.parent, reason="BACKUP_PARENT_INVALID")
    target = parent / raw.name
    if os.path.lexists(target):
        raise RehydrateError(
            "backup output already exists; refusing reuse or overwrite",
            code=ExitCode.IO,
            reason="BACKUP_OUTPUT_EXISTS",
        )
    return target


def _reserve_output_root(output_root: Path) -> Path:
    target = preflight_backup_output(output_root)
    try:
        target.mkdir(mode=0o700, parents=False, exist_ok=False)
    except FileExistsError as exc:
        raise RehydrateError(
            "backup output appeared concurrently; refusing reuse",
            code=ExitCode.IO,
            reason="BACKUP_OUTPUT_RACE",
        ) from exc
    except OSError as exc:
        raise RehydrateError(
            "backup output could not be reserved",
            code=ExitCode.IO,
            reason="BACKUP_OUTPUT_CREATE_FAILED",
        ) from exc
    if not _has_safe_directory_chain(target):
        raise RehydrateError(
            "backup output or one of its ancestors is a link or reparse point",
            code=ExitCode.POLICY_REFUSED,
            reason="BACKUP_PATH_UNSAFE",
        )
    return target


def _safe_existing_directory(path: Path, *, reason: str) -> Path:
    raw = Path(path)
    if not _has_safe_directory_chain(raw):
        code = ExitCode.BACKUP_VERIFY if reason.startswith("BACKUP_LAYOUT") else ExitCode.IO
        raise RehydrateError("backup directory is missing or unsafe", code=code, reason=reason)
    try:
        return raw.resolve(strict=True)
    except OSError as exc:
        code = ExitCode.BACKUP_VERIFY if reason.startswith("BACKUP_LAYOUT") else ExitCode.IO
        raise RehydrateError(
            "backup directory could not be resolved", code=code, reason=reason
        ) from exc


def _has_safe_directory_chain(path: Path) -> bool:
    """Check every existing component from the filesystem anchor without following links."""
    try:
        absolute = Path(os.path.abspath(path))
        if not absolute.is_absolute() or not absolute.anchor:
            return False
        current = Path(absolute.anchor)
        components = absolute.parts[1:]
        metadata = os.lstat(current)
        if not stat.S_ISDIR(metadata.st_mode) or _is_reparse(metadata):
            return False
        for component in components:
            current /= component
            metadata = os.lstat(current)
            if not stat.S_ISDIR(metadata.st_mode) or _is_reparse(metadata):
                return False
    except (OSError, ValueError):
        return False
    return True


def _is_safe_directory(path: Path) -> bool:
    try:
        metadata = os.lstat(path)
    except OSError:
        return False
    return stat.S_ISDIR(metadata.st_mode) and not _is_reparse(metadata)


def _regular_file_metadata(path: Path) -> os.stat_result | None:
    try:
        metadata = os.lstat(path)
    except OSError:
        return None
    if not stat.S_ISREG(metadata.st_mode) or _is_reparse(metadata):
        return None
    return metadata


def _read_bounded_metadata(path: Path, size_limit: int) -> bytes:
    """Read a regular metadata file without trusting an earlier size check."""
    try:
        with path.open("rb") as stream:
            opened = os.fstat(stream.fileno())
            if not stat.S_ISREG(opened.st_mode) or _is_reparse(opened) or opened.st_size <= 0:
                raise _verify_error(
                    "required backup metadata is unsafe or empty",
                    "BACKUP_METADATA_INVALID",
                )
            if opened.st_size > size_limit:
                raise _verify_error(
                    "backup plist metadata is too large",
                    "BACKUP_METADATA_TOO_LARGE",
                )
            data = stream.read(size_limit + 1)
    except RehydrateError:
        raise
    except OSError as exc:
        raise _verify_error(
            "required backup metadata is unreadable", "BACKUP_METADATA_INVALID"
        ) from exc
    if not data:
        raise _verify_error("required backup metadata is empty", "BACKUP_METADATA_EMPTY")
    if len(data) > size_limit:
        raise _verify_error("backup plist metadata is too large", "BACKUP_METADATA_TOO_LARGE")
    return data


def _is_reparse(metadata: os.stat_result) -> bool:
    attributes = getattr(metadata, "st_file_attributes", 0)
    return stat.S_ISLNK(metadata.st_mode) or bool(attributes & _REPARSE_POINT)


def _is_single_component(value: str) -> bool:
    return (
        bool(value)
        and value not in {".", ".."}
        and "\\" not in value
        and "/" not in value
        and "\x00" not in value
        and ":" not in value
        and not value.endswith((" ", "."))
        and Path(value).name == value
        and not Path(value).anchor
    )


def _load_plist(data: bytes) -> dict[str, Any]:
    try:
        value = plistlib.loads(data)
    except (plistlib.InvalidFileException, ValueError, TypeError, OverflowError) as exc:
        raise _verify_error("backup plist metadata is invalid", "BACKUP_METADATA_INVALID") from exc
    if not isinstance(value, dict):
        raise _verify_error("backup plist metadata has an invalid shape", "BACKUP_METADATA_INVALID")
    return value


def _validate_identifiers(
    info: dict[str, Any], manifest: dict[str, Any], expected_udid: str
) -> None:
    lockdown = manifest.get("Lockdown")
    identifiers = (
        info.get("Target Identifier"),
        info.get("Unique Identifier"),
        lockdown.get("UniqueDeviceID") if isinstance(lockdown, dict) else None,
    )
    expected = expected_udid.casefold()
    if any(type(value) is not str or value.casefold() != expected for value in identifiers):
        raise _verify_error("backup identifiers do not match", "BACKUP_IDENTIFIER_MISMATCH")


def _exact_device_directory(root: Path, expected_udid: str, budget: _DirectoryEntryBudget) -> Path:
    """Stream the backup root and reject as soon as its exact shape is disproved."""
    device_root: Path | None = None
    try:
        with os.scandir(root) as entries:
            for entry in entries:
                budget.consume()
                if device_root is not None or entry.name != expected_udid:
                    raise _verify_error(
                        "backup root does not contain the exact device directory",
                        "BACKUP_LAYOUT_INVALID",
                    )
                metadata = entry.stat(follow_symlinks=False)
                if _is_reparse(metadata) or not stat.S_ISDIR(metadata.st_mode):
                    raise _verify_error(
                        "backup device directory is unsafe",
                        "BACKUP_LAYOUT_INVALID",
                    )
                device_root = Path(entry.path)
    except RehydrateError:
        raise
    except OSError as exc:
        raise _verify_error(
            "backup layout could not be inspected", "BACKUP_LAYOUT_INVALID"
        ) from exc
    if device_root is None:
        raise _verify_error(
            "backup root does not contain the exact device directory",
            "BACKUP_LAYOUT_INVALID",
        )
    return device_root


def _hashed_payload_totals(device_root: Path, budget: _DirectoryEntryBudget) -> tuple[int, int]:
    count = 0
    total = 0
    try:
        buckets = os.scandir(device_root)
    except OSError as exc:
        raise _verify_error(
            "backup payload could not be inspected", "BACKUP_PAYLOAD_INVALID"
        ) from exc
    with buckets:
        for bucket in buckets:
            budget.consume()
            if not re.fullmatch(r"[0-9a-fA-F]{2}", bucket.name):
                continue
            try:
                bucket_metadata = bucket.stat(follow_symlinks=False)
            except OSError as exc:
                raise _verify_error(
                    "backup payload metadata is unreadable", "BACKUP_PAYLOAD_INVALID"
                ) from exc
            if _is_reparse(bucket_metadata) or not stat.S_ISDIR(bucket_metadata.st_mode):
                raise _verify_error(
                    "backup contains an unsafe payload bucket", "BACKUP_PAYLOAD_INVALID"
                )
            try:
                entries = os.scandir(bucket.path)
            except OSError as exc:
                raise _verify_error(
                    "backup payload could not be inspected", "BACKUP_PAYLOAD_INVALID"
                ) from exc
            with entries:
                for entry in entries:
                    budget.consume()
                    try:
                        metadata = entry.stat(follow_symlinks=False)
                    except OSError as exc:
                        raise _verify_error(
                            "backup payload metadata is unreadable",
                            "BACKUP_PAYLOAD_INVALID",
                        ) from exc
                    if _is_reparse(metadata):
                        raise _verify_error(
                            "backup contains an unsafe link", "BACKUP_PAYLOAD_INVALID"
                        )
                    if not stat.S_ISREG(metadata.st_mode) or not _HASHED_PAYLOAD.fullmatch(
                        entry.name
                    ):
                        continue
                    if bucket.name.casefold() != entry.name[:2].casefold():
                        continue
                    if count >= MAX_HASHED_PAYLOAD_COUNT:
                        raise _verify_error(
                            "backup contains too many hashed payload files",
                            "BACKUP_PAYLOAD_COUNT_LIMIT",
                        )
                    count += 1
                    total += metadata.st_size
    return count, total


def _verify_error(message: str, reason: str) -> RehydrateError:
    return RehydrateError(message, code=ExitCode.BACKUP_VERIFY, reason=reason)
