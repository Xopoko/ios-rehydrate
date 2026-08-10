# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 iOS Rehydrate contributors
"""Minimal, redacted, no-overwrite JSON receipts."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from ios_rehydrate import __version__
from ios_rehydrate.errors import ExitCode, RehydrateError

SCHEMA = "urn:ios-rehydrate:receipt:v1"
MAX_RECEIPT_BYTES = 1024 * 1024
MAX_RECEIPT_AGE = timedelta(hours=24)
MAX_RECEIPT_FUTURE_SKEW = timedelta(minutes=5)
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_WINDOWS_INVALID_LEAF_CHARACTERS = frozenset('<>:"/\\|?*')
_WINDOWS_RESERVED_NAMES = frozenset(
    {
        "CON",
        "PRN",
        "AUX",
        "NUL",
        "CLOCK$",
        "CONIN$",
        "CONOUT$",
        *(f"COM{number}" for number in range(1, 10)),
        *(f"LPT{number}" for number in range(1, 10)),
        "COM¹",
        "COM²",
        "COM³",
        "LPT¹",
        "LPT²",
        "LPT³",
    }
)


class ReceiptReservation:
    """An exclusively-created receipt held open until commit or safe abort."""

    def __init__(self, path: Path, descriptor: int) -> None:
        self.path = path
        self._descriptor: int | None = descriptor
        metadata = os.fstat(descriptor)
        self._identity = (metadata.st_dev, metadata.st_ino)
        self._operation_started = False
        self._committed = False

    @property
    def operation_started(self) -> bool:
        return self._operation_started

    def mark_operation_started(self) -> None:
        """Prevent a later failure path from deleting mutation evidence."""
        if self._descriptor is None:
            raise RehydrateError(
                "receipt reservation is no longer active",
                code=ExitCode.IO,
                reason="RECEIPT_RESERVATION_INVALID",
            )
        self._assert_identity(empty=True)
        self._operation_started = True

    def commit(self, payload: dict[str, Any]) -> None:
        """Write through the held descriptor without reopening or replacing the path."""
        descriptor = self._descriptor
        if descriptor is None or self._committed:
            raise RehydrateError(
                "receipt reservation is no longer active",
                code=ExitCode.IO,
                reason="RECEIPT_RESERVATION_INVALID",
            )
        try:
            data = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
            if not 0 < len(data) <= MAX_RECEIPT_BYTES:
                raise RehydrateError(
                    "receipt exceeds the safe size limit",
                    code=ExitCode.IO,
                    reason="RECEIPT_TOO_LARGE",
                )
            self._assert_identity(empty=True)
            view = memoryview(data)
            written = 0
            while written < len(view):
                count = os.write(descriptor, view[written:])
                if count <= 0:
                    raise OSError("receipt write made no progress")
                written += count
            os.fsync(descriptor)
            self._assert_identity(expected_size=len(data))
            self._descriptor = None
            os.close(descriptor)
        except RehydrateError:
            self._close_quietly()
            raise
        except Exception as exc:
            self._close_quietly()
            raise RehydrateError(
                "receipt finalization failed; reserved evidence was preserved",
                code=ExitCode.IO,
                reason="RECEIPT_FINALIZE_FAILED",
            ) from exc
        self._descriptor = None
        self._committed = True

    def abort(self) -> bool:
        """Remove only the exact file this object reserved, never a replacement."""
        if self._committed:
            return False
        matches = self._matches_reserved_path()
        self._close_quietly()
        if not matches or not self._matches_reserved_path():
            return False
        try:
            self.path.unlink()
        except FileNotFoundError:
            return True
        except OSError:
            return False
        return True

    def abort_on_pre_operation_failure(self) -> None:
        """Abort a pristine reservation, preserving it after mutation may have begun."""
        if self._operation_started:
            self.preserve()
        else:
            self.abort()

    def preserve(self) -> None:
        """Close the descriptor while retaining reserved or partial evidence."""
        self._close_quietly()

    def _assert_identity(self, *, empty: bool = False, expected_size: int | None = None) -> None:
        descriptor = self._descriptor
        if descriptor is None:
            raise RehydrateError(
                "receipt reservation is no longer active",
                code=ExitCode.IO,
                reason="RECEIPT_RESERVATION_INVALID",
            )
        metadata = os.fstat(descriptor)
        attributes = getattr(metadata, "st_file_attributes", 0)
        size_valid = (not empty or metadata.st_size == 0) and (
            expected_size is None or metadata.st_size == expected_size
        )
        if (
            (metadata.st_dev, metadata.st_ino) != self._identity
            or not stat.S_ISREG(metadata.st_mode)
            or bool(attributes & _REPARSE_POINT)
            or metadata.st_nlink != 1
            or not size_valid
            or not self._matches_reserved_path()
        ):
            raise RehydrateError(
                "receipt reservation identity changed",
                code=ExitCode.IO,
                reason="RECEIPT_RESERVATION_CHANGED",
            )

    def _matches_reserved_path(self) -> bool:
        try:
            metadata = os.lstat(self.path)
        except OSError:
            return False
        attributes = getattr(metadata, "st_file_attributes", 0)
        return (
            stat.S_ISREG(metadata.st_mode)
            and not stat.S_ISLNK(metadata.st_mode)
            and not bool(attributes & _REPARSE_POINT)
            and (metadata.st_dev, metadata.st_ino) == self._identity
        )

    def _close_quietly(self) -> None:
        descriptor = self._descriptor
        self._descriptor = None
        if descriptor is not None:
            with suppress(OSError):
                os.close(descriptor)


def envelope(kind: str, evidence: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "tool": "ios-rehydrate",
        "tool_version": __version__,
        "kind": kind,
        "created_at": datetime.now(UTC).isoformat(),
        "evidence": evidence,
    }


def reserve_receipt(path: Path) -> ReceiptReservation:
    """Reserve a safe, new receipt path with ``O_EXCL`` and retain its descriptor."""
    raw = Path(path)
    leaf = raw.name
    invalid_windows_leaf = (
        any(character in _WINDOWS_INVALID_LEAF_CHARACTERS for character in leaf)
        or any(ord(character) < 32 for character in leaf)
        or leaf.endswith((" ", "."))
        or _is_windows_reserved_leaf(leaf)
    )
    if not leaf or leaf in {".", ".."} or invalid_windows_leaf:
        raise RehydrateError(
            "receipt path is invalid",
            code=ExitCode.IO,
            reason="RECEIPT_PATH_INVALID",
        )
    try:
        parent = _existing_directory_without_links(raw.parent)
    except OSError as exc:
        raise RehydrateError(
            "receipt parent is not a directory",
            code=ExitCode.IO,
            reason="RECEIPT_PARENT_INVALID",
        ) from exc
    target = parent / leaf
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    for optional_flag in ("O_BINARY", "O_CLOEXEC", "O_NOINHERIT", "O_NOFOLLOW"):
        flags |= getattr(os, optional_flag, 0)
    try:
        descriptor = os.open(target, flags, 0o600)
    except FileExistsError as exc:
        raise RehydrateError(
            "receipt already exists; refusing overwrite",
            code=ExitCode.IO,
            reason="RECEIPT_EXISTS",
        ) from exc
    except OSError as exc:
        raise RehydrateError(
            "receipt path could not be reserved safely",
            code=ExitCode.IO,
            reason="RECEIPT_RESERVATION_FAILED",
        ) from exc
    reservation = ReceiptReservation(target, descriptor)
    try:
        reservation._assert_identity(empty=True)
    except BaseException:
        reservation.abort()
        raise
    return reservation


def _is_windows_reserved_leaf(leaf: str) -> bool:
    stem = leaf.rstrip(" .").split(".", 1)[0].upper()
    return stem in _WINDOWS_RESERVED_NAMES


def _existing_directory_without_links(path: Path) -> Path:
    """Resolve an existing directory only after every ancestor passes no-follow checks."""
    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor)
    components = absolute.parts[1:] if absolute.anchor else absolute.parts
    for component in components:
        current /= component
        metadata = os.lstat(current)
        attributes = getattr(metadata, "st_file_attributes", 0)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or bool(attributes & _REPARSE_POINT)
        ):
            raise OSError("unsafe directory ancestor")
    return absolute.resolve(strict=True)


def write_new_receipt(path: Path, payload: dict[str, Any]) -> None:
    """Reserve and write a receipt for callers with no external operation boundary."""
    reservation = reserve_receipt(path)
    try:
        reservation.commit(payload)
    except BaseException:
        reservation.abort()
        raise


def read_receipt(
    path: Path,
    *,
    expected_kind: str,
    max_age: timedelta | None = None,
) -> tuple[dict[str, Any], str]:
    """Read one bounded, regular receipt and validate its public envelope."""
    try:
        metadata = os.lstat(path)
        attributes = getattr(metadata, "st_file_attributes", 0)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or bool(attributes & _REPARSE_POINT)
            or not 0 < metadata.st_size <= MAX_RECEIPT_BYTES
        ):
            raise OSError
        with path.open("rb") as stream:
            opened = os.fstat(stream.fileno())
            if (metadata.st_dev, metadata.st_ino) != (opened.st_dev, opened.st_ino):
                raise OSError
            data = stream.read(MAX_RECEIPT_BYTES + 1)
    except OSError as exc:
        raise RehydrateError(
            "backup receipt is missing or unsafe",
            code=ExitCode.POLICY_REFUSED,
            reason="BACKUP_RECEIPT_INVALID",
        ) from exc
    if len(data) != metadata.st_size:
        raise RehydrateError(
            "backup receipt changed while being read",
            code=ExitCode.POLICY_REFUSED,
            reason="BACKUP_RECEIPT_CHANGED",
        )
    try:
        payload = json.loads(data)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise RehydrateError(
            "backup receipt is not valid JSON",
            code=ExitCode.POLICY_REFUSED,
            reason="BACKUP_RECEIPT_INVALID",
        ) from exc
    if (
        not isinstance(payload, dict)
        or payload.get("schema") != SCHEMA
        or payload.get("tool") != "ios-rehydrate"
        or payload.get("tool_version") != __version__
        or payload.get("kind") != expected_kind
        or not isinstance(payload.get("evidence"), dict)
    ):
        raise RehydrateError(
            "backup receipt does not match the required workflow",
            code=ExitCode.POLICY_REFUSED,
            reason="BACKUP_RECEIPT_MISMATCH",
        )
    created_at = payload.get("created_at")
    try:
        created = datetime.fromisoformat(created_at) if isinstance(created_at, str) else None
        if created is None or created.tzinfo is None or created.utcoffset() is None:
            raise ValueError
        created = created.astimezone(UTC)
    except (TypeError, ValueError, OverflowError) as exc:
        raise RehydrateError(
            "backup receipt has an invalid creation time",
            code=ExitCode.POLICY_REFUSED,
            reason="BACKUP_RECEIPT_TIME_INVALID",
        ) from exc
    now = datetime.now(UTC)
    if created > now + MAX_RECEIPT_FUTURE_SKEW:
        raise RehydrateError(
            "backup receipt creation time is in the future",
            code=ExitCode.POLICY_REFUSED,
            reason="BACKUP_RECEIPT_TIME_INVALID",
        )
    if max_age is not None and (max_age <= timedelta(0) or created < now - max_age):
        raise RehydrateError(
            "backup receipt is too old for this safety gate",
            code=ExitCode.POLICY_REFUSED,
            reason="BACKUP_RECEIPT_STALE",
        )
    return payload, hashlib.sha256(data).hexdigest()
