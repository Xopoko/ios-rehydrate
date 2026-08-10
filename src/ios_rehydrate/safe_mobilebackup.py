# SPDX-License-Identifier: GPL-3.0-or-later
# Portions adapted from pymobiledevice3 DeviceLink/Mobilebackup2 code at
# https://github.com/doronz88/pymobiledevice3/tree/6965e0d3fc24ea058f6da3bfb3fdc05eacb7ba6c
# Copyright (C) pymobiledevice3 authors and contributors
# Copyright (C) 2026 iOS Rehydrate contributors
"""Constrain pymobiledevice3's MobileBackup2 writes to one fresh local root.

This module is a deliberately narrow compatibility boundary for
``pymobiledevice3==10.7.1``.  That release's :class:`DeviceLink` joins paths
supplied by the device directly onto a caller-provided directory.  We reuse its
wire protocol and :class:`Mobilebackup2Service` orchestration, but replace every
DeviceLink handler that reads or mutates the local filesystem.  Re-review this
subclass before changing the pinned dependency: the upstream handler table and
method semantics are part of this boundary.

This is a modified derivative of the pinned upstream ``services/device_link.py``
and ``services/mobilebackup2.py`` implementation, not a clean-room rewrite.
The 2026-08-09 modifications add fail-closed path confinement, bounded control
and transfer parsing, redacted errors, explicit cleanup evidence, and tests for
the exact inherited handler/protocol contract.  See ``docs/PROVENANCE.md``.

The checks are lexical and fail closed.  Before each filesystem operation the
fresh root's identity is checked, followed by ``lstat`` checks for every
existing ancestor and target.  Links and Windows reparse points are never
followed.  There is intentionally no override switch.
"""

from __future__ import annotations

import asyncio
import ctypes
import datetime
import errno
import os
import plistlib
import shutil
import stat
import struct
from collections.abc import AsyncIterator, Callable, Iterable, Mapping
from contextlib import asynccontextmanager, suppress
from pathlib import Path
from types import TracebackType
from typing import Any, BinaryIO, NoReturn, cast

from pymobiledevice3.exceptions import PyMobileDevice3Exception
from pymobiledevice3.service_connection import ServiceConnection
from pymobiledevice3.services.device_link import (
    APPLE_EPOCH,
    BULK_OPERATION_ERROR,
    CODE_ERROR_LOCAL,
    CODE_ERROR_REMOTE,
    CODE_FILE_DATA,
    CODE_FORMAT,
    CODE_SUCCESS,
    ERRNO_TO_DEVICE_ERROR,
    FILE_TRANSFER_TERMINATOR,
    SIZE_FORMAT,
    DeviceLink,
    DLMessage,
)
from pymobiledevice3.services.mobilebackup2 import (
    BackupFilterCallback,
    Mobilebackup2Service,
)

_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_OPEN_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_OPEN_BINARY = getattr(os, "O_BINARY", 0)
_MAX_DEVICE_TEXT_BYTES = 4096
_MAX_CONTROL_PLIST_BYTES = 16 * 1024 * 1024
_MAX_TRANSFER_CHUNK_BYTES = 128 * 1024 * 1024
_MAX_DIRECTORY_ENTRIES = 50_000
_MAX_LOCAL_TREE_ENTRIES = 2_000_000
_CLEANUP_TIMEOUT_SECONDS = 5.0
_SAFETY_ERROR = "mobile backup filesystem request refused"
_TRANSFER_ERROR = "mobile backup transfer failed"
_CLEANUP_ERROR = "mobile backup connection cleanup failed"
_LOCAL_READ_ERROR = b"local read failed"
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
        *(f"COM{number}" for number in "¹²³"),
        *(f"LPT{number}" for number in "¹²³"),
    }
)
_WINDOWS_INVALID_CHARACTERS = frozenset('*?"<>|')
_ALLOWED_CONTROL_COMMANDS = frozenset(
    {
        "DLContentsOfDirectory",
        "DLMessageCopyItem",
        "DLMessageCreateDirectory",
        "DLMessageDeviceReady",
        "DLMessageDownloadFiles",
        "DLMessageGetFreeDiskSpace",
        "DLMessageMoveItems",
        "DLMessageProcessMessage",
        "DLMessagePurgeDiskSpace",
        "DLMessageRemoveItems",
        "DLMessageUploadFiles",
        "DLMessageVersionExchange",
    }
)
_MIN_CONTROL_ITEMS = {
    "DLContentsOfDirectory": 2,
    "DLMessageCopyItem": 3,
    "DLMessageCreateDirectory": 2,
    "DLMessageDeviceReady": 1,
    "DLMessageDownloadFiles": 4,
    "DLMessageGetFreeDiskSpace": 1,
    "DLMessageMoveItems": 4,
    "DLMessageProcessMessage": 2,
    "DLMessagePurgeDiskSpace": 1,
    "DLMessageRemoveItems": 4,
    "DLMessageUploadFiles": 3,
    "DLMessageVersionExchange": 2,
}


class MobileBackupSafetyError(PyMobileDevice3Exception):
    """A constant, privacy-safe failure raised by the local path boundary."""


def _refuse(message: str = _SAFETY_ERROR) -> NoReturn:
    raise MobileBackupSafetyError(message) from None


def _is_reparse(metadata: os.stat_result) -> bool:
    attributes = getattr(metadata, "st_file_attributes", 0)
    return stat.S_ISLNK(metadata.st_mode) or bool(attributes & _REPARSE_POINT)


def _identity(metadata: os.stat_result) -> tuple[int, int]:
    return metadata.st_dev, metadata.st_ino


def _assert_safe_directory_chain(path: Path) -> Path:
    """Return an absolute directory only if no component is a link/reparse point."""
    try:
        absolute = Path(os.path.abspath(path))
        if not absolute.is_absolute() or not absolute.anchor:
            _refuse()
        current = Path(absolute.anchor)
        metadata = os.lstat(current)
        if not stat.S_ISDIR(metadata.st_mode) or _is_reparse(metadata):
            _refuse()
        for component in absolute.parts[1:]:
            current /= component
            metadata = os.lstat(current)
            if not stat.S_ISDIR(metadata.st_mode) or _is_reparse(metadata):
                _refuse()
    except MobileBackupSafetyError:
        raise
    except (OSError, ValueError):
        _refuse()
    return absolute


def _relative_parts(value: object) -> tuple[str, ...]:
    """Parse one device-controlled path without platform normalization."""
    if type(value) is not str:
        _refuse()
    raw = value
    if not raw or len(raw.encode("utf-8", errors="surrogatepass")) > _MAX_DEVICE_TEXT_BYTES:
        _refuse()
    if raw.startswith("/") or "\\" in raw or "\x00" in raw or ":" in raw:
        _refuse()

    parts = tuple(raw.split("/"))
    for component in parts:
        if not component or component in {".", ".."}:
            _refuse()
        if any(ord(character) < 32 for character in component):
            _refuse()
        if any(character in _WINDOWS_INVALID_CHARACTERS for character in component):
            _refuse()
        if component.endswith((" ", ".")):
            _refuse()
        windows_stem = component.partition(".")[0].rstrip(" ").upper()
        if windows_stem in _WINDOWS_RESERVED_NAMES:
            _refuse()
    return parts


class SafeDeviceLink(DeviceLink):
    """DeviceLink whose local filesystem operations stay beneath one root."""

    def __init__(
        self,
        service: ServiceConnection,
        root_path: Path,
        preserve_file: Callable[[str, str], bool] | None = None,
        post_file_receive: Callable[[str, str], None] | None = None,
    ) -> None:
        raw_root = Path(root_path)
        try:
            absolute = _assert_safe_directory_chain(raw_root)
            before = os.lstat(absolute)
            resolved = absolute.resolve(strict=True)
            resolved_metadata = os.lstat(resolved)
        except MobileBackupSafetyError:
            raise
        except (OSError, RuntimeError):
            _refuse()
        if (
            not stat.S_ISDIR(before.st_mode)
            or _is_reparse(before)
            or not stat.S_ISDIR(resolved_metadata.st_mode)
            or _is_reparse(resolved_metadata)
            or _identity(before) != _identity(resolved_metadata)
        ):
            _refuse()
        super().__init__(service, resolved, preserve_file, post_file_receive)
        self._root_identity = _identity(resolved_metadata)

    def _assert_root_identity(self) -> None:
        try:
            metadata = os.lstat(self.root_path)
        except OSError:
            _refuse()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or _is_reparse(metadata)
            or _identity(metadata) != self._root_identity
        ):
            _refuse()

    def _assert_exact_existing_name(
        self,
        parent: Path,
        component: str,
        expected: os.stat_result,
    ) -> None:
        """Reject case, short-name, and other platform aliases for an existing child."""
        inspected = 0
        try:
            with os.scandir(parent) as entries:
                for entry in entries:
                    inspected += 1
                    if inspected > _MAX_DIRECTORY_ENTRIES:
                        _refuse()
                    if entry.name != component:
                        continue
                    # On Windows, DirEntry.stat() may expose zeroed dev/inode
                    # fields; lstat on the enumerated spelling preserves the
                    # identity needed for the alias check.
                    observed = os.lstat(entry.path)
                    if _is_reparse(observed) or _identity(observed) != _identity(expected):
                        _refuse()
                    return
        except MobileBackupSafetyError:
            raise
        except OSError:
            _refuse()
        _refuse()

    def _checked_path(self, value: object) -> tuple[Path, os.stat_result | None, tuple[str, ...]]:
        parts = _relative_parts(value)
        self._assert_root_identity()
        candidate = self.root_path.joinpath(*parts)
        try:
            candidate.relative_to(self.root_path)
        except ValueError:
            _refuse()

        current = self.root_path
        target_metadata: os.stat_result | None = None
        missing_ancestor = False
        for index, component in enumerate(parts):
            parent = current
            current /= component
            if missing_ancestor:
                continue
            try:
                metadata = os.lstat(current)
            except FileNotFoundError:
                missing_ancestor = True
                continue
            except OSError:
                _refuse()
            if _is_reparse(metadata):
                _refuse()
            self._assert_exact_existing_name(parent, component, metadata)
            if index < len(parts) - 1 and not stat.S_ISDIR(metadata.st_mode):
                _refuse()
            if index == len(parts) - 1:
                target_metadata = metadata
        self._assert_root_identity()
        return candidate, target_metadata, parts

    def _ensure_directories(self, parts: tuple[str, ...]) -> None:
        for index in range(1, len(parts) + 1):
            prefix = "/".join(parts[:index])
            path, metadata, _ = self._checked_path(prefix)
            if metadata is None:
                try:
                    path.mkdir(mode=0o700, parents=False, exist_ok=False)
                except OSError:
                    _refuse()
                path, metadata, _ = self._checked_path(prefix)
            if metadata is None or not stat.S_ISDIR(metadata.st_mode):
                _refuse()

    def _ensure_parent(self, parts: tuple[str, ...]) -> None:
        if len(parts) > 1:
            self._ensure_directories(parts[:-1])
        else:
            self._assert_root_identity()

    def _assert_tree_safe(self, path: Path) -> None:
        pending = [path]
        inspected = 0
        while pending:
            current = pending.pop()
            self._assert_root_identity()
            try:
                metadata = os.lstat(current)
            except OSError:
                _refuse()
            inspected += 1
            if inspected > _MAX_LOCAL_TREE_ENTRIES or _is_reparse(metadata):
                _refuse()
            if stat.S_ISREG(metadata.st_mode):
                continue
            if not stat.S_ISDIR(metadata.st_mode):
                _refuse()
            try:
                with os.scandir(current) as entries:
                    for entry in entries:
                        entry_metadata = entry.stat(follow_symlinks=False)
                        inspected += 1
                        if inspected > _MAX_LOCAL_TREE_ENTRIES or _is_reparse(entry_metadata):
                            _refuse()
                        if stat.S_ISDIR(entry_metadata.st_mode):
                            pending.append(Path(entry.path))
                        elif not stat.S_ISREG(entry_metadata.st_mode):
                            _refuse()
            except MobileBackupSafetyError:
                raise
            except OSError:
                _refuse()

    def _open_for_read(self, value: object) -> BinaryIO:
        path, metadata, _ = self._checked_path(value)
        if metadata is None:
            raise FileNotFoundError(errno.ENOENT, _LOCAL_READ_ERROR.decode("ascii")) from None
        if stat.S_ISDIR(metadata.st_mode):
            raise IsADirectoryError(errno.EISDIR, _LOCAL_READ_ERROR.decode("ascii")) from None
        if not stat.S_ISREG(metadata.st_mode):
            _refuse()
        descriptor = -1
        try:
            descriptor = os.open(path, os.O_RDONLY | _OPEN_BINARY | _OPEN_NOFOLLOW)
            opened = os.fstat(descriptor)
            current = os.lstat(path)
            self._assert_root_identity()
            if (
                not stat.S_ISREG(opened.st_mode)
                or _is_reparse(opened)
                or _is_reparse(current)
                or _identity(opened) != _identity(current)
            ):
                _refuse()
            return cast(BinaryIO, os.fdopen(descriptor, "rb"))
        except MobileBackupSafetyError:
            if descriptor >= 0:
                with suppress(OSError):
                    os.close(descriptor)
            raise
        except OSError:
            if descriptor >= 0:
                with suppress(OSError):
                    os.close(descriptor)
            raise

    def _open_for_write(self, value: object) -> BinaryIO:
        path, metadata, parts = self._checked_path(value)
        self._ensure_parent(parts)
        path, metadata, _ = self._checked_path(value)
        if metadata is not None and not stat.S_ISREG(metadata.st_mode):
            _refuse()

        descriptor = -1
        try:
            descriptor = os.open(
                path,
                os.O_WRONLY | os.O_CREAT | _OPEN_BINARY | _OPEN_NOFOLLOW,
                0o600,
            )
            opened = os.fstat(descriptor)
            current = os.lstat(path)
            self._assert_root_identity()
            if (
                not stat.S_ISREG(opened.st_mode)
                or _is_reparse(opened)
                or _is_reparse(current)
                or _identity(opened) != _identity(current)
            ):
                _refuse()
            os.ftruncate(descriptor, 0)
            os.lseek(descriptor, 0, os.SEEK_SET)
            return cast(BinaryIO, os.fdopen(descriptor, "wb"))
        except MobileBackupSafetyError:
            if descriptor >= 0:
                with suppress(OSError):
                    os.close(descriptor)
            raise
        except OSError:
            if descriptor >= 0:
                with suppress(OSError):
                    os.close(descriptor)
            _refuse()

    async def download_files(self, message: DLMessage) -> None:
        try:
            files = message[1]
            if isinstance(files, (str, bytes)) or not isinstance(files, Iterable):
                _refuse()
            status: dict[str, dict[str, Any]] = {}
            file_count = 0
            for value in files:
                file_count += 1
                if file_count > _MAX_DIRECTORY_ENTRIES:
                    _refuse()
                parts = _relative_parts(value)
                remote_path = "/".join(parts)
                encoded = remote_path.encode("utf-8")
                stream: BinaryIO | None = None
                local_error: OSError | None = None
                try:
                    # Validate before reflecting any untrusted value onto the wire.
                    stream = self._open_for_read(remote_path)
                except OSError as exc:
                    local_error = exc
                await self._sendall(struct.pack(SIZE_FORMAT, len(encoded)) + encoded)
                if stream is not None:
                    with stream:
                        while True:
                            try:
                                chunk = stream.read(_MAX_TRANSFER_CHUNK_BYTES)
                            except OSError as exc:
                                local_error = exc
                                break
                            if not chunk:
                                break
                            await self._sendall(
                                struct.pack(
                                    SIZE_FORMAT,
                                    len(chunk) + struct.calcsize(CODE_FORMAT),
                                )
                                + struct.pack(CODE_FORMAT, CODE_FILE_DATA)
                                + chunk
                            )
                if local_error is not None:
                    error_number = local_error.errno if local_error.errno is not None else errno.EIO
                    device_error = ERRNO_TO_DEVICE_ERROR.get(
                        error_number,
                        ERRNO_TO_DEVICE_ERROR[errno.EIO],
                    )
                    status[remote_path] = {
                        "DLFileErrorString": _LOCAL_READ_ERROR.decode("ascii"),
                        "DLFileErrorCode": ctypes.c_uint64(device_error).value,
                    }
                    await self._sendall(
                        struct.pack(
                            SIZE_FORMAT,
                            len(_LOCAL_READ_ERROR) + struct.calcsize(CODE_FORMAT),
                        )
                        + struct.pack(CODE_FORMAT, CODE_ERROR_LOCAL)
                        + _LOCAL_READ_ERROR
                    )
                    continue
                await self._sendall(
                    struct.pack(SIZE_FORMAT, struct.calcsize(CODE_FORMAT))
                    + struct.pack(CODE_FORMAT, CODE_SUCCESS)
                )
            await self._sendall(FILE_TRANSFER_TERMINATOR)
            if status:
                await self.status_response(BULK_OPERATION_ERROR, "Multi status", status)
            else:
                await self.status_response(0)
        except MobileBackupSafetyError:
            raise
        except (asyncio.CancelledError, KeyboardInterrupt):
            raise
        except Exception:
            _refuse(_TRANSFER_ERROR)

    async def contents_of_directory(self, message: DLMessage) -> None:
        try:
            path, metadata, _ = self._checked_path(message[1])
            if metadata is None or not stat.S_ISDIR(metadata.st_mode):
                _refuse()
            data: dict[str, dict[str, Any]] = {}
            inspected = 0
            with os.scandir(path) as entries:
                for entry in entries:
                    inspected += 1
                    if inspected > _MAX_DIRECTORY_ENTRIES:
                        _refuse()
                    entry_metadata = entry.stat(follow_symlinks=False)
                    if _is_reparse(entry_metadata):
                        _refuse()
                    if stat.S_ISDIR(entry_metadata.st_mode):
                        file_type = "DLFileTypeDirectory"
                    elif stat.S_ISREG(entry_metadata.st_mode):
                        file_type = "DLFileTypeRegular"
                    else:
                        file_type = "DLFileTypeUnknown"
                    modified = datetime.datetime.fromtimestamp(
                        entry_metadata.st_mtime - APPLE_EPOCH
                    ).replace(tzinfo=None)
                    data[entry.name] = {
                        "DLFileType": file_type,
                        "DLFileSize": entry_metadata.st_size,
                        "DLFileModificationDate": modified,
                    }
            self._assert_root_identity()
            await self.status_response(0, status_dict=data)
        except MobileBackupSafetyError:
            raise
        except (asyncio.CancelledError, KeyboardInterrupt):
            raise
        except Exception:
            _refuse()

    async def _receive_bounded_text(self) -> str:
        try:
            (size,) = struct.unpack(SIZE_FORMAT, await self._recvall(struct.calcsize(SIZE_FORMAT)))
            if size > _MAX_DEVICE_TEXT_BYTES:
                _refuse(_TRANSFER_ERROR)
            return (await self._recvall(size)).decode("utf-8")
        except MobileBackupSafetyError:
            raise
        except (asyncio.CancelledError, KeyboardInterrupt):
            raise
        except Exception:
            _refuse(_TRANSFER_ERROR)

    async def _consume_checked_transfer(
        self, size: int, code: int, destination: BinaryIO | None = None
    ) -> tuple[int, int]:
        while size and code == CODE_FILE_DATA:
            if size < 0 or size > _MAX_TRANSFER_CHUNK_BYTES:
                _refuse(_TRANSFER_ERROR)
            chunk = await self._recvall(size)
            if destination is not None:
                destination.write(chunk)
            (frame_size,) = struct.unpack(
                SIZE_FORMAT, await self._recvall(struct.calcsize(SIZE_FORMAT))
            )
            (code,) = struct.unpack(CODE_FORMAT, await self._recvall(struct.calcsize(CODE_FORMAT)))
            if frame_size < struct.calcsize(CODE_FORMAT):
                _refuse(_TRANSFER_ERROR)
            size = frame_size - struct.calcsize(CODE_FORMAT)
        return size, code

    async def upload_files(self, _message: DLMessage) -> None:
        try:
            while True:
                device_name = await self._receive_bounded_text()
                if not device_name:
                    break
                file_name = await self._receive_bounded_text()
                _relative_parts(file_name)
                (frame_size,) = struct.unpack(
                    SIZE_FORMAT, await self._recvall(struct.calcsize(SIZE_FORMAT))
                )
                (code,) = struct.unpack(
                    CODE_FORMAT, await self._recvall(struct.calcsize(CODE_FORMAT))
                )
                if frame_size < struct.calcsize(CODE_FORMAT):
                    _refuse(_TRANSFER_ERROR)
                size = frame_size - struct.calcsize(CODE_FORMAT)
                try:
                    preserve = (
                        self.preserve_file(file_name, device_name)
                        if self.preserve_file is not None
                        else True
                    )
                except Exception:
                    _refuse(_TRANSFER_ERROR)
                if preserve:
                    with self._open_for_write(file_name) as stream:
                        size, code = await self._consume_checked_transfer(size, code, stream)
                else:
                    with self._open_for_write(file_name):
                        pass
                    self._discarded_files.add(Path(*_relative_parts(file_name)))
                    size, code = await self._consume_checked_transfer(size, code)

                if code == CODE_ERROR_REMOTE:
                    # Consume only a small, bounded remote diagnostic and never render it.
                    if size > _MAX_DEVICE_TEXT_BYTES:
                        _refuse(_TRANSFER_ERROR)
                    await self._recvall(size)
                    # Pinned pymobiledevice3 treats this as a recoverable per-file
                    # condition (observed for backup_manifest.db).  Continue without
                    # reproducing its raw, device-controlled warning.
                    continue
                if code != CODE_SUCCESS or size != 0:
                    _refuse(_TRANSFER_ERROR)
                if self.post_file_receive is not None:
                    try:
                        self.post_file_receive(file_name, device_name)
                    except Exception:
                        _refuse(_TRANSFER_ERROR)
            await self.status_response(0)
        except MobileBackupSafetyError:
            raise
        except (asyncio.CancelledError, KeyboardInterrupt):
            raise
        except Exception:
            _refuse(_TRANSFER_ERROR)

    async def move_items(self, message: DLMessage) -> None:
        try:
            items = message[1]
            if not isinstance(items, Mapping):
                _refuse()
            for source_value, destination_value in items.items():
                source, source_metadata, source_parts = self._checked_path(source_value)
                if source_metadata is None and self.preserve_file is not None:
                    continue
                if source_metadata is None:
                    _refuse()

                destination, destination_metadata, destination_parts = self._checked_path(
                    destination_value
                )
                self._ensure_parent(destination_parts)
                destination, destination_metadata, _ = self._checked_path(destination_value)
                if destination_metadata is not None and not (
                    stat.S_ISREG(destination_metadata.st_mode)
                    or stat.S_ISDIR(destination_metadata.st_mode)
                ):
                    _refuse()
                source, source_metadata, _ = self._checked_path(source_value)
                destination, destination_metadata, _ = self._checked_path(destination_value)
                if source_metadata is None:
                    _refuse()
                source_identity = _identity(source_metadata)
                self._assert_tree_safe(source)
                source, source_metadata, _ = self._checked_path(source_value)
                if source_metadata is None or _identity(source_metadata) != source_identity:
                    _refuse()
                destination, destination_metadata, _ = self._checked_path(destination_value)
                if destination_metadata is not None and not (
                    stat.S_ISREG(destination_metadata.st_mode)
                    or stat.S_ISDIR(destination_metadata.st_mode)
                ):
                    _refuse()
                if destination_metadata is not None and stat.S_ISDIR(destination_metadata.st_mode):
                    nested = "/".join((*destination_parts, source_parts[-1]))
                    self._checked_path(nested)
                shutil.move(source, destination)
                moved_target = (
                    destination / source_parts[-1]
                    if destination_metadata is not None
                    and stat.S_ISDIR(destination_metadata.st_mode)
                    else destination
                )
                self._assert_tree_safe(moved_target)
                is_directory = stat.S_ISDIR(source_metadata.st_mode)
                self._move_discarded_files(
                    Path(*source_parts), Path(*destination_parts), is_dir=is_directory
                )
                if self.post_file_receive is not None:
                    self.post_file_receive("/".join(destination_parts), "/".join(source_parts))
            await self.status_response(0)
        except MobileBackupSafetyError:
            raise
        except (asyncio.CancelledError, KeyboardInterrupt):
            raise
        except Exception:
            _refuse()

    async def copy_item(self, message: DLMessage) -> None:
        try:
            source, source_metadata, source_parts = self._checked_path(message[1])
            if source_metadata is None and self.preserve_file is not None:
                await self.status_response(0)
                return
            if source_metadata is None:
                _refuse()
            original_source_identity = _identity(source_metadata)

            destination, destination_metadata, destination_parts = self._checked_path(message[2])
            self._ensure_parent(destination_parts)
            destination, destination_metadata, _ = self._checked_path(message[2])
            if destination_metadata is not None and not (
                stat.S_ISREG(destination_metadata.st_mode)
                or stat.S_ISDIR(destination_metadata.st_mode)
            ):
                _refuse()
            if stat.S_ISDIR(source_metadata.st_mode):
                if destination_metadata is not None:
                    _refuse()
                source, source_metadata, _ = self._checked_path(message[1])
                destination, destination_metadata, _ = self._checked_path(message[2])
                if source_metadata is None or destination_metadata is not None:
                    _refuse()
                source_identity = _identity(source_metadata)
                self._assert_tree_safe(source)
                source, source_metadata, _ = self._checked_path(message[1])
                if source_metadata is None or _identity(source_metadata) != source_identity:
                    _refuse()
                destination, destination_metadata, _ = self._checked_path(message[2])
                if destination_metadata is not None:
                    _refuse()
                shutil.copytree(source, destination)
            else:
                actual_destination = destination
                if destination_metadata is not None and stat.S_ISDIR(destination_metadata.st_mode):
                    actual_remote = "/".join((*destination_parts, source_parts[-1]))
                    actual_destination, actual_metadata, _ = self._checked_path(actual_remote)
                    if actual_metadata is not None and not stat.S_ISREG(actual_metadata.st_mode):
                        _refuse()
                source, source_metadata, _ = self._checked_path(message[1])
                if (
                    source_metadata is None
                    or not stat.S_ISREG(source_metadata.st_mode)
                    or _identity(source_metadata) != original_source_identity
                ):
                    _refuse()
                destination, destination_metadata, _ = self._checked_path(message[2])
                if destination_metadata is not None and stat.S_ISDIR(destination_metadata.st_mode):
                    actual_remote = "/".join((*destination_parts, source_parts[-1]))
                    actual_destination, actual_metadata, _ = self._checked_path(actual_remote)
                    if actual_metadata is not None and not stat.S_ISREG(actual_metadata.st_mode):
                        _refuse()
                else:
                    actual_destination, _, _ = self._checked_path(message[2])
                shutil.copy(source, actual_destination)
            self._assert_root_identity()
            self._copy_discarded_files(
                Path(*source_parts),
                Path(*destination_parts),
                is_dir=stat.S_ISDIR(source_metadata.st_mode),
            )
            if self.post_file_receive is not None:
                self.post_file_receive("/".join(destination_parts), "/".join(source_parts))
            await self.status_response(0)
        except MobileBackupSafetyError:
            raise
        except (asyncio.CancelledError, KeyboardInterrupt):
            raise
        except Exception:
            _refuse()

    async def remove_items(self, message: DLMessage) -> None:
        try:
            values = message[1]
            if isinstance(values, (str, bytes)) or not isinstance(values, Iterable):
                _refuse()
            for value in values:
                path, metadata, parts = self._checked_path(value)
                is_directory = metadata is not None and stat.S_ISDIR(metadata.st_mode)
                if metadata is not None:
                    path, metadata, _ = self._checked_path(value)
                    if metadata is None:
                        _refuse()
                    is_directory = stat.S_ISDIR(metadata.st_mode)
                    target_identity = _identity(metadata)
                    self._assert_tree_safe(path)
                    path, metadata, _ = self._checked_path(value)
                    if metadata is None or _identity(metadata) != target_identity:
                        _refuse()
                    is_directory = stat.S_ISDIR(metadata.st_mode)
                    if is_directory:
                        shutil.rmtree(path)
                    elif stat.S_ISREG(metadata.st_mode):
                        path.unlink()
                    else:
                        _refuse()
                self._forget_discarded_files(Path(*parts), is_dir=is_directory)
            await self.status_response(0)
        except MobileBackupSafetyError:
            raise
        except (asyncio.CancelledError, KeyboardInterrupt):
            raise
        except Exception:
            _refuse()

    def cleanup_discarded_files(self) -> None:
        try:
            for relative in sorted(
                self._discarded_files, key=lambda path: len(path.parts), reverse=True
            ):
                raw = relative.as_posix()
                path, metadata, parts = self._checked_path(raw)
                if metadata is not None:
                    if not stat.S_ISREG(metadata.st_mode):
                        _refuse()
                    path.unlink()
                for depth in range(len(parts) - 1, 0, -1):
                    parent_raw = "/".join(parts[:depth])
                    parent, parent_metadata, _ = self._checked_path(parent_raw)
                    if parent_metadata is None or not stat.S_ISDIR(parent_metadata.st_mode):
                        _refuse()
                    try:
                        parent.rmdir()
                    except OSError:
                        break
            self._discarded_files.clear()
        except MobileBackupSafetyError:
            raise
        except Exception:
            _refuse()

    async def create_directory(self, message: DLMessage) -> None:
        try:
            parts = _relative_parts(message[1])
            self._ensure_directories(parts)
            await self.status_response(0)
        except MobileBackupSafetyError:
            raise
        except (asyncio.CancelledError, KeyboardInterrupt):
            raise
        except Exception:
            _refuse()

    async def receive_message(self) -> DLMessage:
        """Receive one bounded, known DeviceLink control message."""
        try:
            prefix = await self._recvall(struct.calcsize(SIZE_FORMAT))
            (size,) = struct.unpack(SIZE_FORMAT, prefix)
            if size <= 0 or size > _MAX_CONTROL_PLIST_BYTES:
                _refuse(_TRANSFER_ERROR)
            decoded = plistlib.loads(await self._recvall(size))
            if not isinstance(decoded, list) or not decoded or type(decoded[0]) is not str:
                _refuse(_TRANSFER_ERROR)
            command = decoded[0]
            if command not in _ALLOWED_CONTROL_COMMANDS:
                _refuse(_TRANSFER_ERROR)
            if len(decoded) < _MIN_CONTROL_ITEMS[command]:
                _refuse(_TRANSFER_ERROR)
            if command == "DLMessageProcessMessage" and not isinstance(decoded[1], Mapping):
                _refuse(_TRANSFER_ERROR)
            return cast(DLMessage, decoded)
        except MobileBackupSafetyError:
            raise
        except (asyncio.CancelledError, KeyboardInterrupt):
            raise
        except Exception:
            _refuse(_TRANSFER_ERROR)

    async def get_free_disk_space(self, message: DLMessage) -> None:
        self._assert_root_identity()
        await super().get_free_disk_space(message)
        self._assert_root_identity()


class SafeMobilebackup2Service(Mobilebackup2Service):
    """Pinned MobileBackup2 service that always constructs :class:`SafeDeviceLink`."""

    device_link_connection_closed: bool = True

    @property
    def _udid(self) -> str:
        value = super()._udid
        if len(_relative_parts(value)) != 1:
            _refuse()
        return value

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        try:
            async with asyncio.timeout(_CLEANUP_TIMEOUT_SECONDS):
                await self.close()
        except BaseException:
            if exc_val is None:
                _refuse(_CLEANUP_ERROR)

    @asynccontextmanager
    async def device_link(
        self,
        backup_directory: Path,
        filter_callback: BackupFilterCallback | None = None,
        password: str = "",
    ) -> AsyncIterator[SafeDeviceLink]:
        del password
        self.device_link_connection_closed = True
        await self.connect()
        if self._service is None:
            _refuse()
        device_link = SafeDeviceLink(
            self._service,
            backup_directory,
            preserve_file=lambda file_name, device_name: self.should_preserve_backup_file(
                file_name, device_name, filter_callback
            ),
        )
        try:
            await device_link.version_exchange()
            await self.version_exchange(device_link)
            yield device_link
        finally:
            try:
                async with asyncio.timeout(_CLEANUP_TIMEOUT_SECONDS):
                    await device_link.disconnect()
            except BaseException:
                self.device_link_connection_closed = False
