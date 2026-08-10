# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 iOS Rehydrate contributors
"""Bounded validation of IPA archives and workflow-required App Store metadata."""

from __future__ import annotations

import hashlib
import io
import os
import plistlib
import re
import stat
import struct
import unicodedata
import zipfile
import zlib
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import cast

from ios_rehydrate.errors import ExitCode, RehydrateError
from ios_rehydrate.privacy import opaque_ref

MAX_IPA_BYTES = 2 * 1024**3
MAX_ZIP_ENTRIES = 50_000
MAX_CENTRAL_DIRECTORY_BYTES = 64 * 1024**2
MAX_EXPANDED_BYTES = 8 * 1024**3
MAX_COMPRESSION_RATIO = 200
MAX_PLIST_BYTES = 8 * 1024**2
MAX_SINF_BYTES = 16 * 1024**2

_WINDOWS_DRIVE = re.compile(r"^[A-Za-z]:")
_BUNDLE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,254}$")
_VERSION_VALUE = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._+-]{0,63}$")
_MINIMUM_OS_VALUE = re.compile(r"^[0-9]+(?:\.[0-9]+)*$")
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_ALLOWED_COMPRESSION_METHODS = frozenset({zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED})
_EOCD_SIGNATURE = b"PK\x05\x06"
_ZIP64_EOCD_SIGNATURE = b"PK\x06\x06"
_ZIP64_LOCATOR_SIGNATURE = b"PK\x06\x07"
_CENTRAL_DIRECTORY_SIGNATURE = b"PK\x01\x02"
_LOCAL_FILE_SIGNATURE = b"PK\x03\x04"
_DATA_DESCRIPTOR_SIGNATURE = b"PK\x07\x08"
_EOCD_FIXED_SIZE = 22
_MAX_EOCD_SIZE = _EOCD_FIXED_SIZE + 0xFFFF
_ZIP64_LOCATOR_SIZE = 20
_ZIP64_EOCD_MINIMUM_SIZE = 56
_CENTRAL_DIRECTORY_HEADER_SIZE = 46
_LOCAL_FILE_HEADER_SIZE = 30
_ZIP64_EXTRA_ID = 0x0001
_UINT16_SENTINEL = 0xFFFF
_UINT32_SENTINEL = 0xFFFFFFFF
_FLAG_ENCRYPTED = 1 << 0
_FLAG_DEFLATE_OPTIONS = (1 << 1) | (1 << 2)
_FLAG_DATA_DESCRIPTOR = 1 << 3
_FLAG_UTF8_NAME = 1 << 11
_SUPPORTED_COMMON_FLAGS = _FLAG_DATA_DESCRIPTOR | _FLAG_UTF8_NAME
_INTEGRITY_CHUNK_BYTES = 64 * 1024


@dataclass(frozen=True, slots=True)
class ValidatedIPA:
    """Validated material needed by the upgrade boundary.

    ``sha256`` is the lowercase hexadecimal digest of ``archive_bytes``.  The
    archive and extracted payloads are immutable bytes so downstream code uses
    exactly the material that passed validation.
    """

    archive_bytes: bytes = field(repr=False)
    sha256: str
    size: int
    bundle_identifier: str = field(repr=False)
    version: str
    build: str
    minimum_os: str
    metadata: bytes = field(repr=False)
    sinf: bytes = field(repr=False)
    has_code_resources: bool
    store_id: str | None = field(repr=False)


@dataclass(frozen=True, slots=True)
class _RawZipEntry:
    """Security-relevant central/local ZIP metadata resolved before ``ZipFile``."""

    raw_name: bytes
    flags: int
    compression_method: int
    crc32: int
    compressed_size: int
    file_size: int
    central_header_offset: int
    local_header_offset: int
    data_offset: int
    data_end: int
    descriptor_uses_zip64: bool
    version_made_by: int
    external_attr: int


def _invalid(reason: str, message: str) -> RehydrateError:
    return RehydrateError(message, code=ExitCode.IPA_INVALID, reason=reason)


def _read_archive(path: Path) -> bytes:
    """Read a stable-size regular file after enforcing the size cap."""
    try:
        path_metadata = os.lstat(path)
        path_attributes = getattr(path_metadata, "st_file_attributes", 0)
        if (
            not stat.S_ISREG(path_metadata.st_mode)
            or stat.S_ISLNK(path_metadata.st_mode)
            or bool(path_attributes & _REPARSE_POINT)
        ):
            raise _invalid("IPA_NOT_REGULAR_FILE", "IPA input is not a regular file")
        with path.open("rb") as stream:
            stat_result = os.fstat(stream.fileno())
            if not stat.S_ISREG(stat_result.st_mode):
                raise _invalid("IPA_NOT_REGULAR_FILE", "IPA input is not a regular file")
            if (path_metadata.st_dev, path_metadata.st_ino) != (
                stat_result.st_dev,
                stat_result.st_ino,
            ):
                raise _invalid("IPA_FILE_CHANGED", "IPA changed while it was being opened")
            if stat_result.st_size > MAX_IPA_BYTES:
                raise _invalid("IPA_FILE_TOO_LARGE", "IPA exceeds the 2 GiB size limit")
            if stat_result.st_size <= 0:
                raise _invalid("IPA_EMPTY", "IPA is empty")
            archive_bytes = stream.read(stat_result.st_size + 1)
    except RehydrateError:
        raise
    except (OSError, ValueError) as exc:
        raise _invalid("IPA_READ_FAILED", "IPA could not be read") from exc

    if len(archive_bytes) != stat_result.st_size:
        raise _invalid("IPA_FILE_CHANGED", "IPA changed while it was being read")
    return archive_bytes


def _zip_directory_invalid() -> RehydrateError:
    return _invalid("IPA_ZIP_DIRECTORY_INVALID", "IPA ZIP directory metadata is invalid")


def _find_eocd(archive_bytes: bytes) -> int:
    """Find the exact EOCD that both this preflight and ``ZipFile`` will select."""
    if len(archive_bytes) < _EOCD_FIXED_SIZE:
        raise _zip_directory_invalid()

    search_start = max(0, len(archive_bytes) - _MAX_EOCD_SIZE)
    last_signature = archive_bytes.rfind(_EOCD_SIGNATURE, search_start)
    candidate: int | None = None
    offset = archive_bytes.find(_EOCD_SIGNATURE, search_start)
    while offset != -1:
        if offset + _EOCD_FIXED_SIZE <= len(archive_bytes):
            comment_size = struct.unpack_from("<H", archive_bytes, offset + 20)[0]
            if offset + _EOCD_FIXED_SIZE + comment_size == len(archive_bytes):
                if candidate is not None:
                    raise _zip_directory_invalid()
                candidate = offset
        offset = archive_bytes.find(_EOCD_SIGNATURE, offset + 1)

    # CPython's ZipFile selects the last signature in this window even when it
    # appears inside a real EOCD comment.  Refuse unless that same signature is
    # our one end-aligned candidate, otherwise the two parsers disagree.
    if candidate is None or candidate != last_signature:
        raise _zip_directory_invalid()
    return candidate


def _read_zip64_directory(
    archive_bytes: bytes,
    eocd_offset: int,
) -> tuple[int, int, int, int]:
    """Read a single-disk ZIP64 locator and its exactly adjacent EOCD record."""
    locator_offset = eocd_offset - _ZIP64_LOCATOR_SIZE
    if locator_offset < 0:
        raise _zip_directory_invalid()

    signature, record_disk, record_offset, total_disks = struct.unpack_from(
        "<4sIQI", archive_bytes, locator_offset
    )
    if signature != _ZIP64_LOCATOR_SIGNATURE:
        raise _zip_directory_invalid()
    if record_disk != 0 or total_disks != 1:
        raise _invalid(
            "IPA_ZIP_MULTIDISK_UNSUPPORTED",
            "IPA uses unsupported multi-disk ZIP storage",
        )
    # CPython 3.11-3.13 seeks exactly 56 bytes before the locator.  Although the
    # ZIP64 format permits extensible data, accepting it here would let ZipFile
    # parse a different embedded record.  v0.1 therefore accepts only the fixed
    # record shape that both parsers address identically.
    if record_offset != locator_offset - _ZIP64_EOCD_MINIMUM_SIZE:
        raise _zip_directory_invalid()

    if archive_bytes[record_offset : record_offset + 4] != _ZIP64_EOCD_SIGNATURE:
        raise _zip_directory_invalid()
    record_payload_size = struct.unpack_from("<Q", archive_bytes, record_offset + 4)[0]
    if record_payload_size != 44:
        raise _zip_directory_invalid()

    (
        _version_made_by,
        version_needed,
        disk_number,
        directory_disk,
        entries_on_disk,
        total_entries,
        directory_size,
        directory_offset,
    ) = struct.unpack_from("<2H2I4Q", archive_bytes, record_offset + 12)
    if disk_number != 0 or directory_disk != 0:
        raise _invalid(
            "IPA_ZIP_MULTIDISK_UNSUPPORTED",
            "IPA uses unsupported multi-disk ZIP storage",
        )
    if version_needed < 45 or entries_on_disk != total_entries:
        raise _zip_directory_invalid()
    return total_entries, directory_size, directory_offset, record_offset


def _zip_local_header_invalid() -> RehydrateError:
    return _invalid("IPA_ZIP_LOCAL_HEADER_INVALID", "IPA ZIP local metadata is invalid")


def _zip_payload_invalid() -> RehydrateError:
    return _invalid("IPA_ZIP_DATA_INVALID", "IPA compressed member data is invalid")


def _zip_record_invalid(*, local: bool) -> RehydrateError:
    return _zip_local_header_invalid() if local else _zip_directory_invalid()


def _parse_extra_fields(extra: bytes, *, local: bool) -> list[tuple[int, bytes]]:
    """Parse one bounded extra area and reject truncated or ambiguous framing."""
    fields: list[tuple[int, bytes]] = []
    cursor = 0
    while cursor < len(extra):
        if len(extra) - cursor < 4:
            raise _zip_record_invalid(local=local)
        field_id, field_size = struct.unpack_from("<HH", extra, cursor)
        cursor += 4
        if field_size > len(extra) - cursor:
            raise _zip_record_invalid(local=local)
        fields.append((field_id, extra[cursor : cursor + field_size]))
        cursor += field_size
    return fields


def _zip64_payload(
    extra: bytes,
    *,
    required_size: int,
    local: bool,
) -> bytes | None:
    payloads = [
        payload
        for field_id, payload in _parse_extra_fields(extra, local=local)
        if field_id == _ZIP64_EXTRA_ID
    ]
    if required_size == 0:
        if payloads:
            # Redundant ZIP64 values can be interpreted differently by parsers.
            raise _zip_record_invalid(local=local)
        return None
    if len(payloads) != 1 or len(payloads[0]) != required_size:
        raise _zip_record_invalid(local=local)
    return payloads[0]


def _validate_zip_method(compression_method: int) -> None:
    if compression_method not in _ALLOWED_COMPRESSION_METHODS:
        raise _invalid(
            "IPA_ZIP_COMPRESSION_UNSUPPORTED",
            "IPA contains an unsupported ZIP compression method",
        )


def _validate_zip_flags(flags: int, compression_method: int) -> None:
    if flags & _FLAG_ENCRYPTED:
        raise _invalid("IPA_ZIP_ENCRYPTED", "IPA contains a ZIP-encrypted member")
    allowed = _SUPPORTED_COMMON_FLAGS
    if compression_method == zipfile.ZIP_DEFLATED:
        allowed |= _FLAG_DEFLATE_OPTIONS
    if flags & ~allowed:
        raise _invalid(
            "IPA_ZIP_FLAGS_UNSUPPORTED",
            "IPA contains unsupported ZIP member flags",
        )


def _resolve_central_zip64(
    extra: bytes,
    *,
    version_needed: int,
    file_size_32: int,
    compressed_size_32: int,
    local_header_offset_32: int,
    member_disk_16: int,
) -> tuple[int, int, int, int, bool]:
    file_size_is_zip64 = file_size_32 == _UINT32_SENTINEL
    compressed_size_is_zip64 = compressed_size_32 == _UINT32_SENTINEL
    local_offset_is_zip64 = local_header_offset_32 == _UINT32_SENTINEL
    member_disk_is_zip64 = member_disk_16 == _UINT16_SENTINEL
    required_size = (
        8 * (file_size_is_zip64 + compressed_size_is_zip64 + local_offset_is_zip64)
        + 4 * member_disk_is_zip64
    )
    payload = _zip64_payload(extra, required_size=required_size, local=False)
    if required_size and version_needed < 45:
        raise _zip_directory_invalid()

    cursor = 0

    def read_uint64() -> int:
        nonlocal cursor
        assert payload is not None
        value = cast(int, struct.unpack_from("<Q", payload, cursor)[0])
        cursor += 8
        return value

    file_size = read_uint64() if file_size_is_zip64 else file_size_32
    compressed_size = read_uint64() if compressed_size_is_zip64 else compressed_size_32
    local_header_offset = read_uint64() if local_offset_is_zip64 else local_header_offset_32
    if member_disk_is_zip64:
        assert payload is not None
        member_disk = struct.unpack_from("<I", payload, cursor)[0]
        cursor += 4
    else:
        member_disk = member_disk_16
    if cursor != required_size:
        raise _zip_directory_invalid()
    return (
        file_size,
        compressed_size,
        local_header_offset,
        member_disk,
        file_size_is_zip64 or compressed_size_is_zip64,
    )


def _resolve_local_zip64(
    extra: bytes,
    *,
    version_needed: int,
    file_size_32: int,
    compressed_size_32: int,
) -> tuple[int, int, bool]:
    file_size_is_zip64 = file_size_32 == _UINT32_SENTINEL
    compressed_size_is_zip64 = compressed_size_32 == _UINT32_SENTINEL
    required_size = 8 * (file_size_is_zip64 + compressed_size_is_zip64)
    payload = _zip64_payload(extra, required_size=required_size, local=True)
    if required_size and version_needed < 45:
        raise _zip_local_header_invalid()

    cursor = 0
    if file_size_is_zip64:
        assert payload is not None
        file_size = struct.unpack_from("<Q", payload, cursor)[0]
        cursor += 8
    else:
        file_size = file_size_32
    if compressed_size_is_zip64:
        assert payload is not None
        compressed_size = struct.unpack_from("<Q", payload, cursor)[0]
        cursor += 8
    else:
        compressed_size = compressed_size_32
    if cursor != required_size:
        raise _zip_local_header_invalid()
    return file_size, compressed_size, file_size_is_zip64 or compressed_size_is_zip64


def _parse_local_entry(
    archive_bytes: bytes,
    *,
    directory_offset: int,
    raw_name: bytes,
    central_flags: int,
    compression_method: int,
    crc32: int,
    compressed_size: int,
    file_size: int,
    local_header_offset: int,
    central_uses_zip64_sizes: bool,
) -> tuple[int, int, bool]:
    if (
        local_header_offset > directory_offset
        or directory_offset - local_header_offset < _LOCAL_FILE_HEADER_SIZE
    ):
        raise _zip_local_header_invalid()
    (
        signature,
        version_needed,
        local_flags,
        local_method,
        _modified_time,
        _modified_date,
        local_crc32,
        local_compressed_size_32,
        local_file_size_32,
        local_name_size,
        local_extra_size,
    ) = struct.unpack_from("<4s5H3I2H", archive_bytes, local_header_offset)
    if signature != _LOCAL_FILE_SIGNATURE:
        raise _zip_local_header_invalid()
    _validate_zip_method(local_method)
    _validate_zip_flags(local_flags, local_method)
    if local_method != compression_method or local_flags != central_flags:
        raise _zip_local_header_invalid()

    variable_size = local_name_size + local_extra_size
    variable_offset = local_header_offset + _LOCAL_FILE_HEADER_SIZE
    if variable_size > directory_offset - variable_offset:
        raise _zip_local_header_invalid()
    name_end = variable_offset + local_name_size
    data_offset = name_end + local_extra_size
    local_name = archive_bytes[variable_offset:name_end]
    if local_name != raw_name:
        raise _zip_local_header_invalid()
    local_extra = archive_bytes[name_end:data_offset]
    local_file_size, local_compressed_size, local_uses_zip64_sizes = _resolve_local_zip64(
        local_extra,
        version_needed=version_needed,
        file_size_32=local_file_size_32,
        compressed_size_32=local_compressed_size_32,
    )

    uses_descriptor = bool(central_flags & _FLAG_DATA_DESCRIPTOR)
    if uses_descriptor:
        if local_crc32 not in {0, crc32}:
            raise _zip_local_header_invalid()
        if local_compressed_size not in {0, compressed_size}:
            raise _zip_local_header_invalid()
        if local_file_size not in {0, file_size}:
            raise _zip_local_header_invalid()
    elif (
        local_crc32 != crc32
        or local_compressed_size != compressed_size
        or local_file_size != file_size
    ):
        raise _zip_local_header_invalid()

    if compressed_size > directory_offset - data_offset:
        raise _zip_local_header_invalid()
    data_end = data_offset + compressed_size
    descriptor_uses_zip64 = (
        central_uses_zip64_sizes
        or local_uses_zip64_sizes
        or compressed_size > _UINT32_SENTINEL
        or file_size > _UINT32_SENTINEL
    )
    return data_offset, data_end, descriptor_uses_zip64


def _validate_data_descriptor(
    archive_bytes: bytes,
    entry: _RawZipEntry,
    *,
    boundary: int,
) -> int:
    if entry.descriptor_uses_zip64:
        unsigned = struct.pack("<IQQ", entry.crc32, entry.compressed_size, entry.file_size)
    else:
        if entry.compressed_size > _UINT32_SENTINEL or entry.file_size > _UINT32_SENTINEL:
            raise _zip_local_header_invalid()
        unsigned = struct.pack("<III", entry.crc32, entry.compressed_size, entry.file_size)
    candidates = (unsigned, _DATA_DESCRIPTOR_SIGNATURE + unsigned)
    matches = [
        len(candidate)
        for candidate in candidates
        if len(candidate) <= boundary - entry.data_end
        and archive_bytes[entry.data_end : entry.data_end + len(candidate)] == candidate
    ]
    if len(matches) != 1:
        raise _zip_local_header_invalid()
    return entry.data_end + matches[0]


def _validate_local_ranges(
    archive_bytes: bytes,
    entries: list[_RawZipEntry],
    *,
    directory_offset: int,
) -> None:
    ordered = sorted(entries, key=lambda entry: entry.local_header_offset)
    for index, entry in enumerate(ordered):
        boundary = (
            ordered[index + 1].local_header_offset if index + 1 < len(ordered) else directory_offset
        )
        if entry.data_end > boundary:
            raise _zip_local_header_invalid()
        record_end = entry.data_end
        if entry.flags & _FLAG_DATA_DESCRIPTOR:
            record_end = _validate_data_descriptor(archive_bytes, entry, boundary=boundary)
        if record_end > boundary:
            raise _zip_local_header_invalid()


def _validate_declared_sizes(entries: list[_RawZipEntry]) -> None:
    expanded_size = 0
    compressed_size = 0
    for entry in entries:
        expanded_size += entry.file_size
        compressed_size += entry.compressed_size
        if expanded_size > MAX_EXPANDED_BYTES:
            raise _invalid("IPA_EXPANDED_TOO_LARGE", "IPA expanded size exceeds the limit")
        if entry.file_size > MAX_COMPRESSION_RATIO * max(entry.compressed_size, 1):
            raise _invalid(
                "IPA_COMPRESSION_RATIO_EXCEEDED",
                "IPA contains an excessive compression ratio",
            )
    if expanded_size > MAX_COMPRESSION_RATIO * max(compressed_size, 1):
        raise _invalid(
            "IPA_COMPRESSION_RATIO_EXCEEDED",
            "IPA has an excessive aggregate compression ratio",
        )


def _validate_stored_payload(payload: memoryview, entry: _RawZipEntry) -> None:
    if entry.compressed_size != entry.file_size:
        raise _invalid("IPA_ZIP_SIZE_MISMATCH", "IPA member size metadata does not match")
    checksum = 0
    for offset in range(0, len(payload), _INTEGRITY_CHUNK_BYTES):
        checksum = zlib.crc32(payload[offset : offset + _INTEGRITY_CHUNK_BYTES], checksum)
    if checksum & _UINT32_SENTINEL != entry.crc32:
        raise _invalid("IPA_CRC_MISMATCH", "IPA integrity check found corrupt data")


def _validate_deflated_payload(payload: memoryview, entry: _RawZipEntry) -> None:
    decompressor = zlib.decompressobj(-zlib.MAX_WBITS)
    produced = 0
    checksum = 0
    cursor = 0
    try:
        while cursor < len(payload):
            chunk_end = min(cursor + _INTEGRITY_CHUNK_BYTES, len(payload))
            pending = bytes(payload[cursor:chunk_end])
            cursor = chunk_end
            while pending:
                output_limit = min(
                    _INTEGRITY_CHUNK_BYTES,
                    entry.file_size - produced + 1,
                )
                output = decompressor.decompress(pending, output_limit)
                checksum = zlib.crc32(output, checksum)
                produced += len(output)
                if produced > entry.file_size:
                    raise _invalid(
                        "IPA_ZIP_SIZE_MISMATCH",
                        "IPA member size metadata does not match",
                    )
                unused_data = decompressor.unused_data
                next_pending = decompressor.unconsumed_tail
                if decompressor.eof:
                    if unused_data or next_pending or cursor != len(payload):
                        raise _zip_payload_invalid()
                    pending = b""
                    break
                if next_pending and len(next_pending) == len(pending) and not output:
                    raise _zip_payload_invalid()
                pending = next_pending
    except zlib.error as exc:
        raise _zip_payload_invalid() from exc

    if (
        not decompressor.eof
        or decompressor.unused_data
        or decompressor.unconsumed_tail
        or produced != entry.file_size
    ):
        raise _invalid("IPA_ZIP_SIZE_MISMATCH", "IPA member size metadata does not match")
    if checksum & _UINT32_SENTINEL != entry.crc32:
        raise _invalid("IPA_CRC_MISMATCH", "IPA integrity check found corrupt data")


def _validate_raw_payloads(archive_bytes: bytes, entries: list[_RawZipEntry]) -> None:
    archive_view = memoryview(archive_bytes)
    for entry in entries:
        payload = archive_view[entry.data_offset : entry.data_end]
        if entry.compression_method == zipfile.ZIP_STORED:
            _validate_stored_payload(payload, entry)
        else:
            _validate_deflated_payload(payload, entry)


def _validate_central_directory(
    archive_bytes: bytes,
    *,
    directory_offset: int,
    directory_size: int,
    expected_entries: int,
) -> list[_RawZipEntry]:
    """Parse and cross-check every central entry and referenced local record."""
    directory_end = directory_offset + directory_size
    cursor = directory_offset
    entries: list[_RawZipEntry] = []

    if expected_entries * _CENTRAL_DIRECTORY_HEADER_SIZE > directory_size:
        raise _zip_directory_invalid()

    while cursor < directory_end:
        if len(entries) >= MAX_ZIP_ENTRIES:
            raise _invalid("IPA_TOO_MANY_ENTRIES", "IPA contains too many archive entries")
        if directory_end - cursor < _CENTRAL_DIRECTORY_HEADER_SIZE:
            raise _zip_directory_invalid()
        (
            signature,
            version_made_by,
            version_needed,
            flags,
            compression_method,
            _modified_time,
            _modified_date,
            crc32,
            compressed_size_32,
            file_size_32,
            name_size,
            extra_size,
            comment_size,
            member_disk_16,
            _internal_attr,
            external_attr,
            local_header_offset_32,
        ) = struct.unpack_from("<4s6H3I5H2I", archive_bytes, cursor)
        if signature != _CENTRAL_DIRECTORY_SIGNATURE:
            raise _zip_directory_invalid()
        _validate_zip_method(compression_method)
        _validate_zip_flags(flags, compression_method)

        record_size = _CENTRAL_DIRECTORY_HEADER_SIZE + name_size + extra_size + comment_size
        if record_size > directory_end - cursor:
            raise _zip_directory_invalid()
        name_offset = cursor + _CENTRAL_DIRECTORY_HEADER_SIZE
        name_end = name_offset + name_size
        extra_end = name_end + extra_size
        raw_name = archive_bytes[name_offset:name_end]
        extra = archive_bytes[name_end:extra_end]
        (
            file_size,
            compressed_size,
            local_header_offset,
            member_disk,
            central_uses_zip64_sizes,
        ) = _resolve_central_zip64(
            extra,
            version_needed=version_needed,
            file_size_32=file_size_32,
            compressed_size_32=compressed_size_32,
            local_header_offset_32=local_header_offset_32,
            member_disk_16=member_disk_16,
        )
        if member_disk != 0:
            raise _invalid(
                "IPA_ZIP_MULTIDISK_UNSUPPORTED",
                "IPA uses unsupported multi-disk ZIP storage",
            )
        try:
            decoded_name = raw_name.decode("utf-8" if flags & _FLAG_UTF8_NAME else "cp437")
        except UnicodeDecodeError as exc:
            raise _zip_directory_invalid() from exc
        _validate_member_name(decoded_name)

        data_offset, data_end, descriptor_uses_zip64 = _parse_local_entry(
            archive_bytes,
            directory_offset=directory_offset,
            raw_name=raw_name,
            central_flags=flags,
            compression_method=compression_method,
            crc32=crc32,
            compressed_size=compressed_size,
            file_size=file_size,
            local_header_offset=local_header_offset,
            central_uses_zip64_sizes=central_uses_zip64_sizes,
        )
        entries.append(
            _RawZipEntry(
                raw_name=raw_name,
                flags=flags,
                compression_method=compression_method,
                crc32=crc32,
                compressed_size=compressed_size,
                file_size=file_size,
                central_header_offset=cursor,
                local_header_offset=local_header_offset,
                data_offset=data_offset,
                data_end=data_end,
                descriptor_uses_zip64=descriptor_uses_zip64,
                version_made_by=version_made_by,
                external_attr=external_attr,
            )
        )
        cursor += record_size

    if cursor != directory_end or len(entries) != expected_entries:
        raise _zip_directory_invalid()
    _validate_local_ranges(archive_bytes, entries, directory_offset=directory_offset)
    _validate_declared_sizes(entries)
    _validate_raw_payloads(archive_bytes, entries)
    return entries


def _preflight_zip(archive_bytes: bytes) -> list[_RawZipEntry]:
    """Reject ZIP directory bombs and ambiguous layouts before ``ZipFile`` parsing."""
    eocd_offset = _find_eocd(archive_bytes)
    (
        _signature,
        disk_number,
        directory_disk,
        entries_on_disk,
        total_entries,
        directory_size,
        directory_offset,
        _comment_size,
    ) = struct.unpack_from("<4s4H2IH", archive_bytes, eocd_offset)

    needs_zip64 = (
        disk_number == _UINT16_SENTINEL
        or directory_disk == _UINT16_SENTINEL
        or entries_on_disk == _UINT16_SENTINEL
        or total_entries == _UINT16_SENTINEL
        or directory_size == _UINT32_SENTINEL
        or directory_offset == _UINT32_SENTINEL
    )
    directory_end = eocd_offset
    if needs_zip64:
        (
            zip64_entries,
            zip64_directory_size,
            zip64_directory_offset,
            directory_end,
        ) = _read_zip64_directory(archive_bytes, eocd_offset)
        if (
            (disk_number != _UINT16_SENTINEL and disk_number != 0)
            or (directory_disk != _UINT16_SENTINEL and directory_disk != 0)
            or (entries_on_disk != _UINT16_SENTINEL and entries_on_disk != zip64_entries)
            or (total_entries != _UINT16_SENTINEL and total_entries != zip64_entries)
            or (directory_size != _UINT32_SENTINEL and directory_size != zip64_directory_size)
            or (directory_offset != _UINT32_SENTINEL and directory_offset != zip64_directory_offset)
        ):
            raise _zip_directory_invalid()
        entries_on_disk = zip64_entries
        total_entries = zip64_entries
        directory_size = zip64_directory_size
        directory_offset = zip64_directory_offset
    elif disk_number != 0 or directory_disk != 0:
        raise _invalid(
            "IPA_ZIP_MULTIDISK_UNSUPPORTED",
            "IPA uses unsupported multi-disk ZIP storage",
        )

    if entries_on_disk != total_entries:
        raise _zip_directory_invalid()
    if total_entries > MAX_ZIP_ENTRIES:
        raise _invalid("IPA_TOO_MANY_ENTRIES", "IPA contains too many archive entries")
    if directory_size > MAX_CENTRAL_DIRECTORY_BYTES:
        raise _invalid(
            "IPA_ZIP_DIRECTORY_TOO_LARGE",
            "IPA ZIP central directory exceeds the size limit",
        )
    if (
        directory_offset > directory_end
        or directory_size > directory_end - directory_offset
        or directory_offset + directory_size != directory_end
    ):
        raise _zip_directory_invalid()

    return _validate_central_directory(
        archive_bytes,
        directory_offset=directory_offset,
        directory_size=directory_size,
        expected_entries=total_entries,
    )


def _validate_member_name(name: str) -> None:
    """Reject names that are unsafe or have ambiguous filesystem meaning."""
    if not name or "\x00" in name or "\\" in name:
        raise _invalid("IPA_MEMBER_PATH_INVALID", "IPA contains an unsafe member path")
    if name.startswith("/") or _WINDOWS_DRIVE.match(name):
        raise _invalid("IPA_MEMBER_PATH_ABSOLUTE", "IPA contains an absolute member path")

    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts:
        raise _invalid("IPA_MEMBER_PATH_TRAVERSAL", "IPA contains a parent member path")

    # PurePosixPath normalizes these aliases, so inspect the original spelling.
    without_directory_marker = name[:-1] if name.endswith("/") else name
    if any(segment in {"", "."} for segment in without_directory_marker.split("/")):
        raise _invalid("IPA_MEMBER_PATH_INVALID", "IPA contains an unsafe member path")


def _validate_member_type(info: zipfile.ZipInfo) -> None:
    """Enforce a coherent slash/type contract while allowing unspecified types."""
    has_directory_marker = info.filename.endswith("/")
    if has_directory_marker and info.file_size != 0:
        raise _invalid("IPA_DIRECTORY_NOT_EMPTY", "IPA contains a non-empty directory member")
    if info.create_system != 3:
        return
    unix_mode = (info.external_attr >> 16) & 0xFFFF
    file_type = stat.S_IFMT(unix_mode)
    if file_type not in {0, stat.S_IFREG, stat.S_IFDIR}:
        raise _invalid("IPA_MEMBER_TYPE_UNSAFE", "IPA contains an unsafe member type")
    if (file_type == stat.S_IFDIR) != has_directory_marker and file_type != 0:
        raise _invalid(
            "IPA_MEMBER_TYPE_MISMATCH",
            "IPA member type does not agree with its path",
        )


def _check_archive_shape(
    infos: list[zipfile.ZipInfo],
    raw_entries: list[_RawZipEntry],
) -> dict[str, zipfile.ZipInfo]:
    if len(infos) > MAX_ZIP_ENTRIES:
        raise _invalid("IPA_TOO_MANY_ENTRIES", "IPA contains too many archive entries")
    if len(infos) != len(raw_entries):
        raise _zip_directory_invalid()

    members: dict[str, zipfile.ZipInfo] = {}
    canonical_names: set[str] = set()
    explicit_directories: dict[str, bool] = {}
    implicit_directories: set[str] = set()
    expanded_size = 0
    compressed_size = 0
    for info, raw_entry in zip(infos, raw_entries, strict=True):
        encoding = "utf-8" if raw_entry.flags & _FLAG_UTF8_NAME else "cp437"
        try:
            decoded_name = raw_entry.raw_name.decode(encoding)
        except UnicodeDecodeError as exc:
            raise _zip_directory_invalid() from exc
        if (
            info.orig_filename != decoded_name
            or info.flag_bits != raw_entry.flags
            or info.compress_type != raw_entry.compression_method
            or raw_entry.crc32 != info.CRC
            or info.compress_size != raw_entry.compressed_size
            or info.file_size != raw_entry.file_size
            or info.header_offset != raw_entry.local_header_offset
            or info.create_system != raw_entry.version_made_by >> 8
            or info.external_attr != raw_entry.external_attr
        ):
            raise _zip_directory_invalid()
        # ZipInfo normalizes Windows separators in ``filename``. Validate the
        # untouched spelling so a hostile archive cannot hide a backslash.
        _validate_member_name(info.orig_filename)
        name = info.filename
        if info.orig_filename != name:
            raise _invalid("IPA_MEMBER_PATH_INVALID", "IPA contains an unsafe member path")
        if name in members:
            raise _invalid("IPA_DUPLICATE_MEMBER", "IPA contains a duplicate archive member")
        canonical_name = unicodedata.normalize(
            "NFC", unicodedata.normalize("NFC", name).casefold()
        ).removesuffix("/")
        if canonical_name in canonical_names:
            raise _invalid(
                "IPA_MEMBER_PATH_COLLISION",
                "IPA contains colliding archive member paths",
            )
        canonical_names.add(canonical_name)
        canonical_parts = canonical_name.split("/")
        for part_count in range(1, len(canonical_parts)):
            ancestor = "/".join(canonical_parts[:part_count])
            if explicit_directories.get(ancestor) is False:
                raise _invalid(
                    "IPA_MEMBER_PATH_CONFLICT",
                    "IPA member paths have conflicting file and directory roles",
                )
            implicit_directories.add(ancestor)
        is_directory = name.endswith("/")
        if canonical_name in implicit_directories and not is_directory:
            raise _invalid(
                "IPA_MEMBER_PATH_CONFLICT",
                "IPA member paths have conflicting file and directory roles",
            )
        explicit_directories[canonical_name] = is_directory
        _validate_member_type(info)
        if info.file_size < 0 or info.compress_size < 0:
            raise _invalid("IPA_ZIP_INVALID", "IPA contains invalid archive sizes")

        expanded_size += info.file_size
        compressed_size += info.compress_size
        if expanded_size > MAX_EXPANDED_BYTES:
            raise _invalid("IPA_EXPANDED_TOO_LARGE", "IPA expanded size exceeds the limit")
        if info.file_size > MAX_COMPRESSION_RATIO * max(info.compress_size, 1):
            raise _invalid(
                "IPA_COMPRESSION_RATIO_EXCEEDED",
                "IPA contains an excessive compression ratio",
            )
        members[name] = info

    if expanded_size > MAX_COMPRESSION_RATIO * max(compressed_size, 1):
        raise _invalid(
            "IPA_COMPRESSION_RATIO_EXCEEDED",
            "IPA has an excessive aggregate compression ratio",
        )
    return members


def _required_member(
    members: dict[str, zipfile.ZipInfo], name: str, *, reason: str, message: str
) -> zipfile.ZipInfo:
    info = members.get(name)
    if info is None or info.is_dir():
        raise _invalid(reason, message)
    return info


def _read_member(
    archive: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    *,
    limit: int,
    too_large_reason: str,
    read_reason: str,
    label: str,
) -> bytes:
    if info.file_size > limit:
        raise _invalid(too_large_reason, f"{label} exceeds the size limit")
    try:
        with archive.open(info, "r") as stream:
            payload = stream.read(limit + 1)
    except (OSError, RuntimeError, ValueError, zipfile.BadZipFile, NotImplementedError) as exc:
        raise _invalid(read_reason, f"{label} could not be read") from exc
    if len(payload) > limit or len(payload) != info.file_size:
        raise _invalid(too_large_reason, f"{label} exceeds the size limit")
    return payload


def _read_plist(
    archive: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    *,
    prefix: str,
    label: str,
) -> tuple[bytes, dict[str, object]]:
    payload = _read_member(
        archive,
        info,
        limit=MAX_PLIST_BYTES,
        too_large_reason=f"{prefix}_TOO_LARGE",
        read_reason=f"{prefix}_READ_FAILED",
        label=label,
    )
    try:
        decoded = plistlib.loads(payload)
    except (ValueError, TypeError, OverflowError) as exc:
        raise _invalid(f"{prefix}_INVALID", f"{label} is not a valid property list") from exc
    if not isinstance(decoded, dict):
        raise _invalid(f"{prefix}_NOT_DICTIONARY", f"{label} must contain a dictionary")
    return payload, cast(dict[str, object], decoded)


def _required_text(
    mapping: dict[str, object],
    key: str,
    *,
    reason: str,
    label: str,
    max_length: int = 255,
) -> str:
    value = mapping.get(key)
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > max_length
        or any(ord(character) < 32 for character in value)
    ):
        raise _invalid(reason, f"{label} is missing or invalid")
    return value


def _app_root(members: dict[str, zipfile.ZipInfo]) -> str:
    roots: set[str] = set()
    for name in members:
        parts = PurePosixPath(name).parts
        if len(parts) >= 2 and parts[0] == "Payload" and parts[1].endswith(".app"):
            roots.add(f"Payload/{parts[1]}")
    if len(roots) != 1:
        raise _invalid("IPA_APP_COUNT_INVALID", "IPA must contain exactly one Payload app")
    return next(iter(roots))


def _metadata_store_id(metadata: dict[str, object]) -> str | None:
    if "itemId" not in metadata:
        return None
    value = metadata["itemId"]
    if isinstance(value, bool):
        raise _invalid("IPA_STORE_ID_INVALID", "iTunes metadata store identifier is invalid")
    if isinstance(value, int):
        if value <= 0:
            raise _invalid("IPA_STORE_ID_INVALID", "iTunes metadata store identifier is invalid")
        return str(value)
    if isinstance(value, str) and value and value.isascii() and value.isdecimal():
        return value
    raise _invalid("IPA_STORE_ID_INVALID", "iTunes metadata store identifier is invalid")


def _validate_zip(
    archive: zipfile.ZipFile,
    archive_bytes: bytes,
    raw_entries: list[_RawZipEntry],
    *,
    expected_bundle_id: str | None,
    expected_store_id: str | None,
) -> ValidatedIPA:
    members = _check_archive_shape(archive.infolist(), raw_entries)
    app_root = _app_root(members)

    info_member = _required_member(
        members,
        f"{app_root}/Info.plist",
        reason="IPA_INFO_PLIST_MISSING",
        message="app Info.plist is missing",
    )
    _, info = _read_plist(
        archive,
        info_member,
        prefix="IPA_INFO_PLIST",
        label="app Info.plist",
    )
    metadata_member = _required_member(
        members,
        "iTunesMetadata.plist",
        reason="IPA_METADATA_PLIST_MISSING",
        message="iTunesMetadata.plist is missing",
    )
    metadata_bytes, metadata = _read_plist(
        archive,
        metadata_member,
        prefix="IPA_METADATA_PLIST",
        label="iTunesMetadata.plist",
    )

    bundle_identifier = _required_text(
        info,
        "CFBundleIdentifier",
        reason="IPA_BUNDLE_ID_INVALID",
        label="app bundle identifier",
    )
    metadata_bundle = _required_text(
        metadata,
        "softwareVersionBundleId",
        reason="IPA_METADATA_BUNDLE_ID_INVALID",
        label="iTunes metadata bundle identifier",
    )
    if metadata_bundle != bundle_identifier:
        raise _invalid(
            "IPA_METADATA_BUNDLE_MISMATCH",
            "app and iTunes metadata bundle identifiers do not match",
        )
    if _BUNDLE_IDENTIFIER.fullmatch(bundle_identifier) is None:
        raise _invalid("IPA_BUNDLE_ID_INVALID", "app bundle identifier is invalid")
    if expected_bundle_id is not None and _BUNDLE_IDENTIFIER.fullmatch(expected_bundle_id) is None:
        raise _invalid("IPA_EXPECTED_BUNDLE_INVALID", "expected app identifier is invalid")
    if expected_bundle_id is not None and bundle_identifier != expected_bundle_id:
        raise _invalid(
            "IPA_EXPECTED_BUNDLE_MISMATCH",
            "IPA bundle identifier does not match the expected app",
        )

    version = _required_text(
        info,
        "CFBundleShortVersionString",
        reason="IPA_VERSION_INVALID",
        label="app version",
        max_length=64,
    )
    if _VERSION_VALUE.fullmatch(version) is None:
        raise _invalid("IPA_VERSION_INVALID", "app version is invalid")
    build = _required_text(
        info,
        "CFBundleVersion",
        reason="IPA_BUILD_INVALID",
        label="app build",
        max_length=64,
    )
    if _VERSION_VALUE.fullmatch(build) is None:
        raise _invalid("IPA_BUILD_INVALID", "app build is invalid")
    minimum_os = _required_text(
        info,
        "MinimumOSVersion",
        reason="IPA_MINIMUM_OS_INVALID",
        label="minimum OS version",
        max_length=64,
    )
    if _MINIMUM_OS_VALUE.fullmatch(minimum_os) is None:
        raise _invalid("IPA_MINIMUM_OS_INVALID", "minimum OS version is invalid")
    executable = _required_text(
        info,
        "CFBundleExecutable",
        reason="IPA_EXECUTABLE_INVALID",
        label="app executable name",
    )
    if "/" in executable or "\\" in executable or executable in {".", ".."}:
        raise _invalid("IPA_EXECUTABLE_INVALID", "app executable name is invalid")
    executable_member = _required_member(
        members,
        f"{app_root}/{executable}",
        reason="IPA_EXECUTABLE_MISSING",
        message="app executable is missing",
    )
    if executable_member.file_size <= 0:
        raise _invalid("IPA_EXECUTABLE_EMPTY", "app executable is empty")

    sinf_member = _required_member(
        members,
        f"{app_root}/SC_Info/{executable}.sinf",
        reason="IPA_SINF_MISSING",
        message="app store authorization material is missing",
    )
    sinf_bytes = _read_member(
        archive,
        sinf_member,
        limit=MAX_SINF_BYTES,
        too_large_reason="IPA_SINF_TOO_LARGE",
        read_reason="IPA_SINF_READ_FAILED",
        label="app store authorization material",
    )
    if not sinf_bytes:
        raise _invalid("IPA_SINF_EMPTY", "app store authorization material is empty")

    code_resources = _required_member(
        members,
        f"{app_root}/_CodeSignature/CodeResources",
        reason="IPA_CODE_RESOURCES_MISSING",
        message="app code resources are missing",
    )
    if code_resources.file_size <= 0:
        raise _invalid("IPA_CODE_RESOURCES_EMPTY", "app code resources are empty")

    store_id = _metadata_store_id(metadata)
    if expected_store_id is not None:
        if not expected_store_id.isascii() or not expected_store_id.isdecimal():
            raise _invalid("IPA_EXPECTED_STORE_ID_INVALID", "expected store identifier is invalid")
        if store_id is None:
            raise _invalid(
                "IPA_EXPECTED_STORE_ID_MISSING",
                "IPA has no store identifier for the requested check",
            )
        if store_id != expected_store_id:
            raise _invalid(
                "IPA_EXPECTED_STORE_MISMATCH",
                "IPA store identifier does not match the expected app",
            )

    return ValidatedIPA(
        archive_bytes=archive_bytes,
        sha256=hashlib.sha256(archive_bytes).hexdigest(),
        size=len(archive_bytes),
        bundle_identifier=bundle_identifier,
        version=version,
        build=build,
        minimum_os=minimum_os,
        metadata=metadata_bytes,
        sinf=sinf_bytes,
        has_code_resources=True,
        store_id=store_id,
    )


def validate_ipa(
    path: Path,
    *,
    expected_bundle_id: str | None = None,
    expected_store_id: str | None = None,
) -> ValidatedIPA:
    """Load and validate one IPA without exposing its path in normal errors."""
    archive_bytes = _read_archive(path)
    try:
        raw_entries = _preflight_zip(archive_bytes)
        with zipfile.ZipFile(io.BytesIO(archive_bytes), "r") as archive:
            return _validate_zip(
                archive,
                archive_bytes,
                raw_entries,
                expected_bundle_id=expected_bundle_id,
                expected_store_id=expected_store_id,
            )
    except RehydrateError:
        raise
    except (
        OSError,
        RuntimeError,
        ValueError,
        zipfile.BadZipFile,
        zipfile.LargeZipFile,
        NotImplementedError,
    ) as exc:
        raise _invalid("IPA_ZIP_INVALID", "IPA is not a valid ZIP archive") from exc


def public_summary(payload: ValidatedIPA) -> dict[str, object]:
    """Return the allow-listed, path-free summary safe for public output."""
    return {
        "sha256": payload.sha256,
        "size": payload.size,
        "version": payload.version,
        "build": payload.build,
        "minimum_os": payload.minimum_os,
        "bundle_ref": opaque_ref(payload.bundle_identifier, namespace="bundle"),
        "store_ref": (
            opaque_ref(payload.store_id, namespace="store")
            if payload.store_id is not None
            else None
        ),
        "has_metadata": bool(payload.metadata),
        "has_sinf": bool(payload.sinf),
        "has_code_resources": payload.has_code_resources,
    }
