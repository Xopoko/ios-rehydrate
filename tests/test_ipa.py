# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 iOS Rehydrate contributors
from __future__ import annotations

import hashlib
import io
import plistlib
import stat
import struct
import zipfile
import zlib
from collections.abc import Mapping
from dataclasses import FrozenInstanceError, fields
from pathlib import Path

import pytest

import ios_rehydrate.ipa as ipa_module
from ios_rehydrate.errors import ExitCode, RehydrateError
from ios_rehydrate.ipa import public_summary, validate_ipa

_SEEDED_PRIVATE_EMAIL = "owner" + "@" + "example.test"
_SEEDED_WINDOWS_PATH = "C:" + "\\" + "Users" + "\\owner"


class _UnseekableBytesIO(io.BytesIO):
    def seekable(self) -> bool:
        return False

    def seek(self, _offset: int, _whence: int = 0) -> int:
        raise io.UnsupportedOperation("fixture is intentionally unseekable")


def _ipa_bytes(
    *,
    bundle_id: str = "test.invalid.synthetic",
    metadata_bundle_id: str | None = None,
    store_id: int | str | None = 123456,
    version: str = "1.2.3",
    build: str = "45",
    minimum_os: str = "16.0",
    extra: Mapping[str, bytes] | None = None,
    compression: int = zipfile.ZIP_DEFLATED,
    use_data_descriptors: bool = False,
    force_zip64_member: str | None = None,
    member_extras: Mapping[str, bytes] | None = None,
) -> bytes:
    info = {
        "CFBundleIdentifier": bundle_id,
        "CFBundleShortVersionString": version,
        "CFBundleVersion": build,
        "MinimumOSVersion": minimum_os,
        "CFBundleExecutable": "SyntheticExecutable",
    }
    metadata: dict[str, object] = {
        "softwareVersionBundleId": metadata_bundle_id or bundle_id,
    }
    if store_id is not None:
        metadata["itemId"] = store_id
    files = {
        "Payload/Synthetic.app/Info.plist": plistlib.dumps(info),
        "Payload/Synthetic.app/SyntheticExecutable": b"synthetic-not-a-real-binary",
        "Payload/Synthetic.app/SC_Info/SyntheticExecutable.sinf": b"synthetic-sinf",
        "Payload/Synthetic.app/_CodeSignature/CodeResources": b"synthetic-signature",
        "iTunesMetadata.plist": plistlib.dumps(metadata),
    }
    files.update(extra or {})
    output = _UnseekableBytesIO() if use_data_descriptors else io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=compression) as archive:
        for name, payload in files.items():
            if name == force_zip64_member:
                with archive.open(name, "w", force_zip64=True) as member:
                    member.write(payload)
            elif member_extras is not None and name in member_extras:
                member = zipfile.ZipInfo(name)
                member.compress_type = compression
                member.extra = member_extras[name]
                archive.writestr(member, payload)
            else:
                archive.writestr(name, payload)
    return output.getvalue()


def _write_ipa(tmp_path: Path, payload: bytes) -> Path:
    path = tmp_path / "synthetic.ipa"
    path.write_bytes(payload)
    return path


def _with_unix_member(payload: bytes, *, name: str, mode: int) -> bytes:
    output = io.BytesIO(payload)
    member = zipfile.ZipInfo(name)
    member.create_system = 3
    member.external_attr = mode << 16
    with zipfile.ZipFile(output, "a") as archive:
        archive.writestr(member, b"synthetic-member")
    return output.getvalue()


def _eocd_offset(payload: bytes | bytearray) -> int:
    offset = payload.rfind(b"PK\x05\x06")
    assert offset >= 0
    return offset


def _entry_offsets(payload: bytes | bytearray, name: str) -> tuple[int, int]:
    eocd_offset = _eocd_offset(payload)
    directory_size, directory_offset = struct.unpack_from("<II", payload, eocd_offset + 12)
    directory_end = directory_offset + directory_size
    cursor = directory_offset
    expected_name = name.encode()
    while cursor < directory_end:
        assert payload[cursor : cursor + 4] == b"PK\x01\x02"
        name_size, extra_size, comment_size = struct.unpack_from("<3H", payload, cursor + 28)
        raw_name = payload[cursor + 46 : cursor + 46 + name_size]
        if raw_name == expected_name:
            local_offset = struct.unpack_from("<I", payload, cursor + 42)[0]
            return cursor, local_offset
        cursor += 46 + name_size + extra_size + comment_size
    raise AssertionError("fixture member was not found")


def _with_central_unix_mode(payload: bytes, *, name: str, mode: int) -> bytes:
    damaged = bytearray(payload)
    central_offset, _local_offset = _entry_offsets(damaged, name)
    version_made_by = struct.unpack_from("<H", damaged, central_offset + 4)[0]
    struct.pack_into("<H", damaged, central_offset + 4, (3 << 8) | (version_made_by & 0xFF))
    struct.pack_into("<I", damaged, central_offset + 38, mode << 16)
    return bytes(damaged)


def _zip64_ipa_bytes() -> bytes:
    """Promote a small valid IPA to a structurally real single-disk ZIP64 archive."""
    payload = _ipa_bytes()
    eocd_offset = _eocd_offset(payload)
    (
        signature,
        disk_number,
        directory_disk,
        entries_on_disk,
        total_entries,
        directory_size,
        directory_offset,
        comment_size,
    ) = struct.unpack_from("<4s4H2IH", payload, eocd_offset)
    assert signature == b"PK\x05\x06"
    assert disk_number == directory_disk == comment_size == 0

    zip64_record = struct.pack(
        "<4sQ2H2I4Q",
        b"PK\x06\x06",
        44,
        45,
        45,
        0,
        0,
        entries_on_disk,
        total_entries,
        directory_size,
        directory_offset,
    )
    zip64_locator = struct.pack(
        "<4sIQI",
        b"PK\x06\x07",
        0,
        eocd_offset,
        1,
    )
    saturated_eocd = struct.pack(
        "<4s4H2IH",
        b"PK\x05\x06",
        0,
        0,
        0xFFFF,
        0xFFFF,
        0xFFFFFFFF,
        0xFFFFFFFF,
        0,
    )
    return payload[:eocd_offset] + zip64_record + zip64_locator + saturated_eocd


def _reason(error: pytest.ExceptionInfo[RehydrateError]) -> str:
    assert error.value.code is ExitCode.IPA_INVALID
    return error.value.reason


def test_validate_ipa_retains_exact_bytes_and_returns_safe_summary(tmp_path: Path) -> None:
    archive_bytes = _ipa_bytes()
    validated = validate_ipa(
        _write_ipa(tmp_path, archive_bytes),
        expected_bundle_id="test.invalid.synthetic",
        expected_store_id="123456",
    )

    assert validated.archive_bytes == archive_bytes
    assert validated.sha256 == hashlib.sha256(archive_bytes).hexdigest()
    assert validated.size == len(archive_bytes)
    assert validated.bundle_identifier == "test.invalid.synthetic"
    assert validated.version == "1.2.3"
    assert validated.build == "45"
    assert validated.minimum_os == "16.0"
    assert validated.metadata.startswith(b"<?xml")
    assert validated.sinf == b"synthetic-sinf"
    assert validated.has_code_resources is True
    assert validated.store_id == "123456"
    field_repr = {field.name: field.repr for field in fields(type(validated))}
    assert field_repr == {
        "archive_bytes": False,
        "sha256": True,
        "size": True,
        "bundle_identifier": False,
        "version": True,
        "build": True,
        "minimum_os": True,
        "metadata": False,
        "sinf": False,
        "has_code_resources": True,
        "store_id": False,
    }
    validated_repr = repr(validated)
    assert "test.invalid.synthetic" not in validated_repr
    assert "synthetic-sinf" not in validated_repr
    assert "softwareVersionBundleId" not in validated_repr
    assert "123456" not in validated_repr

    with pytest.raises(FrozenInstanceError):
        validated.size = 0  # type: ignore[misc]

    summary = public_summary(validated)
    assert set(summary) == {
        "sha256",
        "size",
        "version",
        "build",
        "minimum_os",
        "bundle_ref",
        "store_ref",
        "has_metadata",
        "has_sinf",
        "has_code_resources",
    }
    assert summary["bundle_ref"] != validated.bundle_identifier
    assert summary["store_ref"] != validated.store_id
    assert validated.bundle_identifier not in repr(summary)
    assert validated.store_id not in repr(summary)
    assert "synthetic.ipa" not in repr(summary)


@pytest.mark.parametrize("use_zip64", [False, True], ids=["standard", "zip64"])
def test_preflight_accepts_compatible_standard_and_zip64_archives(
    tmp_path: Path, use_zip64: bool
) -> None:
    archive_bytes = _zip64_ipa_bytes() if use_zip64 else _ipa_bytes()

    validated = validate_ipa(_write_ipa(tmp_path, archive_bytes))

    assert validated.archive_bytes == archive_bytes


@pytest.mark.parametrize(
    "archive_bytes",
    [
        pytest.param(_ipa_bytes(use_data_descriptors=True), id="data-descriptors"),
        pytest.param(
            _ipa_bytes(force_zip64_member="Payload/Synthetic.app/Info.plist"),
            id="local-zip64-sizes",
        ),
    ],
)
def test_preflight_accepts_unambiguous_local_record_variants(
    tmp_path: Path, archive_bytes: bytes
) -> None:
    validated = validate_ipa(_write_ipa(tmp_path, archive_bytes))

    assert validated.archive_bytes == archive_bytes


def test_rejects_redundant_ambiguous_zip64_extra_before_zipfile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    info_name = "Payload/Synthetic.app/Info.plist"
    archive_bytes = _ipa_bytes(member_extras={info_name: struct.pack("<HH", 0x0001, 0)})
    with zipfile.ZipFile(io.BytesIO(archive_bytes), "r") as archive:
        assert archive.testzip() is None
    constructor_called = False

    def unexpected_zipfile(*_args: object, **_kwargs: object) -> None:
        nonlocal constructor_called
        constructor_called = True
        raise AssertionError("ZipFile constructor must not be called")

    monkeypatch.setattr(zipfile, "ZipFile", unexpected_zipfile)
    with pytest.raises(RehydrateError) as error:
        validate_ipa(_write_ipa(tmp_path, archive_bytes))

    assert _reason(error) == "IPA_ZIP_DIRECTORY_INVALID"
    assert constructor_called is False


@pytest.mark.parametrize("damage", ["missing", "truncated"])
def test_rejects_missing_or_truncated_eocd(tmp_path: Path, damage: str) -> None:
    archive_bytes = _ipa_bytes()
    if damage == "missing":
        damaged = bytearray(archive_bytes)
        damaged[_eocd_offset(archive_bytes)] ^= 0xFF
        archive_bytes = bytes(damaged)
    else:
        archive_bytes = archive_bytes[:-1]

    with pytest.raises(RehydrateError) as error:
        validate_ipa(_write_ipa(tmp_path, archive_bytes))

    assert _reason(error) == "IPA_ZIP_DIRECTORY_INVALID"
    assert "synthetic.ipa" not in str(error.value)


@pytest.mark.parametrize("field_offset", [4, 6])
def test_rejects_multidisk_eocd_fields(tmp_path: Path, field_offset: int) -> None:
    damaged = bytearray(_ipa_bytes())
    struct.pack_into("<H", damaged, _eocd_offset(damaged) + field_offset, 1)

    with pytest.raises(RehydrateError) as error:
        validate_ipa(_write_ipa(tmp_path, bytes(damaged)))

    assert _reason(error) == "IPA_ZIP_MULTIDISK_UNSUPPORTED"


def test_rejects_disagreeing_eocd_entry_counts_before_zipfile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    damaged = bytearray(_ipa_bytes())
    eocd_offset = _eocd_offset(damaged)
    entries_on_disk = struct.unpack_from("<H", damaged, eocd_offset + 8)[0]
    struct.pack_into("<H", damaged, eocd_offset + 10, entries_on_disk - 1)
    constructor_called = False

    def unexpected_zipfile(*_args: object, **_kwargs: object) -> None:
        nonlocal constructor_called
        constructor_called = True
        raise AssertionError("ZipFile constructor must not be called")

    monkeypatch.setattr(zipfile, "ZipFile", unexpected_zipfile)
    with pytest.raises(RehydrateError) as error:
        validate_ipa(_write_ipa(tmp_path, bytes(damaged)))

    assert _reason(error) == "IPA_ZIP_DIRECTORY_INVALID"
    assert constructor_called is False


def test_rejects_declared_entry_bomb_before_zipfile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    damaged = bytearray(_ipa_bytes())
    eocd_offset = _eocd_offset(damaged)
    oversized_count = ipa_module.MAX_ZIP_ENTRIES + 1
    struct.pack_into("<H", damaged, eocd_offset + 8, oversized_count)
    struct.pack_into("<H", damaged, eocd_offset + 10, oversized_count)
    constructor_called = False

    def unexpected_zipfile(*_args: object, **_kwargs: object) -> None:
        nonlocal constructor_called
        constructor_called = True
        raise AssertionError("ZipFile constructor must not be called")

    monkeypatch.setattr(zipfile, "ZipFile", unexpected_zipfile)
    with pytest.raises(RehydrateError) as error:
        validate_ipa(_write_ipa(tmp_path, bytes(damaged)))

    assert _reason(error) == "IPA_TOO_MANY_ENTRIES"
    assert constructor_called is False


def test_rejects_declared_central_directory_size_bomb(tmp_path: Path) -> None:
    damaged = bytearray(_ipa_bytes())
    struct.pack_into(
        "<I",
        damaged,
        _eocd_offset(damaged) + 12,
        ipa_module.MAX_CENTRAL_DIRECTORY_BYTES + 1,
    )

    with pytest.raises(RehydrateError) as error:
        validate_ipa(_write_ipa(tmp_path, bytes(damaged)))

    assert _reason(error) == "IPA_ZIP_DIRECTORY_TOO_LARGE"


def test_rejects_invalid_central_directory_offset(tmp_path: Path) -> None:
    damaged = bytearray(_ipa_bytes())
    eocd_offset = _eocd_offset(damaged)
    directory_offset = struct.unpack_from("<I", damaged, eocd_offset + 16)[0]
    struct.pack_into("<I", damaged, eocd_offset + 16, directory_offset + 1)

    with pytest.raises(RehydrateError) as error:
        validate_ipa(_write_ipa(tmp_path, bytes(damaged)))

    assert _reason(error) == "IPA_ZIP_DIRECTORY_INVALID"


def test_rejects_ambiguous_end_aligned_eocd_candidates(tmp_path: Path) -> None:
    archive_bytes = _ipa_bytes()
    eocd_offset = _eocd_offset(archive_bytes)
    damaged = bytearray(archive_bytes)
    struct.pack_into("<H", damaged, eocd_offset + 20, 22)
    damaged.extend(archive_bytes[eocd_offset : eocd_offset + 22])

    with pytest.raises(RehydrateError) as error:
        validate_ipa(_write_ipa(tmp_path, bytes(damaged)))

    assert _reason(error) == "IPA_ZIP_DIRECTORY_INVALID"


def test_rejects_later_eocd_signature_inside_real_comment_before_zipfile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive_bytes = _ipa_bytes()
    eocd_offset = _eocd_offset(archive_bytes)
    fake_eocd = bytearray(22)
    fake_eocd[:4] = b"PK\x05\x06"
    damaged = bytearray(archive_bytes)
    struct.pack_into("<H", damaged, eocd_offset + 20, len(fake_eocd) + 1)
    damaged.extend(fake_eocd)
    damaged.extend(b"x")
    constructor_called = False

    def unexpected_zipfile(*_args: object, **_kwargs: object) -> None:
        nonlocal constructor_called
        constructor_called = True
        raise AssertionError("ZipFile constructor must not be called")

    monkeypatch.setattr(zipfile, "ZipFile", unexpected_zipfile)
    with pytest.raises(RehydrateError) as error:
        validate_ipa(_write_ipa(tmp_path, bytes(damaged)))

    assert _reason(error) == "IPA_ZIP_DIRECTORY_INVALID"
    assert constructor_called is False


def test_rejects_extensible_zip64_record_before_zipfile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive_bytes = bytearray(_zip64_ipa_bytes())
    eocd_offset = _eocd_offset(archive_bytes)
    locator_offset = eocd_offset - 20
    record_offset = struct.unpack_from("<Q", archive_bytes, locator_offset + 8)[0]
    extension = b"synthetic-extension"
    struct.pack_into("<Q", archive_bytes, record_offset + 4, 44 + len(extension))
    damaged = archive_bytes[:locator_offset] + extension + archive_bytes[locator_offset:]
    constructor_called = False

    def unexpected_zipfile(*_args: object, **_kwargs: object) -> None:
        nonlocal constructor_called
        constructor_called = True
        raise AssertionError("ZipFile constructor must not be called")

    monkeypatch.setattr(zipfile, "ZipFile", unexpected_zipfile)
    with pytest.raises(RehydrateError) as error:
        validate_ipa(_write_ipa(tmp_path, bytes(damaged)))

    assert _reason(error) == "IPA_ZIP_DIRECTORY_INVALID"
    assert constructor_called is False


@pytest.mark.parametrize(
    ("damage", "expected_reason"),
    [
        ("locator_signature", "IPA_ZIP_DIRECTORY_INVALID"),
        ("locator_disk", "IPA_ZIP_MULTIDISK_UNSUPPORTED"),
        ("locator_total_disks", "IPA_ZIP_MULTIDISK_UNSUPPORTED"),
        ("record_size", "IPA_ZIP_DIRECTORY_INVALID"),
        ("record_location", "IPA_ZIP_DIRECTORY_INVALID"),
        ("record_disk", "IPA_ZIP_MULTIDISK_UNSUPPORTED"),
        ("record_count", "IPA_ZIP_DIRECTORY_INVALID"),
    ],
)
def test_rejects_invalid_zip64_directory_metadata(
    tmp_path: Path, damage: str, expected_reason: str
) -> None:
    damaged = bytearray(_zip64_ipa_bytes())
    eocd_offset = _eocd_offset(damaged)
    locator_offset = eocd_offset - 20
    record_offset = struct.unpack_from("<Q", damaged, locator_offset + 8)[0]

    if damage == "locator_signature":
        damaged[locator_offset] ^= 0xFF
    elif damage == "locator_disk":
        struct.pack_into("<I", damaged, locator_offset + 4, 1)
    elif damage == "locator_total_disks":
        struct.pack_into("<I", damaged, locator_offset + 16, 2)
    elif damage == "record_size":
        struct.pack_into("<Q", damaged, record_offset + 4, 43)
    elif damage == "record_location":
        struct.pack_into("<Q", damaged, locator_offset + 8, record_offset + 1)
    elif damage == "record_disk":
        struct.pack_into("<I", damaged, record_offset + 16, 1)
    else:
        entries_on_disk = struct.unpack_from("<Q", damaged, record_offset + 24)[0]
        struct.pack_into("<Q", damaged, record_offset + 32, entries_on_disk - 1)

    with pytest.raises(RehydrateError) as error:
        validate_ipa(_write_ipa(tmp_path, bytes(damaged)))

    assert _reason(error) == expected_reason


def test_rejects_lzma_before_crc_or_member_extraction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _write_ipa(tmp_path, _ipa_bytes(compression=zipfile.ZIP_LZMA))
    testzip_called = False
    open_called = False

    def unexpected_testzip(*_args: object, **_kwargs: object) -> None:
        nonlocal testzip_called
        testzip_called = True
        raise AssertionError("testzip must not be called")

    def unexpected_open(*_args: object, **_kwargs: object) -> None:
        nonlocal open_called
        open_called = True
        raise AssertionError("member extraction must not be called")

    monkeypatch.setattr(zipfile.ZipFile, "testzip", unexpected_testzip)
    monkeypatch.setattr(zipfile.ZipFile, "open", unexpected_open)
    with pytest.raises(RehydrateError) as error:
        validate_ipa(path)

    assert _reason(error) == "IPA_ZIP_COMPRESSION_UNSUPPORTED"
    assert testzip_called is False
    assert open_called is False


def test_rejects_local_lzma_method_mismatch_before_zipfile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression: ZipFile trusts the central method and ignores this local LZMA lie."""
    damaged = bytearray(_ipa_bytes())
    _central_offset, local_offset = _entry_offsets(damaged, "Payload/Synthetic.app/Info.plist")
    struct.pack_into("<H", damaged, local_offset + 8, zipfile.ZIP_LZMA)
    archive_bytes = bytes(damaged)
    with zipfile.ZipFile(io.BytesIO(archive_bytes), "r") as archive:
        assert archive.testzip() is None

    constructor_called = False

    def unexpected_zipfile(*_args: object, **_kwargs: object) -> None:
        nonlocal constructor_called
        constructor_called = True
        raise AssertionError("ZipFile constructor must not be called")

    monkeypatch.setattr(zipfile, "ZipFile", unexpected_zipfile)
    with pytest.raises(RehydrateError) as error:
        validate_ipa(_write_ipa(tmp_path, archive_bytes))

    assert _reason(error) == "IPA_ZIP_COMPRESSION_UNSUPPORTED"
    assert constructor_called is False


def test_rejects_deflate_output_beyond_forged_size_and_crc_before_zipfile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression: ZipFile accepts a 1 MiB stream declared as one matching byte."""
    hostile_name = "Payload/Synthetic.app/forged-size.bin"
    damaged = bytearray(_ipa_bytes(extra={hostile_name: b"A" * 1024**2}))
    central_offset, local_offset = _entry_offsets(damaged, hostile_name)
    prefix_crc = zlib.crc32(b"A")
    struct.pack_into("<I", damaged, central_offset + 16, prefix_crc)
    struct.pack_into("<I", damaged, central_offset + 24, 1)
    struct.pack_into("<I", damaged, local_offset + 14, prefix_crc)
    struct.pack_into("<I", damaged, local_offset + 22, 1)
    archive_bytes = bytes(damaged)
    with zipfile.ZipFile(io.BytesIO(archive_bytes), "r") as archive:
        assert archive.testzip() is None
        assert archive.read(hostile_name) == b"A"

    constructor_called = False

    def unexpected_zipfile(*_args: object, **_kwargs: object) -> None:
        nonlocal constructor_called
        constructor_called = True
        raise AssertionError("ZipFile constructor must not be called")

    monkeypatch.setattr(zipfile, "ZipFile", unexpected_zipfile)
    with pytest.raises(RehydrateError) as error:
        validate_ipa(_write_ipa(tmp_path, archive_bytes))

    assert _reason(error) == "IPA_ZIP_SIZE_MISMATCH"
    assert constructor_called is False


def test_rejects_trailing_bytes_inside_declared_deflate_payload(tmp_path: Path) -> None:
    target_name = "iTunesMetadata.plist"
    archive_bytes = _ipa_bytes()
    old_eocd_offset = _eocd_offset(archive_bytes)
    old_directory_offset = struct.unpack_from("<I", archive_bytes, old_eocd_offset + 16)[0]
    old_central_offset, local_offset = _entry_offsets(archive_bytes, target_name)
    old_compressed_size = struct.unpack_from("<I", archive_bytes, old_central_offset + 20)[0]

    damaged = bytearray(
        archive_bytes[:old_directory_offset] + b"\x00" + archive_bytes[old_directory_offset:]
    )
    central_offset = old_central_offset + 1
    eocd_offset = old_eocd_offset + 1
    struct.pack_into("<I", damaged, central_offset + 20, old_compressed_size + 1)
    struct.pack_into("<I", damaged, local_offset + 18, old_compressed_size + 1)
    struct.pack_into("<I", damaged, eocd_offset + 16, old_directory_offset + 1)
    trailing_archive = bytes(damaged)
    with zipfile.ZipFile(io.BytesIO(trailing_archive), "r") as archive:
        assert archive.testzip() is None

    with pytest.raises(RehydrateError) as error:
        validate_ipa(_write_ipa(tmp_path, trailing_archive))

    assert _reason(error) == "IPA_ZIP_DATA_INVALID"


def test_rejects_unsupported_reserved_flags_before_zipfile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    damaged = bytearray(_ipa_bytes())
    central_offset, local_offset = _entry_offsets(damaged, "Payload/Synthetic.app/Info.plist")
    central_flags = struct.unpack_from("<H", damaged, central_offset + 8)[0]
    local_flags = struct.unpack_from("<H", damaged, local_offset + 6)[0]
    struct.pack_into("<H", damaged, central_offset + 8, central_flags | (1 << 14))
    struct.pack_into("<H", damaged, local_offset + 6, local_flags | (1 << 14))
    constructor_called = False

    def unexpected_zipfile(*_args: object, **_kwargs: object) -> None:
        nonlocal constructor_called
        constructor_called = True
        raise AssertionError("ZipFile constructor must not be called")

    monkeypatch.setattr(zipfile, "ZipFile", unexpected_zipfile)
    with pytest.raises(RehydrateError) as error:
        validate_ipa(_write_ipa(tmp_path, bytes(damaged)))

    assert _reason(error) == "IPA_ZIP_FLAGS_UNSUPPORTED"
    assert constructor_called is False


def test_rejects_local_crc_disagreement_without_descriptor(tmp_path: Path) -> None:
    damaged = bytearray(_ipa_bytes())
    _central_offset, local_offset = _entry_offsets(damaged, "Payload/Synthetic.app/Info.plist")
    local_crc = struct.unpack_from("<I", damaged, local_offset + 14)[0]
    struct.pack_into("<I", damaged, local_offset + 14, local_crc ^ 1)

    with pytest.raises(RehydrateError) as error:
        validate_ipa(_write_ipa(tmp_path, bytes(damaged)))

    assert _reason(error) == "IPA_ZIP_LOCAL_HEADER_INVALID"


@pytest.mark.parametrize(
    ("unsafe_name", "expected_reason"),
    [
        ("../outside", "IPA_MEMBER_PATH_TRAVERSAL"),
        ("Payload" + chr(92) + "Synthetic.app" + chr(92) + "bad", "IPA_MEMBER_PATH_INVALID"),
        ("/absolute", "IPA_MEMBER_PATH_ABSOLUTE"),
        ("C:/absolute", "IPA_MEMBER_PATH_ABSOLUTE"),
        ("Payload//Synthetic.app/bad", "IPA_MEMBER_PATH_INVALID"),
        ("Payload/./Synthetic.app/bad", "IPA_MEMBER_PATH_INVALID"),
    ],
)
def test_rejects_unsafe_member_paths(
    tmp_path: Path, unsafe_name: str, expected_reason: str
) -> None:
    archive_bytes = _ipa_bytes(extra={unsafe_name: b"hostile"})
    # zipfile canonicalizes backslashes on Windows when writing. Patch both
    # equal-length filename records to preserve the hostile archive spelling.
    if "\\" in unsafe_name:
        canonical_name = unsafe_name.replace("\\", "/")
        archive_bytes = archive_bytes.replace(canonical_name.encode(), unsafe_name.encode())
    path = _write_ipa(tmp_path, archive_bytes)

    with pytest.raises(RehydrateError) as error:
        validate_ipa(path)

    assert _reason(error) == expected_reason
    assert unsafe_name not in str(error.value)


@pytest.mark.parametrize(
    "mode",
    [
        stat.S_IFIFO | 0o600,
        stat.S_IFCHR | 0o600,
        stat.S_IFBLK | 0o600,
        stat.S_IFSOCK | 0o600,
    ],
)
def test_rejects_special_unix_member_types(tmp_path: Path, mode: int) -> None:
    hostile_name = "Payload/Synthetic.app/hostile-member"
    archive_bytes = _with_unix_member(_ipa_bytes(), name=hostile_name, mode=mode)

    with pytest.raises(RehydrateError) as error:
        validate_ipa(_write_ipa(tmp_path, archive_bytes))

    assert _reason(error) == "IPA_MEMBER_TYPE_UNSAFE"
    assert hostile_name not in str(error.value)


def test_rejects_unix_symlink_member(tmp_path: Path) -> None:
    hostile_name = "Payload/Synthetic.app/symlink-member"
    archive_bytes = _with_unix_member(
        _ipa_bytes(),
        name=hostile_name,
        mode=stat.S_IFLNK | 0o777,
    )

    with pytest.raises(RehydrateError) as error:
        validate_ipa(_write_ipa(tmp_path, archive_bytes))

    assert _reason(error) == "IPA_MEMBER_TYPE_UNSAFE"
    assert hostile_name not in str(error.value)


def test_allows_unspecified_unix_member_type(tmp_path: Path) -> None:
    archive_bytes = _with_unix_member(
        _ipa_bytes(),
        name="Payload/Synthetic.app/untyped-resource",
        mode=0,
    )

    validated = validate_ipa(_write_ipa(tmp_path, archive_bytes))

    assert validated.archive_bytes == archive_bytes


def test_rejects_regular_payload_replacing_an_implicit_parent(tmp_path: Path) -> None:
    archive_bytes = _ipa_bytes(extra={"Payload": b"regular-ancestor"})

    with pytest.raises(RehydrateError) as error:
        validate_ipa(_write_ipa(tmp_path, archive_bytes))

    assert _reason(error) == "IPA_MEMBER_PATH_CONFLICT"


def test_rejects_unix_directory_info_plist_without_slash(tmp_path: Path) -> None:
    archive_bytes = _with_central_unix_mode(
        _ipa_bytes(),
        name="Payload/Synthetic.app/Info.plist",
        mode=stat.S_IFDIR | 0o755,
    )

    with pytest.raises(RehydrateError) as error:
        validate_ipa(_write_ipa(tmp_path, archive_bytes))

    assert _reason(error) == "IPA_MEMBER_TYPE_MISMATCH"


def test_rejects_unix_regular_member_with_directory_slash(tmp_path: Path) -> None:
    output = io.BytesIO(_ipa_bytes())
    member = zipfile.ZipInfo("Payload/Synthetic.app/regular/")
    member.create_system = 3
    member.external_attr = (stat.S_IFREG | 0o644) << 16
    with zipfile.ZipFile(output, "a") as archive:
        archive.writestr(member, b"")

    with pytest.raises(RehydrateError) as error:
        validate_ipa(_write_ipa(tmp_path, output.getvalue()))

    assert _reason(error) == "IPA_MEMBER_TYPE_MISMATCH"


def test_rejects_nonempty_directory_member(tmp_path: Path) -> None:
    archive_bytes = _ipa_bytes(extra={"Payload/Synthetic.app/nonempty-directory/": b"not-empty"})

    with pytest.raises(RehydrateError) as error:
        validate_ipa(_write_ipa(tmp_path, archive_bytes))

    assert _reason(error) == "IPA_DIRECTORY_NOT_EMPTY"


@pytest.mark.parametrize(
    "first,second",
    [
        ("ReadMe.txt", "README.TXT"),
        ("Cafe\N{COMBINING ACUTE ACCENT}.txt", "Caf\N{LATIN SMALL LETTER E WITH ACUTE}.txt"),
    ],
)
def test_rejects_casefolded_or_unicode_normalized_member_collisions(
    tmp_path: Path, first: str, second: str
) -> None:
    prefix = "Payload/Synthetic.app/"
    archive_bytes = _ipa_bytes(extra={f"{prefix}{first}": b"first", f"{prefix}{second}": b"second"})

    with pytest.raises(RehydrateError) as error:
        validate_ipa(_write_ipa(tmp_path, archive_bytes))

    assert _reason(error) == "IPA_MEMBER_PATH_COLLISION"
    assert first not in str(error.value)
    assert second not in str(error.value)


def test_rejects_duplicate_member(tmp_path: Path) -> None:
    output = io.BytesIO(_ipa_bytes())
    with (
        pytest.warns(UserWarning, match="Duplicate name"),
        zipfile.ZipFile(output, "a") as archive,
    ):
        archive.writestr("iTunesMetadata.plist", b"duplicate")

    with pytest.raises(RehydrateError) as error:
        validate_ipa(_write_ipa(tmp_path, output.getvalue()))

    assert _reason(error) == "IPA_DUPLICATE_MEMBER"


def test_rejects_metadata_bundle_mismatch(tmp_path: Path) -> None:
    path = _write_ipa(
        tmp_path,
        _ipa_bytes(metadata_bundle_id="test.invalid.different"),
    )

    with pytest.raises(RehydrateError) as error:
        validate_ipa(path)

    assert _reason(error) == "IPA_METADATA_BUNDLE_MISMATCH"
    assert "test.invalid" not in str(error.value)


def test_expected_store_id_rejects_missing_metadata_value(tmp_path: Path) -> None:
    path = _write_ipa(tmp_path, _ipa_bytes(store_id=None))

    with pytest.raises(RehydrateError) as error:
        validate_ipa(path, expected_store_id="123456")

    assert _reason(error) == "IPA_EXPECTED_STORE_ID_MISSING"


def test_rejects_more_than_one_payload_app(tmp_path: Path) -> None:
    path = _write_ipa(
        tmp_path,
        _ipa_bytes(extra={"Payload/Other.app/file": b"synthetic"}),
    )

    with pytest.raises(RehydrateError) as error:
        validate_ipa(path)

    assert _reason(error) == "IPA_APP_COUNT_INVALID"


def test_rejects_bad_crc_without_disclosing_member_name(tmp_path: Path) -> None:
    archive_bytes = bytearray(_ipa_bytes(compression=zipfile.ZIP_STORED))
    marker = b"synthetic-sinf"
    offset = archive_bytes.index(marker)
    archive_bytes[offset] ^= 0xFF

    with pytest.raises(RehydrateError) as error:
        validate_ipa(_write_ipa(tmp_path, bytes(archive_bytes)))

    assert _reason(error) in {"IPA_CRC_MISMATCH", "IPA_CRC_CHECK_FAILED"}
    assert "SC_Info" not in str(error.value)
    assert "SyntheticExecutable" not in str(error.value)


def test_enforces_file_size_before_archive_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _write_ipa(tmp_path, _ipa_bytes())
    monkeypatch.setattr(ipa_module, "MAX_IPA_BYTES", 1)

    with pytest.raises(RehydrateError) as error:
        validate_ipa(path)

    assert _reason(error) == "IPA_FILE_TOO_LARGE"


def test_enforces_zip_entry_limit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = _write_ipa(tmp_path, _ipa_bytes())
    monkeypatch.setattr(ipa_module, "MAX_ZIP_ENTRIES", 2)

    with pytest.raises(RehydrateError) as error:
        validate_ipa(path)

    assert _reason(error) == "IPA_TOO_MANY_ENTRIES"


def test_enforces_expanded_size_limit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = _write_ipa(tmp_path, _ipa_bytes())
    monkeypatch.setattr(ipa_module, "MAX_EXPANDED_BYTES", 1)

    with pytest.raises(RehydrateError) as error:
        validate_ipa(path)

    assert _reason(error) == "IPA_EXPANDED_TOO_LARGE"


def test_enforces_compression_ratio_limit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = _write_ipa(tmp_path, _ipa_bytes())
    monkeypatch.setattr(ipa_module, "MAX_COMPRESSION_RATIO", 1)

    with pytest.raises(RehydrateError) as error:
        validate_ipa(path)

    assert _reason(error) == "IPA_COMPRESSION_RATIO_EXCEEDED"


def test_enforces_plist_size_limit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = _write_ipa(tmp_path, _ipa_bytes())
    monkeypatch.setattr(ipa_module, "MAX_PLIST_BYTES", 8)

    with pytest.raises(RehydrateError) as error:
        validate_ipa(path)

    assert _reason(error) == "IPA_INFO_PLIST_TOO_LARGE"


def test_rejects_symlink_input(tmp_path: Path) -> None:
    target = _write_ipa(tmp_path, _ipa_bytes())
    link = tmp_path / "linked.ipa"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symlink creation is not available")

    with pytest.raises(RehydrateError) as error:
        validate_ipa(link)

    assert _reason(error) == "IPA_NOT_REGULAR_FILE"


@pytest.mark.parametrize(
    "bundle_id",
    ["invalid bundle", ".invalid", "invalid/segment", "invalid\nsegment"],
)
def test_rejects_invalid_bundle_identifier(tmp_path: Path, bundle_id: str) -> None:
    with pytest.raises(RehydrateError) as error:
        validate_ipa(_write_ipa(tmp_path, _ipa_bytes(bundle_id=bundle_id)))

    assert _reason(error) == "IPA_BUNDLE_ID_INVALID"


@pytest.mark.parametrize(
    ("overrides", "expected_reason", "seeded_private_text"),
    [
        ({"version": _SEEDED_PRIVATE_EMAIL}, "IPA_VERSION_INVALID", _SEEDED_PRIVATE_EMAIL),
        ({"build": _SEEDED_WINDOWS_PATH}, "IPA_BUILD_INVALID", _SEEDED_WINDOWS_PATH),
        (
            {"minimum_os": _SEEDED_PRIVATE_EMAIL},
            "IPA_MINIMUM_OS_INVALID",
            _SEEDED_PRIVATE_EMAIL,
        ),
        ({"minimum_os": _SEEDED_WINDOWS_PATH}, "IPA_MINIMUM_OS_INVALID", _SEEDED_WINDOWS_PATH),
    ],
)
def test_rejects_private_text_in_public_version_fields_without_echoing_it(
    tmp_path: Path,
    overrides: dict[str, str],
    expected_reason: str,
    seeded_private_text: str,
) -> None:
    with pytest.raises(RehydrateError) as error:
        validate_ipa(_write_ipa(tmp_path, _ipa_bytes(**overrides)))

    assert _reason(error) == expected_reason
    assert seeded_private_text not in str(error.value)
