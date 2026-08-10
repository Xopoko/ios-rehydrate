# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 iOS Rehydrate contributors
from __future__ import annotations

import logging
import plistlib
import sqlite3
from pathlib import Path

import pytest
from pyiosbackup.manifest_dbs.sqlite3 import MBFile

from ios_rehydrate import manifest
from ios_rehydrate.errors import RehydrateError


def _tlv(tag: bytes, value: int | bytes) -> bytes:
    payload = value.to_bytes(4, "big") if type(value) is int else value
    return tag + len(payload).to_bytes(4, "big") + payload


def _root_tlvs(
    *,
    iterations: int | bytes = 10_000,
    double_iterations: int | bytes = 10_000_000,
    include_double_protection: bool = True,
) -> list[bytes]:
    elements = [
        _tlv(b"VERS", 3),
        _tlv(b"TYPE", 1),
        _tlv(b"UUID", b"R" * 16),
        _tlv(b"HMCK", b"H" * 40),
        _tlv(b"WRAP", 0),
        _tlv(b"SALT", b"S" * 20),
        _tlv(b"ITER", iterations),
    ]
    if include_double_protection:
        elements.extend(
            (
                _tlv(b"DPSL", b"D" * 20),
                _tlv(b"DPIC", double_iterations),
            )
        )
    return elements


def _class_group(
    class_id: int | bytes = 4,
    *,
    uuid_seed: int = 4,
    class_uuid: bytes | None = None,
    wrapping: int | bytes = 3,
    key_type: int | bytes = 0,
    wrapped_key: bytes = b"W" * 40,
) -> bytes:
    uuid = bytes([uuid_seed]) * 16 if class_uuid is None else class_uuid
    return b"".join(
        (
            _tlv(b"UUID", uuid),
            _tlv(b"CLAS", class_id),
            _tlv(b"WRAP", wrapping),
            _tlv(b"KTYP", key_type),
            _tlv(b"WPKY", wrapped_key),
        )
    )


def _valid_keybag(*, include_double_protection: bool = True) -> bytes:
    return _keybag_with_root(_root_tlvs(include_double_protection=include_double_protection))


def _keybag_with_root(root: list[bytes], classes: bytes | None = None) -> bytes:
    return b"".join((*root, _class_group() if classes is None else classes))


def _keybag_with_root_value(tag: bytes, value: int | bytes) -> bytes:
    root = [_tlv(tag, value) if element[:4] == tag else element for element in _root_tlvs()]
    return _keybag_with_root(root)


def _manifest_key(class_id: int = 4, wrapped_key: bytes = b"M" * 40) -> bytes:
    return class_id.to_bytes(4, "little") + wrapped_key


def _serialized_database(rows: list[tuple[str, bytes]]) -> bytes:
    connection = sqlite3.connect(":memory:")
    try:
        connection.execute(
            """
            CREATE TABLE Files (
                fileID TEXT PRIMARY KEY,
                domain TEXT,
                relativePath TEXT,
                flags INTEGER,
                file BLOB
            )
            """
        )
        for index, (domain, blob) in enumerate(rows):
            connection.execute(
                "INSERT INTO Files VALUES (?, ?, ?, ?, ?)",
                (f"{index:040x}", domain, f"synthetic/{index}", 1, blob),
            )
        connection.commit()
        return connection.serialize()
    finally:
        connection.close()


def _write_encrypted_fixture(
    device_root: Path,
    ciphertext: bytes = b"E" * 16,
    *,
    keybag: object | None = None,
    manifest_key: object | None = None,
    product_version: object = "17.0",
) -> bytes:
    device_root.mkdir()
    manifest_plist = plistlib.dumps(
        {
            "IsEncrypted": True,
            "BackupKeyBag": _valid_keybag() if keybag is None else keybag,
            "ManifestKey": _manifest_key() if manifest_key is None else manifest_key,
            "Lockdown": {"ProductVersion": product_version},
        }
    )
    (device_root / "Manifest.plist").write_bytes(manifest_plist)
    (device_root / "Manifest.db").write_bytes(ciphertext)
    return ciphertext


def _assert_metadata_rejected_before_password(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    keybag: object | None = None,
    manifest_key: object | None = None,
    product_version: object = "17.0",
) -> RehydrateError:
    device_root = tmp_path / "synthetic-device"
    _write_encrypted_fixture(
        device_root,
        keybag=keybag,
        manifest_key=manifest_key,
        product_version=product_version,
    )
    prompted = False

    class TrapKeybag:
        @staticmethod
        def from_manifest(manifest_plist: object, password: str) -> TrapKeybag:
            raise AssertionError("untrusted key material reached PBKDF2")

    def password_provider() -> str:
        nonlocal prompted
        prompted = True
        return "secret"

    monkeypatch.setattr(manifest, "Keybag", TrapKeybag)
    with pytest.raises(RehydrateError) as caught:
        manifest.probe_app_domain(device_root, "com.example.target", password_provider)

    assert caught.value.reason == "MANIFEST_METADATA_INVALID"
    assert prompted is False
    return caught.value


def _mbfile(size: int) -> MBFile:
    return MBFile(
        relative_path="synthetic",
        last_modified=0,
        last_status_change=0,
        created=0,
        size=size,
        mode=0,
        group_id=0,
        user_id=0,
    )


def test_keybag_validation_accepts_synthetic_legacy_and_modern_grammar_shapes() -> None:
    for product_version, keybag in (
        ("10.2", _valid_keybag(include_double_protection=False)),
        ("10.2.1", _valid_keybag()),
        ("17.0", _valid_keybag()),
        (
            "99.999.999",
            _keybag_with_root(
                _root_tlvs(
                    iterations=manifest.MAX_KEYBAG_ITERATIONS,
                    double_iterations=manifest.MAX_KEYBAG_DOUBLE_PROTECTION_ITERATIONS,
                )
            ),
        ),
    ):
        manifest._validate_manifest_key_material(
            {
                "BackupKeyBag": keybag,
                "ManifestKey": _manifest_key(),
                "Lockdown": {"ProductVersion": product_version},
            }
        )


@pytest.mark.parametrize(
    ("iterations", "double_iterations"),
    [
        pytest.param(0, 10_000_000, id="zero-iter"),
        pytest.param(
            manifest.MAX_KEYBAG_ITERATIONS + 1,
            10_000_000,
            id="iter-just-over-limit",
        ),
        pytest.param(10_000, 0, id="zero-dpic"),
        pytest.param(
            10_000,
            manifest.MAX_KEYBAG_DOUBLE_PROTECTION_ITERATIONS + 1,
            id="dpic-just-over-limit",
        ),
    ],
)
def test_probe_rejects_unbounded_keybag_iterations_before_password_or_pbkdf(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    iterations: int,
    double_iterations: int,
) -> None:
    keybag = _keybag_with_root(
        _root_tlvs(
            iterations=iterations,
            double_iterations=double_iterations,
        )
    )

    _assert_metadata_rejected_before_password(tmp_path, monkeypatch, keybag=keybag)


@pytest.mark.parametrize(
    "keybag",
    [
        pytest.param(b"", id="empty"),
        pytest.param(b"VERS", id="truncated-header"),
        pytest.param(
            b"VERS" + (4).to_bytes(4, "big") + b"\x00" * 3,
            id="truncated-payload",
        ),
        pytest.param(_valid_keybag() + b"X", id="trailing-byte"),
        pytest.param(_tlv(b"ZERO", b""), id="zero-size-element"),
        pytest.param(_tlv(b"bad!", b"x"), id="invalid-tag"),
        pytest.param(
            _tlv(b"JUNK", b"x" * (manifest.MAX_KEYBAG_ELEMENT_BYTES + 1)),
            id="element-just-over-limit",
        ),
        pytest.param(
            b"".join(_tlv(b"JUNK", b"x") for _ in range(manifest.MAX_KEYBAG_ELEMENTS + 1)),
            id="element-count-just-over-limit",
        ),
        pytest.param(
            b"X" * (manifest.MAX_BACKUP_KEYBAG_BYTES + 1),
            id="bag-just-over-limit",
        ),
        pytest.param(
            _keybag_with_root(
                _root_tlvs(),
                b"".join(
                    _class_group(class_id, uuid_seed=class_id)
                    for class_id in range(1, manifest.MAX_KEYBAG_CLASSES + 2)
                ),
            ),
            id="class-count-just-over-limit",
        ),
    ],
)
def test_probe_rejects_malformed_or_over_limit_tlv_before_password(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    keybag: bytes,
) -> None:
    _assert_metadata_rejected_before_password(tmp_path, monkeypatch, keybag=keybag)


@pytest.mark.parametrize(
    "tag",
    [b"VERS", b"TYPE", b"UUID", b"WRAP", b"SALT", b"ITER", b"DPSL", b"DPIC"],
)
def test_probe_rejects_missing_required_root_fields(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tag: bytes,
) -> None:
    root = [element for element in _root_tlvs() if element[:4] != tag]

    _assert_metadata_rejected_before_password(
        tmp_path,
        monkeypatch,
        keybag=_keybag_with_root(root),
    )


@pytest.mark.parametrize(
    "tag",
    [b"VERS", b"TYPE", b"UUID", b"WRAP", b"SALT", b"ITER", b"DPSL", b"DPIC"],
)
def test_probe_rejects_duplicate_root_fields(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tag: bytes,
) -> None:
    root = _root_tlvs()
    duplicate = next(element for element in root if element[:4] == tag)
    root.append(duplicate)

    _assert_metadata_rejected_before_password(
        tmp_path,
        monkeypatch,
        keybag=_keybag_with_root(root),
    )


@pytest.mark.parametrize(
    ("tag", "value"),
    [
        pytest.param(b"VERS", 0, id="zero-format-version"),
        pytest.param(b"VERS", 5, id="unknown-format-version"),
        pytest.param(b"VERS", b"\x00" * 3, id="short-format-version"),
        pytest.param(b"TYPE", 2, id="non-backup-type"),
        pytest.param(b"TYPE", b"\x00" * 3, id="short-type"),
        pytest.param(b"UUID", b"U" * 15, id="short-root-uuid"),
        pytest.param(b"UUID", b"U" * 17, id="long-root-uuid"),
        pytest.param(b"WRAP", 1, id="wrapped-root"),
        pytest.param(b"WRAP", b"\x00" * 3, id="short-root-wrap"),
        pytest.param(b"SALT", b"S" * 19, id="short-salt"),
        pytest.param(b"SALT", b"S" * 21, id="long-salt"),
        pytest.param(b"ITER", b"\x00" * 3, id="short-iter"),
        pytest.param(b"DPSL", b"D" * 19, id="short-double-salt"),
        pytest.param(b"DPSL", b"D" * 21, id="long-double-salt"),
        pytest.param(b"DPIC", b"\x00" * 3, id="short-dpic"),
        pytest.param(b"HMCK", b"H" * 39, id="short-hmac-key"),
    ],
)
def test_probe_rejects_invalid_root_field_shapes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tag: bytes,
    value: int | bytes,
) -> None:
    _assert_metadata_rejected_before_password(
        tmp_path,
        monkeypatch,
        keybag=_keybag_with_root_value(tag, value),
    )


@pytest.mark.parametrize(
    "classes",
    [
        pytest.param(_class_group(0), id="zero-class"),
        pytest.param(
            _class_group(manifest.MAX_KEYBAG_CLASS_ID + 1),
            id="class-id-just-over-limit",
        ),
        pytest.param(_class_group(b"\x00" * 3), id="short-class"),
        pytest.param(_class_group(class_uuid=b"U" * 15), id="short-class-uuid"),
        pytest.param(_class_group(class_uuid=b"U" * 17), id="long-class-uuid"),
        pytest.param(_class_group(wrapping=1), id="device-only-wrap"),
        pytest.param(_class_group(wrapping=4), id="unknown-wrap"),
        pytest.param(_class_group(wrapping=b"\x00" * 3), id="short-wrap"),
        pytest.param(_class_group(key_type=1), id="non-symmetric-key-type"),
        pytest.param(_class_group(key_type=b"\x00" * 3), id="short-key-type"),
        pytest.param(_class_group(wrapped_key=b"W" * 39), id="short-wrapped-key"),
        pytest.param(_class_group(wrapped_key=b"W" * 41), id="long-wrapped-key"),
        pytest.param(
            b"".join(
                (
                    _tlv(b"UUID", b"U" * 16),
                    _tlv(b"CLAS", 4),
                    _tlv(b"KTYP", 0),
                    _tlv(b"WRAP", 3),
                    _tlv(b"WPKY", b"W" * 40),
                )
            ),
            id="reordered-fields",
        ),
        pytest.param(_class_group()[:-48], id="missing-wrapped-key"),
        pytest.param(
            _class_group(4, uuid_seed=4) + _class_group(4, uuid_seed=5),
            id="duplicate-class",
        ),
        pytest.param(
            _class_group(4, class_uuid=b"U" * 16) + _class_group(5, class_uuid=b"U" * 16),
            id="duplicate-class-uuid",
        ),
    ],
)
def test_probe_rejects_invalid_class_groups_before_password(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    classes: bytes,
) -> None:
    _assert_metadata_rejected_before_password(
        tmp_path,
        monkeypatch,
        keybag=_keybag_with_root(_root_tlvs(), classes),
    )


@pytest.mark.parametrize(
    "manifest_key",
    [
        pytest.param(_manifest_key(wrapped_key=b"M" * 39), id="short"),
        pytest.param(_manifest_key(wrapped_key=b"M" * 41), id="long"),
        pytest.param(_manifest_key(0), id="zero-class"),
        pytest.param(_manifest_key(5), id="missing-class"),
        pytest.param("not-bytes", id="wrong-type"),
    ],
)
def test_probe_rejects_invalid_manifest_key_before_password(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    manifest_key: object,
) -> None:
    _assert_metadata_rejected_before_password(
        tmp_path,
        monkeypatch,
        manifest_key=manifest_key,
    )


@pytest.mark.parametrize(
    "product_version",
    [
        pytest.param("", id="empty"),
        pytest.param("17", id="missing-minor"),
        pytest.param("17.0.1.2", id="too-many-components"),
        pytest.param("017.0", id="leading-zero"),
        pytest.param("17.beta", id="nonnumeric"),
        pytest.param("0.0", id="zero-major"),
        pytest.param(
            f"{manifest.MAX_PRODUCT_VERSION_MAJOR + 1}.0",
            id="major-just-over-limit",
        ),
        pytest.param(
            f"1.{manifest.MAX_PRODUCT_VERSION_COMPONENT + 1}",
            id="component-just-over-limit",
        ),
        pytest.param(
            "1." + "1" * manifest.MAX_PRODUCT_VERSION_LENGTH,
            id="length-over-limit",
        ),
        pytest.param(17, id="wrong-type"),
    ],
)
def test_probe_rejects_invalid_product_version_before_password(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    product_version: object,
) -> None:
    _assert_metadata_rejected_before_password(
        tmp_path,
        monkeypatch,
        product_version=product_version,
    )


@pytest.mark.parametrize("present_tag", [b"DPSL", b"DPIC"])
def test_probe_rejects_partial_double_protection_fields_even_for_legacy_version(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    present_tag: bytes,
) -> None:
    root = [
        element
        for element in _root_tlvs()
        if element[:4] not in {b"DPSL", b"DPIC"} or element[:4] == present_tag
    ]

    _assert_metadata_rejected_before_password(
        tmp_path,
        monkeypatch,
        keybag=_keybag_with_root(root),
        product_version="10.2",
    )


def test_probe_requires_double_protection_after_ios_10_2_before_password(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _assert_metadata_rejected_before_password(
        tmp_path,
        monkeypatch,
        keybag=_valid_keybag(include_double_protection=False),
        product_version="10.2.1",
    )


def test_probe_suppresses_pyiosbackup_secret_logs_and_restores_logger(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    device_root = tmp_path / "synthetic-device"
    _write_encrypted_fixture(device_root)
    pyiosbackup_logger = logging.getLogger("pyiosbackup")
    monkeypatch.setattr(pyiosbackup_logger, "disabled", False)

    class LoggingKeybag:
        @staticmethod
        def from_manifest(manifest_plist: object, password: str) -> LoggingKeybag:
            pyiosbackup_logger.debug("derived-key=DERIVED_SECRET")
            pyiosbackup_logger.debug("root-elements=ROOT_SECRET")
            raise RuntimeError("RAW_SECRET_EXCEPTION")

    monkeypatch.setattr(manifest, "Keybag", LoggingKeybag)
    with caplog.at_level(logging.DEBUG, logger="pyiosbackup"):
        with pytest.raises(RehydrateError) as caught:
            manifest.probe_app_domain(device_root, "com.example.target", lambda: "secret")
        assert pyiosbackup_logger.disabled is False
        pyiosbackup_logger.debug("post-call-marker")

    messages = "\n".join(record.getMessage() for record in caplog.records)
    assert str(caught.value) == "manifest database decryption failed"
    assert caught.value.reason == "MANIFEST_DECRYPT_FAILED"
    assert "DERIVED_SECRET" not in messages
    assert "ROOT_SECRET" not in messages
    assert "RAW_SECRET_EXCEPTION" not in str(caught.value)
    assert caught.value.__cause__ is None
    assert "post-call-marker" in messages


def test_safe_device_root_rejects_symlinked_nested_ancestor(tmp_path: Path) -> None:
    real_parent = tmp_path / "real-parent"
    device_root = real_parent / "nested" / "device"
    device_root.mkdir(parents=True)
    linked_parent = tmp_path / "linked-parent"
    try:
        linked_parent.symlink_to(real_parent, target_is_directory=True)
    except (NotImplementedError, OSError):
        pytest.skip("directory symlinks are unavailable on this host")

    with pytest.raises(RehydrateError) as caught:
        manifest._safe_device_root(linked_parent / "nested" / "device")

    assert caught.value.reason == "MANIFEST_PATH_INVALID"


def test_safe_device_root_rejects_windows_reparse_on_non_immediate_ancestor_before_resolve(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    unsafe_ancestor = tmp_path / "unsafe-ancestor"
    device_root = unsafe_ancestor / "nested" / "device"
    device_root.mkdir(parents=True)
    real_lstat = manifest.os.lstat
    real_resolve = Path.resolve
    resolve_called = False

    def marked_lstat(path: object) -> object:
        metadata = real_lstat(path)
        if Path(path) != unsafe_ancestor:
            return metadata
        return type(
            "ReparseMetadata",
            (),
            {
                "st_mode": metadata.st_mode,
                "st_file_attributes": manifest._REPARSE_POINT,
            },
        )()

    def tracked_resolve(path: Path, *, strict: bool = False) -> Path:
        nonlocal resolve_called
        resolve_called = True
        return real_resolve(path, strict=strict)

    monkeypatch.setattr(manifest.os, "lstat", marked_lstat)
    monkeypatch.setattr(Path, "resolve", tracked_resolve)

    with pytest.raises(RehydrateError) as caught:
        manifest._safe_device_root(device_root)

    assert caught.value.reason == "MANIFEST_PATH_INVALID"
    assert resolve_called is False


def test_probe_decrypts_in_memory_normalizes_wal_and_aggregates_logical_sizes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    device_root = tmp_path / "synthetic-device"
    ciphertext = _write_encrypted_fixture(device_root)
    database = bytearray(
        _serialized_database(
            [
                ("AppDomain-com.example.target", b"first"),
                ("AppDomain-com.example.target", b"second"),
                ("AppDomain-com.example.other", b"other"),
            ]
        )
    )
    database[18:20] = b"\x02\x02"
    decrypted_with_full_padding = bytes(database) + b"\x10" * 16
    seen_ciphertext: list[bytes] = []
    prompt_result = "synthetic-secret"

    class FakeKeybag:
        @staticmethod
        def from_manifest(manifest_plist: object, password: str) -> FakeKeybag:
            assert password == prompt_result
            return FakeKeybag()

        def decrypt(self, encrypted: bytes, key: bytes) -> bytes:
            seen_ciphertext.append(encrypted)
            return decrypted_with_full_padding

    decoded = iter([_mbfile(11), _mbfile(29)])
    monkeypatch.setattr(manifest, "Keybag", FakeKeybag)
    monkeypatch.setattr(manifest.archiver, "unarchive", lambda blob: next(decoded))

    report = manifest.probe_app_domain(
        device_root,
        "com.example.target",
        lambda: prompt_result,
    )

    assert report.as_public_dict() == {"entry_count": 2, "logical_bytes_total": 40}
    assert seen_ciphertext == [ciphertext]
    assert (device_root / "Manifest.db").read_bytes() == ciphertext
    assert database[18:20] == b"\x02\x02"


def test_probe_query_matches_exact_runtime_bundle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    device_root = tmp_path / "synthetic-device"
    _write_encrypted_fixture(device_root)
    bundle_id = "com.example.target-1"
    database = _serialized_database(
        [
            (f"AppDomain-{bundle_id}", b"exact"),
            ("AppDomain-com.example.target-10", b"other"),
        ]
    )

    class FakeKeybag:
        @staticmethod
        def from_manifest(manifest_plist: object, password: str) -> FakeKeybag:
            return FakeKeybag()

        def decrypt(self, encrypted: bytes, key: bytes) -> bytes:
            return database

    decode_calls: list[bytes] = []
    monkeypatch.setattr(manifest, "Keybag", FakeKeybag)
    monkeypatch.setattr(
        manifest.archiver,
        "unarchive",
        lambda blob: decode_calls.append(blob) or _mbfile(7),
    )

    report = manifest.probe_app_domain(device_root, bundle_id, lambda: "secret")

    assert report.entry_count == 1
    assert report.logical_bytes_total == 7
    assert decode_calls == [b"exact"]


def test_probe_rejects_unaligned_ciphertext_before_password_prompt(tmp_path: Path) -> None:
    device_root = tmp_path / "synthetic-device"
    _write_encrypted_fixture(device_root, ciphertext=b"not-aligned")
    prompted = False

    def password_provider() -> str:
        nonlocal prompted
        prompted = True
        return "secret"

    with pytest.raises(RehydrateError) as caught:
        manifest.probe_app_domain(device_root, "com.example.target", password_provider)
    assert caught.value.reason == "MANIFEST_CIPHERTEXT_INVALID"
    assert prompted is False


def test_probe_rejects_sparse_oversize_database_before_password_prompt(tmp_path: Path) -> None:
    device_root = tmp_path / "synthetic-device"
    _write_encrypted_fixture(device_root)
    with (device_root / "Manifest.db").open("r+b") as stream:
        stream.truncate(manifest.MAX_MANIFEST_DB_BYTES + 1)
    prompted = False

    def password_provider() -> str:
        nonlocal prompted
        prompted = True
        return "secret"

    with pytest.raises(RehydrateError) as caught:
        manifest.probe_app_domain(device_root, "com.example.target", password_provider)

    assert caught.value.reason == "MANIFEST_DATABASE_TOO_LARGE"
    assert prompted is False


def test_probe_bounds_manifest_plist_before_parse(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    device_root = tmp_path / "synthetic-device"
    _write_encrypted_fixture(device_root)
    monkeypatch.setattr(manifest, "MAX_MANIFEST_PLIST_BYTES", 8)

    with pytest.raises(RehydrateError) as caught:
        manifest.probe_app_domain(device_root, "com.example.target", lambda: "secret")

    assert caught.value.reason == "MANIFEST_METADATA_TOO_LARGE"


def test_probe_rejects_invalid_full_block_padding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    device_root = tmp_path / "synthetic-device"
    _write_encrypted_fixture(device_root)
    malformed = _serialized_database([]) + b"\x10" * 15 + b"\x0f"

    class FakeKeybag:
        @staticmethod
        def from_manifest(manifest_plist: object, password: str) -> FakeKeybag:
            return FakeKeybag()

        def decrypt(self, encrypted: bytes, key: bytes) -> bytes:
            return malformed

    monkeypatch.setattr(manifest, "Keybag", FakeKeybag)
    with pytest.raises(RehydrateError) as caught:
        manifest.probe_app_domain(device_root, "com.example.target", lambda: "secret")
    assert caught.value.reason == "MANIFEST_PADDING_INVALID"


def test_probe_rejects_mixed_sqlite_mode_header(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    device_root = tmp_path / "synthetic-device"
    _write_encrypted_fixture(device_root)
    malformed = bytearray(_serialized_database([]))
    malformed[18:20] = b"\x01\x02"

    class FakeKeybag:
        @staticmethod
        def from_manifest(manifest_plist: object, password: str) -> FakeKeybag:
            return FakeKeybag()

        def decrypt(self, encrypted: bytes, key: bytes) -> bytes:
            return bytes(malformed)

    monkeypatch.setattr(manifest, "Keybag", FakeKeybag)
    with pytest.raises(RehydrateError) as caught:
        manifest.probe_app_domain(device_root, "com.example.target", lambda: "secret")
    assert caught.value.reason == "MANIFEST_SQLITE_INVALID"


def test_probe_rejects_pending_manifest_journal_before_password_prompt(tmp_path: Path) -> None:
    device_root = tmp_path / "synthetic-device"
    _write_encrypted_fixture(device_root)
    (device_root / "Manifest.db-wal").write_bytes(b"pending")
    prompted = False

    def password_provider() -> str:
        nonlocal prompted
        prompted = True
        return "secret"

    with pytest.raises(RehydrateError) as caught:
        manifest.probe_app_domain(device_root, "com.example.target", password_provider)
    assert caught.value.reason == "MANIFEST_JOURNAL_INVALID"
    assert prompted is False


def test_probe_validates_files_schema(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    device_root = tmp_path / "synthetic-device"
    _write_encrypted_fixture(device_root)
    connection = sqlite3.connect(":memory:")
    try:
        connection.execute("CREATE TABLE Other (value TEXT)")
        database = connection.serialize()
    finally:
        connection.close()

    class FakeKeybag:
        @staticmethod
        def from_manifest(manifest_plist: object, password: str) -> FakeKeybag:
            return FakeKeybag()

        def decrypt(self, encrypted: bytes, key: bytes) -> bytes:
            return database

    monkeypatch.setattr(manifest, "Keybag", FakeKeybag)
    with pytest.raises(RehydrateError) as caught:
        manifest.probe_app_domain(device_root, "com.example.target", lambda: "secret")
    assert caught.value.reason == "MANIFEST_SCHEMA_INVALID"


def test_probe_rejects_invalid_or_negative_decoded_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    device_root = tmp_path / "synthetic-device"
    _write_encrypted_fixture(device_root)
    database = _serialized_database([("AppDomain-com.example.target", b"entry")])

    class FakeKeybag:
        @staticmethod
        def from_manifest(manifest_plist: object, password: str) -> FakeKeybag:
            return FakeKeybag()

        def decrypt(self, encrypted: bytes, key: bytes) -> bytes:
            return database

    monkeypatch.setattr(manifest, "Keybag", FakeKeybag)
    monkeypatch.setattr(manifest.archiver, "unarchive", lambda blob: _mbfile(-1))

    with pytest.raises(RehydrateError) as caught:
        manifest.probe_app_domain(device_root, "com.example.target", lambda: "secret")
    assert caught.value.reason == "MANIFEST_ENTRY_INVALID"


def test_probe_bounds_entry_blob_before_decode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    device_root = tmp_path / "synthetic-device"
    _write_encrypted_fixture(device_root)
    database = _serialized_database([("AppDomain-com.example.target", b"entry")])

    class FakeKeybag:
        @staticmethod
        def from_manifest(manifest_plist: object, password: str) -> FakeKeybag:
            return FakeKeybag()

        def decrypt(self, encrypted: bytes, key: bytes) -> bytes:
            return database

    decoded = False

    def decode(blob: bytes) -> MBFile:
        nonlocal decoded
        decoded = True
        return _mbfile(1)

    monkeypatch.setattr(manifest, "Keybag", FakeKeybag)
    monkeypatch.setattr(manifest, "MAX_ENTRY_BLOB_BYTES", 4)
    monkeypatch.setattr(manifest.archiver, "unarchive", decode)

    with pytest.raises(RehydrateError) as caught:
        manifest.probe_app_domain(device_root, "com.example.target", lambda: "secret")

    assert caught.value.reason == "MANIFEST_ENTRY_BLOB_TOO_LARGE"
    assert decoded is False


def test_probe_bounds_domain_entry_count_before_decode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    device_root = tmp_path / "synthetic-device"
    _write_encrypted_fixture(device_root)
    database = _serialized_database(
        [
            ("AppDomain-com.example.target", b"one"),
            ("AppDomain-com.example.target", b"two"),
        ]
    )

    class FakeKeybag:
        @staticmethod
        def from_manifest(manifest_plist: object, password: str) -> FakeKeybag:
            return FakeKeybag()

        def decrypt(self, encrypted: bytes, key: bytes) -> bytes:
            return database

    decoded = False

    def decode(blob: bytes) -> MBFile:
        nonlocal decoded
        decoded = True
        return _mbfile(1)

    monkeypatch.setattr(manifest, "Keybag", FakeKeybag)
    monkeypatch.setattr(manifest, "MAX_APP_DOMAIN_ENTRIES", 1)
    monkeypatch.setattr(manifest.archiver, "unarchive", decode)

    with pytest.raises(RehydrateError) as caught:
        manifest.probe_app_domain(device_root, "com.example.target", lambda: "secret")

    assert caught.value.reason == "MANIFEST_ENTRY_COUNT_LIMIT"
    assert decoded is False


def test_probe_bounds_aggregate_logical_size_while_decoding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    device_root = tmp_path / "synthetic-device"
    _write_encrypted_fixture(device_root)
    database = _serialized_database(
        [
            ("AppDomain-com.example.target", b"one"),
            ("AppDomain-com.example.target", b"two"),
        ]
    )

    class FakeKeybag:
        @staticmethod
        def from_manifest(manifest_plist: object, password: str) -> FakeKeybag:
            return FakeKeybag()

        def decrypt(self, encrypted: bytes, key: bytes) -> bytes:
            return database

    decoded = iter([_mbfile(6), _mbfile(5)])
    monkeypatch.setattr(manifest, "Keybag", FakeKeybag)
    monkeypatch.setattr(manifest, "MAX_APP_DOMAIN_LOGICAL_BYTES", 10)
    monkeypatch.setattr(manifest.archiver, "unarchive", lambda blob: next(decoded))

    with pytest.raises(RehydrateError) as caught:
        manifest.probe_app_domain(device_root, "com.example.target", lambda: "secret")

    assert caught.value.reason == "MANIFEST_LOGICAL_SIZE_LIMIT"
