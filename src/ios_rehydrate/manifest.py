# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 iOS Rehydrate contributors
"""Privacy-preserving, in-memory inspection of an encrypted Manifest.db."""

from __future__ import annotations

import logging
import os
import plistlib
import re
import sqlite3
import stat
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path
from threading import Lock
from typing import Any

from bpylist2 import archiver  # type: ignore[import-untyped]
from pyiosbackup.keybag import Keybag  # type: ignore[import-untyped]
from pyiosbackup.manifest_dbs.sqlite3 import MBFile  # type: ignore[import-untyped]
from pyiosbackup.manifest_plist import ManifestPlist  # type: ignore[import-untyped]

from ios_rehydrate.errors import ExitCode, RehydrateError

_AES_BLOCK_BYTES = 16
_SQLITE_HEADER = b"SQLite format 3\x00"
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_BUNDLE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,254}$")
_KEYBAG_TAG = re.compile(rb"[A-Z0-9]{4}")
_REQUIRED_COLUMNS = {
    "fileid": "TEXT",
    "domain": "TEXT",
    "relativepath": "TEXT",
    "flags": "INTEGER",
    "file": "BLOB",
}

# Resource ceilings for attacker-controlled backup metadata.  A 4 MiB keybag
# plist and 512 MiB encrypted SQLite database are deliberately generous for
# their formats while keeping the all-in-memory decrypt path finite.
MAX_MANIFEST_PLIST_BYTES = 4 * 1024 * 1024
MAX_MANIFEST_DB_BYTES = 512 * 1024 * 1024

# Backup keybags are ordinarily about one KiB and currently contain eleven
# protection classes.  These limits leave substantial format headroom without
# allowing the surrounding plist limit to become a keybag parsing or PBKDF2
# work budget.
MAX_BACKUP_KEYBAG_BYTES = 64 * 1024
MAX_KEYBAG_ELEMENT_BYTES = 4 * 1024
MAX_KEYBAG_ELEMENTS = 256
MAX_KEYBAG_CLASSES = 32
MAX_KEYBAG_CLASS_ID = 32
MAX_KEYBAG_ITERATIONS = 1_000_000
MAX_KEYBAG_DOUBLE_PROTECTION_ITERATIONS = 20_000_000
MAX_PRODUCT_VERSION_LENGTH = 16
MAX_PRODUCT_VERSION_MAJOR = 99
MAX_PRODUCT_VERSION_COMPONENT = 999

_KEYBAG_INTEGER_BYTES = 4
_KEYBAG_SALT_BYTES = 20
_KEYBAG_UUID_BYTES = 16
_KEYBAG_WRAPPED_KEY_BYTES = 40
_MANIFEST_KEY_BYTES = _KEYBAG_INTEGER_BYTES + _KEYBAG_WRAPPED_KEY_BYTES
_CLASS_TAGS = (b"UUID", b"CLAS", b"WRAP", b"KTYP", b"WPKY")
_DOUBLE_PROTECTION_VERSION = (10, 2, 0)
_PYIOSBACKUP_LOGGER = logging.getLogger("pyiosbackup")
_PYIOSBACKUP_LOGGER_LOCK = Lock()

# Archived MBFile records are normally tiny.  These limits permit very large
# apps while bounding decode work and corrupt logical-size claims.
MAX_ENTRY_BLOB_BYTES = 8 * 1024 * 1024
MAX_APP_DOMAIN_ENTRIES = 1_000_000
MAX_APP_DOMAIN_LOGICAL_BYTES = 4 * 1024 * 1024 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class ManifestReport:
    """App-domain evidence containing aggregates only."""

    entry_count: int
    logical_bytes_total: int

    def as_public_dict(self) -> dict[str, int]:
        return asdict(self)


def probe_app_domain(
    device_root: Path,
    bundle_id: str,
    password_provider: Callable[[], str],
) -> ManifestReport:
    """Decrypt and query one runtime-provided app domain without a plaintext file.

    The encrypted database is never modified.  Decrypted bytes are held in
    mutable buffers where possible and wiped on every exit path.  Python and
    SQLite may retain internal immutable copies, so this is best-effort memory
    hygiene rather than a hard memory-erasure guarantee.
    """
    if type(bundle_id) is not str or _BUNDLE_IDENTIFIER.fullmatch(bundle_id) is None:
        raise _manifest_error("runtime bundle identifier is invalid", "MANIFEST_BUNDLE_INVALID")
    root = _safe_device_root(device_root)
    manifest_path = _required_file(
        root / "Manifest.plist",
        size_limit=MAX_MANIFEST_PLIST_BYTES,
        invalid_reason="MANIFEST_METADATA_INVALID",
        too_large_reason="MANIFEST_METADATA_TOO_LARGE",
    )
    database_path = _required_file(
        root / "Manifest.db",
        size_limit=MAX_MANIFEST_DB_BYTES,
        invalid_reason="MANIFEST_DATABASE_INVALID",
        too_large_reason="MANIFEST_DATABASE_TOO_LARGE",
    )
    _reject_pending_journal(root)

    try:
        manifest_bytes = _read_bounded_file(
            manifest_path,
            size_limit=MAX_MANIFEST_PLIST_BYTES,
            invalid_reason="MANIFEST_METADATA_INVALID",
            too_large_reason="MANIFEST_METADATA_TOO_LARGE",
        )
        manifest_data = plistlib.loads(manifest_bytes)
    except (plistlib.InvalidFileException, ValueError, TypeError, OverflowError) as exc:
        raise _manifest_error(
            "encrypted backup manifest is invalid", "MANIFEST_METADATA_INVALID"
        ) from exc
    if not isinstance(manifest_data, dict):
        raise _manifest_error(
            "encrypted backup manifest has an invalid shape", "MANIFEST_METADATA_INVALID"
        )
    if manifest_data.get("IsEncrypted") is not True:
        raise _manifest_error(
            "manifest probe requires an encrypted backup", "MANIFEST_NOT_ENCRYPTED"
        )
    _validate_manifest_key_material(manifest_data)

    encrypted = _read_bounded_file(
        database_path,
        size_limit=MAX_MANIFEST_DB_BYTES,
        invalid_reason="MANIFEST_DATABASE_INVALID",
        too_large_reason="MANIFEST_DATABASE_TOO_LARGE",
    )
    plaintext = bytearray()
    password_bytes = bytearray()
    try:
        if not encrypted or len(encrypted) % _AES_BLOCK_BYTES:
            raise _manifest_error(
                "encrypted manifest database is not AES block aligned",
                "MANIFEST_CIPHERTEXT_INVALID",
            )
        password = _get_password(password_provider)
        password_bytes.extend(password.encode("utf-8"))
        try:
            manifest = ManifestPlist(manifest_data)
            # pyiosbackup 0.2.4 logs the derived password key and raw root
            # material at DEBUG.  Serialize this temporary global logger state
            # so concurrent probes cannot restore it while another derivation
            # is still running.
            with _PYIOSBACKUP_LOGGER_LOCK:
                logger_was_disabled = _PYIOSBACKUP_LOGGER.disabled
                _PYIOSBACKUP_LOGGER.disabled = True
                try:
                    keybag = Keybag.from_manifest(manifest, password)
                finally:
                    _PYIOSBACKUP_LOGGER.disabled = logger_was_disabled
            decrypted = keybag.decrypt(bytes(encrypted), manifest.manifest_key)
            if not isinstance(decrypted, bytes):
                raise TypeError("keybag decrypt returned a non-bytes value")
            if len(decrypted) > MAX_MANIFEST_DB_BYTES:
                raise _manifest_error(
                    "decrypted manifest database is too large",
                    "MANIFEST_DATABASE_TOO_LARGE",
                )
            plaintext.extend(decrypted)
            del decrypted
        except RehydrateError:
            raise
        except Exception:
            raise _manifest_error(
                "manifest database decryption failed",
                "MANIFEST_DECRYPT_FAILED",
            ) from None

        _validate_sqlite_body_in_place(plaintext)
        if plaintext[18:20] == b"\x02\x02":
            # A detached WAL is unavailable in a phone backup.  SQLite's own
            # in-memory deserialize path can safely read the main DB after the
            # two header mode bytes are normalized in this private copy only.
            plaintext[18:20] = b"\x01\x01"
        return _query_app_domain(plaintext, bundle_id)
    finally:
        _wipe(password_bytes)
        _wipe(plaintext)


def _get_password(password_provider: Callable[[], str]) -> str:
    try:
        password = password_provider()
    except Exception as exc:
        raise RehydrateError(
            "backup password entry did not complete",
            code=ExitCode.CONFIRMATION,
            reason="MANIFEST_PASSWORD_UNAVAILABLE",
        ) from exc
    if type(password) is not str or not password:
        raise RehydrateError(
            "a nonempty backup password is required",
            code=ExitCode.CONFIRMATION,
            reason="MANIFEST_PASSWORD_REQUIRED",
        )
    return password


def _validate_sqlite_body_in_place(plaintext: bytearray) -> None:
    if len(plaintext) < 100 or plaintext[:16] != _SQLITE_HEADER:
        raise _manifest_error(
            "decrypted manifest is not a SQLite database",
            "MANIFEST_SQLITE_INVALID",
        )
    encoded_page_size = int.from_bytes(plaintext[16:18], "big")
    page_size = 65_536 if encoded_page_size == 1 else encoded_page_size
    if page_size < 512 or page_size > 65_536 or page_size & (page_size - 1):
        raise _manifest_error("SQLite page size is invalid", "MANIFEST_SQLITE_INVALID")
    if tuple(plaintext[18:20]) not in ((1, 1), (2, 2)):
        raise _manifest_error("SQLite mode bytes are invalid", "MANIFEST_SQLITE_INVALID")
    if bytes(plaintext[21:24]) != b"\x40\x20\x20":
        raise _manifest_error("SQLite header fractions are invalid", "MANIFEST_SQLITE_INVALID")

    declared_pages = int.from_bytes(plaintext[28:32], "big")
    if declared_pages:
        logical_length = declared_pages * page_size
        if logical_length < page_size or logical_length > len(plaintext):
            raise _manifest_error("SQLite page count is invalid", "MANIFEST_SQLITE_INVALID")
        padding = bytes(plaintext[logical_length:])
        if padding and not _valid_pkcs7(padding):
            raise _manifest_error(
                "SQLite encryption padding is invalid", "MANIFEST_PADDING_INVALID"
            )
    else:
        logical_length = len(plaintext)
        possible_padding = plaintext[-1]
        if 1 <= possible_padding <= _AES_BLOCK_BYTES:
            candidate = bytes(plaintext[-possible_padding:])
            if _valid_pkcs7(candidate) and (len(plaintext) - possible_padding) % page_size == 0:
                logical_length -= possible_padding
        if logical_length < page_size or logical_length % page_size:
            raise _manifest_error("SQLite body is not page aligned", "MANIFEST_SQLITE_INVALID")

    if logical_length % page_size:
        raise _manifest_error("SQLite body is not page aligned", "MANIFEST_SQLITE_INVALID")
    del plaintext[logical_length:]


def _valid_pkcs7(padding: bytes) -> bool:
    if not padding or len(padding) > _AES_BLOCK_BYTES:
        return False
    width = padding[-1]
    return (
        width == len(padding)
        and 1 <= width <= _AES_BLOCK_BYTES
        and padding == bytes([width]) * width
    )


def _query_app_domain(sqlite_body: bytearray, bundle_id: str) -> ManifestReport:
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(":memory:", isolation_level=None)
        connection.deserialize(sqlite_body)
        connection.execute("PRAGMA temp_store = MEMORY")
        connection.execute("PRAGMA trusted_schema = OFF")
        connection.execute("PRAGMA query_only = ON")
        if connection.execute("PRAGMA query_only").fetchone() != (1,):
            raise sqlite3.DatabaseError("query-only mode was not retained")
        if connection.execute("PRAGMA quick_check(1)").fetchone() != ("ok",):
            raise sqlite3.DatabaseError("quick_check failed")
        _validate_schema(connection)
        domain_parameter = (f"AppDomain-{bundle_id}",)
        summary_row = connection.execute(
            "SELECT COUNT(*), COALESCE(MAX(LENGTH(file)), 0) FROM Files WHERE domain = ?",
            domain_parameter,
        ).fetchone()
        if (
            summary_row is None
            or len(summary_row) != 2
            or type(summary_row[0]) is not int
            or type(summary_row[1]) is not int
            or summary_row[0] < 0
            or summary_row[1] < 0
        ):
            raise _manifest_error("manifest entry count is invalid", "MANIFEST_ENTRY_COUNT_INVALID")
        expected_count, largest_blob = summary_row
        if expected_count > MAX_APP_DOMAIN_ENTRIES:
            raise _manifest_error(
                "app-domain entry count exceeds the safety limit",
                "MANIFEST_ENTRY_COUNT_LIMIT",
            )
        if largest_blob > MAX_ENTRY_BLOB_BYTES:
            raise _manifest_error(
                "manifest entry blob exceeds the safety limit",
                "MANIFEST_ENTRY_BLOB_TOO_LARGE",
            )
        rows = connection.execute(
            "SELECT file FROM Files WHERE domain = ?",
            domain_parameter,
        )
        count = 0
        logical_bytes = 0
        for (blob,) in rows:
            if not isinstance(blob, bytes | bytearray | memoryview):
                raise _manifest_error("manifest entry blob is invalid", "MANIFEST_ENTRY_INVALID")
            if len(blob) > MAX_ENTRY_BLOB_BYTES:
                raise _manifest_error(
                    "manifest entry blob exceeds the safety limit",
                    "MANIFEST_ENTRY_BLOB_TOO_LARGE",
                )
            try:
                metadata = archiver.unarchive(bytes(blob))
            except Exception as exc:
                raise _manifest_error(
                    "manifest entry could not be decoded", "MANIFEST_ENTRY_INVALID"
                ) from exc
            if (
                not isinstance(metadata, MBFile)
                or type(metadata.size) is not int
                or metadata.size < 0
            ):
                raise _manifest_error(
                    "manifest entry metadata is invalid", "MANIFEST_ENTRY_INVALID"
                )
            count += 1
            if count > MAX_APP_DOMAIN_ENTRIES:
                raise _manifest_error(
                    "app-domain entry count exceeds the safety limit",
                    "MANIFEST_ENTRY_COUNT_LIMIT",
                )
            if metadata.size > MAX_APP_DOMAIN_LOGICAL_BYTES - logical_bytes:
                raise _manifest_error(
                    "app-domain logical size exceeds the safety limit",
                    "MANIFEST_LOGICAL_SIZE_LIMIT",
                )
            logical_bytes += metadata.size
        if count != expected_count:
            raise _manifest_error("manifest entry count changed", "MANIFEST_ENTRY_COUNT_INVALID")
        return ManifestReport(entry_count=count, logical_bytes_total=logical_bytes)
    except RehydrateError:
        raise
    except (sqlite3.Error, OverflowError, ValueError) as exc:
        raise _manifest_error(
            "manifest SQLite database is invalid", "MANIFEST_SQLITE_INVALID"
        ) from exc
    finally:
        if connection is not None:
            connection.close()


def _validate_schema(connection: sqlite3.Connection) -> None:
    table = connection.execute(
        "SELECT type FROM sqlite_schema WHERE name = ? COLLATE NOCASE",
        ("Files",),
    ).fetchone()
    if table != ("table",):
        raise _manifest_error("manifest Files table is missing", "MANIFEST_SCHEMA_INVALID")
    columns = {
        str(row[1]).casefold(): str(row[2]).upper()
        for row in connection.execute('PRAGMA table_info("Files")')
    }
    if any(columns.get(name) != affinity for name, affinity in _REQUIRED_COLUMNS.items()):
        raise _manifest_error("manifest Files schema is invalid", "MANIFEST_SCHEMA_INVALID")


def _validate_manifest_key_material(manifest: dict[str, Any]) -> None:
    lockdown = manifest.get("Lockdown")
    keybag_data = manifest.get("BackupKeyBag")
    manifest_key = manifest.get("ManifestKey")
    if (
        type(keybag_data) is not bytes
        or type(manifest_key) is not bytes
        or not isinstance(lockdown, dict)
    ):
        raise _invalid_key_material()

    product_version = _parse_product_version(lockdown.get("ProductVersion"))
    elements = _parse_keybag_tlv(keybag_data)
    class_ids = _validate_keybag_structure(elements, product_version)

    if len(manifest_key) != _MANIFEST_KEY_BYTES:
        raise _invalid_key_material()
    manifest_class = int.from_bytes(manifest_key[:_KEYBAG_INTEGER_BYTES], "little")
    if manifest_class not in class_ids:
        raise _invalid_key_material()


def _parse_product_version(value: object) -> tuple[int, int, int]:
    if type(value) is not str or not value or len(value) > MAX_PRODUCT_VERSION_LENGTH:
        raise _invalid_key_material()
    parts = value.split(".")
    if len(parts) not in (2, 3):
        raise _invalid_key_material()
    if any(
        not part
        or not part.isascii()
        or not part.isdigit()
        or (len(part) > 1 and part.startswith("0"))
        for part in parts
    ):
        raise _invalid_key_material()
    components = [int(part) for part in parts]
    if not 1 <= components[0] <= MAX_PRODUCT_VERSION_MAJOR or any(
        component > MAX_PRODUCT_VERSION_COMPONENT for component in components[1:]
    ):
        raise _invalid_key_material()
    while len(components) < 3:
        components.append(0)
    return components[0], components[1], components[2]


def _parse_keybag_tlv(keybag: bytes) -> list[tuple[bytes, bytes]]:
    if not keybag or len(keybag) > MAX_BACKUP_KEYBAG_BYTES:
        raise _invalid_key_material()
    elements: list[tuple[bytes, bytes]] = []
    offset = 0
    while offset < len(keybag):
        if len(keybag) - offset < 8:
            raise _invalid_key_material()
        tag = keybag[offset : offset + 4]
        size = int.from_bytes(keybag[offset + 4 : offset + 8], "big")
        offset += 8
        if (
            _KEYBAG_TAG.fullmatch(tag) is None
            or size <= 0
            or size > MAX_KEYBAG_ELEMENT_BYTES
            or size > len(keybag) - offset
        ):
            raise _invalid_key_material()
        end = offset + size
        elements.append((tag, keybag[offset:end]))
        if len(elements) > MAX_KEYBAG_ELEMENTS:
            raise _invalid_key_material()
        offset = end
    return elements


def _validate_keybag_structure(
    elements: list[tuple[bytes, bytes]],
    product_version: tuple[int, int, int],
) -> set[int]:
    first_class = next(
        (index for index, (tag, _) in enumerate(elements) if tag == b"CLAS"),
        None,
    )
    if first_class is None or first_class == 0:
        raise _invalid_key_material()
    class_start = first_class - 1
    root_elements = elements[:class_start]
    class_elements = elements[class_start:]
    if not root_elements or not class_elements or len(class_elements) % len(_CLASS_TAGS):
        raise _invalid_key_material()
    class_count = len(class_elements) // len(_CLASS_TAGS)
    if not 1 <= class_count <= MAX_KEYBAG_CLASSES:
        raise _invalid_key_material()

    root_tags = [tag for tag, _ in root_elements]
    if len(root_tags) != len(set(root_tags)):
        raise _invalid_key_material()
    root = dict(root_elements)
    if not {b"VERS", b"TYPE", b"UUID", b"WRAP", b"SALT", b"ITER"} <= root.keys():
        raise _invalid_key_material()
    if any(tag in root for tag in (b"CLAS", b"KTYP", b"WPKY")):
        raise _invalid_key_material()
    if not 1 <= _keybag_integer(root[b"VERS"]) <= 4:
        raise _invalid_key_material()
    if _keybag_integer(root[b"TYPE"]) != 1:
        raise _invalid_key_material()
    if len(root[b"UUID"]) != _KEYBAG_UUID_BYTES or _keybag_integer(root[b"WRAP"]) != 0:
        raise _invalid_key_material()
    if len(root[b"SALT"]) != _KEYBAG_SALT_BYTES:
        raise _invalid_key_material()
    _bounded_iterations(root[b"ITER"], MAX_KEYBAG_ITERATIONS)
    if b"HMCK" in root and len(root[b"HMCK"]) != _KEYBAG_WRAPPED_KEY_BYTES:
        raise _invalid_key_material()

    has_dpsl = b"DPSL" in root
    has_dpic = b"DPIC" in root
    if has_dpsl != has_dpic or (product_version > _DOUBLE_PROTECTION_VERSION and not has_dpsl):
        raise _invalid_key_material()
    if has_dpsl:
        if len(root[b"DPSL"]) != _KEYBAG_SALT_BYTES:
            raise _invalid_key_material()
        _bounded_iterations(
            root[b"DPIC"],
            MAX_KEYBAG_DOUBLE_PROTECTION_ITERATIONS,
        )

    class_ids: set[int] = set()
    class_uuids: set[bytes] = set()
    for offset in range(0, len(class_elements), len(_CLASS_TAGS)):
        group = class_elements[offset : offset + len(_CLASS_TAGS)]
        if tuple(tag for tag, _ in group) != _CLASS_TAGS:
            raise _invalid_key_material()
        values = dict(group)
        class_uuid = values[b"UUID"]
        class_id = _keybag_integer(values[b"CLAS"])
        wrapping = _keybag_integer(values[b"WRAP"])
        key_type = _keybag_integer(values[b"KTYP"])
        if (
            len(class_uuid) != _KEYBAG_UUID_BYTES
            or class_uuid in class_uuids
            or not 1 <= class_id <= MAX_KEYBAG_CLASS_ID
            or class_id in class_ids
            or wrapping not in (2, 3)
            or key_type != 0
            or len(values[b"WPKY"]) != _KEYBAG_WRAPPED_KEY_BYTES
        ):
            raise _invalid_key_material()
        class_uuids.add(class_uuid)
        class_ids.add(class_id)
    return class_ids


def _keybag_integer(value: bytes) -> int:
    if len(value) != _KEYBAG_INTEGER_BYTES:
        raise _invalid_key_material()
    return int.from_bytes(value, "big")


def _bounded_iterations(value: bytes, maximum: int) -> None:
    iterations = _keybag_integer(value)
    if not 1 <= iterations <= maximum:
        raise _invalid_key_material()


def _invalid_key_material() -> RehydrateError:
    return _manifest_error(
        "encrypted manifest key material is invalid", "MANIFEST_METADATA_INVALID"
    )


def _safe_device_root(path: Path) -> Path:
    raw = Path(path)
    try:
        absolute = raw.absolute()
    except OSError as exc:
        raise _manifest_error(
            "backup device directory is missing", "MANIFEST_PATH_INVALID"
        ) from exc
    for component in (*reversed(absolute.parents), absolute):
        try:
            metadata = os.lstat(component)
        except OSError as exc:
            raise _manifest_error(
                "backup device directory is missing", "MANIFEST_PATH_INVALID"
            ) from exc
        if not stat.S_ISDIR(metadata.st_mode) or _is_reparse(metadata):
            raise _manifest_error("backup device directory is unsafe", "MANIFEST_PATH_INVALID")
    try:
        return absolute.resolve(strict=True)
    except OSError as exc:
        raise _manifest_error(
            "backup device directory is unreadable", "MANIFEST_PATH_INVALID"
        ) from exc


def _required_file(
    path: Path,
    *,
    size_limit: int,
    invalid_reason: str,
    too_large_reason: str,
) -> Path:
    try:
        metadata = os.lstat(path)
    except OSError as exc:
        raise _manifest_error("required manifest metadata is missing", invalid_reason) from exc
    if not stat.S_ISREG(metadata.st_mode) or _is_reparse(metadata) or metadata.st_size <= 0:
        raise _manifest_error("required manifest metadata is unsafe or empty", invalid_reason)
    if metadata.st_size > size_limit:
        raise _manifest_error("required manifest metadata is too large", too_large_reason)
    return path


def _read_bounded_file(
    path: Path,
    *,
    size_limit: int,
    invalid_reason: str,
    too_large_reason: str,
) -> bytes:
    """Read a regular file while enforcing the limit again on the open handle."""
    try:
        with path.open("rb") as stream:
            metadata = os.fstat(stream.fileno())
            if not stat.S_ISREG(metadata.st_mode) or _is_reparse(metadata) or metadata.st_size <= 0:
                raise _manifest_error("required manifest metadata is unsafe", invalid_reason)
            if metadata.st_size > size_limit:
                raise _manifest_error("required manifest metadata is too large", too_large_reason)
            data = stream.read(size_limit + 1)
    except RehydrateError:
        raise
    except OSError as exc:
        raise _manifest_error("required manifest metadata is unreadable", invalid_reason) from exc
    if not data:
        raise _manifest_error("required manifest metadata is empty", invalid_reason)
    if len(data) > size_limit:
        raise _manifest_error("required manifest metadata is too large", too_large_reason)
    return data


def _reject_pending_journal(root: Path) -> None:
    for name in ("Manifest.db-wal", "Manifest.db-journal"):
        path = root / name
        if not os.path.lexists(path):
            continue
        try:
            metadata = os.lstat(path)
        except OSError as exc:
            raise _manifest_error(
                "manifest journal state is unreadable", "MANIFEST_JOURNAL_INVALID"
            ) from exc
        if _is_reparse(metadata) or not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 0:
            raise _manifest_error(
                "manifest has pending or unsafe journal state", "MANIFEST_JOURNAL_INVALID"
            )


def _is_reparse(metadata: os.stat_result) -> bool:
    attributes = getattr(metadata, "st_file_attributes", 0)
    return stat.S_ISLNK(metadata.st_mode) or bool(attributes & _REPARSE_POINT)


def _wipe(value: bytearray) -> None:
    if value:
        value[:] = b"\x00" * len(value)


def _manifest_error(message: str, reason: str) -> RehydrateError:
    return RehydrateError(message, code=ExitCode.BACKUP_VERIFY, reason=reason)
