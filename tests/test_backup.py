# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 iOS Rehydrate contributors
from __future__ import annotations

import asyncio
import plistlib
from pathlib import Path
from typing import Any

import pytest

from ios_rehydrate import backup
from ios_rehydrate.errors import ExitCode, RehydrateError

SYNTHETIC_UDID = "00000000" + "-" + "1" * 16


def _write_valid_backup(output_root: Path, udid: str = SYNTHETIC_UDID) -> Path:
    device_root = output_root / udid
    device_root.mkdir(parents=True)
    (device_root / "Info.plist").write_bytes(
        plistlib.dumps(
            {
                "Target Identifier": udid,
                "Unique Identifier": udid.upper(),
            }
        )
    )
    (device_root / "Manifest.plist").write_bytes(
        plistlib.dumps(
            {
                "IsEncrypted": True,
                "Lockdown": {"UniqueDeviceID": udid},
            }
        )
    )
    (device_root / "Status.plist").write_bytes(
        plistlib.dumps(
            {
                "SnapshotState": "finished",
                "BackupState": "new",
                "IsFullBackup": False,
            }
        )
    )
    (device_root / "Manifest.db").write_bytes(b"synthetic-database")
    payload_id = "ab" + "1" * 38
    payload = device_root / payload_id[:2] / payload_id
    payload.parent.mkdir()
    payload.write_bytes(b"payload")
    return device_root


class _Lockdown:
    def __init__(self, values: list[object], udid: str = SYNTHETIC_UDID) -> None:
        self.values = iter(values)
        self.calls: list[tuple[str, str]] = []
        self.udid = udid

    async def get_value(self, domain: str, key: str) -> object:
        self.calls.append((domain, key))
        return next(self.values)


def test_encryption_status_uses_authoritative_domain_and_exact_bool() -> None:
    lockdown = _Lockdown([True])

    assert asyncio.run(backup.encryption_status(lockdown)) is True
    assert lockdown.calls == [("com.apple.mobile.backup", "WillEncrypt")]

    with pytest.raises(RehydrateError) as caught:
        asyncio.run(backup.encryption_status(_Lockdown([1])))
    assert caught.value.code is ExitCode.DEVICE_UNAVAILABLE
    assert caught.value.reason == "BACKUP_ENCRYPTION_STATUS_INVALID"


def test_enable_encryption_is_idempotent_when_already_enabled(tmp_path: Path) -> None:
    invoked = False

    def password_provider() -> tuple[str, str]:
        nonlocal invoked
        invoked = True
        return ("unused", "unused")

    asyncio.run(backup.enable_encryption(_Lockdown([True]), tmp_path, password_provider))
    assert invoked is False


def test_enable_encryption_double_entry_and_confirmation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    changes: list[dict[str, Any]] = []

    class Service:
        def __init__(self, lockdown: object) -> None:
            assert lockdown is device

        async def __aenter__(self) -> Service:
            return self

        async def __aexit__(self, *args: object) -> None:
            return None

        async def change_password(self, **kwargs: Any) -> None:
            changes.append(kwargs)

    device = _Lockdown([False, False, True])
    monkeypatch.setattr(backup, "Mobilebackup2Service", Service)

    report = asyncio.run(
        backup.enable_encryption(
            device,
            tmp_path,
            lambda: ("synthetic-secret", "synthetic-secret"),
        )
    )

    assert len(changes) == 1
    scratch = changes[0]["backup_directory"]
    assert isinstance(scratch, Path)
    assert scratch != tmp_path.resolve()
    assert scratch.parent == tmp_path.resolve()
    assert scratch.name.startswith(".ios-rehydrate-device-link-")
    assert changes[0]["old"] == ""
    assert changes[0]["new"] == "synthetic-secret"
    assert not scratch.exists()
    assert report is not None
    assert report.mobilebackup_connection_closed is True
    assert report.scratch_removed is True


def test_enable_encryption_reports_preserved_nonempty_scratch_on_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scratch_paths: list[Path] = []

    class Service:
        def __init__(self, lockdown: object) -> None:
            del lockdown

        async def __aenter__(self) -> Service:
            return self

        async def __aexit__(self, *args: object) -> None:
            return None

        async def change_password(self, **kwargs: Any) -> None:
            scratch = kwargs["backup_directory"]
            scratch_paths.append(scratch)
            (scratch / "device-controlled-marker").write_bytes(b"preserve")

    monkeypatch.setattr(backup, "Mobilebackup2Service", Service)

    report = asyncio.run(
        backup.enable_encryption(
            _Lockdown([False, False, True]),
            tmp_path,
            lambda: ("synthetic-secret", "synthetic-secret"),
        )
    )

    assert report is not None
    assert report.mobilebackup_connection_closed is True
    assert report.scratch_removed is False
    assert len(scratch_paths) == 1
    assert (scratch_paths[0] / "device-controlled-marker").read_bytes() == b"preserve"


def test_enable_encryption_refuses_state_flip(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class Service:
        def __init__(self, lockdown: object) -> None:
            raise AssertionError("mutation must not be attempted")

    monkeypatch.setattr(backup, "Mobilebackup2Service", Service)
    with pytest.raises(RehydrateError) as caught:
        asyncio.run(
            backup.enable_encryption(
                _Lockdown([False, True]),
                tmp_path,
                lambda: ("synthetic-secret", "synthetic-secret"),
            )
        )
    assert caught.value.reason == "BACKUP_ENCRYPTION_STATE_CHANGED"


def test_enable_encryption_preserves_nonempty_private_scratch_and_operator_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scratch_paths: list[Path] = []
    operator_file = tmp_path / "operator-file"
    operator_file.write_bytes(b"do-not-delete")

    class Service:
        def __init__(self, lockdown: object) -> None:
            pass

        async def __aenter__(self) -> Service:
            return self

        async def __aexit__(self, *args: object) -> None:
            return None

        async def change_password(self, **kwargs: Any) -> None:
            scratch = kwargs["backup_directory"]
            scratch_paths.append(scratch)
            (scratch / "partial-marker").write_bytes(b"preserve")
            raise RuntimeError("synthetic request failure")

    monkeypatch.setattr(backup, "Mobilebackup2Service", Service)

    with pytest.raises(RehydrateError) as caught:
        asyncio.run(
            backup.enable_encryption(
                _Lockdown([False, False, False]),
                tmp_path,
                lambda: ("synthetic-secret", "synthetic-secret"),
            )
        )

    assert caught.value.reason == "BACKUP_ENCRYPTION_OUTCOME_UNKNOWN"
    assert len(scratch_paths) == 1
    assert (scratch_paths[0] / "partial-marker").read_bytes() == b"preserve"
    assert operator_file.read_bytes() == b"do-not-delete"


def test_enable_encryption_reconciles_cancelled_request_that_succeeded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class Service:
        def __init__(self, lockdown: object) -> None:
            pass

        async def __aenter__(self) -> Service:
            return self

        async def __aexit__(self, *args: object) -> None:
            return None

        async def change_password(self, **kwargs: Any) -> None:
            raise asyncio.CancelledError

    monkeypatch.setattr(backup, "Mobilebackup2Service", Service)
    device = _Lockdown([False, False, True])

    report = asyncio.run(
        backup.enable_encryption(
            device,
            tmp_path,
            lambda: ("synthetic-secret", "synthetic-secret"),
        )
    )

    assert len(device.calls) == 3
    assert report is not None
    assert report.mobilebackup_connection_closed is False
    assert report.scratch_removed is True


@pytest.mark.parametrize("interruption", [asyncio.CancelledError, KeyboardInterrupt])
def test_enable_encryption_reports_unknown_interrupted_request(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    interruption: type[BaseException],
) -> None:
    class Service:
        def __init__(self, lockdown: object) -> None:
            pass

        async def __aenter__(self) -> Service:
            return self

        async def __aexit__(self, *args: object) -> None:
            return None

        async def change_password(self, **kwargs: Any) -> None:
            raise interruption

    monkeypatch.setattr(backup, "Mobilebackup2Service", Service)

    with pytest.raises(RehydrateError) as caught:
        asyncio.run(
            backup.enable_encryption(
                _Lockdown([False, False, False]),
                tmp_path,
                lambda: ("synthetic-secret", "synthetic-secret"),
            )
        )

    assert caught.value.code is ExitCode.OUTCOME_UNKNOWN
    assert caught.value.reason == "BACKUP_ENCRYPTION_OUTCOME_UNKNOWN"


def test_validate_backup_returns_only_opaque_refs_and_aggregates(tmp_path: Path) -> None:
    output_root = tmp_path / "fresh-backup"
    _write_valid_backup(output_root)

    report = backup.validate_backup(output_root, SYNTHETIC_UDID)
    public = report.as_public_dict()

    assert report.payload_count == 1
    assert report.payload_bytes == len(b"payload")
    assert report.observed_is_full_backup is False
    assert report.requested_full is False
    assert report.mobilebackup_connection_closed is None
    rendered = repr(public)
    assert SYNTHETIC_UDID not in rendered
    assert str(output_root) not in rendered
    assert set(public) == {
        "backup_ref",
        "device_ref",
        "payload_count",
        "payload_bytes",
        "encrypted",
        "completed",
        "requested_full",
        "observed_is_full_backup",
        "mobilebackup_connection_closed",
    }


def test_validate_backup_never_reads_manifest_database(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output_root = tmp_path / "fresh-backup"
    _write_valid_backup(output_root)
    original_read_bytes = Path.read_bytes

    def guarded_read_bytes(path: Path) -> bytes:
        if path.name == "Manifest.db":
            raise AssertionError("structural validation must not read Manifest.db")
        return original_read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", guarded_read_bytes)

    report = backup.validate_backup(output_root, SYNTHETIC_UDID)

    assert report.completed is True


def test_validate_backup_rejects_sparse_oversize_manifest_database(tmp_path: Path) -> None:
    output_root = tmp_path / "fresh-backup"
    device_root = _write_valid_backup(output_root)
    with (device_root / "Manifest.db").open("r+b") as stream:
        stream.truncate(backup.MAX_MANIFEST_DB_BYTES + 1)

    with pytest.raises(RehydrateError) as caught:
        backup.validate_backup(output_root, SYNTHETIC_UDID)

    assert caught.value.reason == "BACKUP_MANIFEST_DB_TOO_LARGE"


def test_validate_backup_bounds_plist_before_parse(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output_root = tmp_path / "fresh-backup"
    _write_valid_backup(output_root)
    monkeypatch.setitem(backup._PLIST_LIMITS, "Info.plist", 8)

    with pytest.raises(RehydrateError) as caught:
        backup.validate_backup(output_root, SYNTHETIC_UDID)

    assert caught.value.reason == "BACKUP_METADATA_TOO_LARGE"


@pytest.mark.parametrize(
    ("plist_name", "key", "value", "reason"),
    [
        ("Manifest.plist", "IsEncrypted", False, "BACKUP_NOT_ENCRYPTED"),
        ("Status.plist", "SnapshotState", "uploading", "BACKUP_STATE_INCOMPLETE"),
        ("Status.plist", "BackupState", "old", "BACKUP_STATE_INCOMPLETE"),
        ("Status.plist", "IsFullBackup", True, "BACKUP_STATE_INVALID"),
    ],
)
def test_validate_backup_rejects_invalid_final_metadata(
    tmp_path: Path, plist_name: str, key: str, value: object, reason: str
) -> None:
    output_root = tmp_path / "fresh-backup"
    device_root = _write_valid_backup(output_root)
    path = device_root / plist_name
    data = plistlib.loads(path.read_bytes())
    data[key] = value
    path.write_bytes(plistlib.dumps(data))

    with pytest.raises(RehydrateError) as caught:
        backup.validate_backup(output_root, SYNTHETIC_UDID)
    assert caught.value.reason == reason


def test_validate_backup_requires_exact_device_subdirectory(tmp_path: Path) -> None:
    output_root = tmp_path / "fresh-backup"
    _write_valid_backup(output_root)
    (output_root / "unexpected").mkdir()

    with pytest.raises(RehydrateError) as caught:
        backup.validate_backup(output_root, SYNTHETIC_UDID)
    assert caught.value.reason == "BACKUP_LAYOUT_INVALID"


def test_create_backup_reserves_fresh_root_calls_full_and_validates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output_root = tmp_path / "fresh-backup"
    calls: list[dict[str, Any]] = []
    progress: list[float] = []

    class Service:
        def __init__(self, lockdown: object) -> None:
            assert lockdown is device

        async def __aenter__(self) -> Service:
            return self

        async def __aexit__(self, *args: object) -> None:
            return None

        async def backup(self, **kwargs: Any) -> None:
            calls.append(kwargs)
            assert kwargs["backup_directory"].is_dir()
            kwargs["progress_callback"](42.0)
            _write_valid_backup(kwargs["backup_directory"])

    device = _Lockdown([True], udid=SYNTHETIC_UDID)
    monkeypatch.setattr(backup, "Mobilebackup2Service", Service)

    report = asyncio.run(backup.create_backup(device, output_root, progress.append))

    assert report.completed is True
    assert progress == [42.0]
    assert calls[0]["full"] is True
    assert calls[0]["backup_directory"] == output_root.resolve()
    assert report.requested_full is True
    assert report.mobilebackup_connection_closed is True


def test_create_backup_preserves_partial_data_on_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output_root = tmp_path / "fresh-backup"

    class Service:
        def __init__(self, lockdown: object) -> None:
            pass

        async def __aenter__(self) -> Service:
            return self

        async def __aexit__(self, *args: object) -> None:
            return None

        async def backup(self, **kwargs: Any) -> None:
            (kwargs["backup_directory"] / "partial-marker").write_bytes(b"preserve")
            raise RuntimeError("synthetic device failure")

    monkeypatch.setattr(backup, "Mobilebackup2Service", Service)

    with pytest.raises(RehydrateError) as caught:
        asyncio.run(backup.create_backup(_Lockdown([True]), output_root))
    assert caught.value.code is ExitCode.BACKUP_CREATE
    assert caught.value.reason == "BACKUP_CREATE_INCOMPLETE"
    assert (output_root / "partial-marker").read_bytes() == b"preserve"


@pytest.mark.parametrize("interruption", [asyncio.CancelledError, KeyboardInterrupt])
def test_create_backup_maps_interruption_to_preserved_incomplete_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    interruption: type[BaseException],
) -> None:
    output_root = tmp_path / "fresh-backup"

    class Service:
        def __init__(self, lockdown: object) -> None:
            pass

        async def __aenter__(self) -> Service:
            return self

        async def __aexit__(self, *args: object) -> None:
            return None

        async def backup(self, **kwargs: Any) -> None:
            (kwargs["backup_directory"] / "partial-marker").write_bytes(b"preserve")
            raise interruption

    monkeypatch.setattr(backup, "Mobilebackup2Service", Service)

    with pytest.raises(RehydrateError) as caught:
        asyncio.run(backup.create_backup(_Lockdown([True]), output_root))

    assert caught.value.code is ExitCode.BACKUP_CREATE
    assert caught.value.reason == "BACKUP_CREATE_INCOMPLETE"
    assert (output_root / "partial-marker").read_bytes() == b"preserve"


def test_create_backup_refuses_existing_output(tmp_path: Path) -> None:
    output_root = tmp_path / "fresh-backup"
    output_root.mkdir()

    with pytest.raises(RehydrateError) as caught:
        asyncio.run(backup.create_backup(_Lockdown([True]), output_root))
    assert caught.value.reason == "BACKUP_OUTPUT_EXISTS"


def test_preflight_output_does_not_create_target(tmp_path: Path) -> None:
    output_root = tmp_path / "fresh-backup"

    target = backup.preflight_backup_output(output_root)

    assert target == output_root.resolve(strict=False)
    assert not output_root.exists()


def test_create_backup_requires_encryption_before_reserving_output(tmp_path: Path) -> None:
    output_root = tmp_path / "fresh-backup"

    with pytest.raises(RehydrateError) as caught:
        asyncio.run(backup.create_backup(_Lockdown([False]), output_root))
    assert caught.value.reason == "BACKUP_ENCRYPTION_REQUIRED"
    assert not output_root.exists()


def test_validate_backup_enforces_total_directory_entry_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output_root = tmp_path / "fresh-backup"
    _write_valid_backup(output_root)
    monkeypatch.setattr(backup, "MAX_INSPECTED_DIRECTORY_ENTRIES", 1)

    with pytest.raises(RehydrateError) as caught:
        backup.validate_backup(output_root, SYNTHETIC_UDID)

    assert caught.value.reason == "BACKUP_DIRECTORY_ENTRY_LIMIT"


def test_validate_backup_enforces_hashed_payload_count_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output_root = tmp_path / "fresh-backup"
    _write_valid_backup(output_root)
    monkeypatch.setattr(backup, "MAX_HASHED_PAYLOAD_COUNT", 0)

    with pytest.raises(RehydrateError) as caught:
        backup.validate_backup(output_root, SYNTHETIC_UDID)

    assert caught.value.reason == "BACKUP_PAYLOAD_COUNT_LIMIT"


def test_preflight_rejects_nested_ancestor_symlink(tmp_path: Path) -> None:
    real_parent = tmp_path / "real-parent"
    real_parent.mkdir()
    linked_parent = tmp_path / "linked-parent"
    try:
        linked_parent.symlink_to(real_parent, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")

    with pytest.raises(RehydrateError) as caught:
        backup.preflight_backup_output(linked_parent / "fresh-backup")

    assert caught.value.reason == "BACKUP_PARENT_INVALID"
    assert not (real_parent / "fresh-backup").exists()


def test_service_cleanup_cannot_mask_primary_or_leak_raw_exception(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output_root = tmp_path / "fresh-backup"
    leak_marker = "SYNTHETIC-CLEANUP-LEAK-17a9"

    class Service:
        def __init__(self, lockdown: object) -> None:
            pass

        async def __aenter__(self) -> Service:
            return self

        async def __aexit__(self, *args: object) -> None:
            raise RuntimeError(f"cleanup-{leak_marker}")

        async def backup(self, **kwargs: Any) -> None:
            (kwargs["backup_directory"] / "partial-marker").write_bytes(b"preserve")
            raise RuntimeError(f"primary-{leak_marker}")

    monkeypatch.setattr(backup, "Mobilebackup2Service", Service)

    with pytest.raises(RehydrateError) as caught:
        asyncio.run(backup.create_backup(_Lockdown([True]), output_root))

    assert caught.value.reason == "BACKUP_CREATE_INCOMPLETE"
    assert leak_marker not in str(caught.value)
    assert caught.value.__cause__ is None
    assert (output_root / "partial-marker").read_bytes() == b"preserve"


def test_cleanup_only_failure_preserves_valid_backup_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output_root = tmp_path / "fresh-backup"

    class Service:
        def __init__(self, lockdown: object) -> None:
            pass

        async def __aenter__(self) -> Service:
            return self

        async def __aexit__(self, *args: object) -> None:
            raise RuntimeError("synthetic cleanup-only failure")

        async def backup(self, **kwargs: Any) -> None:
            _write_valid_backup(kwargs["backup_directory"])

    monkeypatch.setattr(backup, "Mobilebackup2Service", Service)

    report = asyncio.run(backup.create_backup(_Lockdown([True], udid=SYNTHETIC_UDID), output_root))

    assert report.completed is True
    assert report.mobilebackup_connection_closed is False


def test_device_link_cleanup_status_preserves_valid_backup_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output_root = tmp_path / "fresh-backup"

    class Service:
        device_link_connection_closed = False

        def __init__(self, lockdown: object) -> None:
            pass

        async def __aenter__(self) -> Service:
            return self

        async def __aexit__(self, *args: object) -> None:
            return None

        async def backup(self, **kwargs: Any) -> None:
            _write_valid_backup(kwargs["backup_directory"])

    monkeypatch.setattr(backup, "Mobilebackup2Service", Service)

    report = asyncio.run(backup.create_backup(_Lockdown([True], udid=SYNTHETIC_UDID), output_root))

    assert report.completed is True
    assert report.mobilebackup_connection_closed is False
