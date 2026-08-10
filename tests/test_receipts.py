# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 iOS Rehydrate contributors

import json
import os
from datetime import UTC, datetime, timedelta

import pytest

from ios_rehydrate.errors import ExitCode, RehydrateError
from ios_rehydrate.receipts import (
    MAX_RECEIPT_AGE,
    SCHEMA,
    envelope,
    read_receipt,
    reserve_receipt,
    write_new_receipt,
)


def test_receipt_reservation_is_held_and_commits_successfully(tmp_path) -> None:
    target = tmp_path / "reserved.json"
    payload = envelope("test", {"valid": True})

    reservation = reserve_receipt(target)

    assert target.is_file()
    assert target.stat().st_size == 0
    reservation.commit(payload)
    assert json.loads(target.read_text(encoding="utf-8")) == payload


def test_receipt_reservation_abort_removes_only_pristine_file(tmp_path) -> None:
    target = tmp_path / "reserved.json"
    reservation = reserve_receipt(target)

    assert reservation.abort() is True
    assert not target.exists()


@pytest.mark.parametrize(
    "unsafe_leaf",
    [
        "base.txt:receipt",
        "trailing.",
        "trailing ",
        "CON",
        "CONIN$",
        "COM¹.txt",
        "unsafe<name.json",
    ],
)
def test_receipt_rejects_windows_ads_reserved_and_nonportable_leaf_names(
    tmp_path, unsafe_leaf: str
) -> None:
    base = tmp_path / "base.txt"
    base.write_text("operator evidence", encoding="utf-8")

    with pytest.raises(RehydrateError) as caught:
        reserve_receipt(tmp_path / unsafe_leaf)

    assert caught.value.reason == "RECEIPT_PATH_INVALID"
    assert base.read_text(encoding="utf-8") == "operator evidence"


def test_receipt_rejects_a_nested_symlink_ancestor(tmp_path) -> None:
    real_parent = tmp_path / "real-parent"
    nested = real_parent / "nested"
    nested.mkdir(parents=True)
    linked_parent = tmp_path / "linked-parent"
    try:
        os.symlink(real_parent, linked_parent, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlink creation is unavailable")

    with pytest.raises(RehydrateError) as caught:
        reserve_receipt(linked_parent / "nested" / "receipt.json")

    assert caught.value.reason == "RECEIPT_PARENT_INVALID"
    assert not (nested / "receipt.json").exists()


def test_receipt_reservation_never_deletes_a_replacement(tmp_path) -> None:
    target = tmp_path / "reserved.json"
    displaced = tmp_path / "displaced.json"
    reservation = reserve_receipt(target)
    reservation.preserve()
    target.replace(displaced)
    target.write_text("replacement", encoding="utf-8")

    assert reservation.abort() is False
    assert target.read_text(encoding="utf-8") == "replacement"
    assert displaced.is_file()


def test_receipt_is_redacted_by_contract_and_no_overwrite(tmp_path) -> None:
    target = tmp_path / "receipt.json"
    payload = envelope("test", {"device_ref": "device_1234", "valid": True})

    write_new_receipt(target, payload)

    written = json.loads(target.read_text(encoding="utf-8"))
    assert written["schema"] == SCHEMA
    assert written["evidence"]["device_ref"] == "device_1234"
    with pytest.raises(RehydrateError) as caught:
        write_new_receipt(target, payload)
    assert caught.value.code == ExitCode.IO
    assert caught.value.reason == "RECEIPT_EXISTS"


def test_read_receipt_validates_kind_and_returns_digest(tmp_path) -> None:
    target = tmp_path / "receipt.json"
    payload = envelope("backup-verification", {"device_ref": "device_1234"})
    write_new_receipt(target, payload)

    loaded, digest = read_receipt(target, expected_kind="backup-verification")

    assert loaded == payload
    assert len(digest) == 64
    with pytest.raises(RehydrateError) as caught:
        read_receipt(target, expected_kind="another-kind")
    assert caught.value.reason == "BACKUP_RECEIPT_MISMATCH"


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        ("tool_version", "999.0", "BACKUP_RECEIPT_MISMATCH"),
        ("created_at", "2026-01-01T00:00:00", "BACKUP_RECEIPT_TIME_INVALID"),
        ("created_at", "not-a-time", "BACKUP_RECEIPT_TIME_INVALID"),
        ("created_at", "9999-01-01T00:00:00+00:00", "BACKUP_RECEIPT_TIME_INVALID"),
    ],
)
def test_read_receipt_rejects_wrong_version_or_invalid_time(
    tmp_path, field: str, value: str, reason: str
) -> None:
    target = tmp_path / "receipt.json"
    payload = envelope("backup-verification", {"valid": True})
    payload[field] = value
    write_new_receipt(target, payload)

    with pytest.raises(RehydrateError) as caught:
        read_receipt(target, expected_kind="backup-verification")

    assert caught.value.reason == reason


def test_read_receipt_rejects_stale_safety_gate_evidence(tmp_path) -> None:
    target = tmp_path / "receipt.json"
    payload = envelope("backup-verification", {"valid": True})
    payload["created_at"] = (datetime.now(UTC) - MAX_RECEIPT_AGE - timedelta(minutes=1)).isoformat()
    write_new_receipt(target, payload)

    with pytest.raises(RehydrateError) as caught:
        read_receipt(
            target,
            expected_kind="backup-verification",
            max_age=MAX_RECEIPT_AGE,
        )

    assert caught.value.reason == "BACKUP_RECEIPT_STALE"
