# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 iOS Rehydrate contributors
from __future__ import annotations

import asyncio
import importlib.metadata
import logging
import plistlib
import struct
import warnings
from collections import deque
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
from pymobiledevice3.exceptions import NotEnoughDiskSpaceError
from pymobiledevice3.services.device_link import (
    CODE_ERROR_REMOTE,
    CODE_FILE_DATA,
    CODE_FORMAT,
    CODE_SUCCESS,
    SIZE_FORMAT,
)

import ios_rehydrate.safe_mobilebackup as safe_mobilebackup_module
from ios_rehydrate.safe_mobilebackup import (
    MobileBackupSafetyError,
    SafeDeviceLink,
    SafeMobilebackup2Service,
)

LEAK_MARKER = "SYNTHETIC-MOBILEBACKUP-LEAK-9f73"
EXPECTED_FILESYSTEM_HANDLERS = {
    "DLMessageCreateDirectory": "create_directory",
    "DLMessageUploadFiles": "upload_files",
    "DLMessageGetFreeDiskSpace": "get_free_disk_space",
    "DLMessageMoveItems": "move_items",
    "DLMessageRemoveItems": "remove_items",
    "DLMessageDownloadFiles": "download_files",
    "DLContentsOfDirectory": "contents_of_directory",
    "DLMessageCopyItem": "copy_item",
    "DLMessagePurgeDiskSpace": "purge_disk_space",
}


class _Wire:
    def __init__(self, reads: list[bytes] | None = None, *, fail_send_plist: bool = False) -> None:
        self.reads = deque(reads or [])
        self.received_sizes: list[int] = []
        self.sent_bytes: list[bytes] = []
        self.sent_plists: list[object] = []
        self.fail_send_plist = fail_send_plist

    async def sendall(self, payload: bytes) -> None:
        self.sent_bytes.append(payload)

    async def recvall(self, size: int) -> bytes:
        self.received_sizes.append(size)
        if not self.reads:
            raise AssertionError("unexpected synthetic receive")
        payload = self.reads.popleft()
        assert len(payload) == size
        return payload

    async def send_plist(self, payload: object) -> None:
        if self.fail_send_plist:
            raise RuntimeError(f"cleanup exposed {LEAK_MARKER}")
        self.sent_plists.append(payload)


def _link(root: Path, wire: _Wire | None = None) -> SafeDeviceLink:
    return SafeDeviceLink(cast(Any, wire or _Wire()), root)


def _prefixed(value: str) -> list[bytes]:
    encoded = value.encode()
    return [struct.pack(SIZE_FORMAT, len(encoded)), encoded]


def _upload_reads(
    file_name: str,
    *,
    device_name: str = "SyntheticDomain/record",
    payload: bytes = b"safe-payload",
) -> list[bytes]:
    return [
        *_prefixed(device_name),
        *_prefixed(file_name),
        struct.pack(SIZE_FORMAT, len(payload) + struct.calcsize(CODE_FORMAT)),
        struct.pack(CODE_FORMAT, CODE_FILE_DATA),
        payload,
        struct.pack(SIZE_FORMAT, struct.calcsize(CODE_FORMAT)),
        struct.pack(CODE_FORMAT, CODE_SUCCESS),
        *_prefixed(""),
    ]


def test_boundary_matches_exact_pinned_upstream_handler_table(tmp_path: Path) -> None:
    root = tmp_path / "fresh-root"
    root.mkdir()
    link = _link(root)

    assert importlib.metadata.version("pymobiledevice3") == "11.1.6"
    assert set(link._dl_handlers) == set(EXPECTED_FILESYSTEM_HANDLERS)
    for command, method_name in EXPECTED_FILESYSTEM_HANDLERS.items():
        handler = link._dl_handlers[command]
        assert handler.__self__ is link
        assert handler.__func__ is getattr(SafeDeviceLink, method_name)


@pytest.mark.parametrize(
    ("platform_name", "important_capacity", "expected_capacity"),
    [
        ("win32", None, 12345),
        ("darwin", None, 12345),
        ("darwin", 12000, 12345),
        ("darwin", 15000, 15000),
    ],
)
def test_free_space_reply_does_not_log_the_backup_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    platform_name: str,
    important_capacity: int | None,
    expected_capacity: int,
) -> None:
    root = tmp_path / LEAK_MARKER
    root.mkdir()
    wire = _Wire()
    link = _link(root, wire)
    monkeypatch.setattr(
        safe_mobilebackup_module.shutil, "disk_usage", lambda _: SimpleNamespace(free=12345)
    )
    monkeypatch.setattr(safe_mobilebackup_module, "sys", SimpleNamespace(platform=platform_name))
    monkeypatch.setattr(
        safe_mobilebackup_module,
        "_darwin_important_available_capacity",
        lambda _: important_capacity,
    )
    caplog.set_level(logging.DEBUG, logger="pymobiledevice3.services.device_link")

    asyncio.run(link._dl_handlers["DLMessageGetFreeDiskSpace"](["DLMessageGetFreeDiskSpace"]))

    assert wire.sent_plists == [
        ["DLMessageStatusResponse", 0, "___EmptyParameterString___", expected_capacity]
    ]
    assert LEAK_MARKER not in caplog.text
    assert str(root) not in caplog.text


@pytest.mark.parametrize("details", [[], [LEAK_MARKER, LEAK_MARKER]])
def test_purge_request_fails_closed_without_logging_device_data(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, details: list[str]
) -> None:
    root = tmp_path / LEAK_MARKER
    root.mkdir()
    sentinel = root / "preserved"
    sentinel.write_bytes(b"preserved")
    wire = _Wire()
    link = _link(root, wire)
    caplog.set_level(logging.DEBUG, logger="pymobiledevice3.services.device_link")

    with pytest.raises(NotEnoughDiskSpaceError) as error:
        asyncio.run(
            link._dl_handlers["DLMessagePurgeDiskSpace"](["DLMessagePurgeDiskSpace", *details])
        )

    assert sentinel.read_bytes() == b"preserved"
    assert wire.sent_plists == []
    assert LEAK_MARKER not in str(error.value)
    assert LEAK_MARKER not in caplog.text
    assert str(root) not in caplog.text


@pytest.mark.parametrize(
    "remote_path",
    [
        "",
        f"/{LEAK_MARKER}",
        f"C:/{LEAK_MARKER}",
        f"//server/share/{LEAK_MARKER}",
        f"folder\\{LEAK_MARKER}",
        f"folder/{LEAK_MARKER}\x00suffix",
        f"folder:{LEAK_MARKER}",
        f"folder//{LEAK_MARKER}",
        f"./{LEAK_MARKER}",
        f"folder/../{LEAK_MARKER}",
        f"folder/./{LEAK_MARKER}",
        f"folder/{LEAK_MARKER} ",
        f"folder/{LEAK_MARKER}.",
        "folder/",
        f"CON/{LEAK_MARKER}",
        f"CONIN$/{LEAK_MARKER}",
        f"CONOUT$/{LEAK_MARKER}",
        f"CLOCK$/{LEAK_MARKER}",
        f"COM¹/{LEAK_MARKER}",
        f"LPT²/{LEAK_MARKER}",
        f"folder/bad*{LEAK_MARKER}",
        f"folder/bad?{LEAK_MARKER}",
        f"folder/bad<{LEAK_MARKER}",
        f"folder/bad\x01{LEAK_MARKER}",
    ],
)
def test_every_ambiguous_or_windows_alias_path_is_rejected(
    tmp_path: Path, remote_path: str
) -> None:
    root = tmp_path / "fresh-root"
    root.mkdir()

    with pytest.raises(MobileBackupSafetyError) as caught:
        asyncio.run(_link(root).create_directory(["DLMessageCreateDirectory", remote_path]))

    assert str(caught.value) == "mobile backup filesystem request refused"
    assert caught.value.__cause__ is None
    assert list(root.iterdir()) == []


def test_all_path_handlers_refuse_parent_escape_without_outside_mutation(tmp_path: Path) -> None:
    root = tmp_path / "fresh-root"
    root.mkdir()
    (root / "source.bin").write_bytes(b"inside")
    outside_file = tmp_path / f"{LEAK_MARKER}.bin"
    outside_file.write_bytes(b"operator-data")
    outside_directory = tmp_path / f"{LEAK_MARKER}-directory"
    outside_directory.mkdir()
    (outside_directory / "marker").write_bytes(b"operator-directory-data")
    file_escape = f"../{outside_file.name}"
    directory_escape = f"../{outside_directory.name}"

    calls = [
        lambda: _link(root).download_files(["DLMessageDownloadFiles", [file_escape]]),
        lambda: _link(root).contents_of_directory(["DLContentsOfDirectory", directory_escape]),
        lambda: _link(root).move_items(["DLMessageMoveItems", {file_escape: "stolen.bin"}]),
        lambda: _link(root).move_items(["DLMessageMoveItems", {"source.bin": file_escape}]),
        lambda: _link(root).copy_item(["DLMessageCopyItem", file_escape, "copied.bin"]),
        lambda: _link(root).copy_item(["DLMessageCopyItem", "source.bin", file_escape]),
        lambda: _link(root).remove_items(["DLMessageRemoveItems", [file_escape]]),
        lambda: _link(root).create_directory(["DLMessageCreateDirectory", directory_escape]),
    ]
    for call in calls:
        with pytest.raises(MobileBackupSafetyError):
            asyncio.run(call())
        assert outside_file.read_bytes() == b"operator-data"
        assert (outside_directory / "marker").read_bytes() == b"operator-directory-data"
        assert (root / "source.bin").read_bytes() == b"inside"
        assert {entry.name for entry in root.iterdir()} == {"source.bin"}

    cleanup_link = _link(root)
    cleanup_link._discarded_files.add(Path(file_escape))
    with pytest.raises(MobileBackupSafetyError):
        cleanup_link.cleanup_discarded_files()
    assert outside_file.read_bytes() == b"operator-data"


def test_upload_refuses_escape_before_opening_or_truncating(tmp_path: Path) -> None:
    root = tmp_path / "fresh-root"
    root.mkdir()
    outside = tmp_path / f"{LEAK_MARKER}.bin"
    outside.write_bytes(b"operator-data")
    wire = _Wire(
        [
            *_prefixed(f"device-{LEAK_MARKER}"),
            *_prefixed(f"../{outside.name}"),
        ]
    )

    with pytest.raises(MobileBackupSafetyError) as caught:
        asyncio.run(_link(root, wire).upload_files(["DLMessageUploadFiles"]))

    assert str(caught.value) == "mobile backup filesystem request refused"
    assert outside.read_bytes() == b"operator-data"
    assert list(root.iterdir()) == []


def test_remote_upload_error_is_bounded_generic_and_never_warns_or_prints(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = tmp_path / "fresh-root"
    root.mkdir()
    device_name = f"device-name-{LEAK_MARKER}"
    file_name = f"device/{LEAK_MARKER}.bin"
    remote_error = f"remote-error-{LEAK_MARKER}".encode()
    wire = _Wire(
        [
            *_prefixed(device_name),
            *_prefixed(file_name),
            struct.pack(SIZE_FORMAT, len(remote_error) + struct.calcsize(CODE_FORMAT)),
            struct.pack(CODE_FORMAT, CODE_ERROR_REMOTE),
            remote_error,
            *_upload_reads(
                "device/accepted.bin",
                device_name="SyntheticDomain/accepted",
                payload=b"accepted",
            ),
        ]
    )

    with warnings.catch_warnings(record=True) as emitted:
        warnings.simplefilter("always")
        asyncio.run(_link(root, wire).upload_files(["DLMessageUploadFiles"]))

    captured = capsys.readouterr()
    assert LEAK_MARKER not in captured.out
    assert LEAK_MARKER not in captured.err
    assert emitted == []
    assert (root / "device" / f"{LEAK_MARKER}.bin").read_bytes() == b""
    assert (root / "device" / "accepted.bin").read_bytes() == b"accepted"
    assert wire.sent_plists[-1][0] == "DLMessageStatusResponse"


def test_legitimate_relative_paths_work_for_every_handler(tmp_path: Path) -> None:
    root = tmp_path / "fresh-root"
    root.mkdir()
    link = _link(root)

    asyncio.run(link.create_directory(["DLMessageCreateDirectory", "device/nested"]))
    payload = b"legitimate-safe-payload"
    upload_wire = _Wire(_upload_reads("device/nested/file.bin", payload=payload))
    asyncio.run(_link(root, upload_wire).upload_files(["DLMessageUploadFiles"]))
    assert (root / "device" / "nested" / "file.bin").read_bytes() == payload

    contents_wire = _Wire()
    asyncio.run(
        _link(root, contents_wire).contents_of_directory(["DLContentsOfDirectory", "device/nested"])
    )
    assert contents_wire.sent_plists

    download_wire = _Wire()
    asyncio.run(
        _link(root, download_wire).download_files(
            ["DLMessageDownloadFiles", ["device/nested/file.bin"]]
        )
    )
    assert any(payload in frame for frame in download_wire.sent_bytes)

    asyncio.run(
        _link(root).copy_item(["DLMessageCopyItem", "device/nested/file.bin", "device/copied.bin"])
    )
    assert (root / "device" / "copied.bin").read_bytes() == payload
    asyncio.run(
        _link(root).move_items(["DLMessageMoveItems", {"device/copied.bin": "device/moved.bin"}])
    )
    assert not (root / "device" / "copied.bin").exists()
    assert (root / "device" / "moved.bin").read_bytes() == payload
    asyncio.run(_link(root).remove_items(["DLMessageRemoveItems", ["device/moved.bin"]]))
    assert not (root / "device" / "moved.bin").exists()


def test_legitimate_discarded_placeholder_cleanup_stays_inside_root(tmp_path: Path) -> None:
    root = tmp_path / "fresh-root"
    root.mkdir()
    wire = _Wire(_upload_reads("device/nested/discarded.bin", payload=b"discard-me"))
    link = SafeDeviceLink(cast(Any, wire), root, preserve_file=lambda _file, _device: False)

    asyncio.run(link.upload_files(["DLMessageUploadFiles"]))
    placeholder = root / "device" / "nested" / "discarded.bin"
    assert placeholder.read_bytes() == b""

    link.cleanup_discarded_files()

    assert not placeholder.exists()
    assert list(root.iterdir()) == []


def test_existing_target_symlink_is_rejected_without_touching_outside(tmp_path: Path) -> None:
    root = tmp_path / "fresh-root"
    target_parent = root / "device"
    target_parent.mkdir(parents=True)
    outside = tmp_path / f"{LEAK_MARKER}.bin"
    outside.write_bytes(b"operator-data")
    link_path = target_parent / "incoming.bin"
    try:
        link_path.symlink_to(outside)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")
    wire = _Wire(_upload_reads("device/incoming.bin", payload=b"overwrite-attempt"))

    with pytest.raises(MobileBackupSafetyError):
        asyncio.run(_link(root, wire).upload_files(["DLMessageUploadFiles"]))
    with pytest.raises(MobileBackupSafetyError):
        asyncio.run(_link(root).remove_items(["DLMessageRemoveItems", ["device/incoming.bin"]]))

    assert outside.read_bytes() == b"operator-data"
    assert link_path.is_symlink()


def test_existing_nested_path_ancestor_symlink_is_rejected(tmp_path: Path) -> None:
    root = tmp_path / "fresh-root"
    root.mkdir()
    outside = tmp_path / "operator-directory"
    outside.mkdir()
    marker = outside / "marker.bin"
    marker.write_bytes(b"operator-data")
    linked_ancestor = root / "device"
    try:
        linked_ancestor.symlink_to(outside, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")

    with pytest.raises(MobileBackupSafetyError):
        asyncio.run(
            _link(root).create_directory(["DLMessageCreateDirectory", "device/new-directory"])
        )
    with pytest.raises(MobileBackupSafetyError):
        asyncio.run(_link(root).remove_items(["DLMessageRemoveItems", ["device/marker.bin"]]))

    assert marker.read_bytes() == b"operator-data"
    assert not (outside / "new-directory").exists()


def test_nested_ancestor_symlink_is_rejected_for_confinement_root(tmp_path: Path) -> None:
    real_parent = tmp_path / "real-parent"
    root = real_parent / "fresh-root"
    root.mkdir(parents=True)
    linked_parent = tmp_path / "linked-parent"
    try:
        linked_parent.symlink_to(real_parent, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")

    with pytest.raises(MobileBackupSafetyError):
        _link(linked_parent / "fresh-root")


def test_root_identity_change_fails_closed(tmp_path: Path) -> None:
    root = tmp_path / "fresh-root"
    root.mkdir()
    link = _link(root)
    original = tmp_path / "original-root"
    root.rename(original)
    root.mkdir()

    with pytest.raises(MobileBackupSafetyError):
        asyncio.run(link.create_directory(["DLMessageCreateDirectory", "device"]))

    assert list(root.iterdir()) == []


def test_disconnect_failure_does_not_replace_primary_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "fresh-root"
    root.mkdir()
    wire = _Wire(fail_send_plist=True)

    class Service(SafeMobilebackup2Service):
        def __init__(self) -> None:
            self._service = cast(Any, wire)

        async def connect(self) -> None:
            return None

        async def version_exchange(
            self, device_link: SafeDeviceLink, local_versions: object = None
        ) -> None:
            return None

    async def version_exchange(_self: SafeDeviceLink) -> None:
        return None

    monkeypatch.setattr(SafeDeviceLink, "version_exchange", version_exchange)

    async def run() -> None:
        service = Service()
        async with service.device_link(root):
            raise RuntimeError("primary classified failure")

    with pytest.raises(RuntimeError, match="primary classified failure") as caught:
        asyncio.run(run())
    assert LEAK_MARKER not in str(caught.value)


def test_disconnect_only_failure_records_status_without_replacing_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "fresh-root"
    root.mkdir()
    wire = _Wire(fail_send_plist=True)

    class Service(SafeMobilebackup2Service):
        def __init__(self) -> None:
            self._service = cast(Any, wire)

        async def connect(self) -> None:
            return None

        async def version_exchange(
            self, device_link: SafeDeviceLink, local_versions: object = None
        ) -> None:
            return None

    async def version_exchange(_self: SafeDeviceLink) -> None:
        return None

    monkeypatch.setattr(SafeDeviceLink, "version_exchange", version_exchange)

    async def run() -> bool:
        service = Service()
        async with service.device_link(root):
            pass
        return service.device_link_connection_closed

    assert asyncio.run(run()) is False


def test_existing_windows_case_alias_is_refused_before_overwrite(tmp_path: Path) -> None:
    root = tmp_path / "fresh-root"
    actual = root / "Device" / "File.bin"
    actual.parent.mkdir(parents=True)
    actual.write_bytes(b"original")
    alias = root / "device" / "file.bin"
    try:
        if not alias.exists() or not alias.samefile(actual):
            pytest.skip("filesystem is case-sensitive")
    except OSError as exc:
        pytest.skip(f"case-alias probe unavailable: {exc}")

    wire = _Wire(_upload_reads("device/file.bin", payload=b"overwrite"))
    with pytest.raises(MobileBackupSafetyError):
        asyncio.run(_link(root, wire).upload_files(["DLMessageUploadFiles"]))

    assert actual.read_bytes() == b"original"


def test_contents_of_directory_enforces_entry_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "fresh-root"
    folder = root / "folder"
    folder.mkdir(parents=True)
    for index in range(3):
        (folder / f"entry-{index}").write_bytes(b"x")
    monkeypatch.setattr(safe_mobilebackup_module, "_MAX_DIRECTORY_ENTRIES", 2)
    wire = _Wire()

    with pytest.raises(MobileBackupSafetyError):
        asyncio.run(_link(root, wire).contents_of_directory(["DLContentsOfDirectory", "folder"]))

    assert wire.sent_plists == []


def test_receive_message_rejects_oversize_prefix_before_payload_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "fresh-root"
    root.mkdir()
    monkeypatch.setattr(safe_mobilebackup_module, "_MAX_CONTROL_PLIST_BYTES", 8)
    wire = _Wire([struct.pack(SIZE_FORMAT, 9)])

    with pytest.raises(MobileBackupSafetyError) as caught:
        asyncio.run(_link(root, wire).receive_message())

    assert str(caught.value) == "mobile backup transfer failed"
    assert wire.received_sizes == [struct.calcsize(SIZE_FORMAT)]


def test_receive_message_accepts_one_bounded_known_control_plist(tmp_path: Path) -> None:
    root = tmp_path / "fresh-root"
    root.mkdir()
    payload = plistlib.dumps(["DLMessageDeviceReady"], fmt=plistlib.FMT_BINARY)
    wire = _Wire([struct.pack(SIZE_FORMAT, len(payload)), payload])

    message = asyncio.run(_link(root, wire).receive_message())

    assert message == ["DLMessageDeviceReady"]


def test_download_local_read_error_is_redacted_and_later_file_continues(tmp_path: Path) -> None:
    root = tmp_path / "fresh-root"
    root.mkdir()
    (root / "present.bin").write_bytes(b"present-payload")
    wire = _Wire()

    asyncio.run(
        _link(root, wire).download_files(
            ["DLMessageDownloadFiles", ["missing.bin", "present.bin"], 0, 0]
        )
    )

    combined = b"".join(wire.sent_bytes)
    assert b"local read failed" in combined
    assert b"present-payload" in combined
    assert wire.sent_plists[-1][0] == "DLMessageStatusResponse"
    assert wire.sent_plists[-1][1] != 0


def test_download_directory_error_is_redacted_and_later_file_continues(tmp_path: Path) -> None:
    root = tmp_path / "fresh-root"
    (root / "directory").mkdir(parents=True)
    (root / "present.bin").write_bytes(b"present-payload")
    wire = _Wire()

    asyncio.run(
        _link(root, wire).download_files(
            ["DLMessageDownloadFiles", ["directory", "present.bin"], 0, 0]
        )
    )

    combined = b"".join(wire.sent_bytes)
    assert b"local read failed" in combined
    assert b"present-payload" in combined
