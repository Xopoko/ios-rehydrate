# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 iOS Rehydrate contributors

from __future__ import annotations

import asyncio
import hashlib
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from ios_rehydrate import device
from ios_rehydrate.errors import RehydrateError


def _serial(label: str) -> str:
    digest = hashlib.sha256(label.encode()).hexdigest()
    return f"{digest[:8]}-{digest[8:24]}"


def _mux(label: str, connection_type: str = "USB") -> SimpleNamespace:
    return SimpleNamespace(serial=_serial(label), connection_type=connection_type)


def test_list_devices_is_usb_only_deterministic_and_redacted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    records = [_mux("synthetic-alpha"), _mux("synthetic-network", "Network")]

    async def fake_list(*, usbmux_address: str) -> list[SimpleNamespace]:
        assert usbmux_address == device._local_usbmux_address()
        return records

    monkeypatch.setattr(device, "list_mux_devices", fake_list)

    first = asyncio.run(device.list_devices())
    second = asyncio.run(device.list_devices())

    assert first == second
    assert len(first) == 1
    assert first[0]["connection_type"] == "USB"
    assert first[0]["device_ref"].startswith("device_")
    assert "synthetic-alpha" not in repr(first)
    assert "synthetic-network" not in repr(first)


@pytest.mark.parametrize(
    "invalid_serial",
    ["../escape", "..\\escape", "/absolute", "C:stream", "bad\0value", "a" * 41],
)
def test_malformed_mux_serial_never_reaches_pair_record_lookup(
    invalid_serial: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def fake_list(*, usbmux_address: str) -> list[SimpleNamespace]:
        assert usbmux_address == device._local_usbmux_address()
        return [SimpleNamespace(serial=invalid_serial, connection_type="USB")]

    monkeypatch.setattr(device, "list_mux_devices", fake_list)

    with pytest.raises(RehydrateError) as caught:
        asyncio.run(device.list_devices())

    assert caught.value.reason == "USBMUX_DEVICE_RECORD_INVALID"


def test_open_device_requires_unique_explicit_selector_and_closes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("USBMUXD_SOCKET_ADDRESS", "example.invalid:1234")
    records = [_mux("synthetic-alpha"), _mux("synthetic-beta")]
    captured: dict[str, Any] = {}
    cache_path: Path | None = None

    class FakeLockdown:
        closed = False
        udid = _serial("synthetic-alpha")

        async def close(self) -> None:
            self.closed = True

    lockdown = FakeLockdown()

    async def fake_list(*, usbmux_address: str) -> list[SimpleNamespace]:
        assert usbmux_address == device._local_usbmux_address()
        assert "example.invalid" not in usbmux_address
        return records

    async def fake_create(**kwargs: Any) -> FakeLockdown:
        nonlocal cache_path
        cache_path = kwargs["pairing_records_cache_folder"]
        assert isinstance(cache_path, Path)
        assert cache_path.is_dir()
        captured.update(kwargs)
        return lockdown

    monkeypatch.setattr(device, "list_mux_devices", fake_list)
    monkeypatch.setattr(device, "create_using_usbmux", fake_create)

    async def exercise() -> None:
        evidence = await device.list_devices()
        selected_ref = next(
            item["device_ref"]
            for item in evidence
            if item["device_ref"] == device._device_ref(_serial("synthetic-alpha"))
        )
        close_status = device.DeviceCloseStatus()
        async with device.open_device(selected_ref, close_status=close_status) as opened:
            assert opened is lockdown
            assert not lockdown.closed
        assert close_status.closed is True

    asyncio.run(exercise())

    assert lockdown.closed
    assert cache_path is not None
    assert not cache_path.exists()
    assert captured.pop("pairing_records_cache_folder") == cache_path
    assert captured == {
        "serial": _serial("synthetic-alpha"),
        "identifier": _serial("synthetic-alpha"),
        "connection_type": "USB",
        "usbmux_address": device._local_usbmux_address(),
        "autopair": False,
    }


def test_close_failure_never_masks_success_or_body_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeLockdown:
        udid = _serial("synthetic-close")

        async def close(self) -> None:
            raise RuntimeError("synthetic close failure")

    async def fake_list(*, usbmux_address: str) -> list[SimpleNamespace]:
        assert usbmux_address == device._local_usbmux_address()
        return [_mux("synthetic-close")]

    async def fake_create(**kwargs: Any) -> FakeLockdown:
        del kwargs
        return FakeLockdown()

    monkeypatch.setattr(device, "list_mux_devices", fake_list)
    monkeypatch.setattr(device, "create_using_usbmux", fake_create)

    async def exercise_success() -> None:
        close_status = device.DeviceCloseStatus()
        async with device.open_device(
            _serial("synthetic-close"), close_status=close_status
        ) as opened:
            assert isinstance(opened, FakeLockdown)
        assert close_status.closed is False

    async def exercise_body_failure() -> None:
        close_status = device.DeviceCloseStatus()
        with pytest.raises(RehydrateError) as caught:
            async with device.open_device(_serial("synthetic-close"), close_status=close_status):
                raise RehydrateError(
                    "classified body failure",
                    code=device.ExitCode.POLICY_REFUSED,
                    reason="SYNTHETIC_BODY_FAILURE",
                )
        assert caught.value.reason == "SYNTHETIC_BODY_FAILURE"
        assert close_status.closed is False

    asyncio.run(exercise_success())
    asyncio.run(exercise_body_failure())


def test_open_device_rejects_lockdown_identity_mismatch_before_yield(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selected = _mux("synthetic-selected")

    class FakeLockdown:
        udid = _serial("synthetic-other")

        def __init__(self) -> None:
            self.closed = False

        async def close(self) -> None:
            self.closed = True

    lockdown = FakeLockdown()

    async def fake_list(*, usbmux_address: str) -> list[SimpleNamespace]:
        assert usbmux_address == device._local_usbmux_address()
        return [selected]

    async def fake_create(**kwargs: Any) -> FakeLockdown:
        del kwargs
        return lockdown

    monkeypatch.setattr(device, "list_mux_devices", fake_list)
    monkeypatch.setattr(device, "create_using_usbmux", fake_create)

    async def exercise() -> None:
        yielded = False
        with pytest.raises(RehydrateError) as caught:
            async with device.open_device(selected.serial):
                yielded = True
        assert caught.value.reason == "LOCKDOWN_IDENTITY_MISMATCH"
        assert yielded is False

    asyncio.run(exercise())
    assert lockdown.closed is True


@pytest.mark.parametrize("selector", ["", "   "])
def test_open_device_never_selects_implicitly(
    monkeypatch: pytest.MonkeyPatch, selector: str
) -> None:
    async def fake_list(*, usbmux_address: str) -> list[SimpleNamespace]:
        assert usbmux_address == device._local_usbmux_address()
        return [_mux("synthetic-only")]

    monkeypatch.setattr(device, "list_mux_devices", fake_list)

    async def exercise() -> None:
        with pytest.raises(RehydrateError) as error:
            async with device.open_device(selector):
                pytest.fail("an empty selector must never open a device")
        assert error.value.reason == "DEVICE_SELECTOR_REQUIRED"

    asyncio.run(exercise())


def test_reference_and_duplicate_full_serial_must_be_unique(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_list(*, usbmux_address: str) -> list[SimpleNamespace]:
        assert usbmux_address == device._local_usbmux_address()
        return [_mux("synthetic-duplicate"), _mux("synthetic-duplicate")]

    monkeypatch.setattr(device, "list_mux_devices", fake_list)

    async def exercise() -> None:
        for selector in (
            _serial("synthetic-duplicate"),
            device._device_ref(_serial("synthetic-duplicate")),
        ):
            with pytest.raises(RehydrateError) as error:
                async with device.open_device(selector):
                    pytest.fail("an ambiguous selector must never open a device")
            assert error.value.reason == "DEVICE_SELECTOR_AMBIGUOUS"

    asyncio.run(exercise())


def test_truncated_reference_does_not_select_a_device(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_list(*, usbmux_address: str) -> list[SimpleNamespace]:
        assert usbmux_address == device._local_usbmux_address()
        return [_mux("synthetic-only")]

    monkeypatch.setattr(device, "list_mux_devices", fake_list)

    async def exercise() -> None:
        reference = device._device_ref(_serial("synthetic-only"))
        with pytest.raises(RehydrateError) as error:
            async with device.open_device(reference[:-1]):
                pytest.fail("a truncated reference must never open a device")
        assert error.value.reason == "DEVICE_SELECTOR_NO_MATCH"

    asyncio.run(exercise())
