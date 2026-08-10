# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 iOS Rehydrate contributors
"""Explicit, USB-only device discovery and connection handling."""

from __future__ import annotations

import re
import socket
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass
from ipaddress import ip_address
from pathlib import Path
from tempfile import TemporaryDirectory

from pymobiledevice3.lockdown import LockdownClient, create_using_usbmux
from pymobiledevice3.osu.os_utils import get_os_utils
from pymobiledevice3.usbmux import MuxDevice
from pymobiledevice3.usbmux import list_devices as list_mux_devices

from ios_rehydrate.errors import ExitCode, RehydrateError
from ios_rehydrate.privacy import device_reference

_CONNECTION_TYPE = "USB"
_USB_SERIAL = re.compile(r"(?:[0-9A-Fa-f]{40}|[0-9A-Fa-f]{8}-[0-9A-Fa-f]{16})\Z")


@dataclass(slots=True)
class DeviceCloseStatus:
    """Truthful, redacted status for best-effort local connection cleanup."""

    closed: bool = False


def _local_usbmux_address() -> str:
    """Return the platform's explicit local endpoint without consulting environment overrides."""
    address, family = get_os_utils().usbmux_address
    af_unix = getattr(socket, "AF_UNIX", None)
    if (
        af_unix is not None
        and family == af_unix
        and isinstance(address, str)
        and Path(address).is_absolute()
    ):
        return address
    if (
        family == socket.AF_INET
        and isinstance(address, tuple)
        and len(address) == 2
        and isinstance(address[0], str)
        and isinstance(address[1], int)
        and ip_address(address[0]).is_loopback
        and 0 < address[1] <= 65535
    ):
        return f"{address[0]}:{address[1]}"
    raise RehydrateError(
        "the platform did not provide a local usbmux endpoint",
        code=ExitCode.DEPENDENCY,
        reason="USBMUX_LOCAL_ENDPOINT_INVALID",
    )


def _device_ref(serial: str) -> str:
    return device_reference(serial)


async def _usb_devices() -> list[MuxDevice]:
    """Return only usable USB records, without opening lockdown sessions."""
    try:
        devices = await list_mux_devices(usbmux_address=_local_usbmux_address())
    except Exception:
        raise RehydrateError(
            "USB device discovery failed",
            code=ExitCode.DEVICE_UNAVAILABLE,
            reason="USBMUX_DISCOVERY_FAILED",
        ) from None
    usb_devices = [device for device in devices if device.connection_type == _CONNECTION_TYPE]
    if any(
        not isinstance(device.serial, str) or _USB_SERIAL.fullmatch(device.serial) is None
        for device in usb_devices
    ):
        raise RehydrateError(
            "usbmux returned an invalid USB device record",
            code=ExitCode.DEVICE_UNAVAILABLE,
            reason="USBMUX_DEVICE_RECORD_INVALID",
        )
    return usb_devices


async def list_devices() -> list[dict[str, str]]:
    """List connected USB devices using only opaque, deterministic references."""
    evidence = [
        {"device_ref": _device_ref(device.serial), "connection_type": _CONNECTION_TYPE}
        for device in await _usb_devices()
    ]
    return sorted(evidence, key=lambda item: item["device_ref"])


async def _resolve_device(selector: str) -> MuxDevice:
    normalized = selector.strip()
    if not normalized:
        raise RehydrateError(
            "an explicit USB device selector is required",
            code=ExitCode.DEVICE_SELECTION,
            reason="DEVICE_SELECTOR_REQUIRED",
        )

    matches: list[MuxDevice] = []
    for device in await _usb_devices():
        exact_serial = normalized == device.serial
        exact_reference = normalized == _device_ref(device.serial)
        if exact_serial or exact_reference:
            matches.append(device)

    if not matches:
        raise RehydrateError(
            "USB device selector did not match a connected device",
            code=ExitCode.DEVICE_SELECTION,
            reason="DEVICE_SELECTOR_NO_MATCH",
        )
    if len(matches) != 1:
        raise RehydrateError(
            "USB device selector is ambiguous",
            code=ExitCode.DEVICE_SELECTION,
            reason="DEVICE_SELECTOR_AMBIGUOUS",
        )
    return matches[0]


@asynccontextmanager
async def open_device(
    selector: str,
    *,
    close_status: DeviceCloseStatus | None = None,
) -> AsyncIterator[LockdownClient]:
    """Open exactly one explicitly selected USB device and always close it."""
    device = await _resolve_device(selector)
    # Passing an explicit ephemeral folder prevents pymobiledevice3 from creating its
    # persistent per-user cache. Existing records may still be read from usbmux/iTunes.
    with TemporaryDirectory(prefix="ios-rehydrate-pairing-", ignore_cleanup_errors=True) as cache:
        try:
            lockdown = await create_using_usbmux(
                serial=device.serial,
                identifier=device.serial,
                connection_type=_CONNECTION_TYPE,
                usbmux_address=_local_usbmux_address(),
                autopair=False,
                pairing_records_cache_folder=Path(cache),
            )
        except Exception:
            raise RehydrateError(
                "selected USB device is unavailable",
                code=ExitCode.DEVICE_UNAVAILABLE,
                reason="LOCKDOWN_OPEN_FAILED",
            ) from None

        opened_udid = getattr(lockdown, "udid", None)
        if (
            not isinstance(opened_udid, str)
            or _USB_SERIAL.fullmatch(opened_udid) is None
            or opened_udid.casefold() != device.serial.casefold()
        ):
            with suppress(BaseException):
                await lockdown.close()
            raise RehydrateError(
                "opened lockdown identity does not match the selected USB device",
                code=ExitCode.DEVICE_UNAVAILABLE,
                reason="LOCKDOWN_IDENTITY_MISMATCH",
            )

        try:
            yield lockdown
        finally:
            try:
                await lockdown.close()
            except BaseException:
                # Host-transport cleanup must not replace a known device outcome
                # or the body's already-classified failure.
                if close_status is not None:
                    close_status.closed = False
            else:
                if close_status is not None:
                    close_status.closed = True
