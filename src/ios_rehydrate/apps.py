# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 iOS Rehydrate contributors
"""Redacted, fail-closed inspection of the runtime application database."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.services.installation_proxy import InstallationProxyService

from ios_rehydrate.errors import ExitCode, RehydrateError
from ios_rehydrate.privacy import opaque_ref

_APP_NAMESPACE = "app"
_PUBLIC_VERSION = re.compile(r"[0-9A-Za-z][0-9A-Za-z._+-]{0,63}\Z")
_RETURN_ATTRIBUTES = [
    "CFBundleIdentifier",
    "ApplicationType",
    "CFBundleShortVersionString",
    "CFBundleVersion",
    "IsPlaceholder",
    "IsDemotedApp",
    "StaticDiskUsage",
    "DynamicDiskUsage",
]


class AppState(StrEnum):
    """Policy-relevant application states reported by installation proxy."""

    ABSENT = "ABSENT"
    PLACEHOLDER = "PLACEHOLDER"
    INSTALLED = "INSTALLED"
    SYSTEM = "SYSTEM"
    AMBIGUOUS = "AMBIGUOUS"


@dataclass(frozen=True, slots=True)
class AppSnapshot:
    """The complete, intentionally redacted public application evidence."""

    app_ref: str
    state: AppState
    version: str | None
    build: str | None
    placeholder: bool
    demoted: bool
    sizes: dict[str, int | None]

    def to_evidence(self) -> dict[str, object]:
        return {
            "app_ref": self.app_ref,
            "state": self.state.value,
            "version": self.version,
            "build": self.build,
            "placeholder": self.placeholder,
            "demoted": self.demoted,
            "sizes": dict(self.sizes),
        }


def _empty_snapshot(bundle_identifier: str, state: AppState) -> AppSnapshot:
    return AppSnapshot(
        app_ref=opaque_ref(bundle_identifier, namespace=_APP_NAMESPACE),
        state=state,
        version=None,
        build=None,
        placeholder=False,
        demoted=False,
        sizes={"static": None, "dynamic": None},
    )


def _bounded_string(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value if _PUBLIC_VERSION.fullmatch(value) is not None else None


def _nonnegative_size(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def _snapshot_from_record(bundle_identifier: str, record: dict[str, Any]) -> AppSnapshot:
    application_type = record.get("ApplicationType")
    if application_type not in {"User", "System"}:
        return _empty_snapshot(bundle_identifier, AppState.AMBIGUOUS)

    placeholder = record.get("IsPlaceholder") is True
    demoted = record.get("IsDemotedApp") is True
    if application_type == "System":
        state = AppState.SYSTEM
    elif placeholder or demoted:
        state = AppState.PLACEHOLDER
    else:
        state = AppState.INSTALLED

    return AppSnapshot(
        app_ref=opaque_ref(bundle_identifier, namespace=_APP_NAMESPACE),
        state=state,
        version=_bounded_string(record.get("CFBundleShortVersionString")),
        build=_bounded_string(record.get("CFBundleVersion")),
        placeholder=placeholder,
        demoted=demoted,
        sizes={
            "static": _nonnegative_size(record.get("StaticDiskUsage")),
            "dynamic": _nonnegative_size(record.get("DynamicDiskUsage")),
        },
    )


async def inspect_app(lockdown: LockdownServiceProvider, bundle_identifier: str) -> AppSnapshot:
    """Inspect one exact runtime bundle ID while including offloaded placeholders."""
    options: dict[str, Any] = {
        "ApplicationType": "Any",
        "BundleIDs": [bundle_identifier],
        "ShowPlaceholders": True,
        "ReturnAttributes": list(_RETURN_ATTRIBUTES),
    }
    try:
        async with InstallationProxyService(lockdown) as service:
            result = await service.lookup(options)
    except Exception:
        raise RehydrateError(
            "application inspection failed",
            code=ExitCode.DEVICE_UNAVAILABLE,
            reason="APP_LOOKUP_FAILED",
        ) from None

    if not isinstance(result, dict):
        raise RehydrateError(
            "application inspection returned no result",
            code=ExitCode.DEVICE_UNAVAILABLE,
            reason="APP_LOOKUP_INVALID",
        )

    candidates: list[dict[str, Any]] = []
    malformed_exact_record = False
    for result_identifier, value in result.items():
        if not isinstance(value, dict):
            malformed_exact_record = (
                malformed_exact_record or result_identifier == bundle_identifier
            )
            continue
        runtime_identifier = value.get("CFBundleIdentifier")
        if runtime_identifier == bundle_identifier:
            candidates.append(value)
        elif result_identifier == bundle_identifier:
            malformed_exact_record = True

    if malformed_exact_record or len(candidates) > 1:
        return _empty_snapshot(bundle_identifier, AppState.AMBIGUOUS)
    if not candidates:
        return _empty_snapshot(bundle_identifier, AppState.ABSENT)
    return _snapshot_from_record(bundle_identifier, candidates[0])
