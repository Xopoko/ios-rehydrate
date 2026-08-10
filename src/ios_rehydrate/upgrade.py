# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 iOS Rehydrate contributors
"""Single-purpose, guarded installation-proxy Upgrade operation."""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Callable
from typing import Any

from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.services.afc import AfcService
from pymobiledevice3.services.installation_proxy import InstallationProxyService

from ios_rehydrate.apps import AppSnapshot, AppState, inspect_app
from ios_rehydrate.errors import ExitCode, OutcomeUnknownError, RehydrateError
from ios_rehydrate.ipa import ValidatedIPA

_STAGING_DIRECTORY = "/PublicStaging/ios-rehydrate"
_PREFLIGHT_INSPECT_TIMEOUT_SECONDS = 15.0
_FINAL_ELIGIBILITY_TIMEOUT_SECONDS = 15.0
_UPGRADE_SEND_TIMEOUT_SECONDS = 15 * 60.0
_CLEANUP_TIMEOUT_SECONDS = 15.0
_POSTFLIGHT_ATTEMPTS = 3
_POSTFLIGHT_DELAY_SECONDS = 0.25
_POSTFLIGHT_INSPECT_TIMEOUT_SECONDS = 15.0


def _eligible_target(snapshot: AppSnapshot) -> bool:
    return snapshot.state is AppState.PLACEHOLDER and (snapshot.placeholder or snapshot.demoted)


def _postflight_matches(snapshot: AppSnapshot, payload: ValidatedIPA) -> bool:
    return (
        snapshot.state is AppState.INSTALLED
        and not snapshot.placeholder
        and not snapshot.demoted
        and snapshot.version == payload.version
        and snapshot.build == payload.build
    )


async def _bounded_postflight(
    lockdown: LockdownServiceProvider,
    payload: ValidatedIPA,
    *,
    staging_removed: bool,
) -> AppSnapshot:
    for attempt in range(_POSTFLIGHT_ATTEMPTS):
        try:
            async with asyncio.timeout(_POSTFLIGHT_INSPECT_TIMEOUT_SECONDS):
                snapshot = await inspect_app(lockdown, payload.bundle_identifier)
        except BaseException:
            raise _outcome_unknown(staging_removed=staging_removed) from None
        if snapshot.state is AppState.AMBIGUOUS:
            raise _outcome_unknown(staging_removed=staging_removed)
        if _postflight_matches(snapshot, payload):
            return snapshot
        if attempt + 1 < _POSTFLIGHT_ATTEMPTS:
            try:
                await asyncio.sleep(_POSTFLIGHT_DELAY_SECONDS)
            except BaseException:
                raise _outcome_unknown(staging_removed=staging_removed) from None

    cleanup_suffix = ""
    if not staging_removed:
        cleanup_suffix = "; staging cleanup was also not confirmed"
    raise RehydrateError(
        f"upgrade completed but postflight did not confirm the expected app state{cleanup_suffix}",
        code=ExitCode.POSTCHECK_FAILED,
        reason="UPGRADE_POSTCHECK_FAILED",
    )


def _outcome_unknown(*, staging_removed: bool) -> OutcomeUnknownError:
    if staging_removed:
        return OutcomeUnknownError(staging_removed=True)
    return OutcomeUnknownError(
        "upgrade outcome is unknown; staging cleanup was not confirmed",
        staging_removed=False,
    )


async def _remove_owned_staging_file(afc: AfcService, staging_path: str) -> bool:
    async with asyncio.timeout(_CLEANUP_TIMEOUT_SECONDS):
        return await afc.rm_single(staging_path, force=True)


async def _shielded_cleanup(
    afc: AfcService, staging_path: str
) -> tuple[bool, BaseException | None]:
    """Finish bounded exact-file cleanup even when the calling task is interrupted."""
    cleanup_task = asyncio.create_task(_remove_owned_staging_file(afc, staging_path))
    interruption: BaseException | None = None
    while not cleanup_task.done():
        try:
            await asyncio.shield(cleanup_task)
        except BaseException as error:
            if interruption is None:
                interruption = error

    removed = False
    try:
        removed = cleanup_task.result() is True
    except BaseException as error:
        if interruption is None:
            interruption = error
    return removed, interruption


async def rehydrate_app(
    lockdown: LockdownServiceProvider,
    payload: ValidatedIPA,
    *,
    on_mutation_boundary: Callable[[], None] | None = None,
) -> dict[str, Any]:
    """Rehydrate one existing User placeholder using only the Upgrade command."""
    try:
        async with asyncio.timeout(_PREFLIGHT_INSPECT_TIMEOUT_SECONDS):
            before = await inspect_app(lockdown, payload.bundle_identifier)
    except TimeoutError:
        raise RehydrateError(
            "application preflight inspection timed out",
            code=ExitCode.DEVICE_UNAVAILABLE,
            reason="APP_PREFLIGHT_TIMEOUT",
        ) from None
    if not _eligible_target(before):
        raise RehydrateError(
            "target is not an exact User placeholder or demoted app",
            code=ExitCode.POLICY_REFUSED,
            reason="TARGET_NOT_REHYDRATABLE",
        )

    staging_path = f"{_STAGING_DIRECTORY}/{uuid.uuid4().hex}.ipa"
    options = {
        "CFBundleIdentifier": payload.bundle_identifier,
        "ApplicationSINF": payload.sinf,
        "iTunesMetadata": payload.metadata,
    }
    send_boundary_crossed = False
    staging_write_attempted = False
    staging_removed = False
    try:
        async with AfcService(lockdown) as afc:
            operation_error: BaseException | None = None
            cleanup_error: BaseException | None = None
            try:
                await afc.makedirs(_STAGING_DIRECTORY)
                staging_write_attempted = True
                await afc.set_file_contents(staging_path, payload.archive_bytes)
                try:
                    async with asyncio.timeout(_FINAL_ELIGIBILITY_TIMEOUT_SECONDS):
                        before_send = await inspect_app(lockdown, payload.bundle_identifier)
                except TimeoutError:
                    raise RehydrateError(
                        "final application eligibility inspection timed out",
                        code=ExitCode.DEVICE_UNAVAILABLE,
                        reason="APP_FINAL_PREFLIGHT_TIMEOUT",
                    ) from None
                if not _eligible_target(before_send):
                    raise RehydrateError(
                        "target eligibility changed while the package was staged",
                        code=ExitCode.POLICY_REFUSED,
                        reason="TARGET_CHANGED_DURING_STAGING",
                    )
                before = before_send
                async with InstallationProxyService(lockdown) as installation_proxy:
                    if on_mutation_boundary is not None:
                        on_mutation_boundary()
                    send_boundary_crossed = True
                    async with asyncio.timeout(_UPGRADE_SEND_TIMEOUT_SECONDS):
                        await installation_proxy.send_package(
                            "Upgrade", options, None, staging_path
                        )
            except BaseException as error:
                operation_error = error
            finally:
                staging_removed, cleanup_error = await _shielded_cleanup(afc, staging_path)
            if operation_error is not None:
                raise operation_error
            if cleanup_error is not None:
                raise cleanup_error
    except BaseException as error:
        cleanup_unconfirmed = staging_write_attempted and not staging_removed
        if send_boundary_crossed:
            raise _outcome_unknown(staging_removed=staging_removed) from None
        if cleanup_unconfirmed:
            raise RehydrateError(
                "upgrade was not sent; staging cleanup was not confirmed",
                code=ExitCode.UPGRADE_FAILED,
                reason="STAGING_CLEANUP_UNCONFIRMED",
            ) from None
        if isinstance(error, RehydrateError):
            raise error
        if not isinstance(error, Exception):
            raise
        raise RehydrateError(
            "upgrade could not be started",
            code=ExitCode.UPGRADE_FAILED,
            reason="UPGRADE_START_FAILED",
        ) from None

    after = await _bounded_postflight(
        lockdown,
        payload,
        staging_removed=staging_removed,
    )
    return {
        "operation": "Upgrade",
        "ipa": {"sha256": payload.sha256, "size": payload.size},
        "before": before.to_evidence(),
        "after": after.to_evidence(),
        "cleanup": {"staging_removed": staging_removed},
    }
