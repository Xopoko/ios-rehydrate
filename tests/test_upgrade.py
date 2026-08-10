# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 iOS Rehydrate contributors

from __future__ import annotations

import asyncio
import hashlib
from collections.abc import Awaitable, Callable
from typing import Any

import pytest

from ios_rehydrate import apps, upgrade
from ios_rehydrate.apps import AppSnapshot, AppState
from ios_rehydrate.errors import ExitCode, OutcomeUnknownError, RehydrateError
from ios_rehydrate.ipa import ValidatedIPA
from ios_rehydrate.privacy import opaque_ref

_BUNDLE_ID = "test.invalid.placeholder"


class _InjectedBaseException(BaseException):
    pass


def _snapshot(
    state: AppState,
    *,
    placeholder: bool = False,
    demoted: bool = False,
    version: str | None = None,
    build: str | None = None,
) -> AppSnapshot:
    return AppSnapshot(
        app_ref=opaque_ref(_BUNDLE_ID, namespace="app"),
        state=state,
        version=version,
        build=build,
        placeholder=placeholder,
        demoted=demoted,
        sizes={"static": None, "dynamic": None},
    )


def _payload() -> ValidatedIPA:
    archive_bytes = b"synthetic retained archive bytes"
    return ValidatedIPA(
        archive_bytes=archive_bytes,
        sha256=hashlib.sha256(archive_bytes).hexdigest(),
        size=len(archive_bytes),
        bundle_identifier=_BUNDLE_ID,
        version="2.0",
        build="20",
        minimum_os="17.0",
        metadata=b"synthetic-metadata",
        sinf=b"synthetic-sinf",
        has_code_resources=True,
        store_id="synthetic-store-id",
    )


def _patch_upgrade_services(
    monkeypatch: pytest.MonkeyPatch,
    *,
    inspect: Callable[[object, str], Awaitable[AppSnapshot]],
    send: Callable[[str, dict[str, Any], object, str], Awaitable[None]],
    remove: Callable[[str, bool], Awaitable[bool]],
    stage: Callable[[str, bytes], Awaitable[None]] | None = None,
) -> None:
    class FakeAfc:
        def __init__(self, lockdown: object) -> None:
            pass

        async def __aenter__(self) -> FakeAfc:
            return self

        async def __aexit__(self, *args: object) -> None:
            pass

        async def makedirs(self, path: str) -> None:
            pass

        async def set_file_contents(self, path: str, data: bytes) -> None:
            if stage is not None:
                await stage(path, data)

        async def rm_single(self, path: str, *, force: bool) -> bool:
            return await remove(path, force)

    class FakeProxy:
        def __init__(self, lockdown: object) -> None:
            pass

        async def __aenter__(self) -> FakeProxy:
            return self

        async def __aexit__(self, *args: object) -> None:
            pass

        async def send_package(
            self,
            command: str,
            options: dict[str, Any],
            handler: object,
            path: str,
        ) -> None:
            await send(command, options, handler, path)

    monkeypatch.setattr(upgrade, "inspect_app", inspect)
    monkeypatch.setattr(upgrade, "AfcService", FakeAfc)
    monkeypatch.setattr(upgrade, "InstallationProxyService", FakeProxy)


def test_inspect_app_uses_exact_runtime_id_and_shows_placeholders(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    class FakeProxy:
        closed = False

        def __init__(self, lockdown: object) -> None:
            captured["lockdown"] = lockdown

        async def __aenter__(self) -> FakeProxy:
            return self

        async def __aexit__(self, *args: object) -> None:
            self.closed = True

        async def lookup(self, options: dict[str, Any]) -> dict[str, dict[str, Any]]:
            captured["options"] = options
            return {
                _BUNDLE_ID: {
                    "CFBundleIdentifier": _BUNDLE_ID,
                    "ApplicationType": "User",
                    "CFBundleShortVersionString": "1.0",
                    "CFBundleVersion": "10",
                    "IsPlaceholder": True,
                    "IsDemotedApp": True,
                    "StaticDiskUsage": 120,
                    "DynamicDiskUsage": 34,
                },
                "test.invalid.unrelated": {
                    "CFBundleIdentifier": "test.invalid.unrelated",
                    "ApplicationType": "User",
                },
            }

    monkeypatch.setattr(apps, "InstallationProxyService", FakeProxy)
    lockdown = object()
    snapshot = asyncio.run(apps.inspect_app(lockdown, _BUNDLE_ID))  # type: ignore[arg-type]

    assert snapshot.state is AppState.PLACEHOLDER
    assert snapshot.placeholder and snapshot.demoted
    assert snapshot.sizes == {"static": 120, "dynamic": 34}
    assert captured["lockdown"] is lockdown
    options = captured["options"]
    assert options["BundleIDs"] == [_BUNDLE_ID]
    assert options["ApplicationType"] == "Any"
    assert options["ShowPlaceholders"] is True
    assert "CFBundleIdentifier" in options["ReturnAttributes"]
    assert "IsPlaceholder" in options["ReturnAttributes"]
    evidence = snapshot.to_evidence()
    assert set(evidence) == {
        "app_ref",
        "state",
        "version",
        "build",
        "placeholder",
        "demoted",
        "sizes",
    }
    assert _BUNDLE_ID not in repr(evidence)


@pytest.mark.parametrize(
    ("result", "expected"),
    [
        ({}, AppState.ABSENT),
        (
            {
                _BUNDLE_ID: {
                    "CFBundleIdentifier": _BUNDLE_ID,
                    "ApplicationType": "User",
                }
            },
            AppState.INSTALLED,
        ),
        (
            {
                _BUNDLE_ID: {
                    "CFBundleIdentifier": _BUNDLE_ID,
                    "ApplicationType": "System",
                }
            },
            AppState.SYSTEM,
        ),
        (
            {
                "test.invalid.first": {
                    "CFBundleIdentifier": _BUNDLE_ID,
                    "ApplicationType": "User",
                },
                "test.invalid.second": {
                    "CFBundleIdentifier": _BUNDLE_ID,
                    "ApplicationType": "User",
                },
            },
            AppState.AMBIGUOUS,
        ),
    ],
)
def test_inspect_app_classifies_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
    result: dict[str, dict[str, Any]],
    expected: AppState,
) -> None:
    class FakeProxy:
        def __init__(self, lockdown: object) -> None:
            pass

        async def __aenter__(self) -> FakeProxy:
            return self

        async def __aexit__(self, *args: object) -> None:
            pass

        async def lookup(self, options: dict[str, Any]) -> dict[str, dict[str, Any]]:
            return result

    monkeypatch.setattr(apps, "InstallationProxyService", FakeProxy)
    snapshot = asyncio.run(apps.inspect_app(object(), _BUNDLE_ID))  # type: ignore[arg-type]
    assert snapshot.state is expected


def test_inspect_app_drops_private_or_non_version_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seeded_email = "operator" + "@" + "example.invalid"
    seeded_path = "C:" + "\\" + "Users" + "\\Synthetic Person\\private-build"

    class FakeProxy:
        def __init__(self, lockdown: object) -> None:
            del lockdown

        async def __aenter__(self) -> FakeProxy:
            return self

        async def __aexit__(self, *args: object) -> None:
            return None

        async def lookup(self, options: dict[str, Any]) -> dict[str, dict[str, Any]]:
            del options
            return {
                _BUNDLE_ID: {
                    "CFBundleIdentifier": _BUNDLE_ID,
                    "ApplicationType": "User",
                    "CFBundleShortVersionString": seeded_email,
                    "CFBundleVersion": seeded_path,
                    "IsPlaceholder": True,
                }
            }

    monkeypatch.setattr(apps, "InstallationProxyService", FakeProxy)

    evidence = asyncio.run(
        apps.inspect_app(object(), _BUNDLE_ID)  # type: ignore[arg-type]
    ).to_evidence()

    assert evidence["version"] is None
    assert evidence["build"] is None
    assert seeded_email not in repr(evidence)
    assert seeded_path not in repr(evidence)


def test_upgrade_stages_retained_bytes_sends_exact_command_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = _payload()
    inspections = iter(
        [
            _snapshot(AppState.PLACEHOLDER, placeholder=True, demoted=True),
            _snapshot(AppState.PLACEHOLDER, placeholder=True, demoted=False),
            _snapshot(AppState.INSTALLED, version=payload.version, build=payload.build),
        ]
    )
    captured: dict[str, Any] = {"removed": []}
    boundaries: list[str] = []

    async def fake_inspect(lockdown: object, bundle_identifier: str) -> AppSnapshot:
        assert bundle_identifier == _BUNDLE_ID
        return next(inspections)

    class FakeAfc:
        closed = False

        def __init__(self, lockdown: object) -> None:
            pass

        async def __aenter__(self) -> FakeAfc:
            return self

        async def __aexit__(self, *args: object) -> None:
            self.closed = True
            captured["afc_closed"] = True

        async def makedirs(self, path: str) -> None:
            captured["directory"] = path

        async def set_file_contents(self, path: str, data: bytes) -> None:
            captured["staged_path"] = path
            captured["staged_bytes"] = data

        async def rm_single(self, path: str, *, force: bool) -> bool:
            captured["removed"].append((path, force))
            return True

    class FakeProxy:
        def __init__(self, lockdown: object) -> None:
            pass

        async def __aenter__(self) -> FakeProxy:
            return self

        async def __aexit__(self, *args: object) -> None:
            captured["proxy_closed"] = True

        async def send_package(
            self,
            command: str,
            options: dict[str, Any],
            handler: object,
            path: str,
        ) -> None:
            captured["send"] = (command, options, handler, path)

    monkeypatch.setattr(upgrade, "inspect_app", fake_inspect)
    monkeypatch.setattr(upgrade, "AfcService", FakeAfc)
    monkeypatch.setattr(upgrade, "InstallationProxyService", FakeProxy)

    evidence = asyncio.run(
        upgrade.rehydrate_app(
            object(),  # type: ignore[arg-type]
            payload,
            on_mutation_boundary=lambda: boundaries.append("crossed"),
        )
    )

    staged_path = captured["staged_path"]
    assert captured["directory"] == "/PublicStaging/ios-rehydrate"
    assert staged_path.startswith("/PublicStaging/ios-rehydrate/")
    assert staged_path.endswith(".ipa")
    assert captured["staged_bytes"] is payload.archive_bytes
    command, options, handler, sent_path = captured["send"]
    assert command == "Upgrade"
    assert handler is None
    assert sent_path == staged_path
    assert options == {
        "CFBundleIdentifier": _BUNDLE_ID,
        "ApplicationSINF": payload.sinf,
        "iTunesMetadata": payload.metadata,
    }
    assert captured["removed"] == [(staged_path, True)]
    assert captured["afc_closed"] and captured["proxy_closed"]
    assert evidence["operation"] == "Upgrade"
    assert evidence["before"]["demoted"] is False
    assert evidence["cleanup"] == {"staging_removed": True}
    assert boundaries == ["crossed"]
    assert _BUNDLE_ID not in repr(evidence)


@pytest.mark.parametrize(
    "snapshot",
    [
        _snapshot(AppState.ABSENT),
        _snapshot(AppState.INSTALLED),
        _snapshot(AppState.SYSTEM, placeholder=True, demoted=True),
        _snapshot(AppState.AMBIGUOUS),
    ],
)
def test_upgrade_refuses_every_non_user_placeholder_before_staging(
    monkeypatch: pytest.MonkeyPatch, snapshot: AppSnapshot
) -> None:
    async def fake_inspect(lockdown: object, bundle_identifier: str) -> AppSnapshot:
        return snapshot

    class ForbiddenAfc:
        def __init__(self, lockdown: object) -> None:
            pytest.fail("policy refusal must happen before AFC staging")

    monkeypatch.setattr(upgrade, "inspect_app", fake_inspect)
    monkeypatch.setattr(upgrade, "AfcService", ForbiddenAfc)

    with pytest.raises(RehydrateError) as error:
        asyncio.run(upgrade.rehydrate_app(object(), _payload()))  # type: ignore[arg-type]
    assert error.value.code is ExitCode.POLICY_REFUSED


def test_upgrade_rechecks_eligibility_after_staging_and_never_sends_if_changed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inspections = iter(
        [
            _snapshot(AppState.PLACEHOLDER, placeholder=True),
            _snapshot(AppState.INSTALLED),
        ]
    )
    staged_paths: list[str] = []
    removed: list[tuple[str, bool]] = []
    send_calls = 0

    async def fake_inspect(lockdown: object, bundle_identifier: str) -> AppSnapshot:
        return next(inspections)

    async def fake_stage(path: str, data: bytes) -> None:
        del data
        staged_paths.append(path)

    async def forbidden_send(
        command: str,
        options: dict[str, Any],
        handler: object,
        path: str,
    ) -> None:
        nonlocal send_calls
        del command, options, handler, path
        send_calls += 1

    async def fake_remove(path: str, force: bool) -> bool:
        removed.append((path, force))
        return True

    _patch_upgrade_services(
        monkeypatch,
        inspect=fake_inspect,
        send=forbidden_send,
        remove=fake_remove,
        stage=fake_stage,
    )

    with pytest.raises(RehydrateError) as caught:
        asyncio.run(upgrade.rehydrate_app(object(), _payload()))  # type: ignore[arg-type]

    assert caught.value.reason == "TARGET_CHANGED_DURING_STAGING"
    assert caught.value.code is ExitCode.POLICY_REFUSED
    assert send_calls == 0
    assert len(staged_paths) == 1
    assert removed == [(staged_paths[0], True)]
    assert staged_paths[0] not in str(caught.value)
    assert _BUNDLE_ID not in str(caught.value)


def test_final_eligibility_timeout_cleans_staging_and_never_sends(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inspect_calls = 0
    send_calls = 0
    removed: list[tuple[str, bool]] = []

    async def fake_inspect(lockdown: object, bundle_identifier: str) -> AppSnapshot:
        nonlocal inspect_calls
        inspect_calls += 1
        if inspect_calls == 1:
            return _snapshot(AppState.PLACEHOLDER, demoted=True)
        await asyncio.Event().wait()
        raise AssertionError("unreachable")

    async def forbidden_send(
        command: str,
        options: dict[str, Any],
        handler: object,
        path: str,
    ) -> None:
        nonlocal send_calls
        del command, options, handler, path
        send_calls += 1

    async def fake_remove(path: str, force: bool) -> bool:
        removed.append((path, force))
        return True

    _patch_upgrade_services(
        monkeypatch,
        inspect=fake_inspect,
        send=forbidden_send,
        remove=fake_remove,
    )
    monkeypatch.setattr(upgrade, "_FINAL_ELIGIBILITY_TIMEOUT_SECONDS", 0.001)

    with pytest.raises(RehydrateError) as caught:
        asyncio.run(upgrade.rehydrate_app(object(), _payload()))  # type: ignore[arg-type]

    assert caught.value.reason == "APP_FINAL_PREFLIGHT_TIMEOUT"
    assert caught.value.code is ExitCode.DEVICE_UNAVAILABLE
    assert inspect_calls == 2
    assert send_calls == 0
    assert len(removed) == 1
    assert removed[0][0] not in str(caught.value)
    assert _BUNDLE_ID not in str(caught.value)


@pytest.mark.parametrize(
    "error_type",
    [RuntimeError, asyncio.CancelledError, KeyboardInterrupt, _InjectedBaseException],
)
def test_base_exception_after_send_boundary_is_unknown_and_cleanup_is_shielded(
    monkeypatch: pytest.MonkeyPatch,
    error_type: type[BaseException],
) -> None:
    removed: list[tuple[str, bool]] = []
    shield_calls = 0
    real_shield = asyncio.shield

    def tracking_shield(awaitable: Any) -> Any:
        nonlocal shield_calls
        shield_calls += 1
        return real_shield(awaitable)

    async def fake_inspect(lockdown: object, bundle_identifier: str) -> AppSnapshot:
        return _snapshot(AppState.PLACEHOLDER, demoted=True)

    class FakeAfc:
        def __init__(self, lockdown: object) -> None:
            pass

        async def __aenter__(self) -> FakeAfc:
            return self

        async def __aexit__(self, *args: object) -> None:
            pass

        async def makedirs(self, path: str) -> None:
            pass

        async def set_file_contents(self, path: str, data: bytes) -> None:
            pass

        async def rm_single(self, path: str, *, force: bool) -> bool:
            removed.append((path, force))
            return True

    class FailingProxy:
        def __init__(self, lockdown: object) -> None:
            pass

        async def __aenter__(self) -> FailingProxy:
            return self

        async def __aexit__(self, *args: object) -> None:
            pass

        async def send_package(self, *args: object) -> None:
            raise error_type("synthetic send interruption")

    monkeypatch.setattr(upgrade, "inspect_app", fake_inspect)
    monkeypatch.setattr(upgrade, "AfcService", FakeAfc)
    monkeypatch.setattr(upgrade, "InstallationProxyService", FailingProxy)
    monkeypatch.setattr(upgrade.asyncio, "shield", tracking_shield)

    with pytest.raises(OutcomeUnknownError):
        asyncio.run(upgrade.rehydrate_app(object(), _payload()))  # type: ignore[arg-type]
    assert len(removed) == 1
    assert removed[0][0].startswith("/PublicStaging/ios-rehydrate/")
    assert removed[0][1] is True
    assert shield_calls >= 1


def test_ambiguous_postflight_is_unknown(monkeypatch: pytest.MonkeyPatch) -> None:
    inspections = iter(
        [
            _snapshot(AppState.PLACEHOLDER, placeholder=True),
            _snapshot(AppState.PLACEHOLDER, placeholder=True),
            _snapshot(AppState.AMBIGUOUS),
        ]
    )

    async def fake_inspect(lockdown: object, bundle_identifier: str) -> AppSnapshot:
        return next(inspections)

    class FakeAfc:
        def __init__(self, lockdown: object) -> None:
            pass

        async def __aenter__(self) -> FakeAfc:
            return self

        async def __aexit__(self, *args: object) -> None:
            pass

        async def makedirs(self, path: str) -> None:
            pass

        async def set_file_contents(self, path: str, data: bytes) -> None:
            pass

        async def rm_single(self, path: str, *, force: bool) -> bool:
            return True

    class FakeProxy:
        def __init__(self, lockdown: object) -> None:
            pass

        async def __aenter__(self) -> FakeProxy:
            return self

        async def __aexit__(self, *args: object) -> None:
            pass

        async def send_package(self, *args: object) -> None:
            pass

    monkeypatch.setattr(upgrade, "inspect_app", fake_inspect)
    monkeypatch.setattr(upgrade, "AfcService", FakeAfc)
    monkeypatch.setattr(upgrade, "InstallationProxyService", FakeProxy)

    with pytest.raises(OutcomeUnknownError):
        asyncio.run(upgrade.rehydrate_app(object(), _payload()))  # type: ignore[arg-type]


def test_preflight_inspect_timeout_is_safe_and_never_stages(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0

    async def hanging_inspect(lockdown: object, bundle_identifier: str) -> AppSnapshot:
        nonlocal calls
        calls += 1
        await asyncio.Event().wait()
        raise AssertionError("unreachable")

    class ForbiddenAfc:
        def __init__(self, lockdown: object) -> None:
            pytest.fail("a preflight timeout must not create an AFC service")

    monkeypatch.setattr(upgrade, "inspect_app", hanging_inspect)
    monkeypatch.setattr(upgrade, "AfcService", ForbiddenAfc)
    monkeypatch.setattr(upgrade, "_PREFLIGHT_INSPECT_TIMEOUT_SECONDS", 0.001)

    with pytest.raises(RehydrateError) as error:
        asyncio.run(upgrade.rehydrate_app(object(), _payload()))  # type: ignore[arg-type]

    assert calls == 1
    assert error.value.code is ExitCode.DEVICE_UNAVAILABLE
    assert error.value.reason == "APP_PREFLIGHT_TIMEOUT"
    assert _BUNDLE_ID not in str(error.value)


@pytest.mark.parametrize("error_type", [asyncio.CancelledError, KeyboardInterrupt])
def test_interruption_before_send_is_preserved_after_single_owned_file_cleanup(
    monkeypatch: pytest.MonkeyPatch,
    error_type: type[BaseException],
) -> None:
    staged_path = ""
    removed: list[tuple[str, bool]] = []
    send_calls = 0

    async def fake_inspect(lockdown: object, bundle_identifier: str) -> AppSnapshot:
        return _snapshot(AppState.PLACEHOLDER, demoted=True)

    async def interrupted_stage(path: str, data: bytes) -> None:
        nonlocal staged_path
        staged_path = path
        raise error_type("synthetic pre-send interruption")

    async def forbidden_send(
        command: str,
        options: dict[str, Any],
        handler: object,
        path: str,
    ) -> None:
        nonlocal send_calls
        send_calls += 1

    async def fake_remove(path: str, force: bool) -> bool:
        removed.append((path, force))
        return True

    _patch_upgrade_services(
        monkeypatch,
        inspect=fake_inspect,
        send=forbidden_send,
        remove=fake_remove,
        stage=interrupted_stage,
    )

    with pytest.raises(error_type):
        asyncio.run(upgrade.rehydrate_app(object(), _payload()))  # type: ignore[arg-type]

    assert send_calls == 0
    assert staged_path.startswith("/PublicStaging/ios-rehydrate/")
    assert removed == [(staged_path, True)]


def test_rm_false_before_send_surfaces_cleanup_failure_without_retry_or_identifiers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    staged_path = ""
    removed: list[tuple[str, bool]] = []

    async def fake_inspect(lockdown: object, bundle_identifier: str) -> AppSnapshot:
        return _snapshot(AppState.PLACEHOLDER, placeholder=True)

    async def failing_stage(path: str, data: bytes) -> None:
        nonlocal staged_path
        staged_path = path
        raise RuntimeError("synthetic staging failure")

    async def forbidden_send(
        command: str,
        options: dict[str, Any],
        handler: object,
        path: str,
    ) -> None:
        pytest.fail("send_package must not run after staging fails")

    async def failed_remove(path: str, force: bool) -> bool:
        removed.append((path, force))
        return False

    _patch_upgrade_services(
        monkeypatch,
        inspect=fake_inspect,
        send=forbidden_send,
        remove=failed_remove,
        stage=failing_stage,
    )

    with pytest.raises(RehydrateError) as error:
        asyncio.run(upgrade.rehydrate_app(object(), _payload()))  # type: ignore[arg-type]

    assert error.value.code is ExitCode.UPGRADE_FAILED
    assert error.value.reason == "STAGING_CLEANUP_UNCONFIRMED"
    assert removed == [(staged_path, True)]
    assert staged_path not in str(error.value)
    assert _BUNDLE_ID not in str(error.value)


def test_rm_false_after_success_preserves_postflight_truth_and_reports_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = _payload()
    inspections = iter(
        [
            _snapshot(AppState.PLACEHOLDER, placeholder=True),
            _snapshot(AppState.PLACEHOLDER, placeholder=True),
            _snapshot(AppState.INSTALLED, version=payload.version, build=payload.build),
        ]
    )
    sent_paths: list[str] = []
    removed: list[tuple[str, bool]] = []

    async def fake_inspect(lockdown: object, bundle_identifier: str) -> AppSnapshot:
        return next(inspections)

    async def fake_send(
        command: str,
        options: dict[str, Any],
        handler: object,
        path: str,
    ) -> None:
        assert command == "Upgrade"
        sent_paths.append(path)

    async def failed_remove(path: str, force: bool) -> bool:
        removed.append((path, force))
        return False

    _patch_upgrade_services(
        monkeypatch,
        inspect=fake_inspect,
        send=fake_send,
        remove=failed_remove,
    )

    evidence = asyncio.run(upgrade.rehydrate_app(object(), payload))  # type: ignore[arg-type]

    assert len(sent_paths) == 1
    assert removed == [(sent_paths[0], True)]
    assert evidence["operation"] == "Upgrade"
    assert evidence["after"]["state"] == AppState.INSTALLED.value
    assert evidence["cleanup"] == {"staging_removed": False}
    assert sent_paths[0] not in repr(evidence)
    assert _BUNDLE_ID not in repr(evidence)


def test_rm_false_after_send_failure_is_unknown_and_not_retried(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sent_paths: list[str] = []
    removed: list[tuple[str, bool]] = []

    async def fake_inspect(lockdown: object, bundle_identifier: str) -> AppSnapshot:
        return _snapshot(AppState.PLACEHOLDER, demoted=True)

    async def failing_send(
        command: str,
        options: dict[str, Any],
        handler: object,
        path: str,
    ) -> None:
        sent_paths.append(path)
        raise RuntimeError("synthetic indeterminate send failure")

    async def failed_remove(path: str, force: bool) -> bool:
        removed.append((path, force))
        return False

    _patch_upgrade_services(
        monkeypatch,
        inspect=fake_inspect,
        send=failing_send,
        remove=failed_remove,
    )

    with pytest.raises(OutcomeUnknownError) as error:
        asyncio.run(upgrade.rehydrate_app(object(), _payload()))  # type: ignore[arg-type]

    assert len(sent_paths) == 1
    assert removed == [(sent_paths[0], True)]
    assert "cleanup was not confirmed" in str(error.value)
    assert sent_paths[0] not in str(error.value)
    assert _BUNDLE_ID not in str(error.value)


def test_real_task_cancellation_after_send_waits_for_shielded_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    send_started: asyncio.Event
    cleanup_started: asyncio.Event
    cleanup_release: asyncio.Event
    sent_paths: list[str] = []
    removed: list[tuple[str, bool]] = []

    async def fake_inspect(lockdown: object, bundle_identifier: str) -> AppSnapshot:
        return _snapshot(AppState.PLACEHOLDER, demoted=True)

    async def hanging_send(
        command: str,
        options: dict[str, Any],
        handler: object,
        path: str,
    ) -> None:
        sent_paths.append(path)
        send_started.set()
        await asyncio.Event().wait()

    async def delayed_remove(path: str, force: bool) -> bool:
        removed.append((path, force))
        cleanup_started.set()
        await cleanup_release.wait()
        return True

    _patch_upgrade_services(
        monkeypatch,
        inspect=fake_inspect,
        send=hanging_send,
        remove=delayed_remove,
    )

    async def scenario() -> None:
        nonlocal send_started, cleanup_started, cleanup_release
        send_started = asyncio.Event()
        cleanup_started = asyncio.Event()
        cleanup_release = asyncio.Event()
        task = asyncio.create_task(upgrade.rehydrate_app(object(), _payload()))  # type: ignore[arg-type]

        await asyncio.wait_for(send_started.wait(), timeout=1)
        task.cancel()
        await asyncio.wait_for(cleanup_started.wait(), timeout=1)
        await asyncio.sleep(0)
        assert not task.done()
        cleanup_release.set()

        with pytest.raises(OutcomeUnknownError) as error:
            await task
        assert sent_paths[0] not in str(error.value)
        assert _BUNDLE_ID not in str(error.value)

    asyncio.run(scenario())

    assert len(sent_paths) == 1
    assert removed == [(sent_paths[0], True)]


def test_send_timeout_is_unknown_and_never_retries_send_or_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    send_calls = 0
    sent_path = ""
    removed: list[tuple[str, bool]] = []

    async def fake_inspect(lockdown: object, bundle_identifier: str) -> AppSnapshot:
        return _snapshot(AppState.PLACEHOLDER, placeholder=True)

    async def hanging_send(
        command: str,
        options: dict[str, Any],
        handler: object,
        path: str,
    ) -> None:
        nonlocal send_calls, sent_path
        send_calls += 1
        sent_path = path
        await asyncio.Event().wait()

    async def fake_remove(path: str, force: bool) -> bool:
        removed.append((path, force))
        return True

    _patch_upgrade_services(
        monkeypatch,
        inspect=fake_inspect,
        send=hanging_send,
        remove=fake_remove,
    )
    monkeypatch.setattr(upgrade, "_UPGRADE_SEND_TIMEOUT_SECONDS", 0.001)

    with pytest.raises(OutcomeUnknownError) as error:
        asyncio.run(upgrade.rehydrate_app(object(), _payload()))  # type: ignore[arg-type]

    assert send_calls == 1
    assert removed == [(sent_path, True)]
    assert sent_path not in str(error.value)
    assert _BUNDLE_ID not in str(error.value)


def test_each_postflight_inspection_is_timed_and_does_not_resend(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = _payload()
    inspect_calls = 0
    send_calls = 0
    removed: list[tuple[str, bool]] = []

    async def fake_inspect(lockdown: object, bundle_identifier: str) -> AppSnapshot:
        nonlocal inspect_calls
        inspect_calls += 1
        if inspect_calls <= 2:
            return _snapshot(AppState.PLACEHOLDER, demoted=True)
        if inspect_calls <= 4:
            return _snapshot(AppState.INSTALLED, version="stale", build="stale")
        await asyncio.Event().wait()
        raise AssertionError("unreachable")

    async def fake_send(
        command: str,
        options: dict[str, Any],
        handler: object,
        path: str,
    ) -> None:
        nonlocal send_calls
        send_calls += 1

    async def fake_remove(path: str, force: bool) -> bool:
        removed.append((path, force))
        return True

    _patch_upgrade_services(
        monkeypatch,
        inspect=fake_inspect,
        send=fake_send,
        remove=fake_remove,
    )
    monkeypatch.setattr(upgrade, "_POSTFLIGHT_DELAY_SECONDS", 0)
    monkeypatch.setattr(upgrade, "_POSTFLIGHT_INSPECT_TIMEOUT_SECONDS", 0.001)

    with pytest.raises(OutcomeUnknownError) as error:
        asyncio.run(upgrade.rehydrate_app(object(), payload))  # type: ignore[arg-type]

    assert inspect_calls == 5
    assert send_calls == 1
    assert len(removed) == 1
    assert removed[0][0] not in str(error.value)
    assert _BUNDLE_ID not in str(error.value)
