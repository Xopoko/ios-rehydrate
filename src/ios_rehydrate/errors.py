# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 iOS Rehydrate contributors
"""Stable public error types and exit codes."""

from __future__ import annotations

from enum import IntEnum


class ExitCode(IntEnum):
    OK = 0
    USAGE = 2
    DEVICE_SELECTION = 10
    DEVICE_UNAVAILABLE = 11
    BACKUP_CREATE = 20
    BACKUP_VERIFY = 21
    IPA_INVALID = 30
    POLICY_REFUSED = 40
    CONFIRMATION = 42
    UPGRADE_FAILED = 51
    OUTCOME_UNKNOWN = 52
    POSTCHECK_FAILED = 53
    DEPENDENCY = 70
    IO = 74


class RehydrateError(RuntimeError):
    """Expected failure safe to present without a traceback."""

    def __init__(self, message: str, *, code: ExitCode, reason: str) -> None:
        super().__init__(message)
        self.code = code
        self.reason = reason


class OutcomeUnknownError(RehydrateError):
    """The mutation boundary was crossed, but the final state is unknown."""

    def __init__(
        self,
        message: str = "upgrade outcome is unknown; inspect the device",
        *,
        staging_removed: bool | None = None,
    ) -> None:
        super().__init__(message, code=ExitCode.OUTCOME_UNKNOWN, reason="UPGRADE_OUTCOME_UNKNOWN")
        self.staging_removed = staging_removed
