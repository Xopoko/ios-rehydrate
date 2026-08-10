# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 iOS Rehydrate contributors
"""Privacy-preserving identifiers and defensive error rendering."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

_QUOTED_WINDOWS_PATH = re.compile(r"(?i)(?P<quote>[\"'`])(?:[a-z]:[\\/]|\\\\).*?(?P=quote)")
_QUOTED_POSIX_HOME = re.compile(r"(?P<quote>[\"'`])/(?:Users|home)/.*?(?P=quote)")
_WINDOWS_PATH_TO_END = re.compile(r"(?i)(?:[a-z]:[\\/]|\\\\).*$")
_POSIX_HOME_TO_END = re.compile(r"/(?:Users|home)/.*$")
_EMAIL = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
_MODERN_UDID = re.compile(r"\b[0-9A-F]{8}-[0-9A-F]{16}\b", re.IGNORECASE)
_LEGACY_UDID = re.compile(r"\b[0-9A-F]{40}\b", re.IGNORECASE)


def opaque_ref(value: str, *, namespace: str, length: int = 12) -> str:
    """Return a deterministic pseudonymous reference that omits the raw input."""
    digest = hashlib.sha256(f"ios-rehydrate:{namespace}:{value}".encode()).hexdigest()
    return f"{namespace}_{digest[:length]}"


def device_reference(value: str) -> str:
    """Return a casing-stable reference for a hexadecimal Apple device identifier."""
    return opaque_ref(value.casefold(), namespace="device")


def file_label(path: Path) -> str:
    """Return a path-free label suitable for normal output."""
    suffix = path.suffix.casefold()
    return f"local-file{suffix}" if suffix else "local-file"


def sanitize_text(value: object, *, limit: int = 240) -> str:
    """Remove common local identifiers from a bounded diagnostic."""
    text = " ".join(str(value).split())
    text = _QUOTED_WINDOWS_PATH.sub("<local-path>", text)
    text = _QUOTED_POSIX_HOME.sub("<local-path>", text)
    # An unquoted local path can legally contain spaces, so token-by-whitespace
    # matching is unsafe. Conservatively redact the rest of the bounded error.
    text = _WINDOWS_PATH_TO_END.sub("<local-path>", text)
    text = _POSIX_HOME_TO_END.sub("<local-path>", text)
    text = _EMAIL.sub("<email>", text)
    text = _MODERN_UDID.sub("<device-id>", text)
    text = _LEGACY_UDID.sub("<device-id>", text)
    return text[:limit]
