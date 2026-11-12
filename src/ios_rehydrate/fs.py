# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 iOS Rehydrate contributors
"""Filesystem checks shared by the backup, manifest, receipt, and IPA code."""

from __future__ import annotations

import os
import stat
from pathlib import Path

REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)

WINDOWS_RESERVED_NAMES = frozenset(
    {
        "CON",
        "PRN",
        "AUX",
        "NUL",
        "CLOCK$",
        "CONIN$",
        "CONOUT$",
        *(f"COM{suffix}" for suffix in "123456789¹²³"),
        *(f"LPT{suffix}" for suffix in "123456789¹²³"),
    }
)


def is_link_or_reparse(metadata: os.stat_result) -> bool:
    """True for a symlink or a Windows reparse point (junction, mount point, ...)."""
    attributes = getattr(metadata, "st_file_attributes", 0)
    return stat.S_ISLNK(metadata.st_mode) or bool(attributes & REPARSE_POINT)


def identity(metadata: os.stat_result) -> tuple[int, int]:
    return metadata.st_dev, metadata.st_ino


def has_safe_directory_chain(path: Path) -> bool:
    """True if every component of ``path``, from the anchor down, is a real directory."""
    try:
        absolute = Path(os.path.abspath(path))
        if not absolute.anchor:
            return False
        for directory in (*reversed(absolute.parents), absolute):
            metadata = os.lstat(directory)
            if not stat.S_ISDIR(metadata.st_mode) or is_link_or_reparse(metadata):
                return False
    except (OSError, ValueError):
        return False
    return True
