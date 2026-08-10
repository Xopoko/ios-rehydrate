# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 iOS Rehydrate contributors
"""Fail closed when a repository contains material that must not be published."""

from __future__ import annotations

import argparse
import hashlib
import io
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import unicodedata
import zipfile
import zlib
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Final, Literal
from urllib.parse import unquote, unquote_plus, urlsplit

EXCLUDED_DIRECTORY_NAMES: Final = frozenset(
    {
        ".git",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".venv",
        "__pycache__",
        "build",
        "cache",
        "dist",
    }
)

# Binary images may only be admitted one path at a time after a deliberate review.
ALLOWED_BINARY_IMAGE_PATHS: Final[frozenset[str]] = frozenset()
IMAGE_EXTENSIONS: Final = frozenset({".gif", ".jpeg", ".jpg", ".png", ".webp"})
PUBLIC_URL_HOSTS: Final = frozenset(
    {"files.pythonhosted.org", "fsf.org", "github.com", "pypi.org", "www.gnu.org"}
)
REGULAR_GIT_MODES: Final = frozenset({"100644", "100755"})
MAX_ARCHIVE_BYTES: Final = 512 * 1024 * 1024
MAX_ARCHIVE_MEMBER_BYTES: Final = 64 * 1024 * 1024
MAX_ARCHIVE_TOTAL_BYTES: Final = 256 * 1024 * 1024
MAX_ARCHIVE_MEMBERS: Final = 10_000
ARCHIVE_STREAM_CHUNK_BYTES: Final = 1024 * 1024
TAR_BLOCK_BYTES: Final = 512
TAR_RECORD_BYTES: Final = 20 * TAR_BLOCK_BYTES
MAX_TAR_STREAM_BYTES: Final = (
    MAX_ARCHIVE_TOTAL_BYTES + MAX_ARCHIVE_MEMBERS * 2 * TAR_BLOCK_BYTES + TAR_RECORD_BYTES
)
WINDOWS_REPARSE_ATTRIBUTE: Final = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)

FORBIDDEN_EXTENSIONS: Final = frozenset(
    {
        ".backup",
        ".bak",
        ".bkp",
        ".cer",
        ".cert",
        ".crt",
        ".csr",
        ".db",
        ".db-shm",
        ".db-wal",
        ".der",
        ".ipa",
        ".jks",
        ".jsonl",
        ".key",
        ".keystore",
        ".log",
        ".mobileprovision",
        ".ndjson",
        ".old",
        ".orig",
        ".p10",
        ".p12",
        ".p7b",
        ".p7c",
        ".p8",
        ".pem",
        ".pfx",
        ".plist",
        ".provisionprofile",
        ".pub",
        ".save",
        ".sqlite",
        ".sqlite-shm",
        ".sqlite-wal",
        ".sqlite3",
        ".swo",
        ".swp",
        ".tmp",
    }
)

WINDOWS_USER_PATH_RE: Final = re.compile(r"(?i)(?<![A-Za-z0-9])[A-Z]:[\\/]+Users[\\/]+[^\s\"'<>|]+")
UNC_PATH_RE: Final = re.compile(r"(?i)(?<![\\])\\{2,}[A-Za-z0-9._$-]+[\\/]+[A-Za-z0-9._$-]+")
UNIX_USER_PATH_RE: Final = re.compile(r"(?<![A-Za-z0-9_])/(?:Users|home)/[^\s\"'<>]+")
URL_RE: Final = re.compile(r"(?i)(?<![A-Z0-9+.-])[A-Z][A-Z0-9+.-]*://[^\s\"'<>]+")
EMAIL_RE: Final = re.compile(
    r"(?i)(?<![A-Z0-9.!#$%&'*+/=?^_`{|}~-])"
    r"[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?(?:\."
    r"[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?)+"
)
GITHUB_TOKEN_RE: Final = re.compile(r"\b(?:github_pat_|gh[pousr]_)[A-Za-z0-9_]{20,}\b")
APPLE_APP_PASSWORD_RE: Final = re.compile(r"(?i)\b[a-z]{4}(?:-[a-z]{4}){3}\b")
JWT_RE: Final = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
BEARER_TOKEN_RE: Final = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{20,}\b")
PREFIXED_TOKEN_RE: Final = re.compile(
    r"\b(?:AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{30,}|glpat-[0-9A-Za-z_-]{20,}|"
    r"sk-(?:live-|proj-)?[0-9A-Za-z_-]{20,}|xox[baprs]-[0-9A-Za-z-]{20,})\b"
)
TOKEN_ASSIGNMENT_RE: Final = re.compile(
    r"(?ix)"
    r"\b(?:api[_-]?(?:key|token)|access[_-]?token|auth[_-]?token|client[_-]?secret|"
    r"password|passwd|secret|token)\b"
    r"[\"']?\s*(?:=|:)\s*"
    r"(?P<quote>[\"']?)(?P<value>[A-Za-z0-9_./+=-]{16,})(?P=quote)"
    r"(?=\s*(?:[,;#]|$))"
)
LEGACY_DEVICE_ID_RE: Final = re.compile(r"(?i)(?<![0-9a-f])[0-9a-f]{40}(?![0-9a-f])")
MODERN_DEVICE_ID_RE: Final = re.compile(r"(?i)(?<![0-9a-f])[0-9a-f]{8}-[0-9a-f]{16}(?![0-9a-f])")
UUID_RE: Final = re.compile(
    r"(?i)(?<![0-9a-f])[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}(?![0-9a-f])"
)
PEM_PRIVATE_KEY_RE: Final = re.compile(
    r"-----BEGIN (?:EC |RSA |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"
)
UV_REVISION_LINE_RE: Final = re.compile(r'^\s*(?:commit|rev|revision)\s*=\s*"[0-9a-fA-F]{40}"\s*$')
WINDOWS_DRIVE_RE: Final = re.compile(r"^[A-Za-z]:")
GITHUB_REVISION_SEGMENT_RE: Final = re.compile(r"[0-9a-fA-F]{40}")

PLACEHOLDER_MARKERS: Final = (
    "changeme",
    "dummy",
    "example",
    "fake",
    "insert_here",
    "not-a-real",
    "not_real",
    "placeholder",
    "redacted",
    "replace_me",
    "sample",
    "test-token",
    "test_token",
    "your_",
)


@dataclass(frozen=True, order=True)
class Finding:
    """A location-only report; matched material is intentionally not retained."""

    path: str
    line: int
    category: str


@dataclass(frozen=True)
class WorkspaceEntry:
    """An lstat-classified workspace entry that has not been followed."""

    path: Path
    kind: str


@dataclass(frozen=True)
class IndexEntry:
    """A path and exact object identity read from the Git index."""

    path: str
    mode: str
    object_id: str
    stage: int


class ScanError(Exception):
    """Raised for an operational failure that makes a complete scan impossible."""


def _parse_arguments(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Scan a repository for private or unsafe-to-publish material."
    )
    parser.add_argument("root", nargs="?", default=".", help="repository root (default: .)")
    parser.add_argument(
        "--denylist",
        type=Path,
        help="newline-delimited exact private values; the file must be outside the scan root",
    )
    source = parser.add_mutually_exclusive_group()
    source.add_argument(
        "--git-index",
        action="store_true",
        help="scan exact staged blobs and modes, including normally excluded paths",
    )
    source.add_argument(
        "--archive",
        type=Path,
        help="scan a wheel or source-distribution archive without extracting it",
    )
    return parser.parse_args(argv)


def _is_within(path: Path, directory: Path) -> bool:
    try:
        path.relative_to(directory)
    except ValueError:
        return False
    return True


def _link_category(file_stat: os.stat_result) -> str | None:
    if stat.S_ISLNK(file_stat.st_mode):
        return "symlink"
    attributes = getattr(file_stat, "st_file_attributes", 0)
    if attributes & WINDOWS_REPARSE_ATTRIBUTE:
        return "reparse-point"
    return None


def _normal_private_text(value: str) -> str:
    return unicodedata.normalize("NFC", value).casefold()


def _load_denylist(path: Path | None, root: Path) -> tuple[str, ...]:
    if path is None:
        return ()

    unresolved = Path(os.path.abspath(path.expanduser()))
    try:
        file_stat = os.lstat(unresolved)
    except OSError as error:
        raise ScanError("denylist is not a readable regular file") from error
    if _link_category(file_stat) is not None or not stat.S_ISREG(file_stat.st_mode):
        raise ScanError("denylist is not a readable regular file")

    try:
        resolved = unresolved.resolve(strict=True)
    except OSError as error:
        raise ScanError("denylist is not a readable regular file") from error
    if _is_within(resolved, root):
        raise ScanError("denylist must be outside the scan root")

    try:
        text = _read_regular_file(resolved).decode("utf-8-sig")
    except (OSError, UnicodeError) as error:
        raise ScanError("denylist must be readable UTF-8 text") from error

    # Values stay normalized in memory and are never included in findings or diagnostics.
    values = (_normal_private_text(line) for line in text.splitlines() if line)
    return tuple(dict.fromkeys(values))


def _is_forbidden_extension(path: str) -> bool:
    name = path.rsplit("/", maxsplit=1)[-1].casefold()
    return name.endswith("~") or any(name.endswith(extension) for extension in FORBIDDEN_EXTENSIONS)


def _is_binary(data: bytes) -> bool:
    if not data:
        return False
    if b"\x00" in data:
        return True
    try:
        data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return True

    disallowed_controls = sum(byte < 32 and byte not in {8, 9, 10, 12, 13} for byte in data[:8192])
    return disallowed_controls / min(len(data), 8192) > 0.05


def _looks_like_secret(value: str) -> bool:
    lowered = value.casefold()
    if any(marker in lowered for marker in PLACEHOLDER_MARKERS):
        return False
    if len(set(value)) < 8:
        return False
    has_letter = any(character.isalpha() for character in value)
    has_digit = any(character.isdigit() for character in value)
    has_token_punctuation = any(character in "_./+=-" for character in value)
    return has_letter and (has_digit or has_token_punctuation)


def _contains_legacy_device_id(line: str) -> bool:
    return any(
        match.start() == 0 or line[match.start() - 1] != "@"
        for match in LEGACY_DEVICE_ID_RE.finditer(line)
    )


def _github_path_for_identity_scan(path: str, hostname: str | None) -> str:
    if hostname is None or hostname.casefold() != "github.com":
        return path
    segments = path.split("/")
    if (
        len(segments) >= 5
        and not segments[0]
        and segments[1]
        and segments[2]
        and segments[3].casefold() in {"blob", "commit", "tree"}
        and GITHUB_REVISION_SEGMENT_RE.fullmatch(segments[4]) is not None
    ):
        segments[4] = " " * len(segments[4])
    return "/".join(segments)


def _url_categories_and_inspected_line(line: str) -> tuple[set[str], str]:
    categories: set[str] = set()
    pieces: list[str] = []
    position = 0

    for match in URL_RE.finditer(line):
        pieces.append(line[position : match.start()])
        position = match.end()
        matched_url = match.group(0)
        parsed_url = matched_url.rstrip(".,;:!?)]}")
        trailing_punctuation = matched_url[len(parsed_url) :]
        try:
            parsed = urlsplit(parsed_url)
            hostname = parsed.hostname
            has_userinfo = parsed.username is not None or parsed.password is not None
            path = _github_path_for_identity_scan(unquote(parsed.path), hostname)
            inspected_components: tuple[str, ...] = (
                path,
                unquote_plus(parsed.query),
                unquote(parsed.fragment),
            )
        except ValueError:
            hostname = None
            has_userinfo = "@" in parsed_url
            inspected_components = (parsed_url,)
        if has_userinfo:
            categories.add("url-userinfo")
        if hostname is None or hostname.casefold() not in PUBLIC_URL_HOSTS:
            categories.add("url-host-not-allowlisted")
        pieces.append(" ")
        pieces.append(" ".join(component for component in inspected_components if component))
        pieces.append(trailing_punctuation)
        pieces.append(" ")

    pieces.append(line[position:])
    return categories, "".join(pieces)


def _line_categories(
    line: str,
    *,
    allow_uv_revision: bool,
    denylist: tuple[str, ...],
) -> set[str]:
    categories, inspected_line = _url_categories_and_inspected_line(line)

    if WINDOWS_USER_PATH_RE.search(inspected_line):
        categories.add("windows-user-path")
    if UNC_PATH_RE.search(inspected_line):
        categories.add("unc-path")
    if UNIX_USER_PATH_RE.search(inspected_line):
        categories.add("unix-user-path")
    if EMAIL_RE.search(inspected_line):
        categories.add("email-address")

    inspected_values = (line, inspected_line)
    if (
        any(GITHUB_TOKEN_RE.search(value) for value in inspected_values)
        or any(APPLE_APP_PASSWORD_RE.search(value) for value in inspected_values)
        or any(JWT_RE.search(value) for value in inspected_values)
        or any(BEARER_TOKEN_RE.search(value) for value in inspected_values)
        or any(PREFIXED_TOKEN_RE.search(value) for value in inspected_values)
        or any(
            _looks_like_secret(match.group("value"))
            for value in inspected_values
            for match in TOKEN_ASSIGNMENT_RE.finditer(value)
        )
    ):
        categories.add("token-secret")

    is_exact_uv_revision = allow_uv_revision and UV_REVISION_LINE_RE.fullmatch(line) is not None
    if not is_exact_uv_revision and _contains_legacy_device_id(inspected_line):
        categories.add("legacy-device-id")
    if MODERN_DEVICE_ID_RE.search(inspected_line):
        categories.add("modern-device-id")
    if UUID_RE.search(inspected_line):
        categories.add("uuid")
    if any(PEM_PRIVATE_KEY_RE.search(value) for value in inspected_values):
        categories.add("pem-private-key")
    normalized_values = (_normal_private_text(value) for value in inspected_values)
    if any(private in normalized for normalized in normalized_values for private in denylist):
        categories.add("private-denylist")

    return categories


def _display_path(path: str) -> str:
    escaped: list[str] = []
    named_controls = {"\0": r"\0", "\t": r"\t", "\n": r"\n", "\r": r"\r"}
    for character in path:
        if character in named_controls:
            escaped.append(named_controls[character])
        elif character.isprintable():
            escaped.append(character)
        else:
            codepoint = ord(character)
            width = 4 if codepoint <= 0xFFFF else 8
            escaped.append(f"\\u{codepoint:0{width}x}")
    return "".join(escaped)


def _redacted_path_reference(path: str) -> str:
    digest = hashlib.sha256(path.encode("utf-8", errors="surrogatepass")).hexdigest()[:16]
    return f"<redacted-path:{digest}>"


def _add_categories(
    findings: list[Finding], displayed_path: str, line: int, categories: set[str]
) -> None:
    findings.extend(Finding(displayed_path, line, category) for category in categories)


def _scan_path(findings: list[Finding], path: str, denylist: tuple[str, ...]) -> str:
    categories = _line_categories(path, allow_uv_revision=False, denylist=denylist)
    displayed = _redacted_path_reference(path) if categories else _display_path(path)
    _add_categories(findings, displayed, 1, categories)
    return displayed


def _scan_file_data(
    findings: list[Finding],
    path: str,
    displayed_path: str,
    data: bytes,
    denylist: tuple[str, ...],
) -> None:
    if _is_forbidden_extension(path):
        findings.append(Finding(displayed_path, 1, "forbidden-extension"))
        return

    if _is_binary(data):
        suffix = Path(path).suffix.casefold()
        is_allowed_image = path in ALLOWED_BINARY_IMAGE_PATHS and suffix in IMAGE_EXTENSIONS
        if not is_allowed_image:
            findings.append(Finding(displayed_path, 1, "binary-content"))
        return

    text = data.decode("utf-8-sig")
    allow_uv_revision = path.rsplit("/", maxsplit=1)[-1].casefold() == "uv.lock"
    for line_number, line in enumerate(text.splitlines(), start=1):
        _add_categories(
            findings,
            displayed_path,
            line_number,
            _line_categories(
                line,
                allow_uv_revision=allow_uv_revision,
                denylist=denylist,
            ),
        )


def _file_identity(file_stat: os.stat_result) -> tuple[int, int]:
    return file_stat.st_dev, file_stat.st_ino


def _read_stream(stream: IO[bytes], *, limit: int | None = None) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while chunk := stream.read(1024 * 1024):
        total += len(chunk)
        if limit is not None and total > limit:
            raise ScanError("file exceeds the safe scan size limit")
        chunks.append(chunk)
    return b"".join(chunks)


def _read_regular_file(path: Path, *, limit: int | None = None) -> bytes:
    try:
        before = os.lstat(path)
        if _link_category(before) is not None or not stat.S_ISREG(before.st_mode):
            raise ScanError("refusing to read a non-regular file")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode) or _file_identity(opened) != _file_identity(before):
                raise ScanError("file changed while it was being opened")
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                data = _read_stream(stream, limit=limit)
        finally:
            os.close(descriptor)
        after = os.lstat(path)
    except ScanError:
        raise
    except OSError as error:
        raise ScanError("unable to read a regular file") from error

    if _link_category(after) is not None or _file_identity(after) != _file_identity(before):
        raise ScanError("file changed while it was being read")
    return data


def _iter_workspace_entries(root: Path) -> list[WorkspaceEntry]:
    entries: list[WorkspaceEntry] = []

    def visit(directory: Path) -> None:
        try:
            with os.scandir(directory) as iterator:
                children = sorted(iterator, key=lambda entry: (entry.name.casefold(), entry.name))
        except OSError as error:
            raise ScanError("unable to traverse the scan root") from error

        for child in children:
            path = Path(child.path)
            try:
                child_stat = child.stat(follow_symlinks=False)
            except OSError as error:
                raise ScanError("unable to inspect a repository entry") from error
            link_category = _link_category(child_stat)
            if link_category is not None:
                entries.append(WorkspaceEntry(path, link_category))
                continue
            if child.name.casefold() == ".git":
                continue
            if stat.S_ISDIR(child_stat.st_mode):
                if child.name.casefold() in EXCLUDED_DIRECTORY_NAMES:
                    continue
                entries.append(WorkspaceEntry(path, "directory"))
                visit(path)
                continue
            if stat.S_ISREG(child_stat.st_mode):
                entries.append(WorkspaceEntry(path, "file"))
                continue
            entries.append(WorkspaceEntry(path, "special-file"))

    visit(root)
    return entries


def scan_repository(root: Path, denylist: tuple[str, ...]) -> list[Finding]:
    findings: list[Finding] = []

    for entry in _iter_workspace_entries(root):
        relative = entry.path.relative_to(root).as_posix()
        displayed = _scan_path(findings, relative, denylist)
        if entry.kind != "file":
            if entry.kind != "directory":
                findings.append(Finding(displayed, 1, entry.kind))
            continue
        try:
            data = _read_regular_file(entry.path)
        except ScanError as error:
            raise ScanError(f"unable to read repository file: {displayed}") from error
        _scan_file_data(findings, relative, displayed, data, denylist)

    return sorted(set(findings))


def _git_environment() -> dict[str, str]:
    environment = dict(os.environ)
    for name in (
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_COMMON_DIR",
        "GIT_DIR",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_WORK_TREE",
    ):
        environment.pop(name, None)
    environment["GIT_NO_LAZY_FETCH"] = "1"
    environment["GIT_OPTIONAL_LOCKS"] = "0"
    return environment


def _run_git(root: Path, arguments: Sequence[str], *, input_data: bytes | None = None) -> bytes:
    executable = shutil.which("git")
    if executable is None:
        raise ScanError("unable to inspect the Git index")
    try:
        result = subprocess.run(  # noqa: S603
            [executable, "-C", str(root), "--no-replace-objects", *arguments],
            check=False,
            input=input_data,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=_git_environment(),
        )
    except OSError as error:
        raise ScanError("unable to inspect the Git index") from error
    if result.returncode != 0:
        raise ScanError("unable to inspect the Git index")
    return result.stdout


def _read_index_entries(root: Path) -> list[IndexEntry]:
    output = _run_git(root, ["ls-files", "--stage", "-z"])
    entries: list[IndexEntry] = []
    try:
        for record in output.split(b"\0"):
            if not record:
                continue
            metadata, encoded_path = record.split(b"\t", maxsplit=1)
            encoded_mode, encoded_object_id, encoded_stage = metadata.split()
            entries.append(
                IndexEntry(
                    encoded_path.decode("utf-8"),
                    encoded_mode.decode("ascii"),
                    encoded_object_id.decode("ascii"),
                    int(encoded_stage),
                )
            )
    except (UnicodeError, ValueError) as error:
        raise ScanError("Git index contains an unsupported entry") from error
    return entries


def _read_index_blobs(root: Path, object_ids: Sequence[str]) -> dict[str, bytes]:
    unique_object_ids = list(dict.fromkeys(object_ids))
    if not unique_object_ids:
        return {}
    request = b"".join(object_id.encode("ascii") + b"\n" for object_id in unique_object_ids)
    output = _run_git(root, ["cat-file", "--batch"], input_data=request)
    blobs: dict[str, bytes] = {}
    position = 0
    try:
        for requested_id in unique_object_ids:
            header_end = output.index(b"\n", position)
            header = output[position:header_end].split()
            if len(header) != 3 or header[1] != b"blob":
                raise ValueError
            object_id = header[0].decode("ascii")
            size = int(header[2])
            data_start = header_end + 1
            data_end = data_start + size
            if data_end >= len(output) or output[data_end : data_end + 1] != b"\n":
                raise ValueError
            if object_id != requested_id:
                raise ValueError
            blobs[requested_id] = output[data_start:data_end]
            position = data_end + 1
        if position != len(output):
            raise ValueError
    except (UnicodeError, ValueError) as error:
        raise ScanError("unable to read exact Git index blobs") from error
    return blobs


def scan_git_index(root: Path, denylist: tuple[str, ...]) -> list[Finding]:
    entries = _read_index_entries(root)
    blobs = _read_index_blobs(
        root,
        [
            entry.object_id
            for entry in entries
            if entry.stage == 0 and entry.mode in REGULAR_GIT_MODES
        ],
    )
    findings: list[Finding] = []

    for entry in entries:
        displayed = _scan_path(findings, entry.path, denylist)
        if entry.stage != 0:
            findings.append(Finding(displayed, 1, "unmerged-index"))
        elif entry.mode == "120000":
            findings.append(Finding(displayed, 1, "symlink"))
        elif entry.mode == "160000":
            findings.append(Finding(displayed, 1, "submodule"))
        elif entry.mode not in REGULAR_GIT_MODES:
            findings.append(Finding(displayed, 1, "unsupported-git-mode"))
        else:
            _scan_file_data(findings, entry.path, displayed, blobs[entry.object_id], denylist)

    return sorted(set(findings))


def _unsafe_archive_member_name(name: str) -> bool:
    trimmed = name[:-1] if name.endswith("/") else name
    if not trimmed or "\0" in name or name.startswith(("/", "\\")):
        return True
    if "\\" in name or WINDOWS_DRIVE_RE.match(name):
        return True
    parts = trimmed.split("/")
    return any(
        part in {"", ".", ".."} or ":" in part or part.endswith((" ", ".")) for part in parts
    )


def _register_archive_member(
    findings: list[Finding],
    name: str,
    denylist: tuple[str, ...],
    seen_names: set[str],
) -> str:
    displayed = _scan_path(findings, name, denylist)
    if _unsafe_archive_member_name(name):
        findings.append(Finding(displayed, 1, "unsafe-archive-path"))
    normalized_name = _normal_private_text(name.removesuffix("/"))
    if normalized_name in seen_names:
        findings.append(Finding(displayed, 1, "archive-path-collision"))
    seen_names.add(normalized_name)
    return displayed


def _scan_zip_archive(
    archive_data: bytes,
    denylist: tuple[str, ...],
    archive_displayed: str,
) -> list[Finding]:
    findings: list[Finding] = []
    seen_names: set[str] = set()
    total_size = 0
    try:
        with zipfile.ZipFile(io.BytesIO(archive_data)) as archive:
            if archive.comment:
                findings.append(Finding(archive_displayed, 1, "archive-comment"))
            members = archive.infolist()
            if len(members) > MAX_ARCHIVE_MEMBERS:
                return [Finding(archive_displayed, 1, "archive-too-many-members")]
            for member in members:
                name = member.filename
                displayed = _register_archive_member(findings, name, denylist, seen_names)
                if member.comment:
                    findings.append(Finding(displayed, 1, "archive-member-comment"))
                if member.extra:
                    findings.append(Finding(displayed, 1, "archive-member-extra"))
                unix_mode = member.external_attr >> 16
                if stat.S_ISLNK(unix_mode):
                    findings.append(Finding(displayed, 1, "archive-link"))
                    continue
                if member.is_dir():
                    continue
                file_type = stat.S_IFMT(unix_mode)
                if file_type not in {0, stat.S_IFREG}:
                    findings.append(Finding(displayed, 1, "archive-special-file"))
                    continue
                if member.flag_bits & 0x1:
                    findings.append(Finding(displayed, 1, "archive-encrypted"))
                    continue
                total_size += member.file_size
                if member.file_size > MAX_ARCHIVE_MEMBER_BYTES:
                    findings.append(Finding(displayed, 1, "archive-member-too-large"))
                    continue
                if total_size > MAX_ARCHIVE_TOTAL_BYTES:
                    findings.append(Finding(displayed, 1, "archive-total-too-large"))
                    continue
                with archive.open(member) as stream:
                    data = _read_stream(stream, limit=MAX_ARCHIVE_MEMBER_BYTES)
                _scan_file_data(findings, name, displayed, data, denylist)
    except (OSError, RuntimeError, ScanError, zipfile.BadZipFile) as error:
        raise ScanError("unable to safely read ZIP archive") from error
    return findings


def _scan_tar_metadata(
    findings: list[Finding],
    member: tarfile.TarInfo,
    displayed: str,
    denylist: tuple[str, ...],
) -> None:
    if member.uname or member.gname or member.uid != 0 or member.gid != 0:
        findings.append(Finding(displayed, 1, "archive-tar-identity-metadata"))
    metadata = (
        member.linkname,
        member.uname,
        member.gname,
        *member.pax_headers.keys(),
        *member.pax_headers.values(),
    )
    for value in metadata:
        if value:
            _add_categories(
                findings,
                displayed,
                1,
                _line_categories(value, allow_uv_revision=False, denylist=denylist),
            )


def _scan_tar_archive(
    archive_data: bytes | bytearray,
    denylist: tuple[str, ...],
    archive_displayed: str,
    *,
    mode: Literal["r:*", "r:"] = "r:*",
) -> list[Finding]:
    findings: list[Finding] = []
    seen_names: set[str] = set()
    total_size = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(archive_data), mode=mode) as archive:
            for member_number, member in enumerate(archive, start=1):
                if member_number > MAX_ARCHIVE_MEMBERS:
                    findings.append(Finding(archive_displayed, 1, "archive-too-many-members"))
                    break
                displayed = _register_archive_member(findings, member.name, denylist, seen_names)
                _scan_tar_metadata(findings, member, displayed, denylist)
                if member.issym() or member.islnk():
                    findings.append(Finding(displayed, 1, "archive-link"))
                    continue
                if member.isdir():
                    continue
                if not member.isfile():
                    findings.append(Finding(displayed, 1, "archive-special-file"))
                    continue
                total_size += member.size
                if member.size > MAX_ARCHIVE_MEMBER_BYTES:
                    findings.append(Finding(displayed, 1, "archive-member-too-large"))
                    continue
                if total_size > MAX_ARCHIVE_TOTAL_BYTES:
                    findings.append(Finding(displayed, 1, "archive-total-too-large"))
                    continue
                stream = archive.extractfile(member)
                if stream is None:
                    raise ScanError("unable to read archive member")
                with stream:
                    data = _read_stream(stream, limit=MAX_ARCHIVE_MEMBER_BYTES)
                _scan_file_data(findings, member.name, displayed, data, denylist)
    except (OSError, ScanError, tarfile.TarError) as error:
        raise ScanError("unable to safely read tar archive") from error
    return findings


def _gzip_wrapper_findings(archive_data: bytes, archive_displayed: str) -> list[Finding]:
    if len(archive_data) < 10 or archive_data[:3] != b"\x1f\x8b\x08":
        return []
    if archive_data[3] & 0x1E:
        return [Finding(archive_displayed, 1, "archive-gzip-metadata")]
    return []


def _decompress_gzip_archive(
    archive_data: bytes, archive_displayed: str
) -> tuple[bytearray | None, list[Finding]]:
    framing_finding = Finding(archive_displayed, 1, "archive-gzip-framing")
    too_large_finding = Finding(archive_displayed, 1, "archive-gzip-too-large")
    decompressor = zlib.decompressobj(wbits=zlib.MAX_WBITS | 16)
    output = bytearray()
    position = 0

    try:
        while position < len(archive_data):
            if decompressor.eof:
                return output, [framing_finding]
            compressed = archive_data[position : position + ARCHIVE_STREAM_CHUNK_BYTES]
            position += len(compressed)
            while compressed:
                remaining = MAX_TAR_STREAM_BYTES - len(output)
                produced = decompressor.decompress(
                    compressed,
                    min(ARCHIVE_STREAM_CHUNK_BYTES, remaining + 1),
                )
                if len(produced) > remaining:
                    return None, [too_large_finding]
                output.extend(produced)
                if decompressor.unused_data:
                    return output, [framing_finding]
                compressed = decompressor.unconsumed_tail
        if not decompressor.eof or decompressor.unused_data or decompressor.unconsumed_tail:
            return None, [framing_finding]
    except zlib.error:
        return None, [framing_finding]

    return output, []


def _tar_framing_findings(archive_data: bytes | bytearray, archive_displayed: str) -> list[Finding]:
    framing_finding = Finding(archive_displayed, 1, "archive-tar-framing")
    if not archive_data or len(archive_data) % TAR_RECORD_BYTES != 0:
        return [framing_finding]

    view = memoryview(archive_data)
    offset = 0
    header_count = 0
    while offset + TAR_BLOCK_BYTES <= len(view):
        header = view[offset : offset + TAR_BLOCK_BYTES]
        if not any(header):
            tail_start = offset + 2 * TAR_BLOCK_BYTES
            if tail_start > len(view):
                return [framing_finding]
            if any(view[offset + TAR_BLOCK_BYTES : tail_start]) or any(view[tail_start:]):
                return [framing_finding]
            return []

        header_count += 1
        if header_count > MAX_ARCHIVE_MEMBERS:
            return [Finding(archive_displayed, 1, "archive-too-many-members")]
        try:
            member = tarfile.TarInfo.frombuf(bytes(header), "utf-8", "surrogateescape")
        except tarfile.HeaderError:
            return [framing_finding]
        if member.size < 0:
            return [framing_finding]
        data_end = offset + TAR_BLOCK_BYTES + member.size
        padded_end = (data_end + TAR_BLOCK_BYTES - 1) // TAR_BLOCK_BYTES * TAR_BLOCK_BYTES
        if padded_end > len(view) or any(view[data_end:padded_end]):
            return [framing_finding]
        offset = padded_end

    return [framing_finding]


def scan_archive(path: Path, denylist: tuple[str, ...]) -> list[Finding]:
    archive_name = path.name
    findings: list[Finding] = []
    displayed = _scan_path(findings, archive_name, denylist)
    try:
        archive_stat = os.lstat(path)
    except OSError as error:
        raise ScanError("archive does not exist or is not accessible") from error
    link_category = _link_category(archive_stat)
    if link_category is not None:
        findings.append(Finding(displayed, 1, link_category))
        return sorted(set(findings))
    if not stat.S_ISREG(archive_stat.st_mode):
        findings.append(Finding(displayed, 1, "special-file"))
        return sorted(set(findings))

    lower_name = archive_name.casefold()
    archive_data = _read_regular_file(path, limit=MAX_ARCHIVE_BYTES)
    if lower_name.endswith((".whl", ".zip")):
        findings.extend(_scan_zip_archive(archive_data, denylist, displayed))
    elif lower_name.endswith((".tar.gz", ".tar.bz2", ".tar.xz", ".tgz")):
        if lower_name.endswith((".tar.gz", ".tgz")):
            findings.extend(_gzip_wrapper_findings(archive_data, displayed))
            tar_data, gzip_findings = _decompress_gzip_archive(archive_data, displayed)
            findings.extend(gzip_findings)
            if tar_data is not None:
                tar_findings = _tar_framing_findings(tar_data, displayed)
                findings.extend(tar_findings)
                if not tar_findings:
                    findings.extend(_scan_tar_archive(tar_data, denylist, displayed, mode="r:"))
        else:
            findings.extend(_scan_tar_archive(archive_data, denylist, displayed))
    else:
        raise ScanError("archive must be a wheel or source distribution")
    return sorted(set(findings))


def _resolve_root(value: str) -> Path:
    unresolved = Path(os.path.abspath(Path(value).expanduser()))
    try:
        root_stat = os.lstat(unresolved)
    except OSError as error:
        raise ScanError("scan root does not exist or is not accessible") from error
    if _link_category(root_stat) is not None:
        raise ScanError("scan root must not be a link or reparse point")
    if not stat.S_ISDIR(root_stat.st_mode):
        raise ScanError("scan root must be a directory")
    try:
        return unresolved.resolve(strict=True)
    except OSError as error:
        raise ScanError("scan root does not exist or is not accessible") from error


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parse_arguments(argv)
    try:
        root = _resolve_root(arguments.root)
        denylist = _load_denylist(arguments.denylist, root)
        if arguments.git_index:
            findings = scan_git_index(root, denylist)
        elif arguments.archive is not None:
            archive = Path(os.path.abspath(arguments.archive.expanduser()))
            findings = scan_archive(archive, denylist)
        else:
            findings = scan_repository(root, denylist)
    except (OSError, ScanError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    for finding in findings:
        print(f"{finding.category}\t{finding.path}\t{finding.line}")
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
