# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 iOS Rehydrate contributors
"""Validate built distributions before they are published.

The default gate is offline: it compares a wheel and source distribution with
the current worktree without extracting either archive.  ``--smoke-install``
adds isolated installation and source-tree smoke checks through ``uv``.
"""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import unicodedata
import zipfile
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from email import policy
from email.parser import BytesParser
from pathlib import Path
from typing import Final

from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.utils import (
    InvalidSdistFilename,
    InvalidWheelFilename,
    canonicalize_name,
    parse_sdist_filename,
    parse_wheel_filename,
)
from packaging.version import InvalidVersion, Version

MAX_ARCHIVE_BYTES: Final = 256 * 1024 * 1024
MAX_ARCHIVE_MEMBER_BYTES: Final = 32 * 1024 * 1024
MAX_ARCHIVE_TOTAL_BYTES: Final = 192 * 1024 * 1024
MAX_ARCHIVE_MEMBERS: Final = 10_000
MAX_MEMBER_NAME_CHARS: Final = 1_024
MAX_CAPTURE_BYTES: Final = 64 * 1024
MAX_WORKTREE_FILE_BYTES: Final = 32 * 1024 * 1024
SUBPROCESS_TIMEOUT_SECONDS: Final = 300
WINDOWS_REPARSE_ATTRIBUTE: Final = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
CANONICAL_GZIP_HEADER: Final = bytes.fromhex("1f8b08000011365e02ff")
CANONICAL_SDIST_MTIME: Final = 1_580_601_600
EXPECTED_WHEEL_CONTROL: Final = (
    b"Wheel-Version: 1.0\nGenerator: hatchling 1.32.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
)
EXPECTED_PROJECT_URLS: Final = (
    ("Homepage", "https://github.com/Xopoko/ios-rehydrate"),
    ("Repository", "https://github.com/Xopoko/ios-rehydrate"),
    ("Issues", "https://github.com/Xopoko/ios-rehydrate/issues"),
)

ROOT_SDIST_FILES: Final = (
    "pyproject.toml",
    ".gitignore",
    "uv.lock",
    "README.md",
    "LICENSE",
    "NOTICE.md",
    "PRIVACY.md",
    "SECURITY.md",
    "CONTRIBUTING.md",
)
REQUIRED_SDIST_TREES: Final = ("docs", "scripts", "experiments", "src", "tests")
IGNORED_WORKTREE_DIRECTORIES: Final = frozenset(
    {".mypy_cache", ".pytest_cache", ".ruff_cache", ".venv", "__pycache__"}
)
IGNORED_WORKTREE_SUFFIXES: Final = frozenset({".pyc", ".pyo"})
WINDOWS_DRIVE_RE: Final = re.compile(r"^[A-Za-z]:")
WINDOWS_RESERVED_NAMES: Final = frozenset(
    {
        "aux",
        "con",
        "nul",
        "prn",
        *(f"com{number}" for number in range(1, 10)),
        *(f"lpt{number}" for number in range(1, 10)),
    }
)


class DistributionError(Exception):
    """A bounded, public-safe reason that the release gate failed."""


@dataclass(frozen=True)
class ProjectMetadata:
    """Authoritative release identity read from ``pyproject.toml``."""

    name: str
    version_text: str
    version: Version
    summary: str
    project_urls: tuple[str, ...]
    description_content_type: str
    description: bytes
    license_expression: str
    license_files: tuple[str, ...]
    keywords_header: str
    classifiers: tuple[str, ...]
    requires_python: SpecifierSet
    requirements: tuple[str, ...]


@dataclass(frozen=True)
class WorktreeSnapshot:
    """Files and release identity expected in freshly built artifacts."""

    metadata: ProjectMetadata
    sdist_files: Mapping[str, bytes]
    wheel_package_files: Mapping[str, bytes]


@dataclass(frozen=True)
class ArchiveContents:
    """Validated regular files and explicit directories from an archive."""

    files: Mapping[str, bytes]
    directories: frozenset[str]


@dataclass(frozen=True)
class CheckedArtifacts:
    """The exact current wheel and sdist selected by the gate."""

    wheel: Path
    sdist: Path
    sdist_root: str
    sdist_contents: ArchiveContents


def _parse_arguments(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate the current wheel and source distribution before publication."
    )
    parser.add_argument("root", nargs="?", type=Path, default=Path("."))
    parser.add_argument(
        "--dist-dir",
        type=Path,
        help="artifact directory (default: ROOT/dist)",
    )
    parser.add_argument(
        "--smoke-install",
        action="store_true",
        help="install both artifacts and run isolated CLI/source smoke checks",
    )
    parser.add_argument(
        "--rebuild-compare",
        action="store_true",
        help="rebuild with the pinned local toolchain and require byte-identical artifacts",
    )
    return parser.parse_args(argv)


def _is_link_or_reparse(file_stat: os.stat_result) -> bool:
    return stat.S_ISLNK(file_stat.st_mode) or bool(
        getattr(file_stat, "st_file_attributes", 0) & WINDOWS_REPARSE_ATTRIBUTE
    )


def _file_identity(file_stat: os.stat_result) -> tuple[int, int]:
    return file_stat.st_dev, file_stat.st_ino


def _resolve_directory(path: Path, *, description: str) -> Path:
    unresolved = Path(os.path.abspath(path.expanduser()))
    try:
        file_stat = os.lstat(unresolved)
    except OSError as error:
        raise DistributionError(f"{description} is unavailable") from error
    if _is_link_or_reparse(file_stat) or not stat.S_ISDIR(file_stat.st_mode):
        raise DistributionError(f"{description} must be a real directory")
    try:
        return unresolved.resolve(strict=True)
    except OSError as error:
        raise DistributionError(f"{description} is unavailable") from error


def _read_regular_file(path: Path, *, limit: int, description: str) -> bytes:
    try:
        before = os.lstat(path)
        if _is_link_or_reparse(before) or not stat.S_ISREG(before.st_mode):
            raise DistributionError(f"{description} must be a regular file")
        if before.st_size < 0 or before.st_size > limit:
            raise DistributionError(f"{description} exceeds the size limit")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode) or _file_identity(opened) != _file_identity(before):
                raise DistributionError(f"{description} changed while opening")
            chunks: list[bytes] = []
            total = 0
            while chunk := os.read(descriptor, min(1024 * 1024, limit + 1 - total)):
                total += len(chunk)
                if total > limit:
                    raise DistributionError(f"{description} exceeds the size limit")
                chunks.append(chunk)
        finally:
            os.close(descriptor)
        after = os.lstat(path)
    except DistributionError:
        raise
    except OSError as error:
        raise DistributionError(f"{description} could not be read") from error

    if _is_link_or_reparse(after) or _file_identity(after) != _file_identity(before):
        raise DistributionError(f"{description} changed while reading")
    return b"".join(chunks)


def _load_project_metadata(pyproject_data: bytes, readme_data: bytes) -> ProjectMetadata:
    try:
        document = tomllib.loads(pyproject_data.decode("utf-8"))
        project = document["project"]
        if not isinstance(project, dict):
            raise TypeError
        name = project["name"]
        version_text = project["version"]
        summary = project["description"]
        readme = project["readme"]
        license_expression = project["license"]
        license_files = project["license-files"]
        keywords = project["keywords"]
        classifiers = project["classifiers"]
        requires_python_text = project["requires-python"]
        dependencies = project["dependencies"]
        project_urls = project["urls"]
        if not all(
            isinstance(value, str) and value
            for value in (name, version_text, summary, license_expression, requires_python_text)
        ):
            raise TypeError
        if readme != "README.md":
            raise TypeError
        if not isinstance(license_files, list) or not all(
            isinstance(value, str) and value for value in license_files
        ):
            raise TypeError
        if not isinstance(keywords, list) or not all(
            isinstance(value, str) and value and "," not in value for value in keywords
        ):
            raise TypeError
        if not isinstance(classifiers, list) or not all(
            isinstance(value, str) and value for value in classifiers
        ):
            raise TypeError
        if not isinstance(dependencies, list) or not all(
            isinstance(value, str) and value for value in dependencies
        ):
            raise TypeError
        if (
            not isinstance(project_urls, dict)
            or tuple(project_urls.items()) != EXPECTED_PROJECT_URLS
        ):
            raise TypeError
        expected_license_files = ("LICENSE", "NOTICE.md")
        if tuple(license_files) != expected_license_files:
            raise TypeError
        if len(set(keywords)) != len(keywords) or len(set(classifiers)) != len(classifiers):
            raise TypeError
        version = Version(version_text)
        requires_python = SpecifierSet(requires_python_text)
        requirements = tuple(sorted(str(Requirement(value)) for value in dependencies))
        if len(set(requirements)) != len(requirements):
            raise TypeError
    except (
        InvalidRequirement,
        InvalidSpecifier,
        InvalidVersion,
        KeyError,
        TypeError,
        UnicodeError,
        tomllib.TOMLDecodeError,
    ) as error:
        raise DistributionError("project release metadata is invalid") from error
    return ProjectMetadata(
        name,
        version_text,
        version,
        summary,
        tuple(f"{label}, {url}" for label, url in EXPECTED_PROJECT_URLS),
        "text/markdown",
        readme_data,
        license_expression,
        tuple(license_files),
        ",".join(sorted(keywords)),
        tuple(sorted(classifiers)),
        requires_python,
        requirements,
    )


def _collect_worktree_files(directory: Path, relative_root: str) -> dict[str, bytes]:
    try:
        root_stat = os.lstat(directory)
    except OSError as error:
        raise DistributionError("a required source tree is unavailable") from error
    if _is_link_or_reparse(root_stat) or not stat.S_ISDIR(root_stat.st_mode):
        raise DistributionError("a required source tree must be a real directory")

    collected: dict[str, bytes] = {}

    def visit(current: Path, relative: str) -> None:
        try:
            with os.scandir(current) as iterator:
                entries = sorted(iterator, key=lambda entry: (entry.name.casefold(), entry.name))
        except OSError as error:
            raise DistributionError("a required source tree could not be traversed") from error
        for entry in entries:
            child = Path(entry.path)
            child_relative = f"{relative}/{entry.name}"
            try:
                child_stat = entry.stat(follow_symlinks=False)
            except OSError as error:
                raise DistributionError("a required source entry could not be inspected") from error
            if _is_link_or_reparse(child_stat):
                raise DistributionError("a required source tree contains a link")
            if stat.S_ISDIR(child_stat.st_mode):
                if entry.name in IGNORED_WORKTREE_DIRECTORIES:
                    continue
                visit(child, child_relative)
            elif stat.S_ISREG(child_stat.st_mode):
                if child.suffix.casefold() in IGNORED_WORKTREE_SUFFIXES:
                    continue
                collected[child_relative] = _read_regular_file(
                    child,
                    limit=MAX_WORKTREE_FILE_BYTES,
                    description="a required source file",
                )
            else:
                raise DistributionError("a required source tree contains a special file")

    visit(directory, relative_root)
    if not collected:
        raise DistributionError("a required source tree is empty")
    return collected


def _snapshot_worktree(root: Path) -> WorktreeSnapshot:
    pyproject_data = _read_regular_file(
        root / "pyproject.toml",
        limit=MAX_WORKTREE_FILE_BYTES,
        description="pyproject.toml",
    )
    sdist_files: dict[str, bytes] = {"pyproject.toml": pyproject_data}
    for relative in ROOT_SDIST_FILES[1:]:
        sdist_files[relative] = _read_regular_file(
            root / Path(relative),
            limit=MAX_WORKTREE_FILE_BYTES,
            description="a required root file",
        )
    metadata = _load_project_metadata(pyproject_data, sdist_files["README.md"])
    for relative in REQUIRED_SDIST_TREES:
        sdist_files.update(_collect_worktree_files(root / relative, relative))

    source_package = _collect_worktree_files(root / "src" / "ios_rehydrate", "ios_rehydrate")
    return WorktreeSnapshot(metadata, sdist_files, source_package)


def _select_artifacts(dist_directory: Path, metadata: ProjectMetadata) -> tuple[Path, Path]:
    try:
        entries = list(dist_directory.iterdir())
    except OSError as error:
        raise DistributionError("artifact directory could not be listed") from error
    wheels = [entry for entry in entries if entry.name.casefold().endswith(".whl")]
    sdists = [entry for entry in entries if entry.name.casefold().endswith(".tar.gz")]
    unsupported = [
        entry
        for entry in entries
        if entry.name.casefold().endswith((".tar.bz2", ".tar.xz", ".tgz", ".zip"))
    ]
    if unsupported:
        raise DistributionError("artifact directory contains an unsupported distribution type")
    if len(wheels) != 1 or len(sdists) != 1:
        raise DistributionError("artifact directory must contain exactly one wheel and one sdist")

    wheel = wheels[0]
    sdist = sdists[0]
    try:
        wheel_name, wheel_version, _, _ = parse_wheel_filename(wheel.name)
        sdist_name, sdist_version = parse_sdist_filename(sdist.name)
    except (InvalidWheelFilename, InvalidSdistFilename) as error:
        raise DistributionError("distribution filename is invalid") from error
    expected_name = canonicalize_name(metadata.name)
    expected_distribution_name = expected_name.replace("-", "_")
    expected_wheel_filename = (
        f"{expected_distribution_name}-{metadata.version_text}-py3-none-any.whl"
    )
    expected_sdist_filename = f"{expected_distribution_name}-{metadata.version_text}.tar.gz"
    if (
        wheel_name != expected_name
        or sdist_name != expected_name
        or wheel_version != metadata.version
        or sdist_version != metadata.version
        or wheel.name != expected_wheel_filename
        or sdist.name != expected_sdist_filename
    ):
        raise DistributionError("distribution filename does not match current project metadata")
    return wheel, sdist


def _validated_member_name(name: str, *, is_directory: bool) -> tuple[str, str]:
    if not isinstance(name, str) or not name or len(name) > MAX_MEMBER_NAME_CHARS:
        raise DistributionError("archive contains an invalid member name")
    if any(ord(character) < 32 or ord(character) == 127 for character in name):
        raise DistributionError("archive contains an invalid member name")
    if "\\" in name or name.startswith("/") or WINDOWS_DRIVE_RE.match(name):
        raise DistributionError("archive contains an unsafe member path")
    trimmed = name[:-1] if name.endswith("/") else name
    if not trimmed or (name.endswith("/") and not is_directory):
        raise DistributionError("archive contains an invalid member name")
    parts = trimmed.split("/")
    for part in parts:
        normalized = unicodedata.normalize("NFC", part)
        reserved_stem = normalized.split(".", maxsplit=1)[0].casefold()
        if (
            not part
            or part in {".", ".."}
            or normalized != part
            or ":" in part
            or part.endswith((" ", "."))
            or reserved_stem in WINDOWS_RESERVED_NAMES
        ):
            raise DistributionError("archive contains an unsafe member path")
    normalized_name = "/".join(parts)
    return normalized_name, normalized_name.casefold()


def _register_member(
    name: str,
    *,
    is_directory: bool,
    seen: dict[str, bool],
) -> str:
    normalized_name, comparison_name = _validated_member_name(name, is_directory=is_directory)
    if comparison_name in seen:
        raise DistributionError("archive contains duplicate member paths")
    parts = comparison_name.split("/")
    for index in range(1, len(parts)):
        ancestor = "/".join(parts[:index])
        if seen.get(ancestor) is False:
            raise DistributionError("archive contains conflicting member paths")
    if not is_directory:
        prefix = comparison_name + "/"
        if any(existing.startswith(prefix) for existing in seen):
            raise DistributionError("archive contains conflicting member paths")
    seen[comparison_name] = is_directory
    return normalized_name


def _read_archive_stream(stream: object, *, declared_size: int) -> bytes:
    reader = getattr(stream, "read", None)
    if not callable(reader):
        raise DistributionError("archive member could not be read")
    data = reader(MAX_ARCHIVE_MEMBER_BYTES + 1)
    if not isinstance(data, bytes) or len(data) > MAX_ARCHIVE_MEMBER_BYTES:
        raise DistributionError("archive member exceeds the size limit")
    if len(data) != declared_size:
        raise DistributionError("archive member size is inconsistent")
    return data


def _inspect_wheel(path: Path) -> ArchiveContents:
    archive_data = _read_regular_file(path, limit=MAX_ARCHIVE_BYTES, description="wheel artifact")
    files: dict[str, bytes] = {}
    directories: set[str] = set()
    seen: dict[str, bool] = {}
    total_size = 0
    try:
        with zipfile.ZipFile(io.BytesIO(archive_data)) as archive:
            if archive.comment:
                raise DistributionError("wheel has an unexpected archive comment")
            members = archive.infolist()
            if not members or len(members) > MAX_ARCHIVE_MEMBERS:
                raise DistributionError("wheel has an invalid member count")
            for member in members:
                if member.comment:
                    raise DistributionError("wheel member has an unexpected comment")
                if member.extra:
                    raise DistributionError("wheel member has unexpected extra metadata")
                is_directory = member.is_dir()
                mode = (member.external_attr >> 16) & 0xFFFF
                file_type = stat.S_IFMT(mode)
                if member.flag_bits & 0x1:
                    raise DistributionError("wheel contains an encrypted member")
                if is_directory:
                    if file_type not in (0, stat.S_IFDIR):
                        raise DistributionError("wheel contains a special member")
                elif file_type not in (0, stat.S_IFREG):
                    raise DistributionError("wheel contains a special member")
                name = _register_member(member.filename, is_directory=is_directory, seen=seen)
                if is_directory:
                    directories.add(name)
                    continue
                if member.file_size < 0 or member.file_size > MAX_ARCHIVE_MEMBER_BYTES:
                    raise DistributionError("wheel member exceeds the size limit")
                total_size += member.file_size
                if total_size > MAX_ARCHIVE_TOTAL_BYTES:
                    raise DistributionError("wheel exceeds the expanded size limit")
                with archive.open(member, "r") as stream:
                    files[name] = _read_archive_stream(stream, declared_size=member.file_size)
    except DistributionError:
        raise
    except (
        EOFError,
        NotImplementedError,
        OSError,
        RuntimeError,
        ValueError,
        zipfile.BadZipFile,
    ) as error:
        raise DistributionError("wheel could not be safely inspected") from error
    return ArchiveContents(files, frozenset(directories))


def _inspect_sdist(path: Path) -> ArchiveContents:
    archive_data = _read_regular_file(path, limit=MAX_ARCHIVE_BYTES, description="sdist artifact")
    if not archive_data.startswith(CANONICAL_GZIP_HEADER):
        raise DistributionError("sdist gzip header does not match the canonical release format")
    files: dict[str, bytes] = {}
    directories: set[str] = set()
    seen: dict[str, bool] = {}
    total_size = 0
    member_count = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(archive_data), mode="r:gz") as archive:
            if archive.pax_headers:
                raise DistributionError("sdist has unexpected extended metadata")
            for member in archive:
                member_count += 1
                if member_count > MAX_ARCHIVE_MEMBERS:
                    raise DistributionError("sdist has too many members")
                if member.pax_headers:
                    raise DistributionError("sdist member has unexpected extended metadata")
                if member.isdir():
                    is_directory = True
                elif member.isfile() and not member.issparse():
                    is_directory = False
                else:
                    raise DistributionError("sdist contains a link or special member")
                if not is_directory and (
                    member.uid != 0
                    or member.gid != 0
                    or member.uname != ""
                    or member.gname != ""
                    or member.mode != 0o644
                    or member.mtime != CANONICAL_SDIST_MTIME
                ):
                    raise DistributionError("sdist member identity metadata is not canonical")
                name = _register_member(member.name, is_directory=is_directory, seen=seen)
                if is_directory:
                    directories.add(name)
                    continue
                if member.size < 0 or member.size > MAX_ARCHIVE_MEMBER_BYTES:
                    raise DistributionError("sdist member exceeds the size limit")
                total_size += member.size
                if total_size > MAX_ARCHIVE_TOTAL_BYTES:
                    raise DistributionError("sdist exceeds the expanded size limit")
                stream = archive.extractfile(member)
                if stream is None:
                    raise DistributionError("sdist member could not be read")
                with stream:
                    files[name] = _read_archive_stream(stream, declared_size=member.size)
    except DistributionError:
        raise
    except (EOFError, OSError, ValueError, tarfile.TarError) as error:
        raise DistributionError("sdist could not be safely inspected") from error
    if member_count == 0:
        raise DistributionError("sdist is empty")
    return ArchiveContents(files, frozenset(directories))


def _require_metadata(data: bytes, expected: ProjectMetadata) -> None:
    try:
        message = BytesParser(policy=policy.default).parsebytes(data)
    except (TypeError, ValueError) as error:
        raise DistributionError("artifact metadata could not be parsed") from error
    if message.defects:
        raise DistributionError("artifact metadata is malformed")

    expected_header_counts = Counter(
        {
            "metadata-version": 1,
            "name": 1,
            "version": 1,
            "summary": 1,
            "project-url": len(expected.project_urls),
            "description-content-type": 1,
            "license-expression": 1,
            "license-file": len(expected.license_files),
            "keywords": 1,
            "classifier": len(expected.classifiers),
            "requires-python": 1,
            "requires-dist": len(expected.requirements),
        }
    )
    actual_header_counts = Counter(name.casefold() for name in message)
    if actual_header_counts != expected_header_counts:
        raise DistributionError("artifact metadata header set does not match the release")

    def exact_header(name: str) -> str:
        values = message.get_all(name, [])
        if len(values) != 1:
            raise DistributionError("artifact metadata is missing or ambiguous")
        return str(values[0])

    name = exact_header("Name")
    version = exact_header("Version")
    metadata_version = exact_header("Metadata-Version")
    summary = exact_header("Summary")
    project_urls = tuple(str(value) for value in message.get_all("Project-URL", []))
    description_content_type = exact_header("Description-Content-Type")
    license_expression = exact_header("License-Expression")
    keywords_header = exact_header("Keywords")
    license_files = tuple(str(value) for value in message.get_all("License-File", []))
    classifiers = tuple(str(value) for value in message.get_all("Classifier", []))
    description = message.get_payload(decode=True)
    if not isinstance(description, bytes):
        raise DistributionError("artifact description metadata is malformed")
    try:
        requires_python = SpecifierSet(exact_header("Requires-Python"))
        raw_requirements = message.get_all("Requires-Dist", [])
        requirements = tuple(sorted(str(Requirement(str(value))) for value in raw_requirements))
    except (InvalidRequirement, InvalidSpecifier) as error:
        raise DistributionError("artifact dependency metadata is invalid") from error
    if (
        name != expected.name
        or version != expected.version_text
        or metadata_version != "2.4"
        or summary != expected.summary
        or project_urls != expected.project_urls
        or description_content_type != expected.description_content_type
        or description != expected.description
        or license_expression != expected.license_expression
        or license_files != expected.license_files
        or keywords_header != expected.keywords_header
        or classifiers != expected.classifiers
        or requires_python != expected.requires_python
        or requirements != expected.requirements
        or len(set(requirements)) != len(requirements)
    ):
        raise DistributionError("artifact metadata does not match current project metadata")


def _require_wheel_control(data: bytes) -> None:
    if data != EXPECTED_WHEEL_CONTROL:
        raise DistributionError("wheel control metadata does not match the release")


def _require_wheel_record(files: Mapping[str, bytes], record_path: str) -> None:
    try:
        text = files[record_path].decode("utf-8")
        rows = list(csv.reader(io.StringIO(text), strict=True))
    except (UnicodeError, csv.Error) as error:
        raise DistributionError("wheel RECORD is invalid") from error
    records: dict[str, tuple[str, str]] = {}
    for row in rows:
        if len(row) != 3 or not row[0] or row[0] in records:
            raise DistributionError("wheel RECORD is invalid")
        records[row[0]] = (row[1], row[2])
    if set(records) != set(files):
        raise DistributionError("wheel RECORD does not match the artifact file set")
    for name, data in files.items():
        digest, size = records[name]
        if name == record_path:
            if digest or size:
                raise DistributionError("wheel RECORD self-entry is invalid")
            continue
        expected_digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=")
        if digest != f"sha256={expected_digest.decode('ascii')}" or size != str(len(data)):
            raise DistributionError("wheel RECORD hash or size does not match the artifact")


def _validate_wheel(contents: ArchiveContents, snapshot: WorktreeSnapshot) -> None:
    if contents.directories:
        raise DistributionError("wheel must not contain explicit directory entries")
    files = contents.files
    metadata_paths = [
        name for name in files if name.count("/") == 1 and name.endswith(".dist-info/METADATA")
    ]
    if len(metadata_paths) != 1:
        raise DistributionError("wheel must contain exactly one dist-info METADATA file")
    metadata_path = metadata_paths[0]
    dist_info = metadata_path.removesuffix("/METADATA")
    expected_dist_info = (
        f"{canonicalize_name(snapshot.metadata.name).replace('-', '_')}-"
        f"{snapshot.metadata.version_text}.dist-info"
    )
    if dist_info != expected_dist_info:
        raise DistributionError("wheel dist-info directory does not match current metadata")
    _require_metadata(files[metadata_path], snapshot.metadata)

    for relative, expected_data in snapshot.wheel_package_files.items():
        actual_data = files.get(relative)
        if actual_data is None:
            raise DistributionError("wheel is missing a package file")
        if actual_data != expected_data:
            raise DistributionError("wheel package content is stale or modified")

    for license_name in ("LICENSE", "NOTICE.md"):
        archive_name = f"{dist_info}/licenses/{license_name}"
        actual_data = files.get(archive_name)
        expected_data = snapshot.sdist_files[license_name]
        if actual_data is None:
            raise DistributionError("wheel is missing required license files")
        if actual_data != expected_data:
            raise DistributionError("wheel license content is stale or modified")

    expected_files = set(snapshot.wheel_package_files)
    expected_files.update(
        {
            f"{dist_info}/METADATA",
            f"{dist_info}/WHEEL",
            f"{dist_info}/entry_points.txt",
            f"{dist_info}/RECORD",
            f"{dist_info}/licenses/LICENSE",
            f"{dist_info}/licenses/NOTICE.md",
        }
    )
    if set(files) != expected_files:
        raise DistributionError("wheel file set does not exactly match the current release")
    _require_wheel_control(files[f"{dist_info}/WHEEL"])
    expected_entry_points = b"[console_scripts]\nios-rehydrate = ios_rehydrate.cli:main\n"
    if files[f"{dist_info}/entry_points.txt"] != expected_entry_points:
        raise DistributionError("wheel console entry point does not match the release")
    _require_wheel_record(files, f"{dist_info}/RECORD")


def _validate_sdist(path: Path, contents: ArchiveContents, snapshot: WorktreeSnapshot) -> str:
    if contents.directories:
        raise DistributionError("sdist must not contain explicit directory entries")
    root_name = path.name.removesuffix(".tar.gz")
    prefix = root_name + "/"
    if any(name != root_name and not name.startswith(prefix) for name in contents.directories):
        raise DistributionError("sdist members do not share the expected root directory")
    if any(not name.startswith(prefix) for name in contents.files):
        raise DistributionError("sdist members do not share the expected root directory")

    metadata_name = prefix + "PKG-INFO"
    metadata_data = contents.files.get(metadata_name)
    if metadata_data is None:
        raise DistributionError("sdist is missing PKG-INFO metadata")
    _require_metadata(metadata_data, snapshot.metadata)

    for relative, expected_data in snapshot.sdist_files.items():
        actual_data = contents.files.get(prefix + relative)
        if actual_data is None:
            raise DistributionError("sdist is missing a required public file")
        if actual_data != expected_data:
            raise DistributionError("sdist public content is stale or modified")

    for tree in REQUIRED_SDIST_TREES:
        tree_prefix = prefix + tree + "/"
        if not any(name.startswith(tree_prefix) for name in contents.files):
            raise DistributionError("sdist is missing a required public tree")

    expected_files = {prefix + relative for relative in snapshot.sdist_files}
    expected_files.add(metadata_name)
    if set(contents.files) != expected_files:
        raise DistributionError("sdist file set does not exactly match the current release")
    return root_name


def _smoke_environment() -> dict[str, str]:
    environment = dict(os.environ)
    for name in (
        "CONDA_PREFIX",
        "PYTHONHOME",
        "PYTHONPATH",
        "UV_PROJECT",
        "UV_PROJECT_ENVIRONMENT",
        "VIRTUAL_ENV",
    ):
        environment.pop(name, None)
    environment.update(
        {
            "COLUMNS": "120",
            "NO_COLOR": "1",
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "TERM": "dumb",
            "UV_NO_PROGRESS": "1",
        }
    )
    return environment


def _run_smoke_command(
    command: Sequence[str],
    *,
    cwd: Path,
    environment: Mapping[str, str],
    phase: str,
    capture: bool = False,
) -> bytes:
    output_target = subprocess.PIPE if capture else subprocess.DEVNULL
    try:
        result = subprocess.run(  # noqa: S603
            list(command),
            cwd=cwd,
            env=dict(environment),
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=output_target,
            stderr=output_target,
            timeout=SUBPROCESS_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise DistributionError(f"{phase} could not be completed") from error
    if result.returncode != 0:
        raise DistributionError(f"{phase} failed")
    output = result.stdout if capture else b""
    if not isinstance(output, bytes) or len(output) > MAX_CAPTURE_BYTES:
        raise DistributionError(f"{phase} produced invalid output")
    if capture and isinstance(result.stderr, bytes) and len(result.stderr) > MAX_CAPTURE_BYTES:
        raise DistributionError(f"{phase} produced invalid output")
    return output


def _venv_executable(venv: Path, base_name: str) -> Path:
    if os.name == "nt":
        return venv / "Scripts" / f"{base_name}.exe"
    return venv / "bin" / base_name


def _install_and_probe(
    uv: str, artifact: Path, metadata: ProjectMetadata, *, artifact_kind: str
) -> None:
    try:
        with tempfile.TemporaryDirectory(prefix="ios-rehydrate-install-") as raw_root:
            root = Path(raw_root)
            environment = _smoke_environment()
            venv = root / "venv"
            python = _venv_executable(venv, "python")
            cli = _venv_executable(venv, "ios-rehydrate")
            _run_smoke_command(
                [uv, "venv", str(venv), "--python", sys.executable],
                cwd=root,
                environment=environment,
                phase=f"{artifact_kind} smoke environment creation",
            )
            _run_smoke_command(
                [uv, "pip", "install", "--python", str(python), str(artifact)],
                cwd=root,
                environment=environment,
                phase=f"{artifact_kind} smoke installation",
            )
            version_output = _run_smoke_command(
                [str(cli), "--version"],
                cwd=root,
                environment=environment,
                phase=f"{artifact_kind} version probe",
                capture=True,
            )
            if version_output.strip() != metadata.version_text.encode("utf-8"):
                raise DistributionError(f"{artifact_kind} version probe returned the wrong version")
            help_output = _run_smoke_command(
                [str(cli), "--help"],
                cwd=root,
                environment=environment,
                phase=f"{artifact_kind} help probe",
                capture=True,
            ).lower()
            if b"usage" not in help_output or b"ios-rehydrate" not in help_output:
                raise DistributionError(f"{artifact_kind} help probe returned unexpected output")
    except DistributionError:
        raise
    except OSError as error:
        raise DistributionError(f"{artifact_kind} isolated smoke root failed") from error


def _extract_validated_sdist(contents: ArchiveContents, destination: Path, root_name: str) -> Path:
    try:
        destination.mkdir(parents=True, exist_ok=False)
        for directory in sorted(contents.directories, key=lambda value: (value.count("/"), value)):
            target = destination.joinpath(*directory.split("/"))
            target.mkdir(parents=True, exist_ok=True)
        for name, data in sorted(contents.files.items()):
            target = destination.joinpath(*name.split("/"))
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("xb") as stream:
                stream.write(data)
    except OSError as error:
        raise DistributionError("sdist could not be safely extracted") from error
    extracted_root = destination / root_name
    try:
        root_stat = os.lstat(extracted_root)
    except OSError as error:
        raise DistributionError("sdist extracted root is unavailable") from error
    if _is_link_or_reparse(root_stat) or not stat.S_ISDIR(root_stat.st_mode):
        raise DistributionError("sdist extracted root is invalid")
    return extracted_root


def _run_sdist_source_checks(uv: str, checked: CheckedArtifacts) -> None:
    try:
        with tempfile.TemporaryDirectory(prefix="ios-rehydrate-source-") as raw_root:
            temporary_root = Path(raw_root)
            source_root = _extract_validated_sdist(
                checked.sdist_contents,
                temporary_root / "unpacked",
                checked.sdist_root,
            )
            environment = _smoke_environment()
            environment["UV_PROJECT_ENVIRONMENT"] = str(temporary_root / "dev-env")
            _run_smoke_command(
                [uv, "sync", "--locked"],
                cwd=source_root,
                environment=environment,
                phase="sdist locked development environment creation",
            )
            _run_smoke_command(
                [
                    uv,
                    "run",
                    "--locked",
                    "python",
                    "scripts/run_public_experiment.py",
                ],
                cwd=source_root,
                environment=environment,
                phase="sdist public experiment",
            )
            _run_smoke_command(
                [
                    uv,
                    "run",
                    "--locked",
                    "python",
                    "scripts/check_public_surface.py",
                    ".",
                ],
                cwd=source_root,
                environment=environment,
                phase="sdist public-surface scan",
            )
    except DistributionError:
        raise
    except OSError as error:
        raise DistributionError("sdist source smoke root failed") from error


def _run_smoke_checks(checked: CheckedArtifacts, metadata: ProjectMetadata) -> None:
    uv = shutil.which("uv")
    if uv is None:
        raise DistributionError("uv is required for smoke-install checks")
    _install_and_probe(uv, checked.wheel, metadata, artifact_kind="wheel")
    _install_and_probe(uv, checked.sdist, metadata, artifact_kind="sdist")
    _run_sdist_source_checks(uv, checked)


def _require_identical_artifact(candidate: Path, rebuilt: Path, *, artifact_kind: str) -> None:
    candidate_data = _read_regular_file(
        candidate,
        limit=MAX_ARCHIVE_BYTES,
        description=f"candidate {artifact_kind}",
    )
    rebuilt_data = _read_regular_file(
        rebuilt,
        limit=MAX_ARCHIVE_BYTES,
        description=f"rebuilt {artifact_kind}",
    )
    candidate_digest = hashlib.sha256(candidate_data).digest()
    rebuilt_digest = hashlib.sha256(rebuilt_data).digest()
    if (
        len(candidate_data) != len(rebuilt_data)
        or candidate_digest != rebuilt_digest
        or candidate_data != rebuilt_data
    ):
        raise DistributionError(f"{artifact_kind} is not byte-identical to a fresh rebuild")


def _run_rebuild_compare(checked: CheckedArtifacts, root: Path) -> None:
    uv = shutil.which("uv")
    if uv is None:
        raise DistributionError("uv is required for rebuild-compare checks")
    try:
        with tempfile.TemporaryDirectory(prefix="ios-rehydrate-rebuild-") as raw_root:
            temporary_root = Path(raw_root)
            rebuilt_dist = temporary_root / "dist"
            environment = _smoke_environment()
            environment["VIRTUAL_ENV"] = sys.prefix
            _run_smoke_command(
                [
                    uv,
                    "build",
                    "--no-build-isolation",
                    "--out-dir",
                    str(rebuilt_dist),
                    str(root),
                ],
                cwd=temporary_root,
                environment=environment,
                phase="reproducible distribution rebuild",
            )
            resolved_rebuilt_dist = _resolve_directory(
                rebuilt_dist,
                description="rebuilt artifact directory",
            )
            try:
                rebuilt_entries = list(resolved_rebuilt_dist.iterdir())
            except OSError as error:
                raise DistributionError("rebuilt artifact directory could not be listed") from error
            expected_names = {".gitignore", checked.wheel.name, checked.sdist.name}
            if {entry.name for entry in rebuilt_entries} != expected_names:
                raise DistributionError("fresh rebuild produced an unexpected artifact set")
            if (
                _read_regular_file(
                    resolved_rebuilt_dist / ".gitignore",
                    limit=1,
                    description="rebuilt artifact directory marker",
                )
                != b"*"
            ):
                raise DistributionError("fresh rebuild produced an invalid directory marker")
            _require_identical_artifact(
                checked.wheel,
                resolved_rebuilt_dist / checked.wheel.name,
                artifact_kind="wheel",
            )
            _require_identical_artifact(
                checked.sdist,
                resolved_rebuilt_dist / checked.sdist.name,
                artifact_kind="sdist",
            )
    except DistributionError:
        raise
    except OSError as error:
        raise DistributionError("rebuild-compare temporary root failed") from error


def check_distributions(
    root: Path,
    *,
    dist_directory: Path | None = None,
    smoke_install: bool = False,
    rebuild_compare: bool = False,
) -> None:
    """Validate exactly one current wheel and sdist against ``root``."""

    resolved_root = _resolve_directory(root, description="project root")
    unresolved_dist = dist_directory if dist_directory is not None else resolved_root / "dist"
    if not unresolved_dist.is_absolute():
        unresolved_dist = resolved_root / unresolved_dist
    resolved_dist = _resolve_directory(unresolved_dist, description="artifact directory")

    snapshot = _snapshot_worktree(resolved_root)
    wheel, sdist = _select_artifacts(resolved_dist, snapshot.metadata)
    wheel_contents = _inspect_wheel(wheel)
    sdist_contents = _inspect_sdist(sdist)
    _validate_wheel(wheel_contents, snapshot)
    sdist_root = _validate_sdist(sdist, sdist_contents, snapshot)
    checked = CheckedArtifacts(wheel, sdist, sdist_root, sdist_contents)
    if rebuild_compare:
        _run_rebuild_compare(checked, resolved_root)
    if smoke_install:
        _run_smoke_checks(checked, snapshot.metadata)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parse_arguments(argv)
    try:
        check_distributions(
            arguments.root,
            dist_directory=arguments.dist_dir,
            smoke_install=arguments.smoke_install,
            rebuild_compare=arguments.rebuild_compare,
        )
    except DistributionError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print("distribution artifacts passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
