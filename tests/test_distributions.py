# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 iOS Rehydrate contributors
"""Synthetic tests for the public distribution artifact gate."""

from __future__ import annotations

import base64
import gzip
import hashlib
import importlib.util
import io
import shutil
import stat
import subprocess
import sys
import tarfile
import warnings
import zipfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from pytest_mock import MockerFixture

SCRIPT = Path(__file__).parents[1] / "scripts" / "check_distributions.py"


def _load_distributions() -> Any:
    spec = importlib.util.spec_from_file_location("distribution_gate_under_test", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load distribution gate")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


distributions = _load_distributions()

PROJECT_NAME = "ios-rehydrate"
VERSION = "0.1.0"
SDIST_ROOT = "ios_rehydrate-0.1.0"
DIST_INFO = "ios_rehydrate-0.1.0.dist-info"
SUMMARY = "Synthetic safety-first release gate"
README_DATA = b"# Synthetic project\n"
LICENSE_FILES = ("LICENSE", "NOTICE.md")
PROJECT_KEYWORDS = ("synthetic", "ios")
METADATA_KEYWORDS = "ios,synthetic"
PROJECT_CLASSIFIERS = (
    "Programming Language :: Python :: 3",
    "Development Status :: 3 - Alpha",
)
METADATA_CLASSIFIERS = tuple(sorted(PROJECT_CLASSIFIERS))
PROJECT_URLS = (
    "Homepage, https://github.com/Xopoko/ios-rehydrate",
    "Repository, https://github.com/Xopoko/ios-rehydrate",
    "Issues, https://github.com/Xopoko/ios-rehydrate/issues",
)
PRIVATE_PROJECT_URL = "https:" + "//private.invalid/project"
CANONICAL_GZIP_MTIME = 1_580_601_600
WHEEL_CONTROL = (
    b"Wheel-Version: 1.0\nGenerator: hatchling 1.32.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
)


@dataclass(frozen=True)
class Fixture:
    """A minimal worktree and its synthetic release artifacts."""

    root: Path
    dist: Path
    wheel: Path
    sdist: Path
    files: dict[str, bytes]


@dataclass(frozen=True)
class TarExtra:
    """One optional tar member used by negative-path tests."""

    name: str
    data: bytes = b"extra\n"
    type: bytes = tarfile.REGTYPE
    linkname: str = ""


def _metadata(
    *,
    name: str = PROJECT_NAME,
    version: str = VERSION,
    metadata_version: str = "2.4",
    summary: str = SUMMARY,
    project_urls: Sequence[str] = PROJECT_URLS,
    description_content_type: str = "text/markdown",
    license: str = "MIT",
    license_files: Sequence[str] = LICENSE_FILES,
    keywords: str = METADATA_KEYWORDS,
    classifiers: Sequence[str] = METADATA_CLASSIFIERS,
    requires_python: str = ">=3.11",
    requirement: str = "packaging>=24",
    description: bytes = README_DATA,
    extra_headers: Sequence[tuple[str, str]] = (),
) -> bytes:
    headers = [
        f"Metadata-Version: {metadata_version}",
        f"Name: {name}",
        f"Version: {version}",
        f"Summary: {summary}",
        *(f"Project-URL: {value}" for value in project_urls),
        f"Description-Content-Type: {description_content_type}",
        f"License-Expression: {license}",
        *(f"License-File: {value}" for value in license_files),
        f"Keywords: {keywords}",
        *(f"Classifier: {value}" for value in classifiers),
        f"Requires-Python: {requires_python}",
        f"Requires-Dist: {requirement}",
        *(f"{name}: {value}" for name, value in extra_headers),
    ]
    return ("\n".join(headers) + "\n\n").encode() + description


def _project_files() -> dict[str, bytes]:
    return {
        "pyproject.toml": (
            f'[project]\nname = "{PROJECT_NAME}"\nversion = "{VERSION}"\n'
            f'description = "{SUMMARY}"\nreadme = "README.md"\nlicense = "MIT"\n'
            'license-files = ["LICENSE", "NOTICE.md"]\n'
            'keywords = ["synthetic", "ios"]\n'
            'classifiers = ["Programming Language :: Python :: 3", '
            '"Development Status :: 3 - Alpha"]\n'
            'requires-python = ">=3.11"\ndependencies = ["packaging>=24"]\n'
            "[project.urls]\n"
            'Homepage = "https://github.com/Xopoko/ios-rehydrate"\n'
            'Repository = "https://github.com/Xopoko/ios-rehydrate"\n'
            'Issues = "https://github.com/Xopoko/ios-rehydrate/issues"\n'
        ).encode(),
        ".gitignore": b"dist/\n",
        "uv.lock": b"version = 1\n",
        "README.md": README_DATA,
        "LICENSE": b"Synthetic MIT license\n",
        "NOTICE.md": b"Synthetic notice\n",
        "PRIVACY.md": b"No collection.\n",
        "SECURITY.md": b"Report privately.\n",
        "CONTRIBUTING.md": b"Use synthetic inputs.\n",
        "docs/guide.md": b"Public guide.\n",
        "scripts/check_public_surface.py": b"raise SystemExit(0)\n",
        "scripts/run_public_experiment.py": b"raise SystemExit(0)\n",
        "experiments/public-smoke/fixture.txt": b"synthetic\n",
        "src/ios_rehydrate/__init__.py": b'__version__ = "0.1.0"\n',
        "src/ios_rehydrate/__main__.py": b"from . import __version__\n",
        "src/ios_rehydrate/py.typed": b"",
        "tests/test_sample.py": b"def test_sample():\n    assert True\n",
    }


def _zip_info(
    name: str,
    *,
    mode: int = stat.S_IFREG | 0o644,
    comment: bytes = b"",
    extra: bytes = b"",
) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3
    info.external_attr = mode << 16
    info.comment = comment
    info.extra = extra
    return info


def _write_wheel(
    path: Path,
    files: dict[str, bytes],
    *,
    metadata: bytes | None = None,
    wheel_control: bytes | None = None,
    entry_points: bytes | None = None,
    record_data: bytes | None = None,
    archive_comment: bytes = b"",
    member_comment: bytes = b"",
    member_extra: bytes = b"",
    omit: frozenset[str] = frozenset(),
    extras: Sequence[tuple[zipfile.ZipInfo, bytes]] = (),
) -> None:
    entries = {
        relative.removeprefix("src/"): data
        for relative, data in files.items()
        if relative.startswith("src/ios_rehydrate/")
    }
    entries.update(
        {
            f"{DIST_INFO}/METADATA": metadata if metadata is not None else _metadata(),
            f"{DIST_INFO}/WHEEL": wheel_control if wheel_control is not None else WHEEL_CONTROL,
            f"{DIST_INFO}/entry_points.txt": entry_points
            if entry_points is not None
            else b"[console_scripts]\nios-rehydrate = ios_rehydrate.cli:main\n",
            f"{DIST_INFO}/licenses/LICENSE": files["LICENSE"],
            f"{DIST_INFO}/licenses/NOTICE.md": files["NOTICE.md"],
        }
    )
    if record_data is None:
        record_lines = []
        for name, data in sorted(entries.items()):
            digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=")
            record_lines.append(f"{name},sha256={digest.decode('ascii')},{len(data)}")
        record_lines.append(f"{DIST_INFO}/RECORD,,")
        record_data = ("\n".join(record_lines) + "\n").encode()
    entries[f"{DIST_INFO}/RECORD"] = record_data
    with zipfile.ZipFile(path, "w") as archive:
        archive.comment = archive_comment
        for name, data in sorted(entries.items()):
            if name not in omit:
                info = _zip_info(name)
                if name == f"{DIST_INFO}/METADATA":
                    info.comment = member_comment
                    info.extra = member_extra
                archive.writestr(info, data)
        for info, data in extras:
            archive.writestr(info, data)


def _write_sdist(
    path: Path,
    files: dict[str, bytes],
    *,
    metadata: bytes | None = None,
    gzip_comment: bytes | None = None,
    member_pax_headers: Mapping[str, str] | None = None,
    member_uname: str = "",
    omit: frozenset[str] = frozenset(),
    extras: Sequence[TarExtra] = (),
) -> None:
    entries = {f"{SDIST_ROOT}/{relative}": data for relative, data in files.items()}
    entries[f"{SDIST_ROOT}/PKG-INFO"] = metadata if metadata is not None else _metadata()
    tar_data = io.BytesIO()
    with tarfile.open(fileobj=tar_data, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for name, data in sorted(entries.items()):
            if name in omit:
                continue
            info = tarfile.TarInfo(name)
            info.type = tarfile.REGTYPE
            info.mode = 0o644
            info.size = len(data)
            info.mtime = CANONICAL_GZIP_MTIME
            if name == f"{SDIST_ROOT}/PKG-INFO" and member_pax_headers is not None:
                info.pax_headers = dict(member_pax_headers)
            if name == f"{SDIST_ROOT}/PKG-INFO":
                info.uname = member_uname
            archive.addfile(info, io.BytesIO(data))
        for extra in extras:
            info = tarfile.TarInfo(extra.name)
            info.type = extra.type
            info.mode = 0o644
            info.mtime = CANONICAL_GZIP_MTIME
            info.linkname = extra.linkname
            info.size = len(extra.data) if extra.type == tarfile.REGTYPE else 0
            stream = io.BytesIO(extra.data) if info.size else None
            archive.addfile(info, stream)
    compressed = gzip.compress(
        tar_data.getvalue(),
        compresslevel=9,
        mtime=CANONICAL_GZIP_MTIME,
    )
    if gzip_comment is not None:
        compressed = compressed[:3] + bytes([compressed[3] | 0x10]) + compressed[4:10]
        compressed += (
            gzip_comment
            + b"\0"
            + gzip.compress(
                tar_data.getvalue(),
                compresslevel=9,
                mtime=CANONICAL_GZIP_MTIME,
            )[10:]
        )
    path.write_bytes(compressed)


def _build_fixture(
    tmp_path: Path,
    *,
    wheel_metadata: bytes | None = None,
    wheel_control: bytes | None = None,
    wheel_entry_points: bytes | None = None,
    wheel_record: bytes | None = None,
    wheel_archive_comment: bytes = b"",
    wheel_member_comment: bytes = b"",
    wheel_member_extra: bytes = b"",
    sdist_metadata: bytes | None = None,
    sdist_gzip_comment: bytes | None = None,
    sdist_member_pax_headers: Mapping[str, str] | None = None,
    sdist_member_uname: str = "",
    wheel_omit: frozenset[str] = frozenset(),
    sdist_omit: frozenset[str] = frozenset(),
    wheel_extras: Sequence[tuple[zipfile.ZipInfo, bytes]] = (),
    sdist_extras: Sequence[TarExtra] = (),
) -> Fixture:
    root = tmp_path / "project"
    dist = root / "dist"
    dist.mkdir(parents=True)
    files = _project_files()
    for relative, data in files.items():
        target = root / Path(relative)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    wheel = dist / f"{SDIST_ROOT}-py3-none-any.whl"
    sdist = dist / f"{SDIST_ROOT}.tar.gz"
    _write_wheel(
        wheel,
        files,
        metadata=wheel_metadata,
        wheel_control=wheel_control,
        entry_points=wheel_entry_points,
        record_data=wheel_record,
        archive_comment=wheel_archive_comment,
        member_comment=wheel_member_comment,
        member_extra=wheel_member_extra,
        omit=wheel_omit,
        extras=wheel_extras,
    )
    _write_sdist(
        sdist,
        files,
        metadata=sdist_metadata,
        gzip_comment=sdist_gzip_comment,
        member_pax_headers=sdist_member_pax_headers,
        member_uname=sdist_member_uname,
        omit=sdist_omit,
        extras=sdist_extras,
    )
    return Fixture(root, dist, wheel, sdist, files)


def _failure(fixture: Fixture) -> str:
    with pytest.raises(distributions.DistributionError) as raised:
        distributions.check_distributions(fixture.root)
    return str(raised.value)


def _rebuild_failure(fixture: Fixture) -> str:
    with pytest.raises(distributions.DistributionError) as raised:
        distributions.check_distributions(fixture.root, rebuild_compare=True)
    return str(raised.value)


def test_valid_synthetic_wheel_and_sdist_pass(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    fixture = _build_fixture(tmp_path)
    (fixture.dist / ".gitignore").write_text("*\n", encoding="utf-8")

    assert distributions.main([str(fixture.root)]) == 0

    captured = capsys.readouterr()
    assert captured.out == "distribution artifacts passed\n"
    assert captured.err == ""
    assert str(tmp_path) not in captured.out


@pytest.mark.parametrize("artifact_kind", ["wheel", "sdist"])
def test_exactly_one_artifact_of_each_kind_is_required(tmp_path: Path, artifact_kind: str) -> None:
    fixture = _build_fixture(tmp_path)
    source = fixture.wheel if artifact_kind == "wheel" else fixture.sdist
    suffix = ".whl" if artifact_kind == "wheel" else ".tar.gz"
    shutil.copyfile(source, fixture.dist / f"stale-9.9.9{suffix}")

    assert "exactly one" in _failure(fixture)


def test_distribution_filenames_must_match_current_project(tmp_path: Path) -> None:
    fixture = _build_fixture(tmp_path)
    fixture.wheel.rename(fixture.dist / "other_project-0.1.0-py3-none-any.whl")

    assert "filename does not match" in _failure(fixture)


@pytest.mark.parametrize(
    "wheel_name",
    [
        "ios_rehydrate-0.1.0-1-py3-none-any.whl",
        "ios_rehydrate-0.1.0-cp311-none-win_amd64.whl",
        "ios_rehydrate-0.1.0-py3-none-manylinux_2_17_x86_64.whl",
    ],
)
def test_wheel_filename_must_be_the_exact_universal_release_name(
    tmp_path: Path, wheel_name: str
) -> None:
    fixture = _build_fixture(tmp_path)
    fixture.wheel.rename(fixture.dist / wheel_name)

    assert "filename does not match" in _failure(fixture)


@pytest.mark.parametrize("artifact_kind", ["wheel", "sdist"])
def test_metadata_identity_and_license_must_match(tmp_path: Path, artifact_kind: str) -> None:
    fixture = _build_fixture(
        tmp_path,
        wheel_metadata=_metadata(license="Apache-2.0") if artifact_kind == "wheel" else None,
        sdist_metadata=_metadata(license="Apache-2.0") if artifact_kind == "sdist" else None,
    )

    assert "metadata does not match" in _failure(fixture)


@pytest.mark.parametrize("artifact_kind", ["wheel", "sdist"])
@pytest.mark.parametrize(
    "metadata",
    [
        _metadata(metadata_version="2.3"),
        _metadata(summary="Private tampered summary"),
        _metadata(description_content_type="text/plain"),
        _metadata(keywords="synthetic,ios"),
        _metadata(classifiers=tuple(reversed(METADATA_CLASSIFIERS))),
        _metadata(license_files=("NOTICE.md", "LICENSE")),
        _metadata(description=b"# Private tampered README\n"),
        _metadata(extra_headers=(("Summary", "Private duplicate summary"),)),
    ],
    ids=(
        "metadata-version",
        "summary",
        "description-content-type",
        "keywords-order",
        "classifier-order",
        "license-file-order",
        "readme-description",
        "duplicate-summary",
    ),
)
def test_publication_metadata_must_exactly_match_pyproject_and_readme(
    tmp_path: Path,
    artifact_kind: str,
    metadata: bytes,
) -> None:
    fixture = _build_fixture(
        tmp_path,
        wheel_metadata=metadata if artifact_kind == "wheel" else None,
        sdist_metadata=metadata if artifact_kind == "sdist" else None,
    )

    failure = _failure(fixture)
    assert "metadata" in failure
    assert "Private" not in failure


@pytest.mark.parametrize("artifact_kind", ["wheel", "sdist"])
@pytest.mark.parametrize("header_name", ["Author", "Author-Email", "Home-Page", "Dynamic"])
def test_unknown_core_metadata_headers_are_rejected_without_echoing_values(
    tmp_path: Path,
    artifact_kind: str,
    header_name: str,
) -> None:
    metadata = _metadata(extra_headers=((header_name, "Private Person"),))
    fixture = _build_fixture(
        tmp_path,
        wheel_metadata=metadata if artifact_kind == "wheel" else None,
        sdist_metadata=metadata if artifact_kind == "sdist" else None,
    )

    failure = _failure(fixture)
    assert "metadata header set" in failure
    assert "Private Person" not in failure


@pytest.mark.parametrize("artifact_kind", ["wheel", "sdist"])
@pytest.mark.parametrize(
    ("project_urls", "expected"),
    [
        ((*PROJECT_URLS, f"Private, {PRIVATE_PROJECT_URL}"), "metadata header set"),
        ((*PROJECT_URLS, PROJECT_URLS[0]), "metadata header set"),
        (tuple(reversed(PROJECT_URLS)), "metadata does not match"),
        (
            (
                PROJECT_URLS[0],
                "Repository, https://github.com/PrivateOwner/ios-rehydrate",
                PROJECT_URLS[2],
            ),
            "metadata does not match",
        ),
    ],
    ids=("unknown", "duplicate", "order", "owner"),
)
def test_project_url_headers_are_exact_and_do_not_leak_values(
    tmp_path: Path,
    artifact_kind: str,
    project_urls: Sequence[str],
    expected: str,
) -> None:
    metadata = _metadata(project_urls=project_urls)
    fixture = _build_fixture(
        tmp_path,
        wheel_metadata=metadata if artifact_kind == "wheel" else None,
        sdist_metadata=metadata if artifact_kind == "sdist" else None,
    )

    failure = _failure(fixture)
    assert expected in failure
    assert "private" not in failure.casefold()


def test_project_metadata_requires_the_canonical_repository_owner(tmp_path: Path) -> None:
    fixture = _build_fixture(tmp_path)
    pyproject = fixture.root / "pyproject.toml"
    private_owner = "PrivateOwner"
    pyproject.write_text(
        pyproject.read_text(encoding="utf-8").replace("Xopoko", private_owner),
        encoding="utf-8",
    )

    failure = _failure(fixture)
    assert "project release metadata is invalid" in failure
    assert private_owner not in failure


@pytest.mark.parametrize("artifact_kind", ["wheel", "sdist"])
@pytest.mark.parametrize(
    ("header_name", "value"),
    [
        ("License-File", "LICENSE"),
        ("Classifier", METADATA_CLASSIFIERS[0]),
        ("Requires-Dist", "packaging>=24"),
    ],
)
def test_repeatable_core_metadata_header_counts_are_exact(
    tmp_path: Path,
    artifact_kind: str,
    header_name: str,
    value: str,
) -> None:
    metadata = _metadata(extra_headers=((header_name, value),))
    fixture = _build_fixture(
        tmp_path,
        wheel_metadata=metadata if artifact_kind == "wheel" else None,
        sdist_metadata=metadata if artifact_kind == "sdist" else None,
    )

    assert "metadata header set" in _failure(fixture)


@pytest.mark.parametrize("artifact_kind", ["wheel", "sdist"])
@pytest.mark.parametrize(
    "metadata",
    [
        _metadata(requires_python=">=3.12"),
        _metadata(requirement="packaging>=25"),
        _metadata(requirement="unexpected-package==1"),
    ],
)
def test_runtime_and_dependency_metadata_must_match_project(
    tmp_path: Path,
    artifact_kind: str,
    metadata: bytes,
) -> None:
    fixture = _build_fixture(
        tmp_path,
        wheel_metadata=metadata if artifact_kind == "wheel" else None,
        sdist_metadata=metadata if artifact_kind == "sdist" else None,
    )

    assert "metadata does not match" in _failure(fixture)


@pytest.mark.parametrize(
    ("kwargs", "expected"),
    [
        (
            {
                "wheel_control": WHEEL_CONTROL.replace(
                    b"Root-Is-Purelib: true", b"Root-Is-Purelib: false"
                )
            },
            "control metadata",
        ),
        (
            {"wheel_entry_points": b"[console_scripts]\nother = ios_rehydrate.cli:main\n"},
            "console entry point",
        ),
        ({"wheel_record": b"ios_rehydrate/__init__.py,,\n"}, "RECORD"),
    ],
)
def test_wheel_generated_control_files_are_validated(
    tmp_path: Path,
    kwargs: dict[str, bytes],
    expected: str,
) -> None:
    fixture = _build_fixture(
        tmp_path,
        wheel_control=kwargs.get("wheel_control"),
        wheel_entry_points=kwargs.get("wheel_entry_points"),
        wheel_record=kwargs.get("wheel_record"),
    )

    assert expected in _failure(fixture)


@pytest.mark.parametrize(
    "wheel_control",
    [
        WHEEL_CONTROL.replace(b"hatchling 1.32.0", b"hatchling 1.32.1"),
        WHEEL_CONTROL + b"Author: Private Person\n",
        WHEEL_CONTROL + b"\nPrivate control body\n",
    ],
    ids=("generator", "unknown-header", "body"),
)
def test_wheel_control_metadata_is_exact_pinned_hatchling_output(
    tmp_path: Path,
    wheel_control: bytes,
) -> None:
    fixture = _build_fixture(tmp_path, wheel_control=wheel_control)

    failure = _failure(fixture)
    assert "control metadata" in failure
    assert "Private" not in failure


@pytest.mark.parametrize(
    ("wheel_omit", "sdist_omit", "expected"),
    [
        (frozenset({f"{DIST_INFO}/licenses/NOTICE.md"}), frozenset(), "license"),
        (frozenset(), frozenset({f"{SDIST_ROOT}/PRIVACY.md"}), "public file"),
        (
            frozenset({"ios_rehydrate/__init__.py"}),
            frozenset(),
            "package file",
        ),
    ],
)
def test_required_public_files_are_enforced(
    tmp_path: Path,
    wheel_omit: frozenset[str],
    sdist_omit: frozenset[str],
    expected: str,
) -> None:
    fixture = _build_fixture(tmp_path, wheel_omit=wheel_omit, sdist_omit=sdist_omit)

    assert expected in _failure(fixture)


@pytest.mark.parametrize("artifact_kind", ["wheel", "sdist"])
def test_explicit_archive_directories_are_rejected(tmp_path: Path, artifact_kind: str) -> None:
    fixture = _build_fixture(
        tmp_path,
        wheel_extras=[(_zip_info("unexpected-empty/", mode=stat.S_IFDIR | 0o755), b"")]
        if artifact_kind == "wheel"
        else (),
        sdist_extras=[TarExtra(f"{SDIST_ROOT}/unexpected-empty", type=tarfile.DIRTYPE)]
        if artifact_kind == "sdist"
        else (),
    )

    assert "explicit directory" in _failure(fixture)


def test_artifacts_must_be_byte_identical_to_current_worktree(tmp_path: Path) -> None:
    fixture = _build_fixture(tmp_path)
    (fixture.root / "src" / "ios_rehydrate" / "__init__.py").write_bytes(b"changed\n")

    assert "stale or modified" in _failure(fixture)


@pytest.mark.parametrize("artifact_kind", ["wheel", "sdist"])
def test_unexpected_regular_artifact_file_is_rejected(tmp_path: Path, artifact_kind: str) -> None:
    fixture = _build_fixture(
        tmp_path,
        wheel_extras=[(_zip_info("ios_rehydrate/ghost.py"), b"unexpected\n")]
        if artifact_kind == "wheel"
        else (),
        sdist_extras=[TarExtra(f"{SDIST_ROOT}/src/ios_rehydrate/ghost.py", b"unexpected\n")]
        if artifact_kind == "sdist"
        else (),
    )

    assert "file set does not exactly match" in _failure(fixture)


@pytest.mark.parametrize("artifact_kind", ["wheel", "sdist"])
def test_traversal_member_is_rejected_without_echoing_its_name(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    artifact_kind: str,
) -> None:
    private_member = "../do-not-echo-private-value.txt"
    fixture = _build_fixture(
        tmp_path,
        wheel_extras=[(_zip_info(private_member), b"private archive content")]
        if artifact_kind == "wheel"
        else (),
        sdist_extras=[TarExtra(private_member, b"private archive content")]
        if artifact_kind == "sdist"
        else (),
    )

    assert distributions.main([str(fixture.root)]) == 1

    captured = capsys.readouterr()
    assert "unsafe member path" in captured.err
    assert private_member not in captured.err
    assert "private archive content" not in captured.err
    assert str(tmp_path) not in captured.err


@pytest.mark.parametrize("artifact_kind", ["wheel", "sdist"])
def test_duplicate_archive_members_are_rejected(tmp_path: Path, artifact_kind: str) -> None:
    duplicate_name = (
        "ios_rehydrate/__init__.py" if artifact_kind == "wheel" else f"{SDIST_ROOT}/README.md"
    )
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        fixture = _build_fixture(
            tmp_path,
            wheel_extras=[(_zip_info(duplicate_name), b"duplicate")]
            if artifact_kind == "wheel"
            else (),
            sdist_extras=[TarExtra(duplicate_name, b"duplicate")]
            if artifact_kind == "sdist"
            else (),
        )

    assert "duplicate member" in _failure(fixture)


@pytest.mark.parametrize("artifact_kind", ["wheel", "sdist"])
def test_archive_links_are_rejected(tmp_path: Path, artifact_kind: str) -> None:
    fixture = _build_fixture(
        tmp_path,
        wheel_extras=[
            (
                _zip_info("ios_rehydrate/linked.py", mode=stat.S_IFLNK | 0o777),
                b"target.py",
            )
        ]
        if artifact_kind == "wheel"
        else (),
        sdist_extras=[
            TarExtra(f"{SDIST_ROOT}/linked.py", type=tarfile.SYMTYPE, linkname="target.py")
        ]
        if artifact_kind == "sdist"
        else (),
    )

    assert "special member" in _failure(fixture)


@pytest.mark.parametrize(
    ("kwargs", "expected"),
    [
        ({"wheel_archive_comment": b"private archive comment"}, "archive comment"),
        ({"wheel_member_comment": b"private member comment"}, "member"),
        ({"wheel_member_extra": b"\xfe\xca\x00\x00"}, "extra metadata"),
    ],
)
def test_wheel_comments_and_extra_metadata_are_rejected_without_echoing_values(
    tmp_path: Path,
    kwargs: dict[str, bytes],
    expected: str,
) -> None:
    fixture = _build_fixture(
        tmp_path,
        wheel_archive_comment=kwargs.get("wheel_archive_comment", b""),
        wheel_member_comment=kwargs.get("wheel_member_comment", b""),
        wheel_member_extra=kwargs.get("wheel_member_extra", b""),
    )

    failure = _failure(fixture)
    assert expected in failure
    assert "private" not in failure


def test_sdist_optional_gzip_header_fields_are_rejected_without_echoing_values(
    tmp_path: Path,
) -> None:
    fixture = _build_fixture(tmp_path, sdist_gzip_comment=b"private gzip comment")

    failure = _failure(fixture)
    assert "gzip header" in failure
    assert "private" not in failure


def test_sdist_member_pax_headers_are_rejected_without_echoing_values(tmp_path: Path) -> None:
    fixture = _build_fixture(
        tmp_path,
        sdist_member_pax_headers={"private-key": "private-value"},
    )

    failure = _failure(fixture)
    assert "extended metadata" in failure
    assert "private" not in failure


def test_sdist_member_identity_metadata_is_canonical_without_echoing_values(
    tmp_path: Path,
) -> None:
    fixture = _build_fixture(tmp_path, sdist_member_uname="private-person")

    failure = _failure(fixture)
    assert "identity metadata" in failure
    assert "private-person" not in failure


def _rebuild_runner(
    fixture: Fixture,
    calls: list[tuple[list[str], dict[str, Any]]],
    *,
    tamper_wheel: bool = False,
    unexpected_output: bool = False,
    returncode: int = 0,
) -> Callable[..., subprocess.CompletedProcess[bytes]]:
    def run(command: Sequence[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        command_list = list(command)
        calls.append((command_list, kwargs))
        if returncode == 0:
            output_index = command_list.index("--out-dir") + 1
            output_directory = Path(command_list[output_index])
            output_directory.mkdir(parents=True)
            shutil.copyfile(fixture.wheel, output_directory / fixture.wheel.name)
            shutil.copyfile(fixture.sdist, output_directory / fixture.sdist.name)
            (output_directory / ".gitignore").write_bytes(b"*")
            if tamper_wheel:
                rebuilt_wheel = output_directory / fixture.wheel.name
                rebuilt_wheel.write_bytes(rebuilt_wheel.read_bytes() + b"private tamper")
            if unexpected_output:
                (output_directory / "private-output.txt").write_bytes(b"private output")
        return subprocess.CompletedProcess(
            command_list,
            returncode,
            stdout=b"private subprocess stdout" if returncode else b"",
            stderr=b"private subprocess stderr" if returncode else b"",
        )

    return run


def test_rebuild_compare_uses_exact_external_uv_build_and_cli_flag(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    mocker: MockerFixture,
) -> None:
    fixture = _build_fixture(tmp_path)
    calls: list[tuple[list[str], dict[str, Any]]] = []
    mocker.patch.object(distributions.shutil, "which", return_value="mock-uv")
    mocker.patch.object(
        distributions.subprocess,
        "run",
        side_effect=_rebuild_runner(fixture, calls),
    )

    assert distributions.main([str(fixture.root), "--rebuild-compare"]) == 0

    captured = capsys.readouterr()
    assert captured.out == "distribution artifacts passed\n"
    assert captured.err == ""
    assert len(calls) == 1
    command, kwargs = calls[0]
    assert command[:4] == ["mock-uv", "build", "--no-build-isolation", "--out-dir"]
    assert Path(command[4]).parent == Path(kwargs["cwd"])
    assert Path(command[5]) == fixture.root.resolve()
    assert not Path(kwargs["cwd"]).is_relative_to(fixture.root.resolve())
    assert kwargs["env"]["VIRTUAL_ENV"] == sys.prefix


@pytest.mark.parametrize(
    ("tamper_wheel", "unexpected_output", "expected"),
    [
        (True, False, "byte-identical"),
        (False, True, "unexpected artifact set"),
    ],
)
def test_rebuild_compare_rejects_nonidentical_or_unexpected_outputs(
    tmp_path: Path,
    mocker: MockerFixture,
    tamper_wheel: bool,
    unexpected_output: bool,
    expected: str,
) -> None:
    fixture = _build_fixture(tmp_path)
    calls: list[tuple[list[str], dict[str, Any]]] = []
    mocker.patch.object(distributions.shutil, "which", return_value="mock-uv")
    mocker.patch.object(
        distributions.subprocess,
        "run",
        side_effect=_rebuild_runner(
            fixture,
            calls,
            tamper_wheel=tamper_wheel,
            unexpected_output=unexpected_output,
        ),
    )

    failure = _rebuild_failure(fixture)
    assert expected in failure
    assert "private" not in failure


def test_rebuild_compare_fails_closed_when_uv_is_missing(
    tmp_path: Path, mocker: MockerFixture
) -> None:
    fixture = _build_fixture(tmp_path)
    mocker.patch.object(distributions.shutil, "which", return_value=None)
    run = mocker.patch.object(distributions.subprocess, "run")

    with pytest.raises(distributions.DistributionError, match="uv is required"):
        distributions.check_distributions(fixture.root, rebuild_compare=True)

    run.assert_not_called()


def test_rebuild_failure_does_not_echo_subprocess_output_or_temp_paths(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    mocker: MockerFixture,
) -> None:
    fixture = _build_fixture(tmp_path)
    calls: list[tuple[list[str], dict[str, Any]]] = []
    mocker.patch.object(distributions.shutil, "which", return_value="mock-uv")
    mocker.patch.object(
        distributions.subprocess,
        "run",
        side_effect=_rebuild_runner(fixture, calls, returncode=7),
    )

    assert distributions.main([str(fixture.root), "--rebuild-compare"]) == 1

    captured = capsys.readouterr()
    assert "reproducible distribution rebuild failed" in captured.err
    assert "private subprocess" not in captured.err
    assert str(tmp_path) not in captured.err


def _successful_smoke_runner(
    calls: list[tuple[list[str], dict[str, Any]]],
    source_checks: list[bool],
) -> Callable[..., subprocess.CompletedProcess[bytes]]:
    def run(command: Sequence[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        command_list = list(command)
        calls.append((command_list, kwargs))
        if "scripts/run_public_experiment.py" in command_list:
            cwd = Path(kwargs["cwd"])
            source_checks.append((cwd / "uv.lock").is_file())
        if command_list[-1] == "--version":
            stdout = b"0.1.0\n"
        elif command_list[-1] == "--help":
            stdout = b"Usage: ios-rehydrate [OPTIONS]\n"
        else:
            stdout = b""
        return subprocess.CompletedProcess(command_list, 0, stdout=stdout, stderr=b"")

    return run


def test_smoke_install_uses_isolated_uv_environments_and_sdist_source_checks(
    tmp_path: Path, mocker: MockerFixture
) -> None:
    fixture = _build_fixture(tmp_path)
    calls: list[tuple[list[str], dict[str, Any]]] = []
    source_checks: list[bool] = []
    mocker.patch.object(distributions.shutil, "which", return_value="mock-uv")
    mocker.patch.object(
        distributions.subprocess,
        "run",
        side_effect=_successful_smoke_runner(calls, source_checks),
    )

    distributions.check_distributions(fixture.root, smoke_install=True)

    venv_calls = [(command, kwargs) for command, kwargs in calls if command[1:2] == ["venv"]]
    assert len(venv_calls) == 2
    assert venv_calls[0][1]["cwd"] != venv_calls[1][1]["cwd"]
    installs = [command for command, _ in calls if command[1:3] == ["pip", "install"]]
    assert len(installs) == 2
    assert any(command[-1].endswith(".whl") for command in installs)
    assert any(command[-1].endswith(".tar.gz") for command in installs)
    assert any("scripts/run_public_experiment.py" in command for command, _ in calls)
    assert any("scripts/check_public_surface.py" in command for command, _ in calls)
    assert source_checks == [True]
    for _, kwargs in calls:
        assert kwargs["stdin"] is subprocess.DEVNULL
        assert kwargs["stdout"] in {subprocess.DEVNULL, subprocess.PIPE}
        assert kwargs["stderr"] in {subprocess.DEVNULL, subprocess.PIPE}


def test_smoke_install_fails_closed_when_uv_is_missing(
    tmp_path: Path, mocker: MockerFixture
) -> None:
    fixture = _build_fixture(tmp_path)
    mocker.patch.object(distributions.shutil, "which", return_value=None)
    run = mocker.patch.object(distributions.subprocess, "run")

    with pytest.raises(distributions.DistributionError, match="uv is required"):
        distributions.check_distributions(fixture.root, smoke_install=True)

    run.assert_not_called()


def test_smoke_failure_does_not_echo_subprocess_output_or_temp_paths(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    mocker: MockerFixture,
) -> None:
    fixture = _build_fixture(tmp_path)
    private_output = "private subprocess output"
    mocker.patch.object(distributions.shutil, "which", return_value="mock-uv")
    mocker.patch.object(
        distributions.subprocess,
        "run",
        return_value=subprocess.CompletedProcess(
            ["mock-uv"], 7, stdout=private_output.encode(), stderr=str(tmp_path).encode()
        ),
    )

    assert distributions.main([str(fixture.root), "--smoke-install"]) == 1

    captured = capsys.readouterr()
    assert "smoke environment creation failed" in captured.err
    assert private_output not in captured.err
    assert str(tmp_path) not in captured.err
