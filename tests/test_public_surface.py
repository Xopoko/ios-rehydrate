# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 iOS Rehydrate contributors
"""Tests for the repository public-surface scanner."""

from __future__ import annotations

import gzip
import io
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parents[1] / "scripts" / "check_public_surface.py"


def run_scanner(
    root: Path | None,
    *,
    denylist: Path | None = None,
    cwd: Path | None = None,
    git_index: bool = False,
    archive: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    command = [sys.executable, str(SCRIPT)]
    if denylist is not None:
        command.extend(["--denylist", str(denylist)])
    if git_index:
        command.append("--git-index")
    if archive is not None:
        command.extend(["--archive", str(archive)])
    if root is not None:
        command.append(str(root))
    return subprocess.run(  # noqa: S603
        command,
        cwd=cwd,
        check=False,
        capture_output=True,
        text=True,
    )


def run_git(root: Path, *arguments: str, input_text: str | None = None) -> str:
    executable = shutil.which("git")
    if executable is None:
        pytest.skip("Git is not available")
    result = subprocess.run(  # noqa: S603
        [executable, "-C", str(root), *arguments],
        check=True,
        capture_output=True,
        input=input_text,
        text=True,
    )
    return result.stdout


def finding_set(result: subprocess.CompletedProcess[str]) -> set[tuple[str, str, int]]:
    findings: set[tuple[str, str, int]] = set()
    for line in result.stdout.splitlines():
        category, path, line_number = line.split("\t")
        findings.add((category, path, int(line_number)))
    return findings


def test_clean_tree_skips_generated_directories_and_allows_exact_provenance(
    tmp_path: Path,
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "main.py").write_text("answer = 42\n", encoding="utf-8")
    lock_hash = "a" * 64
    revision = "b" * 40
    lock_url = f"https://github.com/public/project/commit/{revision}"
    (root / "uv.lock").write_text(
        f'hash = "sha256:{lock_hash}"\nrev = "{revision}"\nurl = "{lock_url}"\n',
        encoding="utf-8",
    )
    (root / "public-urls.txt").write_text(
        "\n".join(
            (
                "https://pypi.org/simple",
                "https://files.pythonhosted.org/packages/public.whl",
                "https://www.gnu.org/licenses/gpl-3.0.html",
                "https://fsf.org/",
            )
        ),
        encoding="utf-8",
    )

    hidden_address = "owner" + chr(64) + "example.invalid"
    for directory_name in (".git", ".venv", "cache", "build", "dist"):
        directory = root / directory_name
        directory.mkdir()
        (directory / "ignored.txt").write_text(hidden_address, encoding="utf-8")

    result = run_scanner(root)

    assert result.returncode == 0, result.stderr
    assert result.stdout == ""


def test_default_root_and_location_only_output(tmp_path: Path) -> None:
    secret_address = "person" + chr(64) + "private.invalid"
    (tmp_path / "contact.txt").write_text(f"first line\n{secret_address}\n", encoding="utf-8")

    result = run_scanner(None, cwd=tmp_path)

    assert result.returncode == 1
    assert finding_set(result) == {("email-address", "contact.txt", 2)}
    assert secret_address not in result.stdout
    assert secret_address not in result.stderr
    assert all(len(line.split("\t")) == 3 for line in result.stdout.splitlines())


@pytest.mark.parametrize(
    "suffix",
    [
        ".ipa",
        ".mobileprovision",
        ".p12",
        ".key",
        ".plist",
        ".db",
        ".sqlite",
        ".log",
        ".jsonl",
        ".backup",
    ],
)
def test_forbidden_private_extensions_are_rejected(tmp_path: Path, suffix: str) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    filename = "private" + suffix
    (root / filename).write_text("otherwise harmless\n", encoding="utf-8")

    result = run_scanner(root)

    assert result.returncode == 1
    assert finding_set(result) == {("forbidden-extension", filename, 1)}


def test_binary_content_is_rejected(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "payload.dat").write_bytes(b"text\x00binary")

    result = run_scanner(root)

    assert result.returncode == 1
    assert finding_set(result) == {("binary-content", "payload.dat", 1)}


def test_symlink_is_rejected_without_reading_target(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("private but outside\n", encoding="utf-8")
    link = root / "linked.txt"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("symlink creation is not available")

    result = run_scanner(root)

    assert result.returncode == 1
    assert finding_set(result) == {("symlink", "linked.txt", 1)}


def test_directory_symlink_is_rejected_without_traversal(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    private_address = "owner" + chr(64) + "private.invalid"
    (outside / "secret.txt").write_text(private_address, encoding="utf-8")
    link = root / "cache"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlink creation is not available")

    result = run_scanner(root)

    assert result.returncode == 1
    assert finding_set(result) == {("symlink", "cache", 1)}
    assert private_address not in result.stdout


@pytest.mark.skipif(sys.platform != "win32", reason="Windows junction behavior")
def test_windows_junction_is_rejected_as_reparse_point(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    junction = root / "junction"
    executable = shutil.which("cmd.exe")
    if executable is None:
        pytest.skip("cmd.exe is not available")
    creation = subprocess.run(  # noqa: S603
        [executable, "/d", "/c", "mklink", "/J", str(junction), str(outside)],
        check=False,
        capture_output=True,
        text=True,
    )
    if creation.returncode != 0:
        pytest.skip("junction creation is not available")

    try:
        result = run_scanner(root)
    finally:
        junction.rmdir()

    assert result.returncode == 1
    assert finding_set(result) == {("reparse-point", "junction", 1)}


def test_private_text_categories_are_detected(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    separator = "\\"
    fixtures = {
        "windows.txt": "C:" + separator + "Users" + separator + "owner" + separator + "file.txt",
        "unc.txt": separator * 2 + "server" + separator + "share" + separator + "file.txt",
        "unix.txt": "/" + "home" + "/owner/file.txt",
        "github.txt": "gh" + "p_" + "Ab3" * 12,
        "apple.txt": "abcd-" + "efgh-ijkl-mnop",
        "legacy.txt": "0123456789abcdef" * 2 + "01234567",
        "modern.txt": "00008030-" + "001A2B3C4D5E6F70",
        "uuid.txt": "123e4567-" + "e89b-12d3-a456-426614174000",
        "key.txt": "-----BEGIN " + "PRIVATE KEY-----",
        "generic.txt": '"api_' + 'token": "' + 'Aa0_Bb1_Cc2_Dd3_Ee4_Ff5_"',
    }
    expected_categories = {
        "windows.txt": "windows-user-path",
        "unc.txt": "unc-path",
        "unix.txt": "unix-user-path",
        "github.txt": "token-secret",
        "apple.txt": "token-secret",
        "legacy.txt": "legacy-device-id",
        "modern.txt": "modern-device-id",
        "uuid.txt": "uuid",
        "key.txt": "pem-private-key",
        "generic.txt": "token-secret",
    }
    for filename, value in fixtures.items():
        (root / filename).write_text(value + "\n", encoding="utf-8")

    result = run_scanner(root)

    assert result.returncode == 1
    findings = finding_set(result)
    for filename, category in expected_categories.items():
        assert (category, filename, 1) in findings
        assert fixtures[filename] not in result.stdout


def test_private_url_hosts_and_url_userinfo_are_rejected(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    private_url = "https://" + "git.internal.invalid/team/project"
    credentialed_url = "https://" + "person:private-value" + chr(64) + "github.com/public/project"
    (root / "links.txt").write_text(
        "\n".join(
            (
                "https://github.com/public/project/commit/" + "a" * 40,
                "https://pypi.org/project/public/",
                private_url,
                credentialed_url,
            )
        ),
        encoding="utf-8",
    )

    result = run_scanner(root)

    assert result.returncode == 1
    assert finding_set(result) == {
        ("url-host-not-allowlisted", "links.txt", 3),
        ("url-userinfo", "links.txt", 4),
    }
    assert private_url not in result.stdout
    assert credentialed_url not in result.stdout


def test_allowlisted_url_components_are_scanned_except_github_provenance(
    tmp_path: Path,
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    public_base = "https://" + "github.com/public/project"
    revision = "a" * 40
    modern_identifier = "00008030-" + "001A2B3C4D5E6F70"
    private_address = "person" + chr(64) + "private.invalid"
    other_identifier = "b" * 40
    (root / "links.txt").write_text(
        "\n".join(
            (
                f"{public_base}/commit/{revision}",
                f"{public_base}/tree/{revision}/src",
                f"{public_base}/issues/{modern_identifier}",
                f"{public_base}?path=C%3A%5CUsers%5Cowner%5Cfile.txt",
                f"{public_base}#contact={private_address.replace(chr(64), '%40')}",
                f"{public_base}/blob/{other_identifier}/src/module.py",
            )
        ),
        encoding="utf-8",
    )

    result = run_scanner(root)

    assert result.returncode == 1
    assert finding_set(result) == {
        ("modern-device-id", "links.txt", 3),
        ("windows-user-path", "links.txt", 4),
        ("email-address", "links.txt", 5),
    }
    assert modern_identifier not in result.stdout
    assert private_address not in result.stdout


def test_uv_lock_only_allows_an_exact_revision_assignment(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    revision = "a" * 40
    private_identifier = "b" * 40
    private_uuid = "123e4567-" + "e89b-12d3-a456-426614174000"
    (root / "uv.lock").write_text(
        f'rev = "{revision}"\ndevice = "{private_identifier}"\nid = "{private_uuid}"\n',
        encoding="utf-8",
    )

    result = run_scanner(root)

    assert result.returncode == 1
    assert finding_set(result) == {
        ("legacy-device-id", "uv.lock", 2),
        ("uuid", "uv.lock", 3),
    }


def test_filename_is_scanned(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    filename = "owner" + chr(64) + "private.invalid.txt"
    (root / filename).write_bytes(b"private\x00binary")

    result = run_scanner(root)

    assert result.returncode == 1
    findings = finding_set(result)
    assert {(category, line) for category, _, line in findings} == {
        ("binary-content", 1),
        ("email-address", 1),
    }
    displayed_paths = {path for _, path, _ in findings}
    assert len(displayed_paths) == 1
    displayed = displayed_paths.pop()
    assert displayed.startswith("<redacted-path:")
    assert len(displayed) < 64
    assert filename not in result.stdout
    assert filename not in result.stderr
    assert run_scanner(root).stdout == result.stdout


def test_external_denylist_uses_nfc_and_casefold_and_stays_location_only(
    tmp_path: Path,
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    denylist = tmp_path / "local-denylist.txt"
    denylist.write_text("Caf\u00e9-Owner\n", encoding="utf-8")
    differently_normalized = "CAFE\u0301-OWNER"
    (root / "notes.txt").write_text(
        f"safe\ncontains {differently_normalized} here\n", encoding="utf-8"
    )

    result = run_scanner(root, denylist=denylist)

    assert result.returncode == 1
    assert finding_set(result) == {("private-denylist", "notes.txt", 2)}
    assert differently_normalized not in result.stdout
    assert differently_normalized not in result.stderr


def test_denylist_inside_scan_root_is_cli_misuse(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    denylist = root / "deny.txt"
    denylist.write_text("private-value\n", encoding="utf-8")

    result = run_scanner(root, denylist=denylist)

    assert result.returncode == 2
    assert result.stdout == ""
    assert "outside the scan root" in result.stderr


def test_git_index_scans_exact_staged_blob_inside_excluded_directory(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    run_git(root, "init", "--quiet")
    excluded = root / "dist"
    excluded.mkdir()
    private_address = "staged" + chr(64) + "private.invalid"
    staged_file = excluded / "private.txt"
    staged_file.write_text(private_address + "\n", encoding="utf-8")
    run_git(root, "add", "--force", "dist/private.txt")
    staged_file.write_text("clean worktree content\n", encoding="utf-8")

    workspace_result = run_scanner(root)
    index_result = run_scanner(root, git_index=True)

    assert workspace_result.returncode == 0, workspace_result.stderr
    assert index_result.returncode == 1
    assert finding_set(index_result) == {("email-address", "dist/private.txt", 1)}
    assert private_address not in index_result.stdout


def test_git_index_refuses_symlink_and_submodule_modes(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    run_git(root, "init", "--quiet")
    run_git(root, "config", "user.name", "Public Test")
    run_git(root, "config", "user.email", "public" + chr(64) + "example.invalid")
    link_blob = run_git(root, "hash-object", "-w", "--stdin", input_text="../outside").strip()
    run_git(root, "update-index", "--add", "--cacheinfo", "120000", link_blob, "linked")
    empty_tree = run_git(root, "mktree", input_text="").strip()
    commit = run_git(root, "commit-tree", empty_tree, "-m", "nested").strip()
    run_git(root, "update-index", "--add", "--cacheinfo", "160000", commit, "vendor")

    result = run_scanner(root, git_index=True)

    assert result.returncode == 1
    assert finding_set(result) == {
        ("submodule", "vendor", 1),
        ("symlink", "linked", 1),
    }


def test_wheel_members_paths_and_contents_are_scanned_without_extraction(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    archive = root / "package-0.1-py3-none-any.whl"
    private_url = "https://" + "private.invalid/team/project"
    with zipfile.ZipFile(archive, "w") as wheel:
        wheel.writestr("package/module.py", f'origin = "{private_url}"\n')
        wheel.writestr("../escape.txt", "harmless\n")

    result = run_scanner(root, archive=archive)

    assert result.returncode == 1, result.stderr
    assert ("url-host-not-allowlisted", "package/module.py", 1) in finding_set(result)
    assert ("unsafe-archive-path", "../escape.txt", 1) in finding_set(result)
    assert private_url not in result.stdout


def test_wheel_rejects_zip_comments_and_extra_fields_without_disclosing_them(
    tmp_path: Path,
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    archive = root / "package-0.1-py3-none-any.whl"
    private_address = ("archive" + chr(64) + "private.invalid").encode()
    member = zipfile.ZipInfo("package/module.py")
    member.comment = private_address
    member.extra = b"\xfe\xca" + len(private_address).to_bytes(2, "little") + private_address
    with zipfile.ZipFile(archive, "w") as wheel:
        wheel.comment = private_address
        wheel.writestr(member, "value = 1\n")

    result = run_scanner(root, archive=archive)

    assert result.returncode == 1, result.stderr
    assert finding_set(result) == {
        ("archive-comment", archive.name, 1),
        ("archive-member-comment", "package/module.py", 1),
        ("archive-member-extra", "package/module.py", 1),
    }
    assert private_address.decode() not in result.stdout


def test_sdist_members_contents_and_links_are_scanned_without_extraction(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    archive = root / "package-0.1.tar.gz"
    private_address = "archive" + chr(64) + "private.invalid"
    data = (private_address + "\n").encode()
    archive_buffer = io.BytesIO()
    with tarfile.open(fileobj=archive_buffer, mode="w:gz") as source_distribution:
        regular = tarfile.TarInfo("package-0.1/contact.txt")
        regular.size = len(data)
        source_distribution.addfile(regular, io.BytesIO(data))
        link = tarfile.TarInfo("package-0.1/linked")
        link.type = tarfile.SYMTYPE
        link.linkname = "../outside"
        source_distribution.addfile(link)
    archive.write_bytes(archive_buffer.getvalue())

    result = run_scanner(root, archive=archive)

    assert result.returncode == 1, result.stderr
    assert finding_set(result) == {
        ("archive-link", "package-0.1/linked", 1),
        ("email-address", "package-0.1/contact.txt", 1),
    }
    assert private_address not in result.stdout


def test_sdist_rejects_gzip_optional_metadata_without_disclosing_it(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    archive = root / "package-0.1.tar.gz"
    archive_buffer = io.BytesIO()
    with tarfile.open(fileobj=archive_buffer, mode="w:gz") as source_distribution:
        regular = tarfile.TarInfo("package-0.1/module.py")
        payload = b"value = 1\n"
        regular.size = len(payload)
        source_distribution.addfile(regular, io.BytesIO(payload))
    gzip_data = archive_buffer.getvalue()
    private_address = ("archive" + chr(64) + "private.invalid").encode()
    archive.write_bytes(
        gzip_data[:3]
        + bytes([gzip_data[3] | 0x10])
        + gzip_data[4:10]
        + private_address
        + b"\x00"
        + gzip_data[10:]
    )

    result = run_scanner(root, archive=archive)

    assert result.returncode == 1, result.stderr
    assert ("archive-gzip-metadata", archive.name, 1) in finding_set(result)
    assert private_address.decode() not in result.stdout


def test_sdist_rejects_gzip_trailer_without_disclosing_it(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    archive = root / "package-0.1.tar.gz"
    archive_buffer = io.BytesIO()
    with tarfile.open(fileobj=archive_buffer, mode="w:gz") as source_distribution:
        regular = tarfile.TarInfo("package-0.1/module.py")
        payload = b"value = 1\n"
        regular.size = len(payload)
        source_distribution.addfile(regular, io.BytesIO(payload))
    private_address = ("gzip" + chr(64) + "private.invalid").encode()
    archive.write_bytes(archive_buffer.getvalue() + private_address)

    result = run_scanner(root, archive=archive)

    assert result.returncode == 1, result.stderr
    assert ("archive-gzip-framing", archive.name, 1) in finding_set(result)
    assert private_address.decode() not in result.stdout
    assert private_address.decode() not in result.stderr


def test_sdist_rejects_tar_trailer_without_disclosing_it(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    archive = root / "package-0.1.tar.gz"
    archive_buffer = io.BytesIO()
    with tarfile.open(fileobj=archive_buffer, mode="w:") as source_distribution:
        regular = tarfile.TarInfo("package-0.1/module.py")
        payload = b"value = 1\n"
        regular.size = len(payload)
        source_distribution.addfile(regular, io.BytesIO(payload))
    tar_data = bytearray(archive_buffer.getvalue())
    private_address = ("tar" + chr(64) + "private.invalid").encode()
    tar_data[-len(private_address) :] = private_address
    archive.write_bytes(gzip.compress(tar_data, mtime=0))

    result = run_scanner(root, archive=archive)

    assert result.returncode == 1, result.stderr
    assert finding_set(result) == {("archive-tar-framing", archive.name, 1)}
    assert private_address.decode() not in result.stdout
    assert private_address.decode() not in result.stderr


def test_sdist_rejects_nonzero_member_padding_without_disclosing_it(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    archive = root / "package-0.1.tar.gz"
    archive_buffer = io.BytesIO()
    payload = b"value = 1\n"
    with tarfile.open(fileobj=archive_buffer, mode="w:") as source_distribution:
        regular = tarfile.TarInfo("package-0.1/module.py")
        regular.size = len(payload)
        source_distribution.addfile(regular, io.BytesIO(payload))
    tar_data = bytearray(archive_buffer.getvalue())
    private_address = ("padding" + chr(64) + "private.invalid").encode()
    padding_start = 512 + len(payload)
    tar_data[padding_start : padding_start + len(private_address)] = private_address
    archive.write_bytes(gzip.compress(tar_data, mtime=0))

    result = run_scanner(root, archive=archive)

    assert result.returncode == 1, result.stderr
    assert finding_set(result) == {("archive-tar-framing", archive.name, 1)}
    assert private_address.decode() not in result.stdout
    assert private_address.decode() not in result.stderr


def test_sdist_rejects_tar_identity_metadata_without_disclosing_it(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    archive = root / "package-0.1.tar.gz"
    archive_buffer = io.BytesIO()
    private_uname = "owner" + chr(64) + "private.invalid"
    with tarfile.open(fileobj=archive_buffer, mode="w:gz") as source_distribution:
        regular = tarfile.TarInfo("package-0.1/module.py")
        regular.uname = private_uname
        payload = b"value = 1\n"
        regular.size = len(payload)
        source_distribution.addfile(regular, io.BytesIO(payload))
    archive.write_bytes(archive_buffer.getvalue())

    result = run_scanner(root, archive=archive)

    assert result.returncode == 1, result.stderr
    assert finding_set(result) == {
        ("archive-tar-identity-metadata", "package-0.1/module.py", 1),
        ("email-address", "package-0.1/module.py", 1),
    }
    assert private_uname not in result.stdout
    assert private_uname not in result.stderr


def test_sdist_scans_pax_header_keys_without_disclosing_them(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    archive = root / "package-0.1.tar.gz"
    private_key = "private.operator" + chr(64) + "private.invalid"
    archive_buffer = io.BytesIO()
    with tarfile.open(fileobj=archive_buffer, mode="w:gz") as source_distribution:
        regular = tarfile.TarInfo("package-0.1/module.py")
        payload = b"value = 1\n"
        regular.size = len(payload)
        regular.pax_headers = {private_key: "1"}
        source_distribution.addfile(regular, io.BytesIO(payload))
    archive.write_bytes(archive_buffer.getvalue())

    result = run_scanner(root, archive=archive)

    assert result.returncode == 1, result.stderr
    assert ("email-address", "package-0.1/module.py", 1) in finding_set(result)
    assert private_key not in result.stdout


def test_missing_root_is_cli_misuse(tmp_path: Path) -> None:
    result = run_scanner(tmp_path / "missing")

    assert result.returncode == 2
    assert result.stdout == ""
    assert "error:" in result.stderr
