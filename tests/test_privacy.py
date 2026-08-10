# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 iOS Rehydrate contributors

from pathlib import Path

from ios_rehydrate.privacy import device_reference, file_label, opaque_ref, sanitize_text


def test_opaque_ref_is_stable_and_does_not_embed_input() -> None:
    private_value = "selector-" + "A" * 24
    first = opaque_ref(private_value, namespace="device")
    second = opaque_ref(private_value, namespace="device")

    assert first == second
    assert first.startswith("device_")
    assert private_value not in first


def test_device_reference_is_stable_across_hex_casing() -> None:
    identifier = "ABCDEF12" + "-" + "1234567890ABCDEF"

    assert device_reference(identifier) == device_reference(identifier.casefold())


def test_sanitize_text_removes_common_identifiers() -> None:
    windows_path = "C:" + "\\" + "Users" + "\\" + "local" + "\\" + "input.ipa"
    email = "operator" + "@" + "example.test"
    device_id = "A" * 8 + "-" + "B" * 16

    rendered = sanitize_text(f"failed for {email} on {device_id} at {windows_path}")

    assert windows_path not in rendered
    assert email not in rendered
    assert device_id not in rendered
    assert "<local-path>" in rendered
    assert "<email>" in rendered
    assert "<device-id>" in rendered


def test_sanitize_text_removes_spaced_windows_and_unc_paths_without_suffix_leakage() -> None:
    separator = chr(92)
    windows_path = "C:" + separator + "Users" + separator + "Synthetic Person/secret/thing.ipa"
    unc_path = separator * 2 + "server name" + separator + "share name/private file.ipa"

    windows_rendered = sanitize_text(f"failed at {windows_path}")
    unc_rendered = sanitize_text(f"failed at {unc_path}")

    for original, rendered in (
        (windows_path, windows_rendered),
        (unc_path, unc_rendered),
    ):
        assert original not in rendered
        assert "Person" not in rendered
        assert "private file" not in rendered
        assert rendered.endswith("<local-path>")


def test_file_label_drops_parent_and_stem() -> None:
    label = file_label(Path("sensitive") / "private-name.ipa")
    assert label == "local-file.ipa"
