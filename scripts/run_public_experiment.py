# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 iOS Rehydrate contributors
"""Run the deterministic, device-free public smoke experiment."""

from __future__ import annotations

import hashlib
import io
import json
import plistlib
import tempfile
import zipfile
from pathlib import Path
from typing import Any

from ios_rehydrate.ipa import public_summary, validate_ipa

EXPECTED_RESULT = (
    Path(__file__).parents[1] / "experiments" / "public-smoke" / "expected-result.json"
)
SYNTHETIC_BUNDLE = "test.invalid.public-fixture"
SYNTHETIC_STORE_ID = "424242"


def _zip_entry(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_STORED
    info.create_system = 3
    info.external_attr = 0o100644 << 16
    return info


def build_fixture() -> bytes:
    """Build a rights-clear, structurally App Store-shaped synthetic archive."""
    app_root = "Payload/PublicFixture.app"
    info = plistlib.dumps(
        {
            "CFBundleExecutable": "PublicFixture",
            "CFBundleIdentifier": SYNTHETIC_BUNDLE,
            "CFBundleShortVersionString": "1.0",
            "CFBundleVersion": "1",
            "MinimumOSVersion": "16.0",
        },
        fmt=plistlib.FMT_XML,
        sort_keys=True,
    )
    metadata = plistlib.dumps(
        {
            "itemId": int(SYNTHETIC_STORE_ID),
            "softwareVersionBundleId": SYNTHETIC_BUNDLE,
        },
        fmt=plistlib.FMT_XML,
        sort_keys=True,
    )
    files = {
        "iTunesMetadata.plist": metadata,
        f"{app_root}/Info.plist": info,
        f"{app_root}/PublicFixture": b"synthetic executable placeholder\n",
        f"{app_root}/SC_Info/PublicFixture.sinf": b"synthetic authorization placeholder\n",
        f"{app_root}/_CodeSignature/CodeResources": b"synthetic signature placeholder\n",
    }
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        for name in sorted(files):
            archive.writestr(_zip_entry(name), files[name])
    return stream.getvalue()


def run_experiment() -> dict[str, Any]:
    fixture = build_fixture()
    initial_digest = hashlib.sha256(fixture).hexdigest()
    with tempfile.TemporaryDirectory(prefix="ios-rehydrate-public-") as directory:
        path = Path(directory) / "fixture.ipa"
        path.write_bytes(fixture)
        first = public_summary(
            validate_ipa(
                path,
                expected_bundle_id=SYNTHETIC_BUNDLE,
                expected_store_id=SYNTHETIC_STORE_ID,
            )
        )
        second = public_summary(
            validate_ipa(
                path,
                expected_bundle_id=SYNTHETIC_BUNDLE,
                expected_store_id=SYNTHETIC_STORE_ID,
            )
        )
        unchanged = hashlib.sha256(path.read_bytes()).hexdigest() == initial_digest
    return {
        "experiment": "public-smoke-v1",
        "fixture_sha256": initial_digest,
        "input_unchanged": unchanged,
        "repeat_equal": first == second,
        "summary": first,
    }


def main() -> int:
    actual = run_experiment()
    expected = json.loads(EXPECTED_RESULT.read_text(encoding="utf-8"))
    passed = actual == expected
    print(
        json.dumps(
            {
                "experiment": "public-smoke-v1",
                "passed": passed,
                "input_unchanged": actual["input_unchanged"],
                "repeat_equal": actual["repeat_equal"],
            },
            sort_keys=True,
        )
    )
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
