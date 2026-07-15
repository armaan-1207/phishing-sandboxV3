"""
Tests for the post-detonation telemetry that operates on the sandbox's
own screenshot output: QR decoding (detect_qr) and brand-impersonation
pHash matching (brand_phash.BrandMatcher).

PATCH NOTES (post-audit-review fixes):
  - M8: test_detect_qr_missing_file_fails_gracefully used a hardcoded
    "/tmp/this-file-does-not-exist-12345.png" path, which doesn't exist
    by default on Windows (matching the same class of bug already fixed
    elsewhere in this repo via tempfile.gettempdir()). Now built from
    tempfile.gettempdir() so the test is portable.
  - L15: `import imagehash` was previously done inline inside two test
    functions rather than at module scope. Moved to the top with the
    other imports -- no functional difference, just avoids the repeated
    inline import.
"""

import json
import os
import tempfile

import imagehash
import pytest

qrcode = pytest.importorskip("qrcode")
from PIL import Image, ImageDraw

from backend.phishing_sandbox_scan import detect_qr
from backend.brand_phash import BrandMatcher


def _make_qr_image(data, path):
    img = qrcode.make(data)
    img.save(path)


def test_detect_qr_finds_and_decodes_a_url(tmp_path):
    path = tmp_path / "qr.png"
    _make_qr_image("https://example.com/phish-target", str(path))

    found, urls = detect_qr(str(path))
    if found is None:
        pytest.skip("pyzbar C-library DLL not installed on native Windows host; runs inside Docker container")

    assert found is True
    assert urls == ["https://example.com/phish-target"]


def test_detect_qr_non_url_payload_is_found_but_not_returned_as_a_url(tmp_path):
    path = tmp_path / "qr_text.png"
    _make_qr_image("just some plain text, not a URL", str(path))

    found, urls = detect_qr(str(path))
    if found is None:
        pytest.skip("pyzbar C-library DLL not installed on native Windows host; runs inside Docker container")

    assert found is True
    assert urls == []  # found=True, but nothing recursion-worthy


def test_detect_qr_no_qr_present(tmp_path):
    path = tmp_path / "blank.png"
    img = Image.new("RGB", (200, 200), color="white")
    draw = ImageDraw.Draw(img)
    draw.text((20, 90), "no qr code here", fill="black")
    img.save(path)

    found, urls = detect_qr(str(path))
    if found is None:
        pytest.skip("pyzbar C-library DLL not installed on native Windows host; runs inside Docker container")

    assert found is False
    assert urls == []


def test_detect_qr_missing_file_fails_gracefully():
    missing_path = os.path.join(tempfile.gettempdir(), "this-file-does-not-exist-12345.png")
    found, urls = detect_qr(missing_path)
    assert found is None
    assert urls == []


def test_brand_matcher_with_no_reference_file_always_returns_none(tmp_path):
    matcher = BrandMatcher.from_file(str(tmp_path / "does_not_exist.json"))
    assert matcher.match(str(tmp_path / "anything.png")) is None


def test_brand_matcher_detects_a_close_match(tmp_path):
    # Build a simple synthetic "brand login page" image, hash it into a
    # reference set, then confirm the SAME image (the closest possible
    # case) is reported as a match against itself.
    img_path = tmp_path / "fake_login.png"
    img = Image.new("RGB", (300, 200), color="white")
    draw = ImageDraw.Draw(img)
    draw.rectangle([50, 50, 250, 150], fill="blue")
    draw.text((100, 90), "FakeBrand Login", fill="white")
    img.save(img_path)

    ref_hash = str(imagehash.phash(Image.open(img_path)))
    ref_path = tmp_path / "reference_hashes.json"
    ref_path.write_text(json.dumps({"fakebrand": ref_hash}))

    matcher = BrandMatcher.from_file(str(ref_path))
    result = matcher.match(str(img_path))

    assert result is not None
    assert result["brand"] == "fakebrand"
    assert result["similarity"] == 1.0  # identical image -> identical hash -> perfect match


def test_brand_matcher_no_match_below_threshold(tmp_path):
    # A reference hash for a totally different-looking image shouldn't
    # match an unrelated screenshot.
    ref_img_path = tmp_path / "ref.png"
    ref_img = Image.new("RGB", (300, 200), color="black")
    ImageDraw.Draw(ref_img).ellipse([20, 20, 280, 180], fill="red")
    ref_img.save(ref_img_path)

    ref_hash = str(imagehash.phash(Image.open(ref_img_path)))
    ref_path = tmp_path / "reference_hashes.json"
    ref_path.write_text(json.dumps({"unrelated_brand": ref_hash}))

    target_img_path = tmp_path / "target.png"
    target_img = Image.new("RGB", (300, 200), color="white")
    ImageDraw.Draw(target_img).rectangle([10, 10, 50, 50], fill="green")
    target_img.save(target_img_path)

    matcher = BrandMatcher.from_file(str(ref_path))
    assert matcher.match(str(target_img_path)) is None
