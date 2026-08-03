from __future__ import annotations

import unicodedata

import pytest

from strix.domains.product_security.firmware.worker.paths import (
    UnsafeArchivePath,
    canonicalize_archive_path,
)


@pytest.mark.parametrize(
    "name",
    [
        "",
        ".",
        "/etc/passwd",
        "//server/share/file",
        "../etc/passwd",
        "a/../../etc/passwd",
        r"..\etc\passwd",
        r"C:\Windows\system.ini",
        r"c:relative.txt",
        r"\\server\share\file",
        "a\x00b",
        "invalid-\udcff-name",
    ],
)
def test_unsafe_path_is_rejected(name: str) -> None:
    with pytest.raises(UnsafeArchivePath):
        canonicalize_archive_path(name)


@pytest.mark.parametrize(
    ("name", "canonical"),
    [
        ("a//b", "a/b"),
        ("a/./b", "a/b"),
        ("./a///./b/", "a/b"),
        (r"a\b\file", "a/b/file"),
    ],
)
def test_separators_and_dot_components_are_canonicalized(
    name: str,
    canonical: str,
) -> None:
    path = canonicalize_archive_path(name)

    assert path.display_path == unicodedata.normalize("NFC", name)
    assert path.canonical_path == canonical
    assert path.raw_name_b64 is None
    assert path.path_encoding is None


def test_unicode_is_normalized_to_nfc() -> None:
    decomposed = "config/cafe\u0301.txt"

    path = canonicalize_archive_path(decomposed)

    assert path.display_path == "config/caf\N{LATIN SMALL LETTER E WITH ACUTE}.txt"
    assert path.canonical_path == "config/caf\N{LATIN SMALL LETTER E WITH ACUTE}.txt"


def test_normalized_paths_collide_but_case_remains_significant() -> None:
    dotted = canonicalize_archive_path("a/./b")
    repeated = canonicalize_archive_path("a//b")
    lowercase = canonicalize_archive_path("a/b")
    uppercase = canonicalize_archive_path("A/B")

    assert dotted.canonical_path == repeated.canonical_path == lowercase.canonical_path
    assert uppercase.canonical_path != lowercase.canonical_path


@pytest.mark.parametrize(
    "name",
    [
        "a" * 256,
        f"ok/{'a' * 256}",
        "/".join(["a" * 255] * 17),
    ],
)
def test_utf8_length_limits_are_enforced(name: str) -> None:
    with pytest.raises(UnsafeArchivePath):
        canonicalize_archive_path(name)


def test_component_limit_is_measured_in_utf8_bytes() -> None:
    assert len("\N{EURO SIGN}" * 85) == 85
    accepted = canonicalize_archive_path("\N{EURO SIGN}" * 85)

    assert len(accepted.canonical_path.encode("utf-8")) == 255
    with pytest.raises(UnsafeArchivePath):
        canonicalize_archive_path("\N{EURO SIGN}" * 86)
