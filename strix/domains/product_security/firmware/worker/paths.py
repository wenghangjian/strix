"""Pure archive-member path canonicalization for restricted workers."""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass


MAXIMUM_COMPONENT_BYTES = 255
MAXIMUM_CANONICAL_PATH_BYTES = 4096
_DRIVE_PREFIX = re.compile(r"^[A-Za-z]:")


@dataclass(frozen=True, slots=True)
class CanonicalArchivePath:
    display_path: str
    canonical_path: str
    raw_name_b64: str | None
    path_encoding: str | None


class UnsafeArchivePath(ValueError):  # noqa: N818 - name fixed by the P2a contract
    """An archive member name cannot be represented by the P2a path policy."""


def canonicalize_archive_path(name: str) -> CanonicalArchivePath:
    if not name:
        raise UnsafeArchivePath("Archive member name is empty.")
    if "\x00" in name:
        raise UnsafeArchivePath("Archive member name contains NUL.")

    display_path = unicodedata.normalize("NFC", name)
    security_path = display_path.replace("\\", "/")
    if security_path.startswith("/"):
        raise UnsafeArchivePath("Absolute and UNC archive paths are forbidden.")

    canonical_components: list[str] = []
    for component in security_path.split("/"):
        if component in {"", "."}:
            continue
        if component == "..":
            raise UnsafeArchivePath("Archive path traversal is forbidden.")
        if not canonical_components and _DRIVE_PREFIX.match(component):
            raise UnsafeArchivePath("Drive-prefixed archive paths are forbidden.")
        if _utf8_size(component) > MAXIMUM_COMPONENT_BYTES:
            raise UnsafeArchivePath("Archive path component exceeds its byte limit.")
        canonical_components.append(component)

    if not canonical_components:
        raise UnsafeArchivePath("Archive member name has no canonical components.")
    canonical_path = "/".join(canonical_components)
    if _utf8_size(canonical_path) > MAXIMUM_CANONICAL_PATH_BYTES:
        raise UnsafeArchivePath("Canonical archive path exceeds its byte limit.")

    return CanonicalArchivePath(
        display_path=display_path,
        canonical_path=canonical_path,
        raw_name_b64=None,
        path_encoding=None,
    )


def _utf8_size(value: str) -> int:
    try:
        return len(value.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise UnsafeArchivePath("Archive member name is not valid UTF-8.") from exc
