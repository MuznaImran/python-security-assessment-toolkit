"""Streaming SHA-256 and portable JSON file-integrity manifests.

Manifest paths are relative to a trusted root. This module rejects absolute
paths, traversal, symlinks, and duplicate entries before verifying any file.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Iterable


_CHUNK_SIZE = 1024 * 1024
_HEX_DIGITS = frozenset("0123456789abcdef")


def _path_key(value: str | Path) -> str:
    """Return a comparison key that follows the current platform's rules."""
    return os.path.normcase(os.fspath(value))


def _hash_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while chunk := stream.read(_CHUNK_SIZE):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def sha256_file(path: str | Path) -> str:
    """Hash a regular file in chunks, without loading it entirely into memory."""
    source = Path(path)
    if source.is_symlink() or not source.is_file():
        raise ValueError("path must be an existing regular file, not a symlink")
    return _hash_file(source)[0]


def find_duplicate_files(paths: Iterable[str | Path]) -> list[dict[str, object]]:
    """Group regular files that have identical size and SHA-256 content.

    Hashes are calculated only for size groups containing at least two files.
    Symlinks and repeated path arguments are rejected.
    """
    if isinstance(paths, (str, bytes, Path)):
        raise TypeError("paths must be an iterable of file paths")
    by_size: dict[int, list[Path]] = {}
    seen: set[str] = set()
    for value in paths:
        source = Path(value)
        if source.is_symlink() or not source.is_file():
            raise ValueError(f"path must be an existing regular file: {source}")
        resolved = source.resolve(strict=True)
        key = _path_key(resolved)
        if key in seen:
            raise ValueError(f"duplicate path argument: {source}")
        seen.add(key)
        by_size.setdefault(resolved.stat().st_size, []).append(resolved)

    groups: list[dict[str, object]] = []
    for size, candidates in by_size.items():
        if len(candidates) < 2:
            continue
        by_digest: dict[str, list[str]] = {}
        for candidate in candidates:
            digest, _ = _hash_file(candidate)
            by_digest.setdefault(digest, []).append(str(candidate))
        for digest, matches in by_digest.items():
            if len(matches) > 1:
                groups.append(
                    {"sha256": digest, "size_bytes": size, "files": sorted(matches)}
                )
    groups.sort(key=lambda group: (-len(group["files"]), str(group["sha256"])))
    return groups


def _root_path(root: str | Path) -> Path:
    trusted_root = Path(root).resolve(strict=True)
    if not trusted_root.is_dir():
        raise ValueError("root must be an existing directory")
    return trusted_root


def _validate_relative_path(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("manifest path must be a non-empty string")
    if "\\" in value or "\x00" in value or ":" in value:
        raise ValueError(f"invalid portable manifest path: {value!r}")
    parts = value.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise ValueError(f"manifest path must be relative without traversal: {value!r}")
    return value


def _checked_path(root: Path, relative: str) -> Path:
    candidate = root.joinpath(*relative.split("/"))
    current = root
    for part in relative.split("/"):
        current = current / part
        if current.is_symlink():
            raise ValueError(f"symlinks are not allowed in manifest paths: {relative!r}")
    # Path.resolve also catches junctions and other redirects that is_symlink
    # may not report on every platform.
    resolved = candidate.resolve(strict=False)
    if not resolved.is_relative_to(root):
        raise ValueError(f"manifest path escapes root: {relative!r}")
    return candidate


def create_integrity_manifest(
    paths: Iterable[str | Path], root: str | Path
) -> dict[str, object]:
    """Build a JSON-serializable SHA-256 manifest for files under ``root``.

    Input paths may be absolute or relative to root. Every resulting manifest
    entry uses forward-slash relative paths and records its byte size.
    """
    trusted_root = _root_path(root)
    if isinstance(paths, (str, bytes, Path)):
        raise TypeError("paths must be an iterable of file paths")

    entries: list[dict[str, object]] = []
    seen: set[str] = set()
    for path in paths:
        given = Path(path)
        if ".." in given.parts:
            raise ValueError(f"file path must not contain traversal: {path!s}")
        candidate = given if given.is_absolute() else trusted_root / given
        current = candidate
        while current != current.parent:
            if current.is_symlink():
                raise ValueError(f"symlinks are not allowed in file paths: {path!s}")
            if current == trusted_root:
                break
            current = current.parent
        resolved = candidate.resolve(strict=True)
        if not resolved.is_relative_to(trusted_root):
            raise ValueError(f"file escapes root: {path!s}")
        relative = _validate_relative_path(resolved.relative_to(trusted_root).as_posix())
        checked = _checked_path(trusted_root, relative)
        if candidate.is_symlink() or not checked.is_file():
            raise ValueError(f"file must be regular and not a symlink: {path!s}")
        key = _path_key(relative)
        if key in seen:
            raise ValueError(f"duplicate file path: {relative!r}")
        seen.add(key)
        digest, size = _hash_file(checked)
        entries.append({"path": relative, "sha256": digest, "size_bytes": size})

    if not entries:
        raise ValueError("provide at least one file")
    entries.sort(key=lambda entry: _path_key(str(entry["path"])))
    return {"schema_version": 1, "algorithm": "sha256", "files": entries}


def verify_integrity_manifest(
    manifest: dict[str, object], root: str | Path
) -> dict[str, object]:
    """Compare files with a manifest and report missing or modified paths.

    Invalid or unsafe manifests raise ``ValueError``. A valid manifest with
    missing or modified files returns ``ok=False`` and lists those paths.
    """
    trusted_root = _root_path(root)
    if not isinstance(manifest, dict):
        raise ValueError("manifest must be a JSON object")
    if manifest.get("schema_version") != 1 or manifest.get("algorithm") != "sha256":
        raise ValueError("unsupported manifest schema or digest algorithm")
    files = manifest.get("files")
    if not isinstance(files, list) or not files:
        raise ValueError("manifest files must be a non-empty list")

    validated: list[tuple[str, str, int]] = []
    seen: set[str] = set()
    for entry in files:
        if not isinstance(entry, dict):
            raise ValueError("every manifest entry must be a JSON object")
        relative = _validate_relative_path(entry.get("path"))
        digest = entry.get("sha256")
        size = entry.get("size_bytes")
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or not set(digest) <= _HEX_DIGITS
        ):
            raise ValueError(f"invalid SHA-256 digest for {relative!r}")
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            raise ValueError(f"invalid byte size for {relative!r}")
        key = _path_key(relative)
        if key in seen:
            raise ValueError(f"duplicate manifest path: {relative!r}")
        seen.add(key)
        _checked_path(trusted_root, relative)
        validated.append((relative, digest, size))

    missing: list[str] = []
    modified: list[str] = []
    for relative, expected_digest, expected_size in validated:
        path = _checked_path(trusted_root, relative)
        if not path.exists():
            missing.append(relative)
            continue
        if not path.is_file():
            modified.append(relative)
            continue
        actual_digest, actual_size = _hash_file(path)
        if actual_digest != expected_digest or actual_size != expected_size:
            modified.append(relative)

    return {
        "ok": not missing and not modified,
        "checked": len(validated),
        "missing": missing,
        "modified": modified,
    }
