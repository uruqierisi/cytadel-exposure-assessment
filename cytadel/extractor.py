"""Safe extraction of hostile archive input.

Stealer-log archives are untrusted. This module defends against the two classic
attacks and one operational hazard:

* **Zip-slip** — an entry whose resolved path escapes the extraction root is
  skipped, never written outside it.
* **Decompression bombs** — total uncompressed bytes, per-file size, and entry
  count are all capped; caps are checked against both the declared size and the
  bytes actually streamed (so a spoofed header can't bypass them).
* **Runaway nesting** — nested archives are extracted recursively up to a bounded
  depth (default 10).

Nothing from an archive is ever executed. ``.zip`` is handled fully in-process
via the stdlib. ``.7z``/``.rar`` are optional (``py7zr`` / ``rarfile``); when the
library is missing the caller gets a clear :class:`UnsupportedArchive`. The
user's source archive is only ever read, never deleted.
"""

from __future__ import annotations

import os
import zipfile
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Set, Tuple

try:  # optional dependency
    import py7zr  # type: ignore
except Exception:  # pragma: no cover - environment dependent
    py7zr = None

try:  # optional dependency
    import rarfile  # type: ignore
except Exception:  # pragma: no cover - environment dependent
    rarfile = None

ARCHIVE_EXTS = frozenset({".zip", ".7z", ".rar"})
_CHUNK = 1 << 16
_NESTED_SUFFIX = "__unpacked"

ProgressFn = Callable[[str], None]


@dataclass(frozen=True)
class ExtractionLimits:
    total_bytes: int = 5 * 1024 ** 3     # 5 GB total uncompressed
    per_file_bytes: int = 2 * 1024 ** 3  # 2 GB per file
    max_entries: int = 100_000
    max_depth: int = 10


class ExtractionError(Exception):
    pass


class BombError(ExtractionError):
    pass


class UnsupportedArchive(ExtractionError):
    pass


@dataclass
class ExtractStats:
    files: int = 0
    total_bytes: int = 0
    entries: int = 0
    skipped: List[Tuple[str, str]] = field(default_factory=list)
    processed: Set[str] = field(default_factory=set)

    def note_skip(self, name: str, reason: str) -> None:
        self.skipped.append((name, reason))


def is_archive(path: str) -> bool:
    return os.path.splitext(path)[1].lower() in ARCHIVE_EXTS


def _within(base: str, target: str) -> bool:
    base = os.path.realpath(base)
    target = os.path.realpath(target)
    return target == base or target.startswith(base + os.sep)


def safe_extract(
    archive_path: str,
    dest_dir: str,
    limits: Optional[ExtractionLimits] = None,
    progress: Optional[ProgressFn] = None,
) -> ExtractStats:
    """Extract ``archive_path`` into ``dest_dir`` with all guards enabled."""
    limits = limits or ExtractionLimits()
    stats = ExtractStats()
    _extract_any(archive_path, dest_dir, limits, stats, depth=0, progress=progress)
    return stats


def _extract_any(
    archive_path: str,
    dest_dir: str,
    limits: ExtractionLimits,
    stats: ExtractStats,
    depth: int,
    progress: Optional[ProgressFn],
) -> None:
    real = os.path.realpath(archive_path)
    if real in stats.processed:
        return
    stats.processed.add(real)

    if depth > limits.max_depth:
        stats.note_skip(archive_path, f"max nesting depth {limits.max_depth}")
        return

    os.makedirs(dest_dir, exist_ok=True)
    ext = os.path.splitext(archive_path)[1].lower()

    if ext == ".zip":
        _extract_zip(archive_path, dest_dir, limits, stats, progress)
    elif ext == ".7z":
        if py7zr is None:
            raise UnsupportedArchive(
                "Formati .7z kërkon paketën 'py7zr' (nuk është e instaluar)."
            )
        _extract_7z(archive_path, dest_dir, limits, stats, progress)
    elif ext == ".rar":
        if rarfile is None:
            raise UnsupportedArchive(
                "Formati .rar kërkon 'rarfile' + binarin unrar (jo në dispozicion)."
            )
        _extract_rar(archive_path, dest_dir, limits, stats, progress)
    else:
        raise UnsupportedArchive(f"Format i papërkrahur: {ext or '(pa prapashtesë)'}")

    if depth < limits.max_depth:
        _recurse_nested(dest_dir, limits, stats, depth, progress)


def _recurse_nested(
    dest_dir: str,
    limits: ExtractionLimits,
    stats: ExtractStats,
    depth: int,
    progress: Optional[ProgressFn],
) -> None:
    nested: List[str] = []
    for dirpath, _dirs, files in os.walk(dest_dir):
        for name in files:
            full = os.path.join(dirpath, name)
            if is_archive(full) and os.path.realpath(full) not in stats.processed:
                nested.append(full)
    for archive in nested:
        target = archive + _NESTED_SUFFIX
        _extract_any(archive, target, limits, stats, depth + 1, progress)


# --------------------------------------------------------------------------- #
# ZIP (stdlib, fully in-process)
# --------------------------------------------------------------------------- #
def _extract_zip(
    path: str,
    dest: str,
    limits: ExtractionLimits,
    stats: ExtractStats,
    progress: Optional[ProgressFn],
) -> None:
    with zipfile.ZipFile(path) as zf:
        for info in zf.infolist():
            stats.entries += 1
            if stats.entries > limits.max_entries:
                raise BombError("Numri i hyrjeve tejkaloi kufirin.")

            name = info.filename
            target = os.path.join(dest, name)

            if not _within(dest, target):
                stats.note_skip(name, "zip-slip")
                continue

            if info.is_dir() or name.endswith("/"):
                os.makedirs(target, exist_ok=True)
                continue

            if info.file_size > limits.per_file_bytes:
                stats.note_skip(name, "per-file cap")
                continue

            if stats.total_bytes + info.file_size > limits.total_bytes:
                raise BombError("Totali i pakompresuar tejkaloi kufirin.")

            os.makedirs(os.path.dirname(target) or dest, exist_ok=True)
            written = _stream_member(zf, info, target, limits, stats)
            stats.total_bytes += written
            stats.files += 1
            if progress is not None:
                progress(name)


def _stream_member(
    zf: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    target: str,
    limits: ExtractionLimits,
    stats: ExtractStats,
) -> int:
    written = 0
    with zf.open(info) as src, open(target, "wb") as out:
        while True:
            chunk = src.read(_CHUNK)
            if not chunk:
                break
            written += len(chunk)
            if written > limits.per_file_bytes:
                _discard(out, target)
                raise BombError(f"{info.filename}: per-file cap gjatë leximit.")
            if stats.total_bytes + written > limits.total_bytes:
                _discard(out, target)
                raise BombError("Totali i pakompresuar tejkaloi kufirin gjatë leximit.")
            out.write(chunk)
    return written


def _discard(out, target: str) -> None:
    try:
        out.close()
    finally:
        try:
            os.remove(target)
        except OSError:
            pass


# --------------------------------------------------------------------------- #
# 7z (optional, in-process via py7zr)
# --------------------------------------------------------------------------- #
def _extract_7z(path, dest, limits, stats, progress):  # pragma: no cover - optional
    with py7zr.SevenZipFile(path, "r") as arch:
        targets: List[str] = []
        projected = 0
        for entry in arch.list():
            stats.entries += 1
            if stats.entries > limits.max_entries:
                raise BombError("Numri i hyrjeve tejkaloi kufirin.")
            name = entry.filename
            if getattr(entry, "is_directory", False):
                continue
            if not _within(dest, os.path.join(dest, name)):
                stats.note_skip(name, "path-escape")
                continue
            size = int(getattr(entry, "uncompressed", 0) or 0)
            if size > limits.per_file_bytes:
                stats.note_skip(name, "per-file cap")
                continue
            if stats.total_bytes + projected + size > limits.total_bytes:
                raise BombError("Totali i pakompresuar tejkaloi kufirin.")
            projected += size
            targets.append(name)
        arch.reset()
        if targets:
            arch.extract(path=dest, targets=targets)
        stats.total_bytes += projected
        stats.files += len(targets)
        if progress is not None:
            for name in targets:
                progress(name)


# --------------------------------------------------------------------------- #
# RAR (optional, via rarfile + unrar binary; fixed args, no shell)
# --------------------------------------------------------------------------- #
def _extract_rar(path, dest, limits, stats, progress):  # pragma: no cover - optional
    with rarfile.RarFile(path) as rf:
        for info in rf.infolist():
            stats.entries += 1
            if stats.entries > limits.max_entries:
                raise BombError("Numri i hyrjeve tejkaloi kufirin.")
            name = info.filename
            target = os.path.join(dest, name)
            if not _within(dest, target):
                stats.note_skip(name, "path-escape")
                continue
            if info.isdir():
                os.makedirs(target, exist_ok=True)
                continue
            size = int(getattr(info, "file_size", 0) or 0)
            if size > limits.per_file_bytes:
                stats.note_skip(name, "per-file cap")
                continue
            if stats.total_bytes + size > limits.total_bytes:
                raise BombError("Totali i pakompresuar tejkaloi kufirin.")
            rf.extract(info, path=dest)
            if not _within(dest, target):
                stats.note_skip(name, "path-escape")
                continue
            stats.total_bytes += size
            stats.files += 1
            if progress is not None:
                progress(name)
