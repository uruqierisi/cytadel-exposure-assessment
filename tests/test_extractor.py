"""Safe-extraction guards: zip-slip, bombs, nesting, and normal extraction."""

import io
import os
import zipfile

import pytest

from cytadel.extractor import (
    BombError,
    ExtractionLimits,
    UnsupportedArchive,
    safe_extract,
)


def _make_zip(path, entries):
    """entries: list of (name, data_bytes)."""
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries:
            zf.writestr(name, data)


def test_normal_extraction(tmp_path):
    archive = tmp_path / "logs.zip"
    _make_zip(archive, [("a/passwords.txt", b"hello"), ("b/notes.txt", b"world")])
    dest = tmp_path / "out"
    stats = safe_extract(str(archive), str(dest))
    assert stats.files == 2
    assert (dest / "a" / "passwords.txt").read_bytes() == b"hello"
    # Source archive is never deleted.
    assert archive.exists()


def test_zip_slip_is_skipped(tmp_path):
    archive = tmp_path / "evil.zip"
    _make_zip(archive, [("../escape.txt", b"pwned"), ("safe.txt", b"ok")])
    dest = tmp_path / "out"
    stats = safe_extract(str(archive), str(dest))
    assert (dest / "safe.txt").exists()
    # The traversal entry must not land outside the extraction root.
    assert not (tmp_path / "escape.txt").exists()
    assert any(reason == "zip-slip" for _name, reason in stats.skipped)


def test_per_file_cap_skips_large_declared(tmp_path):
    archive = tmp_path / "big.zip"
    _make_zip(archive, [("huge.txt", b"x" * 5000), ("ok.txt", b"y" * 10)])
    dest = tmp_path / "out"
    limits = ExtractionLimits(per_file_bytes=1000)
    stats = safe_extract(str(archive), str(dest), limits)
    assert (dest / "ok.txt").exists()
    assert not (dest / "huge.txt").exists()
    assert any(reason == "per-file cap" for _name, reason in stats.skipped)


def test_total_cap_raises(tmp_path):
    archive = tmp_path / "bomb.zip"
    _make_zip(archive, [(f"f{i}.txt", b"z" * 1000) for i in range(10)])
    dest = tmp_path / "out"
    limits = ExtractionLimits(total_bytes=2500)
    with pytest.raises(BombError):
        safe_extract(str(archive), str(dest), limits)


def test_entry_count_cap_raises(tmp_path):
    archive = tmp_path / "many.zip"
    _make_zip(archive, [(f"f{i}.txt", b"a") for i in range(20)])
    dest = tmp_path / "out"
    limits = ExtractionLimits(max_entries=5)
    with pytest.raises(BombError):
        safe_extract(str(archive), str(dest), limits)


def test_nested_archive_recursion(tmp_path):
    # Build inner.zip in memory, then embed it inside outer.zip.
    inner_buf = io.BytesIO()
    with zipfile.ZipFile(inner_buf, "w") as inner:
        inner.writestr("deep/inner_passwords.txt", b"inner-data")
    archive = tmp_path / "outer.zip"
    _make_zip(archive, [("nested/inner.zip", inner_buf.getvalue()), ("top.txt", b"t")])
    dest = tmp_path / "out"
    stats = safe_extract(str(archive), str(dest))

    found = []
    for dirpath, _dirs, files in os.walk(dest):
        for name in files:
            if name == "inner_passwords.txt":
                found.append(os.path.join(dirpath, name))
    assert found, "nested archive contents were not extracted"
    assert open(found[0], "rb").read() == b"inner-data"


def test_depth_limit_stops_recursion(tmp_path):
    archive = tmp_path / "shallow.zip"
    _make_zip(archive, [("a.txt", b"a")])
    dest = tmp_path / "out"
    # depth 0 extraction is always allowed; a max_depth of 0 just disables nesting.
    stats = safe_extract(str(archive), str(dest), ExtractionLimits(max_depth=0))
    assert (dest / "a.txt").exists()


def test_unsupported_extension(tmp_path):
    bogus = tmp_path / "file.tar"
    bogus.write_bytes(b"not an archive")
    with pytest.raises(UnsupportedArchive):
        safe_extract(str(bogus), str(tmp_path / "out"))
