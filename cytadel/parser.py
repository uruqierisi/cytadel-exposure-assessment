"""Parse messy infostealer log formats and emit *redacted*, in-scope records.

Two source shapes are supported:

A. **Line format** ``url:username:password`` (one credential per line).
B. **Block format** (Redline / misc) — ``Soft: ... URL: ... Login: ...
   Password: ...`` blocks separated by runs of ``- _ ~ =``.

Plus ANTIPUBLIC / combolist ``email:password`` lines.

Security boundary
-----------------
``split_line`` returns the plaintext password because it is the parsing
primitive that the unit tests exercise. But nothing that leaves this module via
:class:`ExposureRecord` carries plaintext: as soon as a credential is parsed, its
password is handed to a :class:`~cytadel.redact.Redactor` and the plaintext local
goes out of scope. Records flowing to search / report / UI / CSV hold only
redaction signals. Out-of-scope credentials are dropped before redaction.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Callable, Iterable, Iterator, Optional, Tuple

from .redact import Redaction, Redactor

SCHEME_SEP = "://"

# Case-insensitive filenames we especially expect; we scan every ``*.txt``
# regardless so format variants are not missed.
TARGET_NAMES = frozenset(
    {
        "passwords.txt", "all passwords.txt", "_allpasswords_list.txt",
        "password.txt", "all_passwords.txt",
    }
)

SITE_KEYS = frozenset(
    {"url", "uri", "link", "originurl", "host", "hostname", "site",
     "website", "domain", "address", "page"}
)
USER_KEYS = frozenset(
    {"user", "username", "login", "email", "emailaddress", "mail",
     "account", "loginname", "phone"}
)
PASS_KEYS = frozenset(
    {"password", "pass", "passwd", "pwd", "pin", "passcode"}
)
NOISE_KEYS = frozenset({"browser", "application", "soft", "software", "profile"})

_BLOCK_SEP_CHARS = frozenset("-_~=")
_UNKNOWN_SERVICE = "(panjohur)"

InScope = Callable[..., bool]  # (email, url="") -> bool


@dataclass(frozen=True)
class ExposureRecord:
    """A record that flows onward. Holds NO plaintext password."""

    email: str
    service_url: str
    source_file: str
    fmt: str  # 'line' | 'block' | 'antipublic'
    redaction: Redaction


# --------------------------------------------------------------------------- #
# Line-format primitive
# --------------------------------------------------------------------------- #
def split_line(line: str) -> Optional[Tuple[str, str, str]]:
    """Split ``url:username:password`` into ``(url, username, password)``.

    Returns ``None`` when the line has no ``://`` scheme. This function returns
    the plaintext password and is used ONLY internally by the parser and by unit
    tests validating the heuristic — never in the record pipeline.
    """
    line = line.rstrip("\r\n")
    if not line:
        return None
    idx = line.find(SCHEME_SEP)
    if idx == -1:
        return None
    scheme_end = idx + len(SCHEME_SEP)
    rest = line[scheme_end:]

    slash = rest.find("/")

    if slash != -1:
        # A path exists -> the credential separator is the first ':' at/after the
        # path. Any '@' before the path belongs to the URL itself (e.g. an
        # android:// package token) and is kept as part of the URL.
        sep = rest.find(":", slash)
    else:
        # No path -> rest is 'host[:port]:user:pass'; disambiguate host:port from
        # the user separator by colon count. We deliberately do NOT treat '@' as
        # URL userinfo: in stealer 'url:user:pass' lines the '@' is part of the
        # email username (e.g. https://site.com:user@gmail.com:pw), not URL
        # userinfo. Keying off it mis-split the URL and dropped the password on
        # the most common combolist/stealer shape (no path + email username).
        sep = _sep_by_colon_count(rest)

    if sep == -1:
        return None

    url = line[: scheme_end + sep]
    creds = rest[sep + 1:]
    first = creds.find(":")
    if first == -1:
        return url, creds, ""
    return url, creds[:first], creds[first + 1:]


def _sep_by_colon_count(rest: str) -> int:
    positions = [i for i, ch in enumerate(rest) if ch == ":"]
    if len(positions) < 2:
        return positions[0] if positions else -1
    if len(positions) == 2:
        return positions[0]
    # 3+ colons: if the segment between the 1st and 2nd colon is a port
    # (<=5 digits) the host has a :port, so split at the 2nd colon.
    seg = rest[positions[0] + 1: positions[1]]
    if seg.isdigit() and len(seg) <= 5:
        return positions[1]
    return positions[0]


# --------------------------------------------------------------------------- #
# Block-format helpers
# --------------------------------------------------------------------------- #
def _norm_key(key: str) -> str:
    return key.strip().lower().replace(" ", "").replace("-", "").replace("_", "")


def _slot_for(norm_key: str) -> Optional[str]:
    if norm_key in SITE_KEYS:
        return "url"
    if norm_key in USER_KEYS:
        return "user"
    if norm_key in PASS_KEYS:
        return "pass"
    return None


def _is_block_separator(stripped: str) -> bool:
    return len(stripped) >= 3 and all(ch in _BLOCK_SEP_CHARS for ch in stripped)


def _finish_block(
    block: dict, source_file: str, redactor: Redactor, in_scope: InScope
) -> Optional[ExposureRecord]:
    user = block.get("user")
    password = block.get("pass")
    if not user or not password:
        return None
    if not in_scope(user, block.get("url") or ""):
        return None
    return ExposureRecord(
        email=user,
        service_url=block.get("url") or _UNKNOWN_SERVICE,
        source_file=source_file,
        fmt="block",
        redaction=redactor.redact(password),
    )


# --------------------------------------------------------------------------- #
# Unified parser
# --------------------------------------------------------------------------- #
def parse_lines(
    lines: Iterable[str],
    source_file: str,
    redactor: Redactor,
    in_scope: InScope,
) -> Iterator[ExposureRecord]:
    """Parse an iterable of text lines and yield in-scope, redacted records.

    A single pass handles all three shapes. Block fields (``URL:``/``Login:``/
    ``Password:``) are recognised by key before the line-format branch, so a
    Redline block never double-counts as a line-format credential.
    """
    block: dict = {}

    for raw in lines:
        stripped = raw.strip()

        # A blank line or a run of separator chars both terminate a block. Real
        # stealer logs delimit records with EITHER a run of ``- _ ~ =`` OR simply
        # a blank line between blocks; treating only the dashes as a separator
        # merged every block into one and lost all but the first credential.
        if not stripped or _is_block_separator(stripped):
            rec = _finish_block(block, source_file, redactor, in_scope)
            block = {}
            if rec is not None:
                yield rec
            continue

        if ":" not in raw:
            continue

        key, _, value = raw.partition(":")
        norm = _norm_key(key)
        value = value.strip()

        if norm in NOISE_KEYS:
            continue

        slot = _slot_for(norm)
        if slot is not None:
            # A slot that is already filled means a new record started without an
            # explicit separator (some dumps have no blank line or dashes between
            # blocks). Flush the current block and begin a fresh one with this
            # field so consecutive ``URL/USER/PASS`` triples don't collapse into
            # one via ``setdefault`` keeping only the first value.
            if slot in block:
                rec = _finish_block(block, source_file, redactor, in_scope)
                block = {}
                if rec is not None:
                    yield rec
            block[slot] = value
            continue

        # Not a block field -> standalone line-format or ANTIPUBLIC record.
        if SCHEME_SEP in raw:
            parsed = split_line(raw)
            if parsed is None:
                continue
            url, username, password = parsed
            if password and in_scope(username, url):
                yield ExposureRecord(
                    username, url, source_file, "line", redactor.redact(password)
                )
        elif "@" in key:
            email = key.strip()
            password = value  # remainder after the first ':'
            if password and in_scope(email, "ANTIPUBLIC"):
                yield ExposureRecord(
                    email, "ANTIPUBLIC", source_file, "antipublic",
                    redactor.redact(password),
                )

    rec = _finish_block(block, source_file, redactor, in_scope)
    if rec is not None:
        yield rec


def parse_text(
    text: str, source_file: str, redactor: Redactor, in_scope: InScope
) -> Iterator[ExposureRecord]:
    """Convenience wrapper: parse a whole text blob."""
    yield from parse_lines(text.splitlines(), source_file, redactor, in_scope)


# --------------------------------------------------------------------------- #
# Filesystem tree scanning
# --------------------------------------------------------------------------- #
def iter_txt_files(root: str) -> Iterator[str]:
    """Yield every ``*.txt`` file under ``root`` (case-insensitive extension)."""
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            if name.lower().endswith(".txt"):
                yield os.path.join(dirpath, name)


def scan_tree(
    root: str,
    redactor: Redactor,
    in_scope: InScope,
    on_file: Optional[Callable[[str], None]] = None,
) -> Iterator[ExposureRecord]:
    """Scan a directory tree of extracted logs, streaming records.

    Files are read line-by-line in text mode with ``errors='replace'`` so that
    very large logs never load fully into memory and undecodable bytes cannot
    crash the parse.
    """
    for path in iter_txt_files(root):
        rel = os.path.relpath(path, root)
        if on_file is not None:
            on_file(rel)
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                yield from parse_lines(handle, rel, redactor, in_scope)
        except OSError:
            continue
