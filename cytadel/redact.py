"""Turn plaintext passwords into non-reversible exposure signals.

This is the heart of the tool's safety guarantee. A password enters ``redact``
and only structural, non-reversible facts come out:

* ``length`` — how many characters,
* ``classes`` — which character classes are present (lower/upper/digit/symbol),
* ``is_weak`` — a boolean heuristic,
* ``reuse_key`` — a *salted* SHA-256 used ONLY to group identical passwords
  across services within a single run. The salt is random per run and is
  discarded when the process exits; the key is never displayed and never
  exported.

No substring, no masked preview, no first-N characters. The plaintext is not
retained anywhere in the returned object.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, replace

# Character-class tokens (kept short so they read cleanly in the report).
CLASS_LOWER = "lower"
CLASS_UPPER = "upper"
CLASS_DIGIT = "digit"
CLASS_SYMBOL = "symbol"

# Minimum length below which a password is considered weak regardless of classes.
_MIN_STRONG_LEN = 8

# A small embedded list of the most common weak passwords. Intentionally not
# exhaustive — it exists so the "i dobët" flag catches the obvious offenders.
_COMMON_WEAK = frozenset(
    {
        "123456", "123456789", "12345678", "1234567", "1234567890", "12345",
        "123123", "111111", "000000", "654321", "666666", "121212",
        "password", "password1", "passw0rd", "qwerty", "qwerty123", "qwertyuiop",
        "abc123", "iloveyou", "admin", "letmein", "welcome", "monkey", "dragon",
        "football", "1q2w3e4r", "sunshine", "master", "starwars", "superman",
        "qazwsx", "trustno1", "whatever", "zaq12wsx", "asdfgh", "1qaz2wsx",
    }
)


@dataclass(frozen=True)
class Redaction:
    """Non-reversible exposure signals for a single password.

    Carries no plaintext. ``reuse_key`` is a salted hash used purely to group
    identical passwords across services; it is never rendered or exported.
    """

    length: int
    classes: tuple  # ordered subset of the CLASS_* tokens
    is_weak: bool
    reuse_key: str
    is_reused: bool = False  # set by search.py after cross-service grouping

    def charset_label(self) -> str:
        """Compact charset descriptor, e.g. ``a-Z 0-9`` (no plaintext)."""
        present = set(self.classes)
        parts = []
        if CLASS_LOWER in present and CLASS_UPPER in present:
            parts.append("a-Z")
        elif CLASS_LOWER in present:
            parts.append("a-z")
        elif CLASS_UPPER in present:
            parts.append("A-Z")
        if CLASS_DIGIT in present:
            parts.append("0-9")
        if CLASS_SYMBOL in present:
            parts.append("sym")
        return " ".join(parts) if parts else "—"

    def status_label(self) -> str:
        """Albanian-facing status string used in the report and CSV.

        Example: ``12 karaktere · a-Z 0-9 · i ripërdorur``. Contains no
        plaintext and nothing reversible.
        """
        parts = [f"{self.length} karaktere", self.charset_label()]
        flags = []
        if self.is_weak:
            flags.append("i dobët")
        if self.is_reused:
            flags.append("i ripërdorur")
        if flags:
            parts.append(" ".join(flags))
        return " · ".join(parts)

    def with_reused(self, value: bool) -> "Redaction":
        """Return a copy with ``is_reused`` set (immutability preserved)."""
        if value == self.is_reused:
            return self
        return replace(self, is_reused=value)


class Redactor:
    """Produces :class:`Redaction` signals using a per-run salt.

    The salt is generated on construction and never persisted, displayed, or
    exported. Identical passwords produce identical ``reuse_key`` values *within
    the same Redactor instance*, which is exactly what reuse detection needs and
    nothing more.
    """

    def __init__(self, salt: bytes | None = None) -> None:
        self._salt = salt if salt is not None else secrets.token_bytes(32)

    def redact(self, password: str) -> Redaction:
        classes = _classes_of(password)
        return Redaction(
            length=len(password),
            classes=classes,
            is_weak=_is_weak(password, classes),
            reuse_key=self._reuse_key(password),
        )

    def _reuse_key(self, password: str) -> str:
        digest = hashlib.sha256(self._salt + password.encode("utf-8", "replace"))
        return digest.hexdigest()


def _classes_of(password: str) -> tuple:
    has_lower = has_upper = has_digit = has_symbol = False
    for ch in password:
        if ch.isdigit():
            has_digit = True
        elif ch.islower():
            has_lower = True
        elif ch.isupper():
            has_upper = True
        elif not ch.isspace():
            has_symbol = True
    ordered = []
    if has_lower:
        ordered.append(CLASS_LOWER)
    if has_upper:
        ordered.append(CLASS_UPPER)
    if has_digit:
        ordered.append(CLASS_DIGIT)
    if has_symbol:
        ordered.append(CLASS_SYMBOL)
    return tuple(ordered)


def _is_weak(password: str, classes: tuple) -> bool:
    if password.lower() in _COMMON_WEAK:
        return True
    if len(password) < _MIN_STRONG_LEN:
        return True
    if len(classes) <= 1:
        return True
    return False
