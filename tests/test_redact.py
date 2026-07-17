"""Redaction signals are correct, non-reversible, and leak no plaintext."""

from cytadel.redact import (
    CLASS_DIGIT,
    CLASS_LOWER,
    CLASS_SYMBOL,
    CLASS_UPPER,
    Redaction,
    Redactor,
)


def test_length_and_classes():
    red = Redactor(salt=b"s").redact("Ab3!xy")
    assert red.length == 6
    assert set(red.classes) == {CLASS_LOWER, CLASS_UPPER, CLASS_DIGIT, CLASS_SYMBOL}


def test_charset_label_compact():
    red = Redactor(salt=b"s").redact("Abcd1234")
    # lower+upper collapse to a-Z, digits add 0-9
    assert red.charset_label() == "a-Z 0-9"


def test_weak_detection():
    r = Redactor(salt=b"s")
    assert r.redact("password").is_weak  # common list
    assert r.redact("aaa").is_weak  # too short
    assert r.redact("aaaaaaaaaa").is_weak  # single class
    assert not r.redact("Xy9$Kp2mQ").is_weak  # long + mixed


def test_reuse_key_deterministic_within_run():
    r = Redactor(salt=b"fixed")
    assert r.redact("samepass").reuse_key == r.redact("samepass").reuse_key
    assert r.redact("a").reuse_key != r.redact("b").reuse_key


def test_reuse_key_varies_across_salts():
    a = Redactor(salt=b"salt-a").redact("samepass").reuse_key
    b = Redactor(salt=b"salt-b").redact("samepass").reuse_key
    assert a != b


def test_status_label_has_no_plaintext():
    secret = "Tr0ub4dor&3"
    red = Redactor(salt=b"s").redact(secret)
    label = red.status_label()
    assert secret not in label
    assert "karaktere" in label
    # No fragment of the password (length >= 3) should appear in the label.
    for i in range(len(secret) - 2):
        assert secret[i : i + 3] not in label


def test_with_reused_is_immutable():
    red = Redactor(salt=b"s").redact("Xy9$Kp2mQ")
    reused = red.with_reused(True)
    assert red.is_reused is False
    assert reused.is_reused is True
    assert isinstance(reused, Redaction)
    assert "i ripërdorur" in reused.status_label()
