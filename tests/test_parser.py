"""Parser heuristics and the plaintext-never-propagates guarantee."""

import pytest

from cytadel.parser import ExposureRecord, parse_text, split_line
from cytadel.redact import Redactor
from cytadel.search import make_scope_matcher


# --------------------------------------------------------------------------- #
# Line-format splitting heuristic (the required behaviors)
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "line, url, user, password",
    [
        (
            "https://example.com:8080/path:admin:secret",
            "https://example.com:8080/path",
            "admin",
            "secret",
        ),
        (
            "https://site.com/login:user:pass:word:123",
            "https://site.com/login",
            "user",
            "pass:word:123",
        ),
        (
            "android://hash123@com.example.app/:user:pass",
            "android://hash123@com.example.app/",
            "user",
            "pass",
        ),
        (
            "https://login.live.com/oauth:user@example.com:MyP@ss!",
            "https://login.live.com/oauth",
            "user@example.com",
            "MyP@ss!",
        ),
    ],
)
def test_split_line_examples(line, url, user, password):
    assert split_line(line) == (url, user, password)


@pytest.mark.parametrize(
    "line, url, user, password",
    [
        # No path + email username: the '@' must NOT be read as URL userinfo.
        (
            "https://shop.client.com:user@gmail.com:abcd1234",
            "https://shop.client.com",
            "user@gmail.com",
            "abcd1234",
        ),
        # No path + host:port + email username.
        (
            "https://site.com:8080:user@x.com:pw",
            "https://site.com:8080",
            "user@x.com",
            "pw",
        ),
    ],
)
def test_split_line_email_username_no_path(line, url, user, password):
    # Regression: these lines used to lose their password (parsed as "") because
    # the email '@' was mistaken for URL userinfo, so the record was dropped and
    # scans came back with zero accounts.
    assert split_line(line) == (url, user, password)


def test_split_line_ip_with_port():
    # 3+ colons, segment between colon1/colon2 is a port -> split at colon2.
    assert split_line("https://1.2.3.4:8080:user:pass") == (
        "https://1.2.3.4:8080",
        "user",
        "pass",
    )


def test_split_line_host_two_colons():
    assert split_line("ftp://example.com:admin:pass") == (
        "ftp://example.com",
        "admin",
        "pass",
    )


def test_split_line_skips_without_scheme():
    assert split_line("just some text without a scheme") is None
    assert split_line("") is None


def test_split_line_preserves_not_saved_and_schemes():
    url, user, password = split_line("android://x/:user:[NOT_SAVED]")
    assert url == "android://x/"
    assert user == "user"
    assert password == "[NOT_SAVED]"


# --------------------------------------------------------------------------- #
# Scope filtering + block/antipublic parsing
# --------------------------------------------------------------------------- #
def _parse(text, domains=("client-domain.com",), include_service_url=True):
    matcher = make_scope_matcher(domains, include_service_url=include_service_url)
    return list(parse_text(text, "src.txt", Redactor(salt=b"fixed-salt"), matcher))


_SCOPE_TEXT = "\n".join(
    [
        "https://mail.google.com/:jane@client-domain.com:S3cretPassw0rd!",
        # unrelated personal account on an unrelated site -> excluded in both modes
        "https://mail.google.com/:outsider@gmail.com:whatever123",
        # personal provider but ON the client's service -> included only in broad mode
        "https://client-domain.com/login:bob@gmail.com:Zzzz9999",
    ]
)


def test_strict_mode_email_domain_only():
    records = _parse(_SCOPE_TEXT, include_service_url=False)
    assert {r.email for r in records} == {"jane@client-domain.com"}


def test_broad_mode_includes_client_service_any_provider():
    records = _parse(_SCOPE_TEXT)  # broad is the default
    emails = {r.email for r in records}
    assert emails == {"jane@client-domain.com", "bob@gmail.com"}
    assert "outsider@gmail.com" not in emails  # unrelated site stays excluded


def test_subdomain_in_scope():
    text = "https://x/:joe@mail.client-domain.com:Abc12345!"
    records = _parse(text)
    assert len(records) == 1
    assert records[0].email == "joe@mail.client-domain.com"


def test_block_format_parsed():
    text = "\n".join(
        [
            "Soft: Chrome",
            "URL: https://portal.example.com",
            "Login: alice@client-domain.com",
            "Password: Sup3rSecret!!",
            "===============================",
            "Browser: Firefox",
            "Host: https://vpn.example.com",
            "Username: mallory@evil.com",
            "Passwd: nope",
        ]
    )
    records = _parse(text)
    assert len(records) == 1
    rec = records[0]
    assert rec.email == "alice@client-domain.com"
    assert rec.service_url == "https://portal.example.com"
    assert rec.fmt == "block"


def test_antipublic_line():
    text = "carol@client-domain.com:HunterHunter2"
    records = _parse(text)
    assert len(records) == 1
    assert records[0].fmt == "antipublic"
    assert records[0].service_url == "ANTIPUBLIC"


def test_records_carry_no_plaintext():
    # The parsed passwords must not appear anywhere on the record objects.
    secrets = ["S3cretPassw0rd!", "Sup3rSecret!!", "HunterHunter2"]
    text = "\n".join(
        [
            "https://mail.google.com/:jane@client-domain.com:S3cretPassw0rd!",
            "URL: https://portal.example.com",
            "Login: alice@client-domain.com",
            "Password: Sup3rSecret!!",
            "-------------------------------",
            "carol@client-domain.com:HunterHunter2",
        ]
    )
    records = _parse(text)
    assert len(records) == 3
    for rec in records:
        blob = repr(rec)
        for secret in secrets:
            assert secret not in blob
        # ExposureRecord has no password attribute at all.
        assert not hasattr(rec, "password")
        assert isinstance(rec, ExposureRecord)
