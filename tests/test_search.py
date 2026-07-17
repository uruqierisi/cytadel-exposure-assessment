"""De-duplication, reuse flagging, sorting, summary, and CSV redaction."""

from cytadel.parser import ExposureRecord
from cytadel.redact import Redactor
from cytadel.search import (
    analyze,
    make_scope_matcher,
    summarize,
    to_csv_rows,
)


def _rec(email, url, password, redactor):
    return ExposureRecord(email, url, "src.txt", "line", redactor.redact(password))


def test_scope_matcher_email_domain():
    m = make_scope_matcher(["Client-Domain.com", "@other.net"])
    assert m("a@client-domain.com")
    assert m("b@sub.client-domain.com")
    assert m("c@other.net")
    assert not m("d@notclient.com")
    assert not m("no-at-sign")


def test_scope_matcher_includes_service_url_all_providers():
    # Default (broad): any provider counts if the account is on the client's URL.
    m = make_scope_matcher(["client.com"])
    assert m("someone@gmail.com", "https://client.com/login")
    assert m("user@outlook.com", "https://portal.client.com:8080/app")
    assert m("x@icloud.com", "https://client.com")
    # Personal account NOT on the client's service is excluded.
    assert not m("someone@gmail.com", "https://www.xvideos2.com/")
    assert not m("someone@gmail.com", "https://notclient.com/login")


def test_scope_matcher_strict_mode_email_only():
    m = make_scope_matcher(["client.com"], include_service_url=False)
    assert m("staff@client.com", "https://anywhere.com")
    # URL match is ignored in strict mode.
    assert not m("someone@gmail.com", "https://client.com/login")


def test_dedupe_by_service_and_email():
    r = Redactor(salt=b"s")
    records = [
        _rec("a@client.com", "https://x", "pw1", r),
        _rec("a@client.com", "https://x", "pw1", r),  # duplicate
        _rec("a@client.com", "https://y", "pw1", r),  # different service
    ]
    out = analyze(records, mark_reuse=False)
    assert len(out) == 2


def test_reuse_flag_across_services():
    r = Redactor(salt=b"s")
    records = [
        _rec("a@client.com", "https://x", "sharedpw", r),
        _rec("a@client.com", "https://y", "sharedpw", r),
        _rec("a@client.com", "https://z", "uniquepw", r),
    ]
    out = analyze(records, mark_reuse=True)
    by_url = {rec.service_url: rec for rec in out}
    assert by_url["https://x"].redaction.is_reused
    assert by_url["https://y"].redaction.is_reused
    assert not by_url["https://z"].redaction.is_reused


def test_sorted_by_service_then_email():
    r = Redactor(salt=b"s")
    records = [
        _rec("b@client.com", "https://z", "pw", r),
        _rec("a@client.com", "https://a", "pw", r),
        _rec("b@client.com", "https://a", "pw", r),
    ]
    out = analyze(records, mark_reuse=False)
    ordered = [(rec.service_url, rec.email) for rec in out]
    assert ordered == sorted(ordered)


def test_summary_counts():
    r = Redactor(salt=b"s")
    records = analyze(
        [
            _rec("a@client.com", "https://x", "sharedpw", r),
            _rec("a@client.com", "https://y", "sharedpw", r),
            _rec("a@client.com", "https://z", "aa", r),  # weak (short)
        ]
    )
    summary = summarize(records)
    assert summary.total_accounts == 3
    assert summary.distinct_services == 3
    assert summary.distinct_emails == 1
    assert summary.reused == 2
    assert summary.weak >= 1


def test_csv_rows_have_no_plaintext():
    r = Redactor(salt=b"s")
    secret = "S3cretValue!!"
    records = analyze([_rec("a@client.com", "https://x", secret, r)])
    rows = to_csv_rows(records)
    flat = "\n".join("|".join(map(str, row)) for row in rows)
    assert secret not in flat
    assert "karaktere" in flat  # redacted status is present instead
