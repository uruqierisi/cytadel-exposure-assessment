"""End-to-end: synthetic zip -> extract -> parse -> analyze -> PDF + CSV.

Asserts (a) an in-scope account appears in both outputs, and (b) NO plaintext
password appears anywhere in the generated PDF or CSV bytes. The PDF is built
with compression disabled so the byte-level assertion is meaningful.
"""

import zipfile

from cytadel.extractor import safe_extract
from cytadel.parser import scan_tree
from cytadel.pdf_report import ReportMeta, build_pdf
from cytadel.redact import Redactor
from cytadel.search import analyze, export_csv, make_scope_matcher

DOMAIN = "client-domain.com"
IN_SCOPE_EMAIL = "jane@client-domain.com"
IN_SCOPE_EMAIL_2 = "john@client-domain.com"
IN_SCOPE_GMAIL = "bob@gmail.com"  # personal provider, but on the client's service
SECRET_1 = "S3cretPassw0rd!"
SECRET_2 = "An0therHardPw#9"
SECRET_3 = "GmailOnSite#7"
OUT_OF_SCOPE_SECRET = "outsiderPW12345"


def _build_sample_zip(path):
    passwords = "\n".join(
        [
            f"https://mail.google.com/:{IN_SCOPE_EMAIL}:{SECRET_1}",
            f"https://vpn.acme.io/login:{IN_SCOPE_EMAIL_2}:{SECRET_2}",
            # personal provider on the CLIENT's service -> included (broad mode)
            f"https://client-domain.com/app:{IN_SCOPE_GMAIL}:{SECRET_3}",
            # unrelated personal account on an unrelated site -> excluded
            f"https://mail.google.com/:outsider@gmail.com:{OUT_OF_SCOPE_SECRET}",
        ]
    )
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("victim-01/passwords.txt", passwords)


def test_end_to_end_no_plaintext(tmp_path):
    archive = tmp_path / "stealer_logs.zip"
    _build_sample_zip(archive)

    extract_dir = tmp_path / "extracted"
    safe_extract(str(archive), str(extract_dir))

    in_scope = make_scope_matcher([DOMAIN])  # broad: email domain OR client service
    records = list(scan_tree(str(extract_dir), Redactor(), in_scope))
    records = analyze(records)

    emails = {r.email for r in records}
    assert IN_SCOPE_EMAIL in emails
    assert IN_SCOPE_EMAIL_2 in emails
    assert IN_SCOPE_GMAIL in emails  # any-provider account on the client's service
    assert "outsider@gmail.com" not in emails  # unrelated site stays out

    pdf_path = tmp_path / "report.pdf"
    build_pdf(
        str(pdf_path),
        ReportMeta(client="Acme Corp", report_id="SEC-2025-001", date="2026-07-16"),
        [DOMAIN],
        records,
        compress=False,  # so the byte check below is real
    )
    csv_path = tmp_path / "report.csv"
    export_csv(str(csv_path), records)

    pdf_bytes = pdf_path.read_bytes()
    csv_bytes = csv_path.read_bytes()

    # (a) in-scope account is present in both outputs
    assert IN_SCOPE_EMAIL.encode() in pdf_bytes
    assert IN_SCOPE_EMAIL.encode() in csv_bytes

    # (b) NO plaintext password anywhere
    for secret in (SECRET_1, SECRET_2, SECRET_3, OUT_OF_SCOPE_SECRET):
        assert secret.encode() not in pdf_bytes, f"plaintext leaked into PDF: {secret}"
        assert secret.encode() not in csv_bytes, f"plaintext leaked into CSV: {secret}"

    # redacted status is what appears instead
    assert b"karaktere" in csv_bytes
