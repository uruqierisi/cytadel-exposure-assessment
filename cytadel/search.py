"""Scope matching, de-duplication, reuse flagging, sorting, and CSV export.

Scope is defined by the **client's own email domain**: a record is in scope only
when the username/email sits at one of the client domains. URL matching is *not*
used for inclusion — that would pull in unrelated individuals whose credentials
merely happen to mention a service. This keeps the report about the client's
people and nobody else's.
"""

from __future__ import annotations

import csv
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Iterable, List, Sequence

from .parser import ExposureRecord

CSV_HEADER = [
    "Email/Llogaria",
    "Shërbimi/URL",
    "Statusi i fjalëkalimit",
    "Veprimi i kërkuar",
    "Burimi",
    "Formati",
]
REQUIRED_ACTION = "Reset i menjëhershëm + MFA"


def _host_of(url: str) -> str:
    """Extract the host from a service URL (scheme/userinfo/port/path stripped)."""
    u = (url or "").strip().lower()
    i = u.find("://")
    if i != -1:
        u = u[i + 3:]
    at = u.find("@")
    slash = u.find("/")
    if at != -1 and (slash == -1 or at < slash):
        u = u[at + 1:]
    for sep in ("/", ":", "?", "#"):
        j = u.find(sep)
        if j != -1:
            u = u[:j]
    return u


def _domain_matches(host: str, normalized) -> bool:
    return any(host == d or host.endswith("." + d) for d in normalized)


def make_scope_matcher(domains: Iterable[str], include_service_url: bool = True):
    """Build a predicate deciding whether a record is in the client's scope.

    A record matches when the **email domain** is a client domain (exact or a
    subdomain of it — ``user@mail.client.com`` counts for ``client.com``).

    When ``include_service_url`` is True (default), a record ALSO matches when
    the **service URL's host** is a client domain — so accounts on the client's
    own service are included regardless of the email provider (gmail, outlook,
    hotmail, yahoo, icloud, …). Set it False to restrict strictly to the client
    email domain. Case-insensitive; a leading ``@`` on a supplied domain is
    tolerated. This changes *which redacted records appear* only — plaintext is
    never emitted in either mode.
    """
    normalized = {
        d.strip().lower().lstrip("@")
        for d in domains
        if d and d.strip()
    }

    def matcher(email: str, url: str = "") -> bool:
        e = (email or "").strip().lower()
        at = e.rfind("@")
        if at != -1 and _domain_matches(e[at + 1:], normalized):
            return True
        if include_service_url and url:
            host = _host_of(url)
            if host and _domain_matches(host, normalized):
                return True
        return False

    return matcher


@dataclass(frozen=True)
class ExposureSummary:
    total_accounts: int = 0
    distinct_services: int = 0
    distinct_emails: int = 0
    reused: int = 0
    weak: int = 0
    source_files: int = 0


def _dedupe(records: Iterable[ExposureRecord]) -> List[ExposureRecord]:
    """De-duplicate by ``(service_url, email)`` keeping the first seen."""
    seen: dict = {}
    for rec in records:
        key = (rec.service_url, rec.email.lower())
        if key not in seen:
            seen[key] = rec
    return list(seen.values())


def _mark_reuse(records: Sequence[ExposureRecord]) -> List[ExposureRecord]:
    """Flag records whose password appears across 2+ distinct services.

    Grouping uses the salted reuse key only; the key itself is never exposed.
    New record/redaction objects are created (immutability preserved).
    """
    services_by_key = defaultdict(set)
    for rec in records:
        services_by_key[rec.redaction.reuse_key].add(rec.service_url.lower())

    out: List[ExposureRecord] = []
    for rec in records:
        reused = len(services_by_key[rec.redaction.reuse_key]) >= 2
        new_red = rec.redaction.with_reused(reused)
        if new_red is rec.redaction:
            out.append(rec)
        else:
            out.append(
                ExposureRecord(
                    email=rec.email,
                    service_url=rec.service_url,
                    source_file=rec.source_file,
                    fmt=rec.fmt,
                    redaction=new_red,
                )
            )
    return out


def analyze(
    records: Iterable[ExposureRecord], mark_reuse: bool = True
) -> List[ExposureRecord]:
    """De-duplicate, optionally flag reuse, and sort for reporting."""
    deduped = _dedupe(records)
    if mark_reuse:
        deduped = _mark_reuse(deduped)
    deduped.sort(key=lambda r: (r.service_url.lower(), r.email.lower()))
    return deduped


def summarize(records: Sequence[ExposureRecord]) -> ExposureSummary:
    return ExposureSummary(
        total_accounts=len(records),
        distinct_services=len({r.service_url.lower() for r in records}),
        distinct_emails=len({r.email.lower() for r in records}),
        reused=sum(1 for r in records if r.redaction.is_reused),
        weak=sum(1 for r in records if r.redaction.is_weak),
        source_files=len({r.source_file for r in records}),
    )


def to_csv_rows(records: Sequence[ExposureRecord]) -> List[list]:
    """Rows mirroring the report table — redacted status only, no plaintext."""
    rows = [list(CSV_HEADER)]
    for rec in records:
        rows.append(
            [
                rec.email,
                rec.service_url,
                rec.redaction.status_label(),
                REQUIRED_ACTION,
                rec.source_file,
                rec.fmt,
            ]
        )
    return rows


def export_csv(path: str, records: Sequence[ExposureRecord]) -> None:
    """Write the matched rows to CSV (UTF-8 BOM for spreadsheet friendliness)."""
    with open(path, "w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.writer(handle)
        writer.writerows(to_csv_rows(records))
