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


def make_scope_matcher(domains: Iterable[str]):
    """Build a predicate matching emails whose domain is a client domain.

    Matches an exact domain or any subdomain of it (``user@mail.client.com``
    counts for ``client.com``). Case-insensitive. A leading ``@`` on a supplied
    domain is tolerated.
    """
    normalized = {
        d.strip().lower().lstrip("@")
        for d in domains
        if d and d.strip()
    }

    def matcher(email: str) -> bool:
        e = (email or "").strip().lower()
        at = e.rfind("@")
        if at == -1:
            return False
        domain = e[at + 1:]
        return any(domain == d or domain.endswith("." + d) for d in normalized)

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
