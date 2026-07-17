"""Branded Cytadel exposure PDF — remediation-driven, never plaintext.

The findings table shows only redacted password *status*; the plaintext never
enters this module (records carry redaction signals only). Sections are in
Albanian to match the existing Cytadel template. A running header appears on
every page and the findings table repeats its header row across page breaks.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import List, Optional, Sequence

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.lib.utils import ImageReader
from reportlab.pdfgen.canvas import Canvas
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    Image,
    ListFlowable,
    ListItem,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

from .parser import ExposureRecord
from .resources import asset_path
from .search import REQUIRED_ACTION, summarize

ACCENT = colors.HexColor("#6E0B0B")   # dark red / near-black accent
INK = colors.HexColor("#1A1A1A")
MUTED = colors.HexColor("#5A5A5A")
ZEBRA = colors.HexColor("#F7F2F2")
HEADER_BG = colors.HexColor("#2A0A0A")
BORDER = colors.HexColor("#D8C9C9")

_HEADER_LEFT = "CONFIDENTIAL - SECURITY INCIDENT REPORT"
_HEADER_RIGHT = "Cytadel.eu"
_MARGIN = 2 * cm
_COVER_LOGO_HEIGHT_PT = 120  # ~120px tall, aspect preserved


@dataclass(frozen=True)
class ReportMeta:
    client: str
    report_id: str
    date: str
    prepared_by: str = "Cytadel.eu"
    classification: str = "KONFIDENCIAL"
    distribution: str = "Vetëm për Personelin e Autorizuar"


def _canvasmaker(compress: bool):
    """Canvas factory; disables PDF stream compression when requested so the
    'no plaintext in bytes' assertion in tests is meaningful."""

    class _Cytadel(Canvas):
        def __init__(self, *args, **kwargs):
            kwargs["pageCompression"] = 1 if compress else 0
            super().__init__(*args, **kwargs)

    return _Cytadel


def _styles():
    base = getSampleStyleSheet()
    s = {}
    s["cover_title"] = ParagraphStyle(
        "cover_title", parent=base["Title"], fontSize=26, leading=32,
        alignment=TA_CENTER, textColor=ACCENT, spaceAfter=18,
    )
    s["cover_client"] = ParagraphStyle(
        "cover_client", parent=base["Title"], fontSize=34, leading=40,
        alignment=TA_CENTER, textColor=INK, spaceAfter=24,
    )
    s["cover_brand"] = ParagraphStyle(
        "cover_brand", parent=base["Normal"], fontSize=16, leading=20,
        alignment=TA_CENTER, textColor=MUTED,
    )
    s["h1"] = ParagraphStyle(
        "h1", parent=base["Heading1"], fontSize=15, leading=19,
        textColor=ACCENT, spaceBefore=6, spaceAfter=10,
    )
    s["h2"] = ParagraphStyle(
        "h2", parent=base["Heading2"], fontSize=12, leading=16,
        textColor=INK, spaceBefore=8, spaceAfter=6,
    )
    s["body"] = ParagraphStyle(
        "body", parent=base["Normal"], fontSize=10, leading=15,
        textColor=INK, alignment=TA_LEFT, spaceAfter=8,
    )
    s["meta"] = ParagraphStyle(
        "meta", parent=base["Normal"], fontSize=10.5, leading=18, textColor=INK,
    )
    s["bullet"] = ParagraphStyle(
        "bullet", parent=base["Normal"], fontSize=10, leading=14, textColor=INK,
    )
    s["disclaimer"] = ParagraphStyle(
        "disclaimer", parent=base["Normal"], fontSize=8.5, leading=12,
        textColor=MUTED,
    )
    s["cell"] = ParagraphStyle(
        "cell", parent=base["Normal"], fontSize=8.5, leading=11, textColor=INK,
    )
    s["cell_head"] = ParagraphStyle(
        "cell_head", parent=base["Normal"], fontSize=9, leading=12,
        textColor=colors.white, alignment=TA_LEFT,
    )
    return s


def _draw_frame(canvas: Canvas, doc: BaseDocTemplate) -> None:
    canvas.saveState()
    width, height = A4
    canvas.setFont("Helvetica-Bold", 8)
    canvas.setFillColor(ACCENT)
    canvas.drawString(_MARGIN, height - 1.25 * cm, _HEADER_LEFT)
    canvas.drawRightString(width - _MARGIN, height - 1.25 * cm, _HEADER_RIGHT)
    canvas.setStrokeColor(ACCENT)
    canvas.setLineWidth(0.7)
    canvas.line(_MARGIN, height - 1.42 * cm, width - _MARGIN, height - 1.42 * cm)

    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(MUTED)
    canvas.drawCentredString(width / 2.0, 1.1 * cm, f"Faqe {doc.page}")
    canvas.restoreState()


def _derive_sources(records: Sequence[ExposureRecord]) -> List[str]:
    kinds = {r.fmt for r in records}
    out: List[str] = []
    if kinds & {"line", "block"}:
        out.append("Stealer logs (malware infostealer)")
    if "antipublic" in kinds:
        out.append("ANTIPUBLIC / combolist")
    if not out:
        out.append("Stealer logs (malware infostealer)")
    out.append("Burime të tjera të komprometimit (breach)")
    return out


def _logo_flowable(logo_path: str, target_height_pt: float) -> Optional[Image]:
    """Build a centered Image scaled to ``target_height_pt``, keeping aspect."""
    if not logo_path or not os.path.exists(logo_path):
        return None
    try:
        reader = ImageReader(logo_path)
        src_w, src_h = reader.getSize()
        if src_h <= 0:
            return None
        width = target_height_pt * (src_w / src_h)
        img = Image(logo_path, width=width, height=target_height_pt)
        img.hAlign = "CENTER"
        return img
    except Exception:
        return None


def _cover(story, styles, meta, logo_path):
    story.append(Spacer(1, 4 * cm))
    logo = _logo_flowable(logo_path, _COVER_LOGO_HEIGHT_PT)
    if logo is not None:
        story.append(logo)
        story.append(Spacer(1, 1.2 * cm))
    else:
        story.append(Spacer(1, 1 * cm))
    story.append(Paragraph("Raport i sigurisë kibernetike", styles["cover_title"]))
    story.append(Paragraph(_esc(meta.client), styles["cover_client"]))
    story.append(Paragraph("Cytadel Security", styles["cover_brand"]))
    story.append(PageBreak())


def _metadata_page(story, styles, meta):
    story.append(Paragraph("CONFIDENTIAL / SECURITY INCIDENT REPORT", styles["h1"]))
    story.append(
        Paragraph(
            "Analiza e Malware-it Infostealer &amp; Vlerësimi i Kërcënimit",
            styles["h2"],
        )
    )
    story.append(Spacer(1, 0.4 * cm))
    rows = [
        ("Klasifikimi i Raportit", meta.classification),
        ("Data e Raportit", meta.date),
        ("Përgatitur nga", meta.prepared_by),
        ("ID e Raportit", meta.report_id),
        ("Shpërndarja", meta.distribution),
    ]
    data = [
        [
            Paragraph(f"<b>{_esc(label)}</b>", styles["meta"]),
            Paragraph(_esc(value), styles["meta"]),
        ]
        for label, value in rows
    ]
    table = Table(data, colWidths=[5.5 * cm, 11 * cm])
    table.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LINEBELOW", (0, 0), (-1, -2), 0.4, BORDER),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    story.append(table)
    story.append(PageBreak())


def _description_page(story, styles, meta, domains, records):
    story.append(
        Paragraph("PËRSHKRIM I RAPORTIT – EKSPOZIMI I KREDENCIALEVE", styles["h1"])
    )
    n = len(records)
    domain_str = ", ".join(domains) if domains else "domenin e klientit"
    story.append(
        Paragraph(
            "Ky raport dokumenton llogaritë e personelit të "
            f"<b>{_esc(meta.client)}</b> të gjetura të ekspozuara në loge të "
            "malware-it infostealer dhe burime të tjera komprometimi. Për arsye "
            "ligjore (minimizimi i të dhënave, GDPR) dhe sigurie, raporti nuk "
            "përmban fjalëkalime në tekst të thjeshtë — vetëm statusin e tyre të "
            "redaktuar dhe veprimin e kërkuar.",
            styles["body"],
        )
    )
    story.append(
        Paragraph(
            f"Raporti dokumenton <b>{n}</b> llogari të ekspozuara në domenin "
            f"<b>{_esc(domain_str)}</b>.",
            styles["body"],
        )
    )
    story.append(Paragraph("BURIMI I TË DHËNAVE", styles["h2"]))
    story.append(
        ListFlowable(
            [ListItem(Paragraph(_esc(s), styles["bullet"])) for s in _derive_sources(records)],
            bulletType="bullet",
            leftIndent=14,
        )
    )
    story.append(PageBreak())


def _contents_page(story, styles):
    story.append(Paragraph("PËRMBAJTJA E RAPORTIT", styles["h1"]))
    story.append(
        Paragraph(
            "Tabela e ekspozimit paraqet për çdo llogari të kompromentuar:",
            styles["body"],
        )
    )
    columns = [
        "<b>LLOGARIA/EMAIL</b> — identifikuesi i llogarisë së ekspozuar",
        "<b>SHËRBIMI/URL</b> — shërbimi ku është përdorur llogaria",
        "<b>STATUSI I FJALËKALIMIT</b> — vetëm sinjale të redaktuara "
        "(gjatësia, klasat e karaktereve, i dobët/i ripërdorur) — kurrë vlera",
        "<b>VEPRIMI</b> — masa e kërkuar e riparimit",
    ]
    story.append(
        ListFlowable(
            [ListItem(Paragraph(c, styles["bullet"])) for c in columns],
            bulletType="bullet",
            leftIndent=14,
        )
    )
    story.append(Paragraph("Rreziqet kryesore", styles["h2"]))
    risks = [
        "Qasje e paautorizuar në llogaritë dhe sistemet e organizatës.",
        "Vjedhje identiteti dhe keqpërdorim i të dhënave personale.",
        "Sulme social-engineering dhe phishing të synuar.",
        "Ekspozim i rrjetit të brendshëm përmes kredencialeve të ripërdorura.",
    ]
    story.append(
        ListFlowable(
            [ListItem(Paragraph(_esc(r), styles["bullet"])) for r in risks],
            bulletType="bullet",
            leftIndent=14,
        )
    )
    story.append(Spacer(1, 0.4 * cm))
    story.append(
        Paragraph("SHPËRNDARJA: VETËM PËR PERSONELIN E AUTORIZUAR", styles["h2"])
    )
    story.append(PageBreak())


def _findings_table(story, styles, records):
    story.append(Paragraph("LLOGARITË E EKSPOZUARA", styles["h1"]))
    if not records:
        story.append(
            Paragraph(
                "Nuk u gjet asnjë llogari e ekspozuar brenda domeneve të klientit.",
                styles["body"],
            )
        )
        story.append(PageBreak())
        return

    head = [
        Paragraph("Email/Llogaria", styles["cell_head"]),
        Paragraph("Shërbimi/URL", styles["cell_head"]),
        Paragraph("Fjalëkalimi (status)", styles["cell_head"]),
        Paragraph("Veprimi i kërkuar", styles["cell_head"]),
    ]
    data = [head]
    for rec in records:
        data.append(
            [
                Paragraph(_esc(rec.email), styles["cell"]),
                Paragraph(_esc(rec.service_url), styles["cell"]),
                Paragraph(_esc(rec.redaction.status_label()), styles["cell"]),
                Paragraph(_esc(REQUIRED_ACTION), styles["cell"]),
            ]
        )

    table = Table(
        data,
        colWidths=[5.0 * cm, 5.4 * cm, 4.0 * cm, 2.6 * cm],
        repeatRows=1,
    )
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), HEADER_BG),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.3, BORDER),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
    ]
    for row in range(1, len(data)):
        if row % 2 == 0:
            style.append(("BACKGROUND", (0, row), (-1, row), ZEBRA))
    table.setStyle(TableStyle(style))
    story.append(table)
    story.append(PageBreak())


def _recommendations_page(story, styles):
    story.append(Paragraph("REKOMANDIMET", styles["h1"]))
    recs = [
        "Detyroni menjëherë ndryshimin e fjalëkalimit për çdo llogari të listuar.",
        "Zbatoni autentifikimin shumëfaktorësh (MFA) në të gjitha llogaritë.",
        "Bllokoni ripërdorimin e fjalëkalimeve dhe zbatoni një menaxher fjalëkalimesh.",
        "Monitoroni për ekspozime të mëtejshme dhe aktivitet të dyshimtë hyrjeje.",
        "Rishikoni pajisjet e prekura nga malware-i dhe pastroni infeksionet.",
    ]
    story.append(
        ListFlowable(
            [ListItem(Paragraph(_esc(r), styles["bullet"])) for r in recs],
            bulletType="1",
            leftIndent=14,
        )
    )
    story.append(Spacer(1, 0.6 * cm))
    story.append(
        Paragraph(
            "MOHIM PËRGJEGJËSIE / KONFIDENCIALITET: Ky dokument përmban informacion "
            "konfidencial të sigurisë dhe destinohet vetëm për personelin e "
            "autorizuar të klientit. Ndalohet shpërndarja, kopjimi ose zbulimi i "
            "tij te palë të treta pa autorizim me shkrim. Të dhënat janë "
            "përpunuar në përputhje me parimin e minimizimit të të dhënave.",
            styles["disclaimer"],
        )
    )


def build_pdf(
    path: str,
    meta: ReportMeta,
    domains: Sequence[str],
    records: Sequence[ExposureRecord],
    logo_path: Optional[str] = None,
    compress: bool = True,
) -> str:
    """Render the full report to ``path`` and return it.

    The cover uses the bundled dark logo (``assets/logo_dark.png``) by default;
    pass ``logo_path`` only to override it.
    """
    if logo_path is None:
        logo_path = asset_path("logo_dark.png")
    styles = _styles()
    doc = BaseDocTemplate(
        path,
        pagesize=A4,
        leftMargin=_MARGIN,
        rightMargin=_MARGIN,
        topMargin=2.2 * cm,
        bottomMargin=1.8 * cm,
        title=f"Cytadel Exposure Report — {meta.client}",
        author=meta.prepared_by,
    )
    frame = Frame(
        doc.leftMargin,
        doc.bottomMargin,
        doc.width,
        doc.height,
        id="main",
    )
    doc.addPageTemplates(
        [PageTemplate(id="cytadel", frames=[frame], onPage=_draw_frame)]
    )

    story: list = []
    _cover(story, styles, meta, logo_path)
    _metadata_page(story, styles, meta)
    _description_page(story, styles, meta, list(domains), records)
    _contents_page(story, styles)
    _findings_table(story, styles, records)
    _recommendations_page(story, styles)

    doc.build(story, canvasmaker=_canvasmaker(compress))
    return path


def _esc(text: str) -> str:
    """Escape text for reportlab Paragraph mini-markup."""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )
