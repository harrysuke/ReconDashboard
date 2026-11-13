"""PDF report generation with ReportLab.

Produces a self-contained "scan diff + vulnerability summary" document: what
changed since the previous scan and what is currently exposed. Pure Python, no
system libraries (unlike WeasyPrint), so it works on a bare Windows host.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    HRFlowable,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from recon.db import DATA_DIR, init_db
from recon.models import Asset, AssetVulnerability, ChangeEvent, ScanRun, Target, Vulnerability

REPORT_DIR = DATA_DIR / "reports"
REPORT_DIR.mkdir(parents=True, exist_ok=True)

INK = colors.HexColor("#0f172a")
MUTED = colors.HexColor("#64748b")
LINE = colors.HexColor("#e2e8f0")
CRIT = colors.HexColor("#dc2626")
HIGH = colors.HexColor("#ea580c")
MED = colors.HexColor("#d97706")
LOW = colors.HexColor("#0891b2")
SEV_COLORS = {"critical": CRIT, "high": HIGH, "medium": MED, "low": LOW,
              "unknown": MUTED, "info": MUTED}


def _hex(color: colors.Color) -> str:
    return "#" + color.hexval()[2:]


def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("t", parent=base["Title"], fontName="Helvetica-Bold",
                                fontSize=22, textColor=INK, alignment=TA_LEFT, spaceAfter=2),
        "sub": ParagraphStyle("s", parent=base["Normal"], fontSize=9.5, textColor=MUTED,
                              spaceAfter=14, leading=14),
        "h2": ParagraphStyle("h2", parent=base["Heading2"], fontName="Helvetica-Bold",
                             fontSize=13, textColor=INK, spaceBefore=16, spaceAfter=6),
        "body": ParagraphStyle("b", parent=base["Normal"], fontSize=9, textColor=INK, leading=13),
        "small": ParagraphStyle("sm", parent=base["Normal"], fontSize=8, textColor=MUTED, leading=11),
        "cell": ParagraphStyle("c", parent=base["Normal"], fontSize=8, textColor=INK, leading=10.5),
        "cellmono": ParagraphStyle("cm", parent=base["Normal"], fontName="Courier",
                                   fontSize=7.5, textColor=INK, leading=10),
    }


def _header_footer(canvas, doc) -> None:
    canvas.saveState()
    w, h = A4
    canvas.setStrokeColor(LINE)
    canvas.setLineWidth(0.6)
    canvas.line(18 * mm, h - 14 * mm, w - 18 * mm, h - 14 * mm)
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(MUTED)
    canvas.drawString(18 * mm, h - 12 * mm, "OSINT & CVE Recon Dashboard")
    canvas.drawRightString(w - 18 * mm, h - 12 * mm, datetime.now().strftime("%Y-%m-%d %H:%M"))
    canvas.line(18 * mm, 14 * mm, w - 18 * mm, 14 * mm)
    canvas.drawString(18 * mm, 10 * mm, "Automated reconnaissance report - handle as confidential")
    canvas.drawRightString(w - 18 * mm, 10 * mm, f"Page {doc.page}")
    canvas.restoreState()


def _table(data, col_widths, *, header: bool = True, zebra: bool = True) -> Table:
    table = Table(data, colWidths=col_widths, repeatRows=1 if header else 0)
    style = [
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("LINEBELOW", (0, 0), (-1, -1), 0.4, LINE),
    ]
    if header:
        style += [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 7.8),
            ("TEXTCOLOR", (0, 0), (-1, 0), INK),
        ]
    if zebra:
        for i in range(1, len(data)):
            if i % 2 == 0:
                style.append(("BACKGROUND", (0, i), (-1, i), colors.HexColor("#fafbfc")))
    table.setStyle(TableStyle(style))
    return table


def _kpi_row(st: dict, cells: list[tuple[str, str]]) -> Table:
    data = [[Paragraph(
        f'<font size=16><b>{v}</b></font><br/><font size=7 color="#64748b">{k}</font>',
        st["cell"]) for k, v in cells]]
    t = Table(data, colWidths=[28 * mm] * len(cells))
    t.setStyle(TableStyle([
        ("BOX", (0, 0), (-1, -1), 0.6, LINE),
        ("INNERGRID", (0, 0), (-1, -1), 0.6, LINE),
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    return t


def _risk(crit: int, high: int, assets: int) -> float:
    return round(min(100.0, (crit * 10 + high * 5) / max(1, assets) * 12), 1)


def build_report(scan_id: int, target_id: int | None = None) -> Path:
    """Render a PDF for one scan and return the file path."""
    init_db()
    st = _styles()

    scan = ScanRun.get_or_none(ScanRun.id == scan_id)
    if scan is None:
        raise ValueError(f"scan {scan_id} not found")
    target = Target.get_or_none(Target.id == scan.target_id)
    label = target.display if target else "unknown"
    value = target.value if target else ""

    changes = list(
        ChangeEvent.select().where(ChangeEvent.scan == scan_id).order_by(ChangeEvent.id.desc())
    )
    new_keys = {c.asset_key for c in changes if c.kind == "new_asset" and c.asset_key}
    closed_keys = {c.asset_key for c in changes if c.kind == "closed_asset" and c.asset_key}

    assets = list(
        Asset.select()
        .where(Asset.target_id == scan.target_id, Asset.is_active == True)  # noqa: E712
        .order_by(Asset.port)
    )

    findings: list[dict] = []
    query = (
        AssetVulnerability
        .select(AssetVulnerability, Asset, Vulnerability)
        .join(Asset)
        .switch(AssetVulnerability)
        .join(Vulnerability)
        .where(Asset.target_id == scan.target_id, Asset.is_active == True)  # noqa: E712
        .order_by(Vulnerability.cvss_score.desc())
    )
    for link in query:
        findings.append(dict(
            cve=link.vuln.cve_id, cvss=link.vuln.cvss_score, sev=link.vuln.severity,
            title=link.vuln.title or link.vuln.description, exploited=link.vuln.exploited,
            asset=f"{link.asset.ip}:{link.asset.port}", host=link.asset.hostname,
            product=link.asset.product, version=link.asset.version,
            confidence=link.confidence,
        ))

    distinct = {f["cve"] for f in findings}
    crit = len({f["cve"] for f in findings if f["sev"] == "critical"})
    high = len({f["cve"] for f in findings if f["sev"] == "high"})

    path = REPORT_DIR / f"recon_scan{scan_id}.pdf"
    doc = SimpleDocTemplate(
        str(path), pagesize=A4,
        leftMargin=18 * mm, rightMargin=18 * mm, topMargin=20 * mm, bottomMargin=20 * mm,
        title=f"Recon report - {label}", author="ReconDashboard",
    )

    story: list = []
    story.append(Paragraph("OSINT &amp; CVE Reconnaissance Report", st["title"]))
    started_txt = scan.started_at.strftime("%Y-%m-%d %H:%M UTC") if scan.started_at else "-"
    story.append(Paragraph(
        f"Target <b>{label}</b> ({value}) &nbsp;|&nbsp; Scan #{scan_id} &nbsp;|&nbsp; "
        f"{started_txt} &nbsp;|&nbsp; mode {scan.mode} &nbsp;|&nbsp; {scan.duration_label} "
        f"&nbsp;|&nbsp; {scan.subdomains_found} subdomains from CT logs",
        st["sub"],
    ))
    story.append(HRFlowable(width="100%", thickness=0.8, color=LINE, spaceAfter=10))
    story.append(_kpi_row(st, [
        ("Assets", str(len(assets))), ("New", f"+{len(new_keys)}"),
        ("Distinct CVEs", str(len(distinct))), ("Critical", str(crit)),
        ("High", str(high)), ("Risk", f"{_risk(crit, high, len(assets))}"),
    ]))
    story.append(Spacer(1, 8))
    story.append(Paragraph(
        "Exposure is derived from public sources only (certificate transparency, Shodan "
        "fingerprints, HTTP banner grabbing) and correlated against the NVD/CIRCL CVE corpus. "
        "A version match is an indicator, not proof of exploitability - validate before acting.",
        st["small"]))

    # --- severity breakdown -------------------------------------------------
    story.append(Paragraph("Vulnerability summary", st["h2"]))
    sev_counts: dict[str, int] = {}
    for f in findings:
        sev_counts[f["sev"]] = sev_counts.get(f["sev"], 0) + 1
    if sev_counts:
        rows = [[Paragraph(h, st["cell"]) for h in ("Severity", "Findings", "Unique CVEs")]]
        for sev in ("critical", "high", "medium", "low", "unknown"):
            if sev_counts.get(sev):
                uniq = len({f["cve"] for f in findings if f["sev"] == sev})
                rows.append([
                    Paragraph(f'<font color="{_hex(SEV_COLORS[sev])}"><b>{sev.upper()}</b></font>',
                              st["cell"]),
                    Paragraph(str(sev_counts[sev]), st["cell"]),
                    Paragraph(str(uniq), st["cell"]),
                ])
        story.append(_table(rows, [40 * mm, 30 * mm, 30 * mm]))
    else:
        story.append(Paragraph("No known CVEs matched the discovered service versions.", st["body"]))

    # --- the diff -----------------------------------------------------------
    story.append(Paragraph("Newly exposed assets since the previous scan", st["h2"]))
    new_assets = [a for a in assets if a.asset_key in new_keys]
    if new_assets:
        rows = [[Paragraph(h, st["cell"]) for h in
                 ("Endpoint", "Host", "Product / version", "Service", "Title")]]
        for a in new_assets[:40]:
            rows.append([
                Paragraph(f"{a.ip}:{a.port}", st["cellmono"]),
                Paragraph(a.hostname or "-", st["cell"]),
                Paragraph(f"{a.product} {a.version}".strip() or "-", st["cell"]),
                Paragraph(a.service or "-", st["cell"]),
                Paragraph((a.title or "-")[:60], st["cell"]),
            ])
        story.append(_table(rows, [32 * mm, 44 * mm, 40 * mm, 20 * mm, 40 * mm]))
    else:
        story.append(Paragraph("No new assets were exposed during this scan.", st["body"]))

    if closed_keys:
        story.append(Paragraph("Assets that disappeared", st["h2"]))
        story.append(Paragraph(", ".join(sorted(closed_keys)), st["body"]))

    # --- prioritised findings ----------------------------------------------
    story.append(PageBreak())
    story.append(Paragraph("Prioritised findings", st["h2"]))
    if findings:
        rows = [[Paragraph(h, st["cell"]) for h in
                 ("CVE", "CVSS", "Asset", "Product", "Summary", "Conf.")]]
        for f in findings[:45]:
            rows.append([
                Paragraph(f'<font color="{_hex(SEV_COLORS.get(f["sev"], MUTED))}"><b>{f["cve"]}</b>'
                          f'</font>{" *" if f["exploited"] else ""}', st["cell"]),
                Paragraph(f"{f['cvss']:.1f}", st["cell"]),
                Paragraph(f["asset"], st["cellmono"]),
                Paragraph(f"{f['product']} {f['version']}".strip() or "-", st["cell"]),
                Paragraph((f["title"] or "")[:110], st["cell"]),
                Paragraph(f["confidence"], st["cell"]),
            ])
        story.append(_table(rows, [26 * mm, 12 * mm, 26 * mm, 30 * mm, 66 * mm, 16 * mm]))
        story.append(Spacer(1, 4))
        story.append(Paragraph(
            "* CVE has been observed exploited in the wild (known-exploited list).", st["small"]))
    else:
        story.append(Paragraph("No findings to prioritise.", st["body"]))

    # --- inventory ----------------------------------------------------------
    story.append(Paragraph("Full service inventory", st["h2"]))
    rows = [[Paragraph(h, st["cell"]) for h in
             ("Endpoint", "Host", "Port", "Product", "TLS", "Sources")]]
    for a in assets[:80]:
        rows.append([
            Paragraph(f"{a.ip}:{a.port}/{a.protocol}", st["cellmono"]),
            Paragraph(a.hostname or "-", st["cell"]),
            Paragraph(str(a.port), st["cell"]),
            Paragraph(f"{a.product} {a.version}".strip() or a.service or "-", st["cell"]),
            Paragraph("yes" if a.tls else "no", st["cell"]),
            Paragraph((a.sources or "").replace(",", ", "), st["cell"]),
        ])
    story.append(_table(rows, [34 * mm, 46 * mm, 14 * mm, 46 * mm, 12 * mm, 24 * mm]))

    # --- change log ---------------------------------------------------------
    story.append(Paragraph("Change log", st["h2"]))
    if changes:
        rows = [[Paragraph(h, st["cell"]) for h in ("Kind", "Severity", "Event", "Detail")]]
        for c in changes[:60]:
            rows.append([
                Paragraph(c.kind.replace("_", " "), st["cell"]),
                Paragraph(c.severity, st["cell"]),
                Paragraph(c.title[:80], st["cell"]),
                Paragraph((c.detail or "")[:90], st["cell"]),
            ])
        story.append(_table(rows, [28 * mm, 18 * mm, 70 * mm, 52 * mm]))
    else:
        story.append(Paragraph("No changes recorded.", st["body"]))

    doc.build(story, onFirstPage=_header_footer, onLaterPages=_header_footer)
    return path


def build_portfolio_report() -> Path:
    """Estate-wide summary across every target, using each one's latest state."""
    init_db()
    st = _styles()
    rows_data: list[list] = []
    total_assets = total_cves = 0

    for t in Target.select().order_by(Target.id):
        assets = list(Asset.select().where(Asset.target_id == t.id, Asset.is_active == True))  # noqa: E712
        cves = list(
            Vulnerability
            .select(Vulnerability.id, Vulnerability.severity)
            .join(AssetVulnerability, on=(AssetVulnerability.vuln == Vulnerability.id))
            .join(Asset, on=(AssetVulnerability.asset == Asset.id))
            .where(Asset.target_id == t.id, Asset.is_active == True)  # noqa: E712
            .distinct()
        )
        crit = sum(1 for v in cves if v.severity == "critical")
        high = sum(1 for v in cves if v.severity == "high")
        latest = (ScanRun.select()
                  .where(ScanRun.target_id == t.id, ScanRun.status == "success")
                  .order_by(ScanRun.started_at.desc()).first())
        total_assets += len(assets)
        total_cves += len(cves)
        rows_data.append([
            Paragraph(t.display, st["cell"]),
            Paragraph(t.value, st["cellmono"]),
            Paragraph(t.kind, st["cell"]),
            Paragraph(str(len(assets)), st["cell"]),
            Paragraph(str(len(cves)), st["cell"]),
            Paragraph(f'<font color="#dc2626">{crit}</font>', st["cell"]),
            Paragraph(f'<font color="#ea580c">{high}</font>', st["cell"]),
            Paragraph(latest.started_at.strftime("%Y-%m-%d") if latest and latest.started_at
                      else "never", st["cell"]),
        ])

    path = REPORT_DIR / f"estate_summary_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf"
    doc = SimpleDocTemplate(str(path), pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm,
                            topMargin=20 * mm, bottomMargin=20 * mm,
                            title="Estate exposure summary")
    story = [
        Paragraph("Estate Exposure Summary", st["title"]),
        Paragraph(f"{len(rows_data)} targets &nbsp;|&nbsp; {total_assets} active services "
                  f"&nbsp;|&nbsp; {total_cves} distinct CVEs", st["sub"]),
        HRFlowable(width="100%", thickness=0.8, color=LINE, spaceAfter=10),
        _table(
            [[Paragraph(h, st["cell"]) for h in
              ("Target", "Scope", "Kind", "Assets", "CVEs", "Crit", "High", "Last scan")]]
            + rows_data,
            [42 * mm, 42 * mm, 16 * mm, 16 * mm, 14 * mm, 12 * mm, 12 * mm, 22 * mm],
        ),
        Spacer(1, 10),
        Paragraph("Generated from stored scan history. Severity is derived from CVSS base scores.",
                  st["small"]),
    ]
    doc.build(story, onFirstPage=_header_footer, onLaterPages=_header_footer)
    return path
