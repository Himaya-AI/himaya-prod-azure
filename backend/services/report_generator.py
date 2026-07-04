"""
Generates bilingual (Arabic + English) PDF audit reports with Himaya branding.
Uses ReportLab with arabic-reshaper + python-bidi for RTL Arabic text.
"""

import io
import os
import uuid
from datetime import datetime, date
from pathlib import Path
from typing import Optional

try:
    import boto3
    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable, Image,
)
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.lib.enums import TA_RIGHT, TA_LEFT, TA_CENTER
import arabic_reshaper
from bidi.algorithm import get_display

# ── Paths ──────────────────────────────────────────────────────────────────────
_THIS_DIR = Path(__file__).parent
LOGO_PATH = _THIS_DIR / "himaya_logo.png"
PUBLIC_LOGO_PATH = Path(__file__).parent.parent.parent / "frontend" / "public" / "himaya-logo.png"


def _get_logo_path() -> Optional[str]:
    """Return path to Himaya logo if it exists."""
    for p in [LOGO_PATH, PUBLIC_LOGO_PATH]:
        if p.exists():
            return str(p)
    return None


def reshape_arabic(text: str) -> str:
    """Reshape Arabic text for correct RTL rendering."""
    try:
        reshaped = arabic_reshaper.reshape(text)
        return get_display(reshaped)
    except Exception:
        return text


# ── Colour palette ─────────────────────────────────────────────────────────────
HIMAYA_RED    = colors.HexColor("#e94560")
HIMAYA_NAVY   = colors.HexColor("#16213e")
HIMAYA_BLUE   = colors.HexColor("#3b6ef6")
HIMAYA_DARK   = colors.HexColor("#0d1324")
SLATE_200     = colors.HexColor("#e2e8f0")
SLATE_400     = colors.HexColor("#94a3b8")
SLATE_600     = colors.HexColor("#475569")
EMERALD       = colors.HexColor("#4ade80")
AMBER         = colors.HexColor("#fbbf24")
RED_SOFT      = colors.HexColor("#f87171")
ROW_ALT       = colors.HexColor("#f8fafc")
ROW_BASE      = colors.white


def _score_color(pct: int):
    if pct >= 80:  return EMERALD
    if pct >= 60:  return AMBER
    return RED_SOFT


class AuditReportGenerator:

    def __init__(self, container: str = "himaya-reports"):
        self.container = container
        self.azure_account = os.getenv("AZURE_STORAGE_ACCOUNT", "")
        self.s3_bucket = os.getenv("S3_BUCKET", "")
        self.aws_region = os.getenv("AWS_REGION", "us-east-1")
        if self.azure_account:
            try:
                from azure.identity import DefaultAzureCredential
                from azure.storage.blob import BlobServiceClient
                self.blob_client = BlobServiceClient(
                    account_url=f"https://{self.azure_account}.blob.core.windows.net",
                    credential=DefaultAzureCredential(),
                )
            except Exception:
                self.blob_client = None
        elif HAS_BOTO3:
            self.s3_client = boto3.client("s3", region_name=self.aws_region)
        else:
            self.s3_client = None
            self.blob_client = None

    def generate_report(
        self,
        org_name: str,
        framework: str,
        date_from: date,
        date_to: date,
        threats: list,
        compliance_controls: list,
        overall_score: int,
        org_id: str,
        all_frameworks_controls: dict | None = None,  # {fw_key: [controls]}
    ) -> tuple:
        """
        Generate a professional PDF compliance report with Himaya branding.
        Returns (pdf_bytes, s3_key).
        """
        buffer = io.BytesIO()
        logo_path = _get_logo_path()

        page_w, page_h = A4
        margin = 2.0 * cm

        # ── Style definitions ──────────────────────────────────────────────────
        styles = getSampleStyleSheet()

        def _style(name, **kw):
            return ParagraphStyle(name, **kw)

        h1 = _style("H1", fontSize=16, textColor=HIMAYA_NAVY, spaceAfter=6, spaceBefore=12, fontName="Helvetica-Bold")
        h2 = _style("H2", fontSize=13, textColor=HIMAYA_NAVY, spaceAfter=4, spaceBefore=8, fontName="Helvetica-Bold")
        body = _style("Body", fontSize=9, textColor=SLATE_600, spaceAfter=4, leading=14)
        body_en = _style("BodyEN", fontSize=9, textColor=colors.HexColor("#1e293b"), spaceAfter=4, leading=14)
        ar_style = _style("Arabic", fontSize=10, alignment=TA_RIGHT, leading=16, spaceAfter=4)
        center = _style("Center", fontSize=9, alignment=TA_CENTER, textColor=SLATE_400)
        caption = _style("Caption", fontSize=8, textColor=SLATE_400, spaceAfter=2)
        brand_title = _style("Brand", fontSize=32, textColor=HIMAYA_RED, alignment=TA_CENTER, fontName="Helvetica-Bold", spaceAfter=4)
        brand_sub = _style("BrandSub", fontSize=18, textColor=HIMAYA_NAVY, alignment=TA_CENTER, fontName="Helvetica-Bold", spaceAfter=2)
        finding = _style("Finding", fontSize=9, textColor=colors.HexColor("#1e293b"), leading=15, leftIndent=12, spaceAfter=3)

        story = []

        FW_LABELS = {
            "SAMA_CSF":  "SAMA Cyber Security Framework",
            "NCA_ECC":   "NCA Essential Cybersecurity Controls",
            "UAE_NESA":  "UAE NESA Compliance",
            "CBUAE":     "Central Bank of UAE Cybersecurity",
            "NIST_CSF":  "NIST Cybersecurity Framework",
            "HIPAA":     "Health Insurance Portability and Accountability Act",
            "SOC2":      "SOC 2 Trust Services Criteria",
            "CCPA":      "California Consumer Privacy Act",
            "GDPR":      "EU General Data Protection Regulation",
            "ISO_27001": "ISO/IEC 27001 Information Security Management",
            "DORA":      "EU Digital Operational Resilience Act",
            "NIS2":      "EU Network and Information Security Directive 2",
        }
        fw_label = FW_LABELS.get(framework, framework.replace("_", " "))

        # ══════════════════════════════════════════════════════════════════════
        # COVER PAGE — drawn directly on canvas via onFirstPage callback
        # This is the only reliable way to prevent overlap in ReportLab.
        # All text is placed at absolute y-coordinates; nothing can collide.
        # ══════════════════════════════════════════════════════════════════════

        _cover_meta = {
            "org_name": org_name,
            "fw_label": fw_label,
            "overall_score": overall_score,
            "grade": _grade(overall_score),
            "score_color": _score_color(overall_score),
            "date_from": date_from.strftime("%B %d, %Y"),
            "date_to": date_to.strftime("%B %d, %Y"),
            "generated": datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
            "logo_path": logo_path,
        }

        def _draw_cover(canv, doc):
            from reportlab.lib.units import cm as _cm
            canv.saveState()
            W, H = canv._pagesize  # A4: 595 x 842 pts

            # Dark navy header band
            canv.setFillColor(colors.HexColor("#16213e"))
            canv.rect(0, H - 3.5*_cm, W, 3.5*_cm, fill=1, stroke=0)

            # Red accent stripe
            canv.setFillColor(colors.HexColor("#e94560"))
            canv.rect(0, H - 3.55*_cm, W, 0.35*_cm, fill=1, stroke=0)

            # Logo in header (white background not needed — on dark band)
            if _cover_meta["logo_path"]:
                try:
                    canv.drawImage(_cover_meta["logo_path"], 1.8*_cm, H - 2.8*_cm,
                                   width=3.5*_cm, height=1.4*_cm,
                                   preserveAspectRatio=True, mask="auto")
                except Exception:
                    pass
            # "HIMAYA" in header
            canv.setFont("Helvetica-Bold", 11)
            canv.setFillColor(colors.white)
            canv.drawRightString(W - 1.8*_cm, H - 1.6*_cm, "HIMAYA")
            canv.setFont("Helvetica", 8)
            canv.setFillColor(colors.HexColor("#94a3b8"))
            canv.drawRightString(W - 1.8*_cm, H - 2.2*_cm, "Email Security Platform")

            # Main title block — vertically centred on page
            cy = H * 0.62  # start point ~62% down from top

            canv.setFont("Helvetica-Bold", 28)
            canv.setFillColor(colors.HexColor("#e94560"))
            canv.drawCentredString(W / 2, cy, "Himaya Email Security Program")

            cy -= 1.0 * _cm
            canv.setFont("Helvetica-Bold", 17)
            canv.setFillColor(colors.HexColor("#16213e"))
            canv.drawCentredString(W / 2, cy, "Evidence and Compliance Report")

            cy -= 0.5 * _cm
            canv.setStrokeColor(colors.HexColor("#e94560"))
            canv.setLineWidth(1.5)
            canv.line(W*0.2, cy, W*0.8, cy)

            cy -= 0.7 * _cm
            canv.setFont("Helvetica", 11)
            canv.setFillColor(colors.HexColor("#3b6ef6"))
            canv.drawCentredString(W / 2, cy, "Comprehensive Multi-Framework Compliance Assessment")

            # Meta info box
            cy -= 1.2 * _cm
            box_x, box_w, row_h = 1.8*_cm, W - 3.6*_cm, 0.72*_cm
            meta_rows = [
                ("Organization",     _cover_meta["org_name"]),
                ("Primary Framework",_cover_meta["fw_label"]),
                ("Compliance Score", f"{_cover_meta['overall_score']}%   Grade {_cover_meta['grade']}"),
                ("Reporting Period", f"{_cover_meta['date_from']} — {_cover_meta['date_to']}"),
                ("Generated",        _cover_meta["generated"]),
                ("Platform",         "Himaya · app.himaya.ai"),
            ]
            box_h = len(meta_rows) * row_h + 0.3*_cm
            # Box background
            canv.setFillColor(colors.HexColor("#f8fafc"))
            canv.setStrokeColor(colors.HexColor("#e2e8f0"))
            canv.setLineWidth(0.5)
            canv.roundRect(box_x, cy - box_h, box_w, box_h, 6, fill=1, stroke=1)

            row_y = cy - 0.45*_cm
            for label, val in meta_rows:
                # Label col
                canv.setFont("Helvetica", 9)
                canv.setFillColor(colors.HexColor("#94a3b8"))
                canv.drawString(box_x + 0.4*_cm, row_y, label + ":")
                # Value col
                is_score = label == "Compliance Score"
                canv.setFont("Helvetica-Bold" if is_score else "Helvetica", 9)
                canv.setFillColor(_cover_meta["score_color"] if is_score else colors.HexColor("#16213e"))
                canv.drawString(box_x + 5.2*_cm, row_y, str(val))
                # Divider
                if label != "Platform":
                    canv.setStrokeColor(colors.HexColor("#e2e8f0"))
                    canv.setLineWidth(0.3)
                    canv.line(box_x + 0.3*_cm, row_y - 0.22*_cm, box_x + box_w - 0.3*_cm, row_y - 0.22*_cm)
                row_y -= row_h

            # Confidential footer
            canv.setFont("Helvetica-Oblique", 7.5)
            canv.setFillColor(colors.HexColor("#e94560"))
            canv.drawCentredString(W / 2, 1.4*_cm,
                "CONFIDENTIAL — This report contains sensitive security information. "
                "Distribution limited to authorised personnel only.")

            canv.restoreState()

        # Cover page is just a blank frame — everything drawn in _draw_cover callback
        story.append(Spacer(1, 1))  # placeholder so the page exists
        story.append(PageBreak())

        # ══════════════════════════════════════════════════════════════════════
        # EXECUTIVE SUMMARY
        # ══════════════════════════════════════════════════════════════════════
        story.append(Paragraph("Executive Summary", h1))
        story.append(Paragraph(reshape_arabic("الملخص التنفيذي"), ar_style))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#e2e8f0")))
        story.append(Spacer(1, 0.3 * cm))

        threat_count = len(threats)
        critical_count = sum(1 for t in threats if t.get("risk_score", 0) >= 90)
        high_count = sum(1 for t in threats if 70 <= t.get("risk_score", 0) < 90)
        quarantined_count = sum(1 for t in threats if t.get("action_taken") in ("QUARANTINE", "QUARANTINED"))
        blocked_count = sum(1 for t in threats if t.get("action_taken") in ("BLOCK", "BLOCK_DELETE"))

        total_controls = len(compliance_controls)
        compliant_count = sum(1 for c in compliance_controls if c.get("status") == "compliant")
        partial_count = sum(1 for c in compliance_controls if c.get("status") == "partial")
        non_compliant_count = sum(1 for c in compliance_controls if c.get("status") == "non_compliant")

        # Summary narrative
        grade = _grade(overall_score)
        narrative = _generate_narrative(
            org_name=org_name,
            framework=fw_label,
            overall_score=overall_score,
            grade=grade,
            threat_count=threat_count,
            critical_count=critical_count,
            quarantined_count=quarantined_count,
            total_controls=total_controls,
            compliant_count=compliant_count,
            non_compliant_count=non_compliant_count,
            date_from=date_from,
            date_to=date_to,
        )
        story.append(Paragraph(narrative, body_en))
        story.append(Spacer(1, 0.4 * cm))

        # KPI grid
        kpi_data = [
            ["Metric", "Value", "Arabic", "Status"],
            ["Overall Compliance Score", f"{overall_score}%", reshape_arabic("نسبة الامتثال"), grade],
            ["Total Controls Assessed", str(total_controls), reshape_arabic("إجمالي الضوابط"), "—"],
            ["Fully Compliant Controls", str(compliant_count), reshape_arabic("ضوابط ممتثلة"), f"{round(compliant_count / total_controls * 100) if total_controls else 0}%"],
            ["Partially Implemented", str(partial_count), reshape_arabic("جزئي"), "Needs work"],
            ["Non-Compliant Controls", str(non_compliant_count), reshape_arabic("غير ممتثل"), "Action required" if non_compliant_count else "None"],
            ["Total Threats Detected", str(threat_count), reshape_arabic("التهديدات"), "—"],
            ["Critical Threats (Score ≥90)", str(critical_count), reshape_arabic("حرج"), "High priority" if critical_count else "None"],
            ["Emails Quarantined", str(quarantined_count), reshape_arabic("محجوز"), "—"],
            ["Emails Blocked", str(blocked_count), reshape_arabic("محظور"), "—"],
        ]
        kpi_table = Table(kpi_data, colWidths=[5.5 * cm, 2.5 * cm, 4.5 * cm, 4 * cm])
        kpi_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), HIMAYA_NAVY),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#e2e8f0")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [ROW_BASE, ROW_ALT]),
            ("ALIGN", (1, 0), (1, -1), "CENTER"),
            ("ALIGN", (3, 0), (3, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("ROWPADDING", (0, 0), (-1, -1), 5),
            # Highlight score row
            ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#f0fdf4") if overall_score >= 80 else colors.HexColor("#fffbeb") if overall_score >= 60 else colors.HexColor("#fef2f2")),
            ("FONTNAME", (0, 1), (-1, 1), "Helvetica-Bold"),
        ]))
        story.append(kpi_table)

        story.append(PageBreak())

        # ══════════════════════════════════════════════════════════════════════
        # AI-DRIVEN FINDINGS & RECOMMENDATIONS
        # ══════════════════════════════════════════════════════════════════════
        story.append(Paragraph("AI-Driven Findings & Recommendations", h1))
        story.append(Paragraph(reshape_arabic("النتائج والتوصيات المستندة إلى الذكاء الاصطناعي"), ar_style))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#e2e8f0")))
        story.append(Spacer(1, 0.3 * cm))

        findings, recommendations = _generate_findings_and_recommendations(
            overall_score=overall_score,
            compliance_controls=compliance_controls,
            threats=threats,
            framework=fw_label,
        )

        story.append(Paragraph("Key Findings", h2))
        story.append(Paragraph(reshape_arabic("النتائج الرئيسية"), ar_style))
        for i, f in enumerate(findings, 1):
            story.append(Paragraph(f"<b>{i}.</b> {f}", finding))

        story.append(Spacer(1, 0.4 * cm))
        story.append(Paragraph("Recommendations", h2))
        story.append(Paragraph(reshape_arabic("التوصيات"), ar_style))
        for i, r in enumerate(recommendations, 1):
            story.append(Paragraph(f"<b>{i}.</b> {r}", finding))

        story.append(PageBreak())

        # ══════════════════════════════════════════════════════════════════════
        # CONTROL STATUS DETAIL
        # ══════════════════════════════════════════════════════════════════════
        story.append(Paragraph(f"{framework} Control Status Detail", h1))
        story.append(Paragraph(reshape_arabic(f"تفاصيل حالة ضوابط {framework}"), ar_style))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#e2e8f0")))
        story.append(Spacer(1, 0.2 * cm))

        if compliance_controls:
            # Determine whether any controls have Arabic names
            has_arabic = any(c.get("control_name_ar") or c.get("name_ar") for c in compliance_controls)
            if has_arabic:
                ctrl_headers = ["Control ID", "Control Name", reshape_arabic("اسم الضابط"), "Status", "Evidence"]
                col_widths = [2.2 * cm, 5.0 * cm, 4.0 * cm, 2.5 * cm, 1.8 * cm]
            else:
                ctrl_headers = ["Control ID", "Control Name", "Status", "Evidence", "Notes"]
                col_widths = [2.4 * cm, 7.5 * cm, 2.5 * cm, 1.6 * cm, 3.5 * cm]

            ctrl_data = [ctrl_headers]
            # Include ALL controls — no artificial limit
            name_style = ParagraphStyle("CN", fontSize=8, textColor=colors.HexColor("#1e293b"), leading=11, wordWrap='LTR')
            notes_style = ParagraphStyle("NT", fontSize=7, textColor=SLATE_600, leading=10, wordWrap='LTR')
            for ctrl in compliance_controls:
                status_val = ctrl.get("status", "not_started")
                status_label, status_color = _ctrl_status_style(status_val)
                name = ctrl.get("control_name_en") or ctrl.get("name_en") or ctrl.get("control_id", "")
                status_para = Paragraph(f"<b>{status_label}</b>",
                    ParagraphStyle("S", fontSize=8, textColor=status_color, fontName="Helvetica-Bold"))
                if has_arabic:
                    ar_name = ctrl.get("control_name_ar") or ctrl.get("name_ar") or ""
                    ctrl_data.append([
                        ctrl.get("control_id", ""),
                        Paragraph(name, name_style),
                        Paragraph(reshape_arabic(ar_name), ar_style),
                        status_para,
                        str(ctrl.get("evidence_count", 0)),
                    ])
                else:
                    notes = (ctrl.get("notes") or "")[:80]
                    ctrl_data.append([
                        ctrl.get("control_id", ""),
                        Paragraph(name, name_style),
                        status_para,
                        str(ctrl.get("evidence_count", 0)),
                        Paragraph(notes, notes_style) if notes else "",
                    ])

            ctrl_table = Table(ctrl_data, colWidths=col_widths, repeatRows=1)
            ctrl_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), HIMAYA_NAVY),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#e2e8f0")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [ROW_BASE, ROW_ALT]),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ]))
            story.append(ctrl_table)
        else:
            story.append(Paragraph("No control data available for this framework.", body))

        story.append(PageBreak())

        # ══════════════════════════════════════════════════════════════════════
        # ALL FRAMEWORKS ASSESSMENT
        # ══════════════════════════════════════════════════════════════════════
        if all_frameworks_controls:
            story.append(Paragraph("All Regulatory Frameworks — Assessment Summary", h1))
            story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#e2e8f0")))
            story.append(Spacer(1, 0.3*cm))

            # Summary scorecard across all frameworks
            fw_summary_data = [["Framework", "Region", "Controls", "Compliant", "Partial", "Score", "Grade"]]
            FW_REGION = {
                "SAMA_CSF":"Gulf","NCA_ECC":"Gulf","UAE_NESA":"Gulf","CBUAE":"Gulf",
                "NIST_CSF":"US","HIPAA":"US","SOC2":"US","CCPA":"US",
                "GDPR":"EU","ISO_27001":"EU","DORA":"EU","NIS2":"EU",
            }
            for fw_key, fw_ctrls in all_frameworks_controls.items():
                if not fw_ctrls:
                    continue
                tot = len(fw_ctrls)
                comp = sum(1 for c in fw_ctrls if c.get("status") == "compliant")
                part = sum(1 for c in fw_ctrls if c.get("status") == "partial")
                sc = round((comp + part*0.5)/tot*100) if tot else 0
                fw_summary_data.append([
                    FW_LABELS.get(fw_key, fw_key.replace("_"," ")),
                    FW_REGION.get(fw_key,"—"),
                    str(tot), str(comp), str(part),
                    Paragraph(f"<b>{sc}%</b>", ParagraphStyle("SC", fontSize=8, textColor=_score_color(sc), fontName="Helvetica-Bold")),
                    Paragraph(f"<b>{_grade(sc)}</b>", ParagraphStyle("GR", fontSize=8, textColor=_score_color(sc), fontName="Helvetica-Bold")),
                ])

            fw_sum_table = Table(fw_summary_data, colWidths=[5.8*cm, 1.6*cm, 1.6*cm, 1.8*cm, 1.6*cm, 1.6*cm, 1.5*cm], repeatRows=1)
            fw_sum_table.setStyle(TableStyle([
                ("BACKGROUND", (0,0),(-1,0), HIMAYA_NAVY),
                ("TEXTCOLOR", (0,0),(-1,0), colors.white),
                ("FONTNAME", (0,0),(-1,0), "Helvetica-Bold"),
                ("FONTSIZE", (0,0),(-1,-1), 8),
                ("GRID", (0,0),(-1,-1), 0.3, colors.HexColor("#e2e8f0")),
                ("ROWBACKGROUNDS", (0,1),(-1,-1), [ROW_BASE, ROW_ALT]),
                ("VALIGN", (0,0),(-1,-1), "MIDDLE"),
                ("TOPPADDING", (0,0),(-1,-1), 5),
                ("BOTTOMPADDING", (0,0),(-1,-1), 5),
                ("ALIGN", (2,0),(-1,-1), "CENTER"),
            ]))
            story.append(fw_sum_table)
            story.append(Spacer(1, 0.4*cm))

            # Per-framework detailed control pages
            name_style2 = ParagraphStyle("CN2", fontSize=8, textColor=colors.HexColor("#1e293b"), leading=11, wordWrap='LTR')
            for fw_key, fw_ctrls in all_frameworks_controls.items():
                if not fw_ctrls or fw_key == framework:
                    continue  # primary framework already shown above
                story.append(PageBreak())
                story.append(Paragraph(FW_LABELS.get(fw_key, fw_key.replace("_"," ")), h1))
                story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#e2e8f0")))
                story.append(Spacer(1, 0.2*cm))

                has_ar = any(c.get("control_name_ar") or c.get("name_ar") for c in fw_ctrls)
                if has_ar:
                    hdr = ["ID", "Control Name", reshape_arabic("اسم الضابط"), "Status", "Evid."]
                    cw  = [2.0*cm, 5.2*cm, 4.0*cm, 2.5*cm, 1.5*cm]
                else:
                    hdr = ["ID", "Control Name", "Status", "Evidence", "Notes"]
                    cw  = [2.4*cm, 7.5*cm, 2.5*cm, 1.6*cm, 3.5*cm]

                tbl_data = [hdr]
                for c in fw_ctrls:
                    sv = c.get("status","not_started")
                    sl, sc2 = _ctrl_status_style(sv)
                    nm = c.get("control_name_en") or c.get("name_en") or c.get("control_id","")
                    sp = Paragraph(f"<b>{sl}</b>", ParagraphStyle("S2", fontSize=8, textColor=sc2, fontName="Helvetica-Bold"))
                    if has_ar:
                        tbl_data.append([c.get("control_id",""), Paragraph(nm, name_style2),
                                         Paragraph(reshape_arabic(c.get("control_name_ar","") or ""), ar_style), sp, str(c.get("evidence_count",0))])
                    else:
                        tbl_data.append([c.get("control_id",""), Paragraph(nm, name_style2),
                                         sp, str(c.get("evidence_count",0)),
                                         Paragraph((c.get("notes") or "")[:80], ParagraphStyle("NT2", fontSize=7, textColor=SLATE_600, leading=10))])

                ft = Table(tbl_data, colWidths=cw, repeatRows=1)
                ft.setStyle(TableStyle([
                    ("BACKGROUND",(0,0),(-1,0),HIMAYA_NAVY),("TEXTCOLOR",(0,0),(-1,0),colors.white),
                    ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,-1),8),
                    ("GRID",(0,0),(-1,-1),0.3,colors.HexColor("#e2e8f0")),
                    ("ROWBACKGROUNDS",(0,1),(-1,-1),[ROW_BASE,ROW_ALT]),
                    ("VALIGN",(0,0),(-1,-1),"TOP"),
                    ("TOPPADDING",(0,0),(-1,-1),5),("BOTTOMPADDING",(0,0),(-1,-1),5),
                    ("LEFTPADDING",(0,0),(-1,-1),4),("RIGHTPADDING",(0,0),(-1,-1),4),
                ]))
                story.append(ft)

            story.append(PageBreak())

        # ══════════════════════════════════════════════════════════════════════
        # THREAT / INCIDENT LOG
        # ══════════════════════════════════════════════════════════════════════
        story.append(Paragraph("Incident Log", h1))
        story.append(Paragraph(reshape_arabic("سجل الحوادث"), ar_style))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#e2e8f0")))
        story.append(Spacer(1, 0.2 * cm))

        if threats:
            inc_data = [["Date", "Threat Type", "Recipient", "Risk Score", "Action Taken"]]
            for t in threats[:60]:
                score = t.get("risk_score", 0)
                inc_data.append([
                    str(t.get("detected_at", ""))[:10],
                    t.get("threat_type", "").replace("_", " ").title(),
                    (t.get("recipient_email", "") or "")[:35],
                    Paragraph(
                        f"<b>{score}</b>",
                        ParagraphStyle("RS", fontSize=8, fontName="Helvetica-Bold",
                            textColor=RED_SOFT if score >= 80 else AMBER if score >= 50 else EMERALD),
                    ),
                    t.get("action_taken", ""),
                ])

            inc_table = Table(inc_data, colWidths=[2.4 * cm, 3.5 * cm, 5.5 * cm, 1.8 * cm, 3.5 * cm])
            inc_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), HIMAYA_NAVY),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 7.5),
                ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#e2e8f0")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [ROW_BASE, ROW_ALT]),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("ROWPADDING", (0, 0), (-1, -1), 4),
                ("ALIGN", (3, 0), (3, -1), "CENTER"),
            ]))
            story.append(inc_table)
            if len(threats) > 60:
                story.append(Paragraph(f"* Showing {min(60, len(threats))} of {len(threats)} incidents.", caption))
        else:
            story.append(Paragraph("No incidents detected in the reporting period.", body))

        story.append(PageBreak())

        # ══════════════════════════════════════════════════════════════════════
        # THREAT SOURCE GEOGRAPHY
        # ══════════════════════════════════════════════════════════════════════
        story.append(Paragraph("Threat Source Locations", h1))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#e2e8f0")))
        story.append(Spacer(1, 0.3*cm))

        from collections import Counter as _GeoCounter
        geo_threats = [t for t in threats if t.get("sender_country") and t["sender_country"] not in ("Unknown","")]
        if geo_threats:
            geo_counts = _GeoCounter(t["sender_country"] for t in geo_threats)
            total_geo = len(geo_threats)
            geo_data = [["Country / Region", "Threats", "% of Total", "Sender IPs (sample)"]]
            for country, cnt in geo_counts.most_common(20):
                sample_ips = list({
                    t.get("sender_ip","") for t in threats
                    if t.get("sender_country") == country and t.get("sender_ip")
                })[:3]
                ip_str = ", ".join(sample_ips) if sample_ips else "—"
                pct = round(cnt / total_geo * 100)
                geo_data.append([country, str(cnt), f"{pct}%", ip_str])

            geo_table = Table(geo_data, colWidths=[5.5*cm, 2.0*cm, 2.5*cm, 7.0*cm], repeatRows=1)
            geo_table.setStyle(TableStyle([
                ("BACKGROUND",(0,0),(-1,0),HIMAYA_NAVY),("TEXTCOLOR",(0,0),(-1,0),colors.white),
                ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,-1),8),
                ("GRID",(0,0),(-1,-1),0.3,colors.HexColor("#e2e8f0")),
                ("ROWBACKGROUNDS",(0,1),(-1,-1),[ROW_BASE,ROW_ALT]),
                ("VALIGN",(0,0),(-1,-1),"MIDDLE"),
                ("TOPPADDING",(0,0),(-1,-1),5),("BOTTOMPADDING",(0,0),(-1,-1),5),
                ("ALIGN",(1,0),(2,-1),"CENTER"),
            ]))
            story.append(geo_table)
            not_geo = len(threats) - total_geo
            if not_geo:
                story.append(Paragraph(f"* {not_geo} threats had no resolvable source location.", caption))
        else:
            story.append(Paragraph(
                "No geolocation data available. IP addresses are extracted from email headers during "
                "message processing and resolved to country at report generation time.",
                body
            ))

        # ── Footer on last page ────────────────────────────────────────────────
        story.append(Spacer(1, 1 * cm))
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#e2e8f0")))
        story.append(Spacer(1, 0.3 * cm))
        story.append(Paragraph(
            f"Generated by Himaya Email Security Platform · app.himaya.ai · "
            f"{datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')} · Confidential",
            _style("Footer", fontSize=7, textColor=SLATE_400, alignment=TA_CENTER),
        ))

        # ── Build PDF ─────────────────────────────────────────────────────────
        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            rightMargin=margin,
            leftMargin=margin,
            topMargin=margin,
            bottomMargin=margin,
            title=f"Himaya Email Security Program — Evidence and Compliance Report — {org_name}",
            author="Himaya",
            subject=f"{framework} Audit Report",
        )
        def _first_page(canv, doc):
            _draw_cover(canv, doc)
            # No page number on cover

        doc.build(story, onFirstPage=_first_page, onLaterPages=_add_page_number)
        pdf_bytes = buffer.getvalue()

        # ── Upload to blob storage ─────────────────────────────────────────────
        blob_key = f"reports/{org_id}/{framework}/{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf"
        if self.blob_client:
            try:
                from azure.storage.blob import ContentSettings
                blob = self.blob_client.get_blob_client(container=self.container, blob=blob_key)
                blob.upload_blob(
                    pdf_bytes,
                    overwrite=True,
                    content_settings=ContentSettings(content_type="application/pdf"),
                )
            except Exception:
                pass
        elif self.s3_client:
            try:
                self.s3_client.put_object(
                    Bucket=self.s3_bucket,
                    Key=blob_key,
                    Body=pdf_bytes,
                    ContentType="application/pdf",
                )
            except Exception:
                pass

        return pdf_bytes, blob_key

    async def generate_html_report(
        self,
        org_id: str,
        framework: str,
        controls_data: list,
        threats_data: list,
        policies_data: list,
        employees_data: list,
        dns_data: dict,
        org_name: str,
        domain: str,
        claude_analysis: str = "",
        all_frameworks_controls: dict | None = None,
    ) -> str:
        """Generate a white-background HTML compliance report with Himaya branding."""
        import base64 as _b64
        from collections import Counter as _Counter

        # Embed logo
        logo_path = _get_logo_path()
        if logo_path:
            with open(logo_path, "rb") as f:
                logo_b64 = _b64.b64encode(f.read()).decode()
            logo_html = f'<img src="data:image/png;base64,{logo_b64}" style="height:30px;width:auto;" alt="Himaya">'
        else:
            logo_html = '<img src="https://app.himaya.ai/himaya-logo.png" style="height:30px;width:auto;" alt="Himaya">'

        # Scores
        compliant = sum(1 for c in controls_data if c.get("status") == "compliant")
        partial   = sum(1 for c in controls_data if c.get("status") == "partial")
        total     = len(controls_data)
        score     = round((compliant + partial * 0.5) / total * 100) if total else 0
        grade     = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F"
        grade_color = "#16a34a" if score >= 75 else "#d97706" if score >= 50 else "#dc2626"

        # Threat summary
        flagged   = len(threats_data)
        blocked   = sum(1 for t in threats_data if t.get("action_taken") in ("QUARANTINED", "BLOCKED", "BLOCK_DELETE"))
        block_pct = round(blocked / flagged * 100) if flagged else 0

        # Top countries
        countries = _Counter(t.get("sender_country", "Unknown") for t in threats_data if t.get("sender_country"))
        top_countries = countries.most_common(8)

        # Employees at risk
        emp_counts: dict = {}
        for t in threats_data:
            r = t.get("recipient_email", "")
            if r:
                emp_counts[r] = emp_counts.get(r, 0) + 1
        top_employees = sorted(emp_counts.items(), key=lambda x: x[1], reverse=True)[:10]

        date_str = datetime.now().strftime("%B %d, %Y")
        fw_label = framework.replace("_", " ")

        def badge(status: str) -> str:
            m = {
                "compliant": ("#dcfce7", "#166534"),
                "partial": ("#fef9c3", "#854d0e"),
                "non_compliant": ("#fee2e2", "#991b1b"),
                "not_started": ("#f1f5f9", "#475569"),
            }
            bg, fg = m.get(status, ("#f1f5f9", "#475569"))
            return f'<span style="background:{bg};color:{fg};padding:2px 8px;border-radius:99px;font-size:11px;font-weight:600">{status.replace("_", " ")}</span>'

        controls_rows = "".join(
            f'<tr>'
            f'<td style="font-family:monospace;font-size:11px;color:#94a3b8;padding:9px 12px;border-bottom:1px solid #f1f5f9">{c.get("control_id", "")}</td>'
            f'<td style="padding:9px 12px;border-bottom:1px solid #f1f5f9;font-size:13px">{c.get("control_name_en") or c.get("name_en") or c.get("control_id", "")}</td>'
            f'<td style="padding:9px 12px;border-bottom:1px solid #f1f5f9">{badge(c.get("status", "not_started"))}</td>'
            f'<td style="padding:9px 12px;border-bottom:1px solid #f1f5f9;font-size:12px;color:#64748b">{c.get("evidence_count", 0)}</td>'
            f'<td style="padding:9px 12px;border-bottom:1px solid #f1f5f9;font-size:12px;color:#64748b;max-width:260px">{c.get("notes", "—") or "—"}</td>'
            f'</tr>'
            for c in controls_data
        )

        # Build IP samples per country for the geo table
        _ip_by_country: dict = {}
        for t in threats_data:
            c = t.get("sender_country","")
            ip = t.get("sender_ip","")
            if c and ip:
                _ip_by_country.setdefault(c, set()).add(ip)

        country_rows = "".join(
            f'<tr>'
            f'<td style="padding:9px 12px;border-bottom:1px solid #f1f5f9">{country}</td>'
            f'<td style="padding:9px 12px;border-bottom:1px solid #f1f5f9;font-weight:600">{cnt}</td>'
            f'<td style="padding:9px 12px;border-bottom:1px solid #f1f5f9">{round(cnt / flagged * 100) if flagged else 0}%</td>'
            f'<td style="padding:9px 12px;border-bottom:1px solid #f1f5f9;font-family:monospace;font-size:11px;color:#64748b">'
            f'{", ".join(list(_ip_by_country.get(country, set()))[:3]) or "—"}</td>'
            f'</tr>'
            for country, cnt in top_countries
        ) if top_countries else "<tr><td colspan='4' style='padding:12px;color:#94a3b8'>No geo data available — IPs extracted from email headers during processing</td></tr>"

        emp_rows = "".join(
            f'<tr><td style="padding:9px 12px;border-bottom:1px solid #f1f5f9">{email}</td>'
            f'<td style="padding:9px 12px;border-bottom:1px solid #f1f5f9;font-weight:600;color:#dc2626">{cnt}</td></tr>'
            for email, cnt in top_employees
        ) if top_employees else "<tr><td colspan='2' style='padding:12px;color:#94a3b8'>No employee threat data available</td></tr>"

        policy_rows = "".join(
            f'<tr><td style="padding:9px 12px;border-bottom:1px solid #f1f5f9">{p.get("name", "")}</td>'
            f'<td style="padding:9px 12px;border-bottom:1px solid #f1f5f9">{p.get("action", "")}</td>'
            f'<td style="padding:9px 12px;border-bottom:1px solid #f1f5f9">{p.get("priority", "")}</td></tr>'
            for p in policies_data[:20]
        ) if policies_data else "<tr><td colspan='3' style='padding:12px;color:#94a3b8'>No policies configured</td></tr>"

        ai_section = (
            f'<div style="background:#f0f7ff;border-left:4px solid #3b6ef6;padding:16px 20px;border-radius:0 8px 8px 0;margin-bottom:8px">'
            f'<p style="color:#1e40af;font-size:13px;line-height:1.7;white-space:pre-wrap">{claude_analysis}</p></div>'
        ) if claude_analysis else ""

        # Build all-frameworks section HTML
        _FW_LABELS_HTML = {
            "SAMA_CSF":"SAMA Cyber Security Framework","NCA_ECC":"NCA Essential Cybersecurity Controls",
            "UAE_NESA":"UAE NESA Compliance","CBUAE":"Central Bank of UAE Cybersecurity",
            "NIST_CSF":"NIST Cybersecurity Framework","HIPAA":"HIPAA","SOC2":"SOC 2",
            "CCPA":"CCPA","GDPR":"GDPR","ISO_27001":"ISO 27001","DORA":"DORA","NIS2":"NIS 2",
        }
        _FW_REGION_HTML = {
            "SAMA_CSF":"Gulf","NCA_ECC":"Gulf","UAE_NESA":"Gulf","CBUAE":"Gulf",
            "NIST_CSF":"US","HIPAA":"US","SOC2":"US","CCPA":"US",
            "GDPR":"EU","ISO_27001":"EU","DORA":"EU","NIS2":"EU",
        }
        _STATUS_BADGE = {
            "compliant": ("#dcfce7","#166534"),
            "partial": ("#fef9c3","#854d0e"),
            "non_compliant": ("#fee2e2","#991b1b"),
            "not_started": ("#f1f5f9","#475569"),
        }

        if all_frameworks_controls:
            # Summary scorecard
            sc_rows = ""
            for fw_k, fw_cs in all_frameworks_controls.items():
                if not fw_cs: continue
                t2=len(fw_cs); c2=sum(1 for x in fw_cs if x.get("status")=="compliant"); p2=sum(1 for x in fw_cs if x.get("status")=="partial")
                sc2=round((c2+p2*0.5)/t2*100) if t2 else 0
                gc="#16a34a" if sc2>=75 else "#d97706" if sc2>=50 else "#dc2626"
                grade2="A" if sc2>=90 else "B" if sc2>=75 else "C" if sc2>=60 else "D" if sc2>=40 else "F"
                sc_rows += (f'<tr><td style="padding:9px 12px;border-bottom:1px solid #f1f5f9">{_FW_LABELS_HTML.get(fw_k,fw_k)}</td>'
                           f'<td style="padding:9px 12px;border-bottom:1px solid #f1f5f9;font-size:11px;color:#64748b">{_FW_REGION_HTML.get(fw_k,"")}</td>'
                           f'<td style="padding:9px 12px;border-bottom:1px solid #f1f5f9;text-align:center">{t2}</td>'
                           f'<td style="padding:9px 12px;border-bottom:1px solid #f1f5f9;text-align:center;font-weight:600;color:#16a34a">{c2}</td>'
                           f'<td style="padding:9px 12px;border-bottom:1px solid #f1f5f9;text-align:center;font-weight:600;color:{gc}">{sc2}%</td>'
                           f'<td style="padding:9px 12px;border-bottom:1px solid #f1f5f9;text-align:center;font-weight:900;color:{gc};font-size:16px">{grade2}</td></tr>')

            # Per-framework control detail tables
            fw_detail_html = ""
            for fw_k, fw_cs in all_frameworks_controls.items():
                if not fw_cs: continue
                ctrl_rows_fw = ""
                for c in fw_cs:
                    st = c.get("status","not_started")
                    bg, fg = _STATUS_BADGE.get(st, ("#f1f5f9","#475569"))
                    nm = c.get("control_name_en") or c.get("name_en") or c.get("control_id","")
                    ctrl_rows_fw += (f'<tr>'
                        f'<td style="font-family:monospace;font-size:11px;color:#94a3b8;padding:8px 10px;border-bottom:1px solid #f1f5f9">{c.get("control_id","")}</td>'
                        f'<td style="padding:8px 10px;border-bottom:1px solid #f1f5f9;font-size:12px">{nm}</td>'
                        f'<td style="padding:8px 10px;border-bottom:1px solid #f1f5f9"><span style="background:{bg};color:{fg};padding:2px 7px;border-radius:99px;font-size:10px;font-weight:600">{st.replace("_"," ")}</span></td>'
                        f'<td style="padding:8px 10px;border-bottom:1px solid #f1f5f9;text-align:center;font-size:12px;color:#64748b">{c.get("evidence_count",0)}</td>'
                        f'</tr>')
                fw_detail_html += f"""
<div class="section-title">{_FW_LABELS_HTML.get(fw_k, fw_k)} <span style="font-size:12px;font-weight:400;color:#64748b;margin-left:8px">({_FW_REGION_HTML.get(fw_k,"")})</span></div>
<table><thead><tr><th>ID</th><th>Control Name</th><th>Status</th><th>Evidence</th></tr></thead>
<tbody>{ctrl_rows_fw}</tbody></table>"""

            all_fw_html = f"""
  <div class="section-title">All Frameworks — Compliance Summary</div>
  <table><thead><tr><th>Framework</th><th>Region</th><th>Controls</th><th>Compliant</th><th>Score</th><th>Grade</th></tr></thead>
  <tbody>{sc_rows}</tbody></table>
  {fw_detail_html}"""
        else:
            all_fw_html = ""

        html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>Himaya Email Security Program — Evidence and Compliance Report</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#fff;color:#1a1a2e;font-size:14px;line-height:1.6}}
table{{width:100%;border-collapse:collapse;font-size:13px}}
th{{background:#f1f5f9;color:#475569;font-weight:600;text-align:left;padding:10px 12px;border-bottom:2px solid #e2e8f0}}
.section-title{{font-size:16px;font-weight:700;color:#1a1f3c;border-bottom:2px solid #e94560;padding-bottom:6px;margin:28px 0 16px}}
.stat-grid{{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-bottom:24px}}
.stat-card{{background:#f8fafc;border:1px solid #e2e8f0;border-radius:10px;padding:16px}}
</style></head><body>

<div style="background:#1a1f3c;padding:24px 40px;display:flex;align-items:center;justify-content:space-between">
  <div>
    <table style="width:auto;border-collapse:collapse"><tr><td bgcolor="#1a1f3c">{logo_html}</td></tr></table>
    <h1 style="color:#fff;font-size:22px;font-weight:700;margin-top:8px">Himaya Email Security Program — Evidence and Compliance Report</h1>
    <div style="color:#94a3b8;font-size:13px">{org_name} &nbsp;&middot;&nbsp; {domain}</div>
  </div>
  <div style="color:#94a3b8;font-size:12px;text-align:right">
    <strong style="color:#fff;display:block;font-size:14px">CONFIDENTIAL</strong>
    Generated {date_str}<br>Powered by Himaya
  </div>
</div>

<div style="max-width:900px;margin:0 auto;padding:32px 40px">

  <div class="section-title">Overall Compliance Grade</div>
  <div style="display:inline-flex;align-items:center;gap:20px;background:#f8fafc;border:1px solid #e2e8f0;border-radius:12px;padding:20px 28px;margin-bottom:28px">
    <div style="font-size:60px;font-weight:900;color:{grade_color};line-height:1">{grade}</div>
    <div>
      <div style="font-size:30px;font-weight:800;color:#1a1f3c">{score}%</div>
      <div style="color:#64748b;font-size:13px">compliance score</div>
      <div style="color:#64748b;font-size:12px;margin-top:4px">{compliant} compliant &nbsp;&middot;&nbsp; {partial} partial &nbsp;&middot;&nbsp; {total - compliant - partial} non-compliant &nbsp;&middot;&nbsp; {total} total</div>
    </div>
  </div>

  <div class="section-title">Email Security Overview (Last 90 Days)</div>
  <div class="stat-grid">
    <div class="stat-card"><div style="font-size:11px;color:#94a3b8;text-transform:uppercase;letter-spacing:.05em">Threats Detected</div><div style="font-size:28px;font-weight:800;color:#1a1f3c;margin-top:4px">{flagged}</div></div>
    <div class="stat-card"><div style="font-size:11px;color:#94a3b8;text-transform:uppercase;letter-spacing:.05em">Blocked / Quarantined</div><div style="font-size:28px;font-weight:800;color:#dc2626;margin-top:4px">{blocked}</div></div>
    <div class="stat-card"><div style="font-size:11px;color:#94a3b8;text-transform:uppercase;letter-spacing:.05em">Block Rate</div><div style="font-size:28px;font-weight:800;color:#16a34a;margin-top:4px">{block_pct}%</div></div>
  </div>

  <div class="section-title">Email Authentication (DNS Records)</div>
  <table style="width:auto;margin-bottom:24px">
    <tr><td style="font-weight:600;color:#475569;padding:6px 16px 6px 0;font-size:12px;min-width:80px">Domain</td><td style="font-family:monospace;font-size:12px;color:#374151">{dns_data.get("domain", "\u2014")}</td></tr>
    <tr><td style="font-weight:600;color:#475569;padding:6px 16px 6px 0;font-size:12px">SPF</td><td style="font-family:monospace;font-size:12px;color:#374151;word-break:break-all">{dns_data.get("spf", "Not checked")}</td></tr>
    <tr><td style="font-weight:600;color:#475569;padding:6px 16px 6px 0;font-size:12px">DMARC</td><td style="font-family:monospace;font-size:12px;color:#374151;word-break:break-all">{dns_data.get("dmarc", "Not checked")}</td></tr>
    <tr><td style="font-weight:600;color:#475569;padding:6px 16px 6px 0;font-size:12px">MX</td><td style="font-family:monospace;font-size:12px;color:#374151">{", ".join(dns_data.get("mx", []) or ["None found"])}</td></tr>
  </table>

  {"<div class='section-title'>AI Compliance Analysis</div>" + ai_section if claude_analysis else ""}

  <div class="section-title">Control Assessment \u2014 {fw_label}</div>
  <table><thead><tr><th>ID</th><th>Control</th><th>Status</th><th>Evidence</th><th>Notes</th></tr></thead>
  <tbody>{controls_rows}</tbody></table>

  <div class="section-title">Threat Source Locations</div>
  <table><thead><tr><th>Country</th><th>Threats</th><th>% of Total</th><th>Sample IPs</th></tr></thead>
  <tbody>{country_rows}</tbody></table>

  <div class="section-title">Employees — Threat Exposure</div>
  <table><thead><tr><th>Employee</th><th>Threats Received</th></tr></thead>
  <tbody>{emp_rows}</tbody></table>

  <div class="section-title">Active Email Security Policies</div>
  <table><thead><tr><th>Policy Name</th><th>Action</th><th>Priority</th></tr></thead>
  <tbody>{policy_rows}</tbody></table>

  {all_fw_html}

</div>

<div style="background:#f8fafc;border-top:1px solid #e2e8f0;padding:20px 40px;text-align:center;color:#94a3b8;font-size:11px">
  This report is generated by Himaya and is intended for internal compliance use only.<br>
  Himaya Security &nbsp;&middot;&nbsp; app.himaya.ai &nbsp;&middot;&nbsp; {date_str}
</div>
</body></html>"""
        return html


# ── Page number callback ───────────────────────────────────────────────────────
def _add_page_number(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(colors.HexColor("#94a3b8"))
    page_num = canvas.getPageNumber()
    canvas.drawRightString(
        doc.pagesize[0] - doc.rightMargin,
        doc.bottomMargin - 0.5 * cm,
        f"Page {page_num}",
    )
    # Left: Himaya branding
    canvas.drawString(
        doc.leftMargin,
        doc.bottomMargin - 0.5 * cm,
        "Himaya · Confidential",
    )
    canvas.restoreState()


# ── Grade helper ───────────────────────────────────────────────────────────────
def _grade(score: int) -> str:
    if score >= 90: return "Excellent"
    if score >= 80: return "Good"
    if score >= 65: return "Satisfactory"
    if score >= 50: return "Needs Improvement"
    return "Non-Compliant"


# ── Control status styling ─────────────────────────────────────────────────────
def _ctrl_status_style(status: str):
    return {
        "compliant":     ("✓ Compliant", EMERALD),
        "partial":       ("⚠ Partial",   AMBER),
        "non_compliant": ("✗ Non-Compliant", RED_SOFT),
        "not_started":   ("— Not Started", SLATE_400),
    }.get(status, (status, SLATE_400))


# ── Narrative generator ────────────────────────────────────────────────────────
def _generate_narrative(
    org_name, framework, overall_score, grade,
    threat_count, critical_count, quarantined_count,
    total_controls, compliant_count, non_compliant_count,
    date_from, date_to,
) -> str:
    period = f"{date_from.strftime('%B %d, %Y')} to {date_to.strftime('%B %d, %Y')}"
    posture = (
        "demonstrates strong compliance posture" if overall_score >= 80
        else "shows a satisfactory compliance posture with room for improvement" if overall_score >= 65
        else "reveals significant compliance gaps that require immediate remediation"
    )
    threat_stmt = (
        f"During the assessment period, Himaya detected {threat_count} potential threats"
        + (f", including {critical_count} critical-severity incident{'s' if critical_count != 1 else ''}" if critical_count else "")
        + f". {quarantined_count} email{'s were' if quarantined_count != 1 else ' was'} quarantined automatically."
        if threat_count > 0
        else "No threats were detected during the assessment period, indicating effective preventive controls."
    )
    ctrl_stmt = (
        f"Of {total_controls} assessed controls, {compliant_count} are fully compliant"
        + (f" and {non_compliant_count} require remediation" if non_compliant_count else "")
        + "."
    )

    return (
        f"{org_name} {posture} under the {framework} for the period {period}. "
        f"Overall compliance score: <b>{overall_score}%</b> ({grade}). "
        f"{threat_stmt} {ctrl_stmt} "
        f"This report was automatically generated by Himaya and is intended for use in regulatory submissions and internal audits."
    )


# ── Findings + recommendations ─────────────────────────────────────────────────
def _generate_findings_and_recommendations(
    overall_score: int,
    compliance_controls: list,
    threats: list,
    framework: str,
) -> tuple[list[str], list[str]]:
    total = len(compliance_controls)
    compliant = [c for c in compliance_controls if c.get("status") == "compliant"]
    partial = [c for c in compliance_controls if c.get("status") == "partial"]
    non_compliant = [c for c in compliance_controls if c.get("status") == "non_compliant"]
    threat_types = {}
    for t in threats:
        tt = t.get("threat_type", "Unknown")
        threat_types[tt] = threat_types.get(tt, 0) + 1

    findings = []
    recommendations = []

    # Compliance findings
    if len(compliant) > 0:
        findings.append(
            f"{len(compliant)} of {total} {framework} controls are fully compliant, "
            f"representing {round(len(compliant)/total*100) if total else 0}% of the assessed control set."
        )
    if non_compliant:
        nc_names = ", ".join(c.get("control_name_en", c.get("control_id", ""))[:50] for c in non_compliant[:3])
        findings.append(
            f"{len(non_compliant)} control{'s remain' if len(non_compliant)>1 else ' remains'} non-compliant: "
            f"{nc_names}{' and others' if len(non_compliant)>3 else ''}. "
            f"These represent the highest regulatory risk and should be addressed first."
        )
    if partial:
        findings.append(
            f"{len(partial)} control{'s are' if len(partial)>1 else ' is'} partially implemented. "
            f"Completing evidence collection and finalising configuration for these controls can significantly improve the overall score."
        )

    # Threat findings
    if threats:
        top_types = sorted(threat_types.items(), key=lambda x: x[1], reverse=True)[:3]
        top_str = ", ".join(f"{tt} ({cnt})" for tt, cnt in top_types)
        findings.append(
            f"Himaya detected {len(threats)} threats during the reporting period. "
            f"Most prevalent threat types: {top_str}."
        )
        critical_count = sum(1 for t in threats if t.get("risk_score", 0) >= 90)
        if critical_count:
            findings.append(
                f"{critical_count} critical-severity threat{'s' if critical_count>1 else ''} (risk score ≥90) "
                f"{'were' if critical_count>1 else 'was'} detected — these pose the highest organizational risk."
            )
    else:
        findings.append(
            "No threats were detected during the reporting period. This indicates effective email security controls are in place."
        )

    # Recommendations
    if non_compliant:
        recommendations.append(
            f"Immediately address the {len(non_compliant)} non-compliant control{'s' if len(non_compliant)>1 else ''}. "
            f"Assign ownership to named individuals and set 30-day remediation deadlines."
        )
    if partial:
        recommendations.append(
            f"Complete implementation for {len(partial)} partial control{'s' if len(partial)>1 else ''} "
            f"by gathering required evidence and finalizing configurations."
        )
    if overall_score < 80:
        recommendations.append(
            "Establish a quarterly compliance review cycle to track progress toward an 80%+ compliance score required by most regulatory bodies."
        )
    if len(threats) > 10:
        recommendations.append(
            f"The {len(threats)} detected threats indicate active targeting. "
            f"Review and tighten email security policies, especially for top threat types."
        )
    recommendations.append(
        "Archive this report and associated evidence in your document management system as proof of due diligence for regulatory submissions."
    )
    recommendations.append(
        "Enable automated compliance evidence collection in Himaya to continuously capture threat response actions as audit evidence."
    )

    return findings, recommendations


