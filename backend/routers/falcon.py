"""
Falcon Agent — AI-powered security intelligence assistant.
Connects to SageMaker, databases, and internal signals to answer
customer questions about their security environment.
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database import get_db
from backend.routers.auth import get_current_user

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/falcon", tags=["falcon"])


# ── Request/Response Models ───────────────────────────────────────────────────

class ChatMessage(BaseModel):
    role: str
    content: str


class ChatRequest(BaseModel):
    message: str
    history: list[ChatMessage] = []


class AgentAction(BaseModel):
    type: str  # report, policy, query, alert
    label: str
    data: Optional[dict] = None


class ChatResponse(BaseModel):
    reply: str
    actions: list[AgentAction] = []


class ReportRequest(BaseModel):
    type: str  # threat_summary, executive_summary, compliance_detailed, data_exposure
    format: str = "pdf"


# ── Context Gathering ─────────────────────────────────────────────────────────

async def gather_security_context(org_id: str, db: AsyncSession) -> dict:
    """Gather current security metrics and context for the AI."""
    context = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "org_id": org_id,
    }

    try:
        # Recent threats (last 7 days)
        threats_result = await db.execute(
            text("""
                SELECT 
                    COUNT(*) as total,
                    SUM(CASE WHEN risk_score >= 80 THEN 1 ELSE 0 END) as critical,
                    SUM(CASE WHEN risk_score >= 60 AND risk_score < 80 THEN 1 ELSE 0 END) as high,
                    SUM(CASE WHEN status = 'quarantined' THEN 1 ELSE 0 END) as quarantined,
                    SUM(CASE WHEN status = 'resolved' THEN 1 ELSE 0 END) as resolved
                FROM threats 
                WHERE org_id = :org_id 
                AND created_at > NOW() - INTERVAL '7 days'
            """),
            {"org_id": org_id}
        )
        row = threats_result.fetchone()
        if row:
            context["threats_7d"] = {
                "total": int(row[0] or 0),
                "critical": int(row[1] or 0),
                "high": int(row[2] or 0),
                "quarantined": int(row[3] or 0),
                "resolved": int(row[4] or 0),
            }

        # Threat types distribution
        types_result = await db.execute(
            text("""
                SELECT threat_type, COUNT(*) as count
                FROM threats 
                WHERE org_id = :org_id 
                AND created_at > NOW() - INTERVAL '7 days'
                GROUP BY threat_type
                ORDER BY count DESC
                LIMIT 5
            """),
            {"org_id": org_id}
        )
        context["threat_types"] = [
            {"type": r[0], "count": int(r[1])} for r in types_result.fetchall()
        ]

        # DLP events (if enterprise)
        try:
            dlp_result = await db.execute(
                text("""
                    SELECT 
                        COUNT(*) as total,
                        SUM(CASE WHEN action_taken = 'BLOCK' THEN 1 ELSE 0 END) as blocked,
                        SUM(CASE WHEN action_taken = 'HOLD' THEN 1 ELSE 0 END) as held
                    FROM dlp_events 
                    WHERE org_id = :org_id 
                    AND created_at > NOW() - INTERVAL '7 days'
                """),
                {"org_id": org_id}
            )
            dlp_row = dlp_result.fetchone()
            if dlp_row:
                context["dlp_7d"] = {
                    "total": int(dlp_row[0] or 0),
                    "blocked": int(dlp_row[1] or 0),
                    "held": int(dlp_row[2] or 0),
                }
        except Exception:
            pass  # DLP tables may not exist

        # SaaS security alerts
        try:
            saas_result = await db.execute(
                text("""
                    SELECT 
                        COUNT(*) as total,
                        SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical,
                        SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high,
                        SUM(CASE WHEN status = 'open' THEN 1 ELSE 0 END) as open
                    FROM saas_alerts 
                    WHERE org_id = :org_id 
                    AND created_at > NOW() - INTERVAL '7 days'
                """),
                {"org_id": org_id}
            )
            saas_row = saas_result.fetchone()
            if saas_row:
                context["saas_alerts_7d"] = {
                    "total": int(saas_row[0] or 0),
                    "critical": int(saas_row[1] or 0),
                    "high": int(saas_row[2] or 0),
                    "open": int(saas_row[3] or 0),
                }
        except Exception:
            pass

        # Compliance scores
        try:
            compliance_result = await db.execute(
                text("""
                    SELECT framework, overall_score, gaps_critical, gaps_high
                    FROM compliance_assessments 
                    WHERE org_id = :org_id 
                    ORDER BY assessed_at DESC
                    LIMIT 5
                """),
                {"org_id": org_id}
            )
            context["compliance"] = [
                {
                    "framework": r[0],
                    "score": float(r[1]) if r[1] else 0,
                    "critical_gaps": int(r[2] or 0),
                    "high_gaps": int(r[3] or 0),
                }
                for r in compliance_result.fetchall()
            ]
        except Exception:
            pass

        # Active policies count
        try:
            policies_result = await db.execute(
                text("""
                    SELECT COUNT(*) FROM policies 
                    WHERE org_id = :org_id AND enabled = true
                """),
                {"org_id": org_id}
            )
            pol_row = policies_result.fetchone()
            context["active_policies"] = int(pol_row[0] or 0) if pol_row else 0
        except Exception:
            pass

    except Exception as exc:
        logger.warning(f"Error gathering security context: {exc}")

    return context


# ── AI Response Generation ────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are Bluebird, a security intelligence assistant for the Helios email security platform. 
You help security teams understand their threat landscape, analyze risks, and make decisions.

You have access to real-time security data from the user's environment:
- Email threats (phishing, BEC, malware, spam)
- DLP events (data loss prevention)
- SaaS security alerts (Teams, SharePoint)
- Compliance posture (SAMA, NCA frameworks)
- Security policies

Guidelines:
1. Be concise and actionable. Security teams are busy.
2. Prioritize critical issues first.
3. When showing numbers, provide context (e.g., "12 threats this week, up 20% from last week")
4. Suggest specific actions when relevant.
5. Use markdown formatting for clarity (bold, lists, headers).
6. If you can generate a report, mention it.
7. Be professional but approachable.

Current security context will be provided with each query.
"""


async def generate_ai_response(
    message: str,
    context: dict,
    history: list[ChatMessage],
) -> tuple[str, list[AgentAction]]:
    """Generate AI response using Claude/SageMaker."""
    import httpx

    # Try SageMaker endpoint first, then Claude API
    sagemaker_endpoint = os.getenv("BLUEBIRD_SAGEMAKER_ENDPOINT")
    anthropic_key = os.getenv("ANTHROPIC_API_KEY")

    messages = [{"role": m.role, "content": m.content} for m in history[-8:]]
    messages.append({"role": "user", "content": f"""
Security Context:
```json
{json.dumps(context, indent=2)}
```

User Query: {message}
"""})

    # Determine actions based on query intent
    actions = []
    lower_msg = message.lower()
    
    if any(kw in lower_msg for kw in ["report", "pdf", "summary", "download"]):
        actions.append(AgentAction(
            type="report",
            label="Generate Report",
            data={"type": "executive_summary", "format": "pdf"}
        ))
    
    if any(kw in lower_msg for kw in ["policy", "policies", "configure", "enable"]):
        actions.append(AgentAction(
            type="policy",
            label="Manage Policies"
        ))

    # Try Claude API
    if anthropic_key:
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                response = await client.post(
                    "https://api.anthropic.com/v1/messages",
                    headers={
                        "x-api-key": anthropic_key,
                        "anthropic-version": "2023-06-01",
                        "content-type": "application/json",
                    },
                    json={
                        "model": "claude-sonnet-4-20250514",
                        "max_tokens": 1024,
                        "system": SYSTEM_PROMPT,
                        "messages": messages,
                    },
                )
                if response.status_code == 200:
                    data = response.json()
                    reply = data.get("content", [{}])[0].get("text", "")
                    return reply, actions
        except Exception as exc:
            logger.warning(f"Claude API error: {exc}")

    # Fallback: Generate contextual response without AI
    return generate_contextual_fallback(message, context), actions


def generate_contextual_fallback(message: str, context: dict) -> str:
    """Generate a response based on actual context data."""
    lower_msg = message.lower()

    threats_7d = context.get("threats_7d", {})
    dlp_7d = context.get("dlp_7d", {})
    saas_alerts = context.get("saas_alerts_7d", {})
    compliance = context.get("compliance", [])
    threat_types = context.get("threat_types", [])

    if any(kw in lower_msg for kw in ["threat", "attack", "risk", "security"]):
        total = threats_7d.get("total", 0)
        critical = threats_7d.get("critical", 0)
        high = threats_7d.get("high", 0)
        quarantined = threats_7d.get("quarantined", 0)

        types_summary = "\n".join([
            f"• **{t['type']}** - {t['count']} incidents"
            for t in threat_types[:3]
        ]) if threat_types else "No threat data available"

        return f"""**Security Overview (Last 7 Days)**

📊 **Threat Summary:**
• Total threats detected: **{total}**
• Critical severity: **{critical}**
• High severity: **{high}**
• Successfully quarantined: **{quarantined}**

**Top Threat Types:**
{types_summary}

{"⚠️ **Action Required:** You have " + str(critical) + " critical threats that need immediate attention." if critical > 0 else "✅ No critical threats currently active."}

Would you like me to generate a detailed threat report?"""

    if any(kw in lower_msg for kw in ["compliance", "sama", "nca", "framework"]):
        if compliance:
            comp_summary = "\n".join([
                f"• **{c['framework']}**: {c['score']:.0f}/100 ({c['critical_gaps']} critical gaps)"
                for c in compliance
            ])
            return f"""**Compliance Posture Summary**

{comp_summary}

{"⚠️ There are critical compliance gaps that need attention." if any(c['critical_gaps'] > 0 for c in compliance) else "✅ No critical compliance gaps detected."}

I can generate a detailed compliance report with remediation steps."""
        return "No compliance assessments found. Would you like me to run a compliance check?"

    if any(kw in lower_msg for kw in ["dlp", "data", "leak", "sensitive"]):
        total_dlp = dlp_7d.get("total", 0)
        blocked = dlp_7d.get("blocked", 0)
        held = dlp_7d.get("held", 0)

        return f"""**Data Loss Prevention Summary (Last 7 Days)**

📊 **DLP Events:**
• Total events: **{total_dlp}**
• Blocked: **{blocked}**
• Held for review: **{held}**

{"⚠️ You have " + str(held) + " emails held for DLP review." if held > 0 else "✅ No emails currently held for review."}

Would you like me to analyze data exposure risks in more detail?"""

    if any(kw in lower_msg for kw in ["policy", "policies", "recommend"]):
        active = context.get("active_policies", 0)
        return f"""**Policy Overview**

You currently have **{active}** active security policies.

**Recommended Policy Enhancements:**
1. **External Attachment Scanning** - Scan all attachments from external senders
2. **Impersonation Protection** - Block emails impersonating executives
3. **Link Rewriting** - Protect users from malicious URLs
4. **Bulk Send Limits** - Restrict mass external emails

Would you like help configuring any of these policies?"""

    # Default response
    return f"""I can help you understand your security environment. Here's what I can do:

• **Threat Analysis** - Review current threats and risk scores
• **Compliance Status** - Check SAMA/NCA framework adherence
• **DLP Overview** - Analyze data loss prevention events
• **Policy Management** - Get recommendations for your environment
• **Generate Reports** - Create executive summaries and detailed reports

What would you like to explore?"""


# ── API Routes ────────────────────────────────────────────────────────────────

@router.post("/chat", response_model=ChatResponse)
async def chat(
    body: ChatRequest,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Chat with Bluebird AI assistant."""
    # Gather current security context
    context = await gather_security_context(str(current_user.org_id), db)

    # Generate AI response
    reply, actions = await generate_ai_response(
        body.message,
        context,
        body.history,
    )

    return ChatResponse(reply=reply, actions=actions)


@router.post("/generate-report")
async def generate_report(
    body: ReportRequest,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Generate a security report based on type."""
    import io
    import base64
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.enums import TA_CENTER, TA_LEFT
    
    # Gather data
    context = await gather_security_context(str(current_user.org_id), db)
    threats_7d = context.get("threats_7d", {})
    dlp_7d = context.get("dlp_7d", {})
    compliance = context.get("compliance", [])
    threat_types = context.get("threat_types", [])
    
    report_titles = {
        "threat_summary": "Threat Summary Report",
        "executive_summary": "Executive Security Summary",
        "compliance_detailed": "Compliance Assessment Report",
        "data_exposure": "Data Exposure Analysis",
    }
    
    report_title = report_titles.get(body.type, "Security Report")
    
    # Create PDF
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, topMargin=0.75*inch, bottomMargin=0.75*inch)
    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        spaceAfter=30,
        alignment=TA_CENTER,
        textColor=colors.HexColor('#1e3a5f'),
    )
    section_style = ParagraphStyle(
        'Section',
        parent=styles['Heading2'],
        fontSize=14,
        spaceBefore=20,
        spaceAfter=10,
        textColor=colors.HexColor('#3b6ef6'),
    )
    
    elements = []
    
    # Header
    elements.append(Paragraph(f"<b>{report_title}</b>", title_style))
    elements.append(Paragraph(f"Generated: {datetime.now(timezone.utc).strftime('%B %d, %Y at %H:%M UTC')}", styles['Normal']))
    elements.append(Spacer(1, 20))
    
    if body.type in ["threat_summary", "executive_summary"]:
        # Threat Summary Section
        elements.append(Paragraph("Threat Overview (Last 7 Days)", section_style))
        
        threat_data = [
            ["Metric", "Value"],
            ["Total Threats Detected", str(threats_7d.get("total", 0))],
            ["Critical Severity", str(threats_7d.get("critical", 0))],
            ["High Severity", str(threats_7d.get("high", 0))],
            ["Successfully Quarantined", str(threats_7d.get("quarantined", 0))],
            ["Resolved", str(threats_7d.get("resolved", 0))],
        ]
        
        threat_table = Table(threat_data, colWidths=[3*inch, 2*inch])
        threat_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#3b6ef6')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 11),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f5f7fa')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e0e0e0')),
            ('FONTSIZE', (0, 1), (-1, -1), 10),
            ('TOPPADDING', (0, 1), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 1), (-1, -1), 8),
        ]))
        elements.append(threat_table)
        elements.append(Spacer(1, 15))
        
        # Threat Types
        if threat_types:
            elements.append(Paragraph("Top Threat Types", section_style))
            type_data = [["Threat Type", "Count"]]
            for t in threat_types[:5]:
                type_data.append([t.get('type', 'Unknown'), str(t.get('count', 0))])
            
            type_table = Table(type_data, colWidths=[3*inch, 2*inch])
            type_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#6366f1')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e0e0e0')),
                ('BACKGROUND', (0, 1), (-1, -1), colors.white),
                ('TOPPADDING', (0, 1), (-1, -1), 6),
                ('BOTTOMPADDING', (0, 1), (-1, -1), 6),
            ]))
            elements.append(type_table)
    
    if body.type in ["data_exposure", "executive_summary"]:
        # DLP Section
        elements.append(Paragraph("Data Loss Prevention (Last 7 Days)", section_style))
        
        dlp_data = [
            ["Metric", "Value"],
            ["Total DLP Events", str(dlp_7d.get("total", 0))],
            ["Blocked", str(dlp_7d.get("blocked", 0))],
            ["Held for Review", str(dlp_7d.get("held", 0))],
            ["Allowed (After Warn)", str(dlp_7d.get("warned", 0))],
        ]
        
        dlp_table = Table(dlp_data, colWidths=[3*inch, 2*inch])
        dlp_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#10b981')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e0e0e0')),
            ('BACKGROUND', (0, 1), (-1, -1), colors.white),
            ('TOPPADDING', (0, 1), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 1), (-1, -1), 6),
        ]))
        elements.append(dlp_table)
    
    if body.type in ["compliance_detailed", "executive_summary"]:
        # Compliance Section
        elements.append(Paragraph("Compliance Status", section_style))
        
        if compliance:
            comp_data = [["Framework", "Score", "Critical Gaps"]]
            for c in compliance:
                comp_data.append([
                    c.get('framework', 'Unknown'),
                    f"{c.get('score', 0):.0f}/100",
                    str(c.get('critical_gaps', 0))
                ])
            
            comp_table = Table(comp_data, colWidths=[2.5*inch, 1.5*inch, 1.5*inch])
            comp_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f59e0b')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e0e0e0')),
                ('BACKGROUND', (0, 1), (-1, -1), colors.white),
                ('TOPPADDING', (0, 1), (-1, -1), 6),
                ('BOTTOMPADDING', (0, 1), (-1, -1), 6),
            ]))
            elements.append(comp_table)
        else:
            elements.append(Paragraph("No compliance assessments available.", styles['Normal']))
    
    # Footer note
    elements.append(Spacer(1, 30))
    elements.append(Paragraph(
        "<i>This report was generated by Helios Security Platform. For questions, contact your administrator.</i>",
        ParagraphStyle('Footer', parent=styles['Normal'], fontSize=9, textColor=colors.grey)
    ))
    
    # Build PDF
    doc.build(elements)
    pdf_bytes = buffer.getvalue()
    buffer.close()
    
    # Return as base64 for download
    pdf_base64 = base64.b64encode(pdf_bytes).decode('utf-8')
    
    return {
        "status": "complete",
        "filename": f"{body.type}_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf",
        "content_type": "application/pdf",
        "data": pdf_base64,
    }


@router.get("/quick-stats")
async def quick_stats(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get quick security stats for the agent context."""
    context = await gather_security_context(str(current_user.org_id), db)
    return context
