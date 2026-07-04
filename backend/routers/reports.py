from datetime import datetime, timedelta
from fastapi import APIRouter, Depends
from fastapi.responses import HTMLResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, text as _sql
from typing import Optional
import uuid as _uuid

from backend.database import get_db
from backend.routers.auth import get_current_user
from backend.models.db_models import Threat, Organization

router = APIRouter(prefix="/api/reports", tags=["reports"])


@router.get("")
async def list_reports(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    return []


@router.post("/generate")
async def generate_report(
    payload: dict,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    report_id = str(_uuid.uuid4())
    report_type = payload.get("type", "threat_summary")
    return {
        "report_id": report_id,
        "type": report_type,
        "status": "ready",
        "download_url": f"/api/reports/{report_id}/download?org_id={current_user.org_id}",
        "generated_at": datetime.utcnow().isoformat(),
    }


@router.get("/{report_id}/status")
async def report_status(report_id: str, current_user=Depends(get_current_user)):
    return {"report_id": report_id, "status": "ready"}


@router.get("/{report_id}/download")
async def download_report(
    report_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    # TENANT ISOLATION: All queries below are scoped to current_user.org_id.
    # Each customer/tenant only sees their own threat, compliance and org data.
    # No cross-tenant data leakage is possible through this endpoint.
    """Generate and return an HTML compliance/threat report with Himaya branding."""
    org = (await db.execute(
        select(Organization).where(Organization.id == current_user.org_id)
    )).scalar_one_or_none()
    org_name = org.name if org else "Unknown Organization"
    compliance_score = org.compliance_score if org else 0

    since_30 = datetime.utcnow() - timedelta(days=30)

    # Threat stats
    total_threats = (await db.execute(_sql(
        "SELECT COUNT(*) FROM threats WHERE org_id=:oid AND threat_type!='CLEAN' AND detected_at>=:s"
    ), {"oid": str(current_user.org_id), "s": since_30})).scalar() or 0

    quarantined = (await db.execute(_sql(
        "SELECT COUNT(*) FROM threats WHERE org_id=:oid AND action_taken='QUARANTINED' AND detected_at>=:s"
    ), {"oid": str(current_user.org_id), "s": since_30})).scalar() or 0

    clean = (await db.execute(_sql(
        "SELECT COUNT(*) FROM threats WHERE org_id=:oid AND threat_type='CLEAN' AND detected_at>=:s"
    ), {"oid": str(current_user.org_id), "s": since_30})).scalar() or 0

    # Top threat types
    type_rows = (await db.execute(_sql("""
        SELECT threat_type, COUNT(*) as cnt
        FROM threats WHERE org_id=:oid AND threat_type!='CLEAN' AND detected_at>=:s
        GROUP BY threat_type ORDER BY cnt DESC LIMIT 8
    """), {"oid": str(current_user.org_id), "s": since_30})).all()

    # Top targets
    target_rows = (await db.execute(_sql("""
        SELECT recipient_email, COUNT(*) as cnt, AVG(risk_score) as avg_score
        FROM threats WHERE org_id=:oid AND threat_type!='CLEAN' AND detected_at>=:s
        GROUP BY recipient_email ORDER BY cnt DESC LIMIT 8
    """), {"oid": str(current_user.org_id), "s": since_30})).all()

    # Compliance by framework
    fw_rows = (await db.execute(_sql("""
        SELECT cc.framework,
               COUNT(*) as total,
               COUNT(CASE WHEN cs.status='compliant' THEN 1 END) as compliant,
               COUNT(CASE WHEN cs.status='partial' THEN 1 END) as partial
        FROM compliance_controls cc
        LEFT JOIN compliance_status cs ON cc.id=cs.control_id AND cs.org_id=:oid
        GROUP BY cc.framework ORDER BY cc.framework
    """), {"oid": str(current_user.org_id)})).all()

    type_table = "".join(
        f'<tr><td style="padding:7px 12px;font-size:12px;color:#e2e8f0;">{r.threat_type.replace("_"," ")}</td><td style="padding:7px 12px;font-size:13px;font-weight:700;color:#f97316;">{r.cnt}</td></tr>'
        for r in type_rows
    ) or '<tr><td colspan="2" style="padding:12px;text-align:center;color:#22c55e;font-size:12px;">No threats detected</td></tr>'

    target_table = "".join(
        f'<tr><td style="padding:7px 12px;font-size:12px;color:#e2e8f0;">{r.recipient_email}</td><td style="padding:7px 12px;font-size:13px;font-weight:700;color:#ef4444;">{r.cnt}</td><td style="padding:7px 12px;font-size:12px;color:#94a3b8;">{round(float(r.avg_score or 0))}</td></tr>'
        for r in target_rows
    ) or '<tr><td colspan="3" style="padding:12px;text-align:center;color:#22c55e;font-size:12px;">No at-risk employees</td></tr>'

    fw_table = ""
    for r in fw_rows:
        pct = round((r.compliant + r.partial * 0.5) / r.total * 100) if r.total else 0
        bar_color = "#22c55e" if pct >= 80 else "#f97316" if pct >= 60 else "#ef4444"
        fw_table += f'<tr><td style="padding:7px 12px;font-size:12px;color:#e2e8f0;font-weight:600;">{r.framework.replace("_"," ")}</td><td style="padding:7px 12px;font-size:12px;color:#94a3b8;">{r.total}</td><td style="padding:7px 12px;font-size:12px;color:#22c55e;">{r.compliant}</td><td style="padding:7px 12px;font-size:13px;font-weight:700;color:{bar_color};">{pct}%</td></tr>'

    generated_at = datetime.utcnow().strftime("%B %d, %Y at %H:%M UTC")
    period = f"{since_30.strftime('%b %d')} – {datetime.utcnow().strftime('%b %d, %Y')}"

    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<title>Helios Security Report — {org_name}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: #0a0a0f; color: #e2e8f0; font-family: system-ui, -apple-system, sans-serif; padding: 40px 20px; }}
  .container {{ max-width: 820px; margin: 0 auto; }}
  h2 {{ font-size: 13px; color: #64748b; text-transform: uppercase; letter-spacing: .08em; margin: 28px 0 12px; }}
  table {{ width: 100%; border-collapse: collapse; background: #0d1117; border-radius: 8px; border: 1px solid #1e293b; margin-bottom: 8px; }}
  thead th {{ padding: 8px 12px; text-align: left; font-size: 10px; color: #64748b; text-transform: uppercase; letter-spacing: .06em; border-bottom: 1px solid #1e293b; }}
  tbody tr:last-child td {{ border-bottom: none; }}
  @media print {{ body {{ background: white; color: #0f172a; }} table {{ border: 1px solid #e2e8f0; }} }}
</style>
</head><body>
<div class="container">
  <!-- Header -->
  <div style="background:#111117;border-radius:12px;padding:28px 32px;border:1px solid #1e293b;margin-bottom:28px;display:flex;align-items:center;gap:20px;">
    <div style="width:52px;height:52px;background:linear-gradient(135deg,#3b6ef6,#8b5cf6);border-radius:10px;display:flex;align-items:center;justify-content:center;flex-shrink:0;">
      <span style="color:white;font-size:26px;font-weight:900;">H</span>
    </div>
    <div style="flex:1;">
      <div style="font-size:20px;font-weight:800;color:#f8fafc;">Helios Security Report</div>
      <div style="font-size:13px;color:#64748b;margin-top:3px;">{org_name} · {period}</div>
    </div>
    <div style="text-align:right;">
      <div style="font-size:11px;color:#64748b;">Generated</div>
      <div style="font-size:12px;color:#94a3b8;">{generated_at}</div>
    </div>
  </div>

  <!-- KPI cards -->
  <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:24px;">
    <div style="background:#111117;border-radius:8px;padding:16px;border:1px solid #1e293b;">
      <div style="font-size:10px;color:#64748b;text-transform:uppercase;letter-spacing:.06em;">Threats Detected</div>
      <div style="font-size:30px;font-weight:800;color:#ef4444;margin-top:6px;">{total_threats}</div>
    </div>
    <div style="background:#111117;border-radius:8px;padding:16px;border:1px solid #1e293b;">
      <div style="font-size:10px;color:#64748b;text-transform:uppercase;letter-spacing:.06em;">Quarantined</div>
      <div style="font-size:30px;font-weight:800;color:#f97316;margin-top:6px;">{quarantined}</div>
    </div>
    <div style="background:#111117;border-radius:8px;padding:16px;border:1px solid #1e293b;">
      <div style="font-size:10px;color:#64748b;text-transform:uppercase;letter-spacing:.06em;">Clean Emails</div>
      <div style="font-size:30px;font-weight:800;color:#22c55e;margin-top:6px;">{clean}</div>
    </div>
    <div style="background:#111117;border-radius:8px;padding:16px;border:1px solid #1e293b;">
      <div style="font-size:10px;color:#64748b;text-transform:uppercase;letter-spacing:.06em;">Compliance Score</div>
      <div style="font-size:30px;font-weight:800;color:#3b6ef6;margin-top:6px;">{compliance_score}%</div>
    </div>
  </div>

  <h2>Threat Classification Breakdown (30 Days)</h2>
  <table><thead><tr><th>Threat Type</th><th>Count</th></tr></thead><tbody>{type_table}</tbody></table>

  <h2>Most Targeted Employees (30 Days)</h2>
  <table><thead><tr><th>Email</th><th>Threats</th><th>Avg Risk Score</th></tr></thead><tbody>{target_table}</tbody></table>

  <h2>Compliance Posture by Framework</h2>
  <table><thead><tr><th>Framework</th><th>Total Controls</th><th>Compliant</th><th>Score</th></tr></thead><tbody>{fw_table}</tbody></table>

  <div style="margin-top:32px;padding-top:16px;border-top:1px solid #1e293b;font-size:11px;color:#475569;">
    Helios by Himaya Technologies · app.himaya.ai · Confidential — For internal use only
  </div>
</div>
</body></html>"""

    from fastapi.responses import HTMLResponse
    return HTMLResponse(
        content=html,
        headers={
            "Content-Disposition": f'attachment; filename="helios-report-{datetime.utcnow().strftime("%Y%m%d")}.html"',
            "Content-Type": "text/html; charset=utf-8",
        }
    )
