"""
Daily Digest Worker — sends threat summary email to org admins every day at 08:00 UTC.
"""
import asyncio
import logging
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


async def run_daily_digest_loop():
    """Background task — fires digest at 08:00 UTC daily."""
    while True:
        try:
            now = datetime.utcnow()
            # Next 08:00 UTC
            next_run = now.replace(hour=8, minute=0, second=0, microsecond=0)
            if next_run <= now:
                next_run += timedelta(days=1)
            wait_secs = (next_run - now).total_seconds()
            logger.info(f"Daily digest scheduled in {wait_secs/3600:.1f}h (next run: {next_run.strftime('%Y-%m-%d %H:%M')} UTC)")
            await asyncio.sleep(wait_secs)
            await _send_all_digests()
        except Exception as e:
            logger.error(f"Daily digest loop error: {e}", exc_info=True)
            await asyncio.sleep(3600)  # retry in 1h on error


async def send_daily_digest_now(org_id=None):
    """Manually trigger daily digest for testing. Pass org_id to target one org."""
    await _send_all_digests(target_org_id=org_id)


async def _send_all_digests(target_org_id=None):
    from backend.database import AsyncSessionLocal
    from backend.models.db_models import Organization, User, Threat
    from backend.services.email_service import send_email
    from sqlalchemy import select, func

    async with AsyncSessionLocal() as db:
        query = select(Organization).where(Organization.status == "active")
        if target_org_id:
            query = query.where(Organization.id == target_org_id)
        orgs = (await db.execute(query)).scalars().all()
        for org in orgs:
            try:
                # Check if digest is enabled for this org
                # Read alert prefs from org_metadata JSONB column
                _meta = org.org_metadata or {}
                prefs = _meta.get("alert_prefs", {})
                if not prefs.get("daily_digest", True):
                    continue

                # Gather today's stats
                since = datetime.utcnow() - timedelta(hours=24)
                threats_today = (await db.execute(
                    select(Threat).where(
                        Threat.org_id == org.id,
                        Threat.detected_at >= since,
                        Threat.threat_type != "CLEAN",
                    ).order_by(Threat.risk_score.desc()).limit(10)
                )).scalars().all()

                total_today = (await db.execute(
                    select(func.count(Threat.id)).where(
                        Threat.org_id == org.id,
                        Threat.detected_at >= since,
                    )
                )).scalar() or 0

                clean_today = (await db.execute(
                    select(func.count(Threat.id)).where(
                        Threat.org_id == org.id,
                        Threat.detected_at >= since,
                        Threat.threat_type == "CLEAN",
                    )
                )).scalar() or 0

                threat_today = total_today - clean_today

                # Get at-risk targets
                at_risk = {}
                for t in threats_today:
                    if t.recipient_email:
                        at_risk[t.recipient_email] = at_risk.get(t.recipient_email, 0) + 1

                top_targets = sorted(at_risk.items(), key=lambda x: -x[1])[:5]

                # Notify admins AND analysts
                admins = (await db.execute(
                    select(User).where(
                        User.org_id == org.id,
                        User.role.in_(["admin", "analyst"]),
                        User.is_active == True,
                    )
                )).scalars().all()

                for admin in admins:
                    html = _build_digest_html(org.name, threat_today, clean_today, threats_today[:5], top_targets)
                    send_email(
                        to=admin.email,
                        subject=f"Helios Daily Digest — {org.name} — {datetime.utcnow().strftime('%b %d, %Y')}",
                        html_body=html,
                    )
                logger.info(f"Daily digest sent for org {org.id}: {threat_today} threats, {len(admins)} admins notified")
            except Exception as e:
                logger.warning(f"Daily digest failed for org {org.id}: {e}")


def _build_digest_html(org_name: str, threat_count: int, clean_count: int, top_threats, top_targets) -> str:
    threat_rows = ""
    for t in top_threats:
        score_color = "#ef4444" if t.risk_score >= 80 else "#f97316" if t.risk_score >= 60 else "#eab308"
        threat_rows += f"""
        <tr style="border-bottom:1px solid #1e293b;">
          <td style="padding:8px 12px;font-size:12px;color:#94a3b8;">{t.sender or '—'}</td>
          <td style="padding:8px 12px;font-size:12px;color:#e2e8f0;">{t.recipient_email or '—'}</td>
          <td style="padding:8px 12px;font-size:12px;color:#94a3b8;">{(t.threat_type or 'UNKNOWN').replace('_',' ')}</td>
          <td style="padding:8px 12px;font-size:13px;font-weight:700;color:{score_color};">{t.risk_score or 0}</td>
        </tr>"""

    target_rows = ""
    for email, count in top_targets:
        target_rows += f"""
        <tr style="border-bottom:1px solid #1e293b;">
          <td style="padding:8px 12px;font-size:12px;color:#e2e8f0;">{email}</td>
          <td style="padding:8px 12px;font-size:13px;font-weight:700;color:#f97316;">{count}</td>
        </tr>"""

    summary_color = "#ef4444" if threat_count >= 10 else "#f97316" if threat_count >= 3 else "#22c55e"
    summary_text = (
        f"{threat_count} potential threat{'s' if threat_count != 1 else ''} detected in the past 24 hours."
        if threat_count > 0 else
        "All clear — no threats detected in the past 24 hours."
    )

    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"></head>
<body style="margin:0;padding:0;background:#0a0a0f;font-family:system-ui,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="max-width:620px;margin:40px auto;">
  <tr><td style="background:#111117;border-radius:12px 12px 0 0;padding:28px 32px;border-bottom:1px solid #1e293b;">
    <div style="display:flex;align-items:center;gap:12px;">
      <!-- Himaya logo — table-cell backdrop (email-client safe) -->
      <table cellpadding="0" cellspacing="0" style="border-radius:10px;">
        <tr>
          <td bgcolor="#1a1f3c" style="padding:8px 18px;border-radius:10px;
              background:#1a1f3c;border:1px solid #2a3f80;">
            <img src="https://app.himaya.ai/himaya-logo.png"
                 alt="Himaya" width="120" height="27"
                 style="display:block;border:0;outline:0;height:auto;" />
          </td>
        </tr>
      </table>
      <div>
        <div style="color:#64748b;font-size:11px;margin-top:4px;letter-spacing:.05em;">DAILY SECURITY DIGEST</div>
      </div>
    </div>
  </td></tr>
  <tr><td style="background:#111117;padding:24px 32px;">
    <div style="background:#0d1117;border-radius:8px;padding:16px 20px;border-left:4px solid {summary_color};margin-bottom:20px;">
      <div style="color:#e2e8f0;font-size:14px;font-weight:600;">{org_name}</div>
      <div style="color:{summary_color};font-size:13px;margin-top:4px;">{summary_text}</div>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:24px;">
      <div style="background:#0d1117;border-radius:8px;padding:14px 16px;border:1px solid #1e293b;">
        <div style="color:#64748b;font-size:11px;text-transform:uppercase;letter-spacing:.05em;">Threats Detected</div>
        <div style="color:#ef4444;font-size:28px;font-weight:800;margin-top:4px;">{threat_count}</div>
      </div>
      <div style="background:#0d1117;border-radius:8px;padding:14px 16px;border:1px solid #1e293b;">
        <div style="color:#64748b;font-size:11px;text-transform:uppercase;letter-spacing:.05em;">Clean Emails</div>
        <div style="color:#22c55e;font-size:28px;font-weight:800;margin-top:4px;">{clean_count}</div>
      </div>
    </div>
    {'<h3 style="color:#94a3b8;font-size:11px;text-transform:uppercase;letter-spacing:.1em;margin-bottom:12px;">Top Threats</h3><table width="100%" cellpadding="0" cellspacing="0" style="background:#0d1117;border-radius:8px;border:1px solid #1e293b;margin-bottom:24px;"><thead><tr style="border-bottom:1px solid #1e293b;"><th style="padding:8px 12px;text-align:left;font-size:10px;color:#64748b;text-transform:uppercase;">Sender</th><th style="padding:8px 12px;text-align:left;font-size:10px;color:#64748b;text-transform:uppercase;">Target</th><th style="padding:8px 12px;text-align:left;font-size:10px;color:#64748b;text-transform:uppercase;">Type</th><th style="padding:8px 12px;text-align:left;font-size:10px;color:#64748b;text-transform:uppercase;">Score</th></tr></thead><tbody>' + threat_rows + '</tbody></table>' if top_threats else '<div style="background:#0d1117;border-radius:8px;padding:20px;text-align:center;border:1px solid #1e293b;margin-bottom:24px;color:#22c55e;font-size:13px;">✓ No threats in the past 24 hours</div>'}
    {'<h3 style="color:#94a3b8;font-size:11px;text-transform:uppercase;letter-spacing:.1em;margin-bottom:12px;">Most Targeted Employees</h3><table width="100%" cellpadding="0" cellspacing="0" style="background:#0d1117;border-radius:8px;border:1px solid #1e293b;margin-bottom:24px;"><thead><tr style="border-bottom:1px solid #1e293b;"><th style="padding:8px 12px;text-align:left;font-size:10px;color:#64748b;text-transform:uppercase;">Email</th><th style="padding:8px 12px;text-align:left;font-size:10px;color:#64748b;text-transform:uppercase;">Threats</th></tr></thead><tbody>' + target_rows + '</tbody></table>' if top_targets else ''}
  </td></tr>
  <tr><td style="background:#0d0d12;padding:16px 32px;border-radius:0 0 12px 12px;border-top:1px solid #1e293b;">
    <p style="color:#475569;font-size:11px;margin:0;">Helios by Himaya Technologies · <a href="https://app.himaya.ai" style="color:#3b6ef6;">app.himaya.ai</a></p>
  </td></tr>
</table>
</body></html>"""
