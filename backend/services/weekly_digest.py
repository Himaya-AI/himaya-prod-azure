"""
Weekly Digest Worker — sends threat summary to org admins every Monday at 08:00 UTC.

Includes:
  - Total threat count for the week
  - Inboxes affected (unique recipient emails)
  - Country breakdown based on sender domain TLD + known geo-domains
  - Discovered URLs / links from threat_indicators
  - Top threat types
"""
import asyncio
import logging
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import List, Tuple

logger = logging.getLogger(__name__)


# ── TLD → Country mapping for IP/domain geo inference ──────────────────────────
TLD_COUNTRY = {
    ".sa": "Saudi Arabia", ".ae": "UAE", ".kw": "Kuwait", ".qa": "Qatar",
    ".bh": "Bahrain", ".om": "Oman", ".eg": "Egypt", ".jo": "Jordan",
    ".ru": "Russia", ".cn": "China", ".ng": "Nigeria", ".gh": "Ghana",
    ".za": "South Africa", ".br": "Brazil", ".in": "India", ".pk": "Pakistan",
    ".tr": "Turkey", ".ir": "Iran", ".vn": "Vietnam", ".ph": "Philippines",
    ".ro": "Romania", ".ua": "Ukraine", ".pl": "Poland", ".de": "Germany",
    ".uk": "United Kingdom", ".gb": "United Kingdom", ".fr": "France",
    ".nl": "Netherlands", ".it": "Italy", ".es": "Spain", ".ca": "Canada",
    ".au": "Australia", ".jp": "Japan", ".kr": "South Korea", ".mx": "Mexico",
    ".co": "Colombia",
    ".com": "Unknown/Global", ".net": "Unknown/Global", ".org": "Unknown/Global",
    ".io": "Unknown/Global", ".info": "Unknown/Global",
}

# Known provider domains → country
DOMAIN_COUNTRY = {
    "gmail.com": "USA/Global", "yahoo.com": "USA/Global", "hotmail.com": "USA/Global",
    "outlook.com": "USA/Global", "protonmail.com": "Switzerland",
    "yandex.ru": "Russia", "mail.ru": "Russia", "163.com": "China", "qq.com": "China",
}


async def _bulk_resolve_ips(ips: list[str]) -> dict[str, str]:
    """Batch-resolve up to 100 IPs → country via ip-api.com (free, no key, 45 req/min)."""
    if not ips:
        return {}
    import httpx
    result: dict[str, str] = {}
    # Process in chunks of 100 (api limit)
    for i in range(0, len(ips), 100):
        batch = [{"query": ip, "fields": "query,country,status"} for ip in ips[i:i+100]]
        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                resp = await client.post(
                    "http://ip-api.com/batch?fields=query,country,status",
                    json=batch,
                )
            if resp.status_code == 200:
                for row in resp.json():
                    if row.get("status") == "success" and row.get("country"):
                        result[row["query"]] = row["country"]
        except Exception as e:
            logger.warning(f"IP geolocation batch failed: {e}")
    return result


def _infer_country(sender_domain: str | None) -> str:
    if not sender_domain:
        return "Unknown"
    domain = sender_domain.lower().strip()
    if domain in DOMAIN_COUNTRY:
        return DOMAIN_COUNTRY[domain]
    # Try TLD
    parts = domain.split(".")
    if len(parts) >= 2:
        tld = "." + parts[-1]
        if tld in TLD_COUNTRY:
            return TLD_COUNTRY[tld]
        # country.TLD pattern like .co.uk
        if len(parts) >= 3:
            cc = "." + parts[-2]
            if cc in TLD_COUNTRY and len(parts[-2]) == 2:
                return TLD_COUNTRY[cc]
    return "Unknown"


def _extract_urls(threat_indicators: dict | None) -> List[str]:
    """Pull URLs from threat_indicators JSONB."""
    if not threat_indicators:
        return []
    urls = []
    for key in ("suspicious_urls", "malicious_urls", "urls", "links", "discovered_urls"):
        val = threat_indicators.get(key)
        if isinstance(val, list):
            urls.extend(str(u) for u in val if u)
        elif isinstance(val, str) and val:
            urls.append(val)
    # Deduplicate, keep max 20
    seen = set()
    result = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            result.append(u)
        if len(result) >= 20:
            break
    return result


async def run_weekly_digest_loop():
    """Background task — fires every Monday at 08:00 UTC."""
    while True:
        try:
            now = datetime.utcnow()
            # Next Monday 08:00 UTC
            days_until_monday = (7 - now.weekday()) % 7  # weekday(): Mon=0
            if days_until_monday == 0 and now.hour >= 8:
                days_until_monday = 7  # Already past 08:00 on Monday, wait for next week
            next_run = (now + timedelta(days=days_until_monday)).replace(
                hour=8, minute=0, second=0, microsecond=0
            )
            wait_secs = (next_run - now).total_seconds()
            logger.info(
                f"Weekly digest scheduled in {wait_secs/3600:.1f}h "
                f"(next run: {next_run.strftime('%Y-%m-%d %H:%M')} UTC — Monday)"
            )
            await asyncio.sleep(wait_secs)
            await _send_all_weekly_digests()
        except Exception as e:
            logger.error(f"Weekly digest loop error: {e}", exc_info=True)
            await asyncio.sleep(3600)


async def send_weekly_digest_now(org_id=None):
    """Manually trigger weekly digest — for testing. Pass org_id to target one org."""
    await _send_all_weekly_digests(target_org_id=org_id)


async def _send_all_weekly_digests(target_org_id=None):
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
                # Read alert prefs from org_metadata JSONB column
                _meta = org.org_metadata or {}
                prefs = _meta.get("alert_prefs", {})
                if not prefs.get("weekly_digest", True):
                    logger.info(f"Weekly digest disabled for org {org.id}, skipping")
                    continue

                since = datetime.utcnow() - timedelta(days=7)

                # All threats this week (non-clean)
                threats_this_week = (await db.execute(
                    select(Threat).where(
                        Threat.org_id == org.id,
                        Threat.detected_at >= since,
                        Threat.threat_type != "CLEAN",
                    ).order_by(Threat.risk_score.desc())
                )).scalars().all()

                total_scanned = (await db.execute(
                    select(func.count(Threat.id)).where(
                        Threat.org_id == org.id,
                        Threat.detected_at >= since,
                    )
                )).scalar() or 0

                # Inboxes affected (unique recipients with threats)
                affected_inboxes: dict[str, int] = defaultdict(int)
                for t in threats_this_week:
                    if t.recipient_email:
                        affected_inboxes[t.recipient_email] += 1
                top_inboxes = sorted(affected_inboxes.items(), key=lambda x: -x[1])[:8]

                # Country breakdown — prefer sender IP geolocation, fall back to TLD
                unique_ips: list[str] = list({
                    (t.auth_results or {}).get("sender_ip", "")
                    for t in threats_this_week
                    if (t.auth_results or {}).get("sender_ip")
                })
                ip_country_map = await _bulk_resolve_ips(unique_ips)
                logger.info(f"Resolved {len(ip_country_map)}/{len(unique_ips)} IPs to country for org {org.id}")

                country_counts: Counter = Counter()
                for t in threats_this_week:
                    ip = (t.auth_results or {}).get("sender_ip", "")
                    if ip and ip in ip_country_map:
                        country = ip_country_map[ip]
                    else:
                        country = _infer_country(t.sender_domain)
                    country_counts[country] += 1
                top_countries = country_counts.most_common(8)

                # IOCs — suspicious/malicious URLs
                # Priority: new structured fields → legacy indicator strings → ai_explanation_en regex
                import re as _re
                _url_pattern = _re.compile(r'https?://[^\s,\'"<>]+')
                _att_from_expl = _re.compile(r'Dangerous attachments?:\s*([^\n⚠]+)', _re.IGNORECASE)
                _url_from_expl = _re.compile(r'(?:Malicious|Suspicious) URLs? detected:\s*([^\n⚠]+)', _re.IGNORECASE)

                all_urls: list[str] = []
                for t in threats_this_week:
                    ti = t.threat_indicators or {}
                    # New structured fields (threats scanned after latest deploy)
                    all_urls.extend(ti.get("suspicious_urls", []))
                    all_urls.extend(ti.get("malicious_urls", []))
                    # Legacy: content indicator strings like "suspicious_urls:3"
                    all_urls.extend(_extract_urls(ti))
                    # Legacy: parse ai_explanation_en for URLs
                    expl = t.ai_explanation_en or ""
                    for m in _url_from_expl.finditer(expl):
                        for raw in m.group(1).split(","):
                            u = raw.strip().rstrip(".")
                            if u.startswith("http"):
                                all_urls.append(u)
                    # Also scan the whole explanation for any http URLs
                    for u in _url_pattern.findall(expl):
                        if not any(skip in u for skip in ("app.himaya.ai", "himaya.ai/threats")):
                            all_urls.append(u)
                seen_urls: set = set()
                unique_urls: list[str] = []
                for u in all_urls:
                    if u not in seen_urls:
                        seen_urls.add(u)
                        unique_urls.append(u)
                discovered_urls = unique_urls[:20]

                # IOCs — suspicious attachments
                all_suspicious_attachments: list[str] = []
                for t in threats_this_week:
                    ti = t.threat_indicators or {}
                    all_suspicious_attachments.extend(ti.get("suspicious_attachments", []))
                    # Legacy: parse ai_explanation_en
                    expl = t.ai_explanation_en or ""
                    for m in _att_from_expl.finditer(expl):
                        for fname in m.group(1).split(","):
                            fname = fname.strip().rstrip(".")
                            if fname and len(fname) > 2:
                                all_suspicious_attachments.append(fname)
                seen_att: set = set()
                unique_suspicious_attachments: list[str] = []
                for a in all_suspicious_attachments:
                    if a not in seen_att:
                        seen_att.add(a)
                        unique_suspicious_attachments.append(a)

                # Attachment type breakdown (all attachments, not just suspicious)
                attachment_type_counts: Counter = Counter()
                for t in threats_this_week:
                    ti = t.threat_indicators or {}
                    for att_type in ti.get("attachment_types", []):
                        attachment_type_counts[att_type] += 1

                # Top sender IPs (for IP ranges section)
                ip_counts: Counter = Counter()
                for t in threats_this_week:
                    ip = (t.auth_results or {}).get("sender_ip", "")
                    if ip:
                        ip_counts[ip] += 1
                top_ips = [(ip, count, ip_country_map.get(ip, _infer_country(None)))
                           for ip, count in ip_counts.most_common(10)]

                # Threat type breakdown
                type_counts: Counter = Counter(t.threat_type for t in threats_this_week if t.threat_type)
                top_types = type_counts.most_common(5)

                # Risk trend vs prior week
                prior_week_count = (await db.execute(
                    select(func.count(Threat.id)).where(
                        Threat.org_id == org.id,
                        Threat.detected_at >= since - timedelta(days=7),
                        Threat.detected_at < since,
                        Threat.threat_type != "CLEAN",
                    )
                )).scalar() or 0

                this_count = len(threats_this_week)
                if prior_week_count == 0:
                    trend = "stable"
                elif this_count > prior_week_count * 1.1:
                    trend = "increasing"
                elif this_count < prior_week_count * 0.9:
                    trend = "decreasing"
                else:
                    trend = "stable"

                # Notify admins AND analysts
                admins = (await db.execute(
                    select(User).where(
                        User.org_id == org.id,
                        User.role.in_(["admin", "analyst"]),
                        User.is_active == True,
                    )
                )).scalars().all()

                week_start = since.strftime("%b %d")
                week_end = datetime.utcnow().strftime("%b %d, %Y")

                for admin in admins:
                    html = _build_weekly_html(
                        org_name=org.name,
                        week_start=week_start,
                        week_end=week_end,
                        total_scanned=total_scanned,
                        threat_count=this_count,
                        prior_count=prior_week_count,
                        trend=trend,
                        top_inboxes=top_inboxes,
                        top_countries=top_countries,
                        discovered_urls=discovered_urls,
                        top_types=top_types,
                        top_ips=top_ips,
                        unique_suspicious_attachments=unique_suspicious_attachments,
                        attachment_type_counts=dict(attachment_type_counts),
                    )
                    send_email(
                        to=admin.email,
                        subject=(
                            f"Helios Weekly Security Digest — {org.name} — "
                            f"{week_start}–{week_end}"
                        ),
                        html_body=html,
                    )
                logger.info(
                    f"Weekly digest sent for org {org.id}: {this_count} threats, "
                    f"{len(top_inboxes)} inboxes, {len(discovered_urls)} URLs, "
                    f"{len(admins)} admins notified"
                )
            except Exception as e:
                logger.warning(f"Weekly digest failed for org {org.id}: {e}", exc_info=True)


def _build_weekly_html(
    org_name: str,
    week_start: str,
    week_end: str,
    total_scanned: int,
    threat_count: int,
    prior_count: int,
    trend: str,
    top_inboxes: List[Tuple[str, int]],
    top_countries: List[Tuple[str, int]],
    discovered_urls: List[str],
    top_types: List[Tuple[str, int]],
    top_ips: list | None = None,
    unique_suspicious_attachments: list | None = None,
    attachment_type_counts: dict | None = None,
) -> str:
    top_ips = top_ips or []
    unique_suspicious_attachments = unique_suspicious_attachments or []
    attachment_type_counts = attachment_type_counts or {}

    BG = "#0a0a0f"
    CARD = "#111117"
    CARD2 = "#0d1117"
    BORDER = "#1e293b"
    WHITE = "#e2e8f0"
    MUTED = "#64748b"
    BLUE = "#3b6ef6"
    RED = "#ef4444"
    GREEN = "#22c55e"
    ORANGE = "#f97316"
    FONT = "system-ui,-apple-system,sans-serif"

    trend_icon = "→"
    trend_color = "#facc15"
    if trend == "increasing":
        trend_icon, trend_color = "↑", RED
    elif trend == "decreasing":
        trend_icon, trend_color = "↓", GREEN

    # Inbox rows
    inbox_rows = ""
    for email, count in top_inboxes:
        inbox_rows += f"""
        <tr style="border-bottom:1px solid {BORDER};">
          <td style="padding:8px 14px;font-size:12px;color:{WHITE};">{email}</td>
          <td style="padding:8px 14px;font-size:13px;font-weight:700;color:{ORANGE};">{count}</td>
        </tr>"""

    # Country rows
    country_rows = ""
    total_geo = sum(c for _, c in top_countries) or 1
    for country, count in top_countries:
        pct = round(count / total_geo * 100)
        color = RED if country in ("Russia", "China", "Iran", "Nigeria") else ORANGE if pct > 20 else MUTED
        country_rows += f"""
        <tr style="border-bottom:1px solid {BORDER};">
          <td style="padding:8px 14px;font-size:12px;color:{WHITE};">{country}</td>
          <td style="padding:8px 14px;font-size:12px;color:{color};">{count} ({pct}%)</td>
        </tr>"""

    # URL rows
    url_items = ""
    for url in discovered_urls[:10]:
        short = url[:60] + "…" if len(url) > 60 else url
        url_items += f"""
        <tr style="border-bottom:1px solid {BORDER};">
          <td style="padding:7px 14px;font-size:11px;color:{RED};font-family:monospace;word-break:break-all;">{short}</td>
        </tr>"""

    # Threat type rows
    type_rows = ""
    for ttype, count in top_types:
        label = (ttype or "UNKNOWN").replace("_", " ").title()
        type_rows += f"""
        <tr style="border-bottom:1px solid {BORDER};">
          <td style="padding:8px 14px;font-size:12px;color:{WHITE};">{label}</td>
          <td style="padding:8px 14px;font-size:13px;font-weight:700;color:{ORANGE};">{count}</td>
        </tr>"""

    summary_color = RED if threat_count >= 20 else ORANGE if threat_count >= 5 else GREEN
    summary_msg = (
        f"{threat_count} threat{'s' if threat_count != 1 else ''} detected this week."
        if threat_count > 0 else "All clear — no threats detected this week. ✓"
    )

    inbox_section = f"""
    <h3 style="color:{MUTED};font-size:10px;text-transform:uppercase;letter-spacing:.1em;margin:24px 0 10px;">
      Affected Inboxes ({len(top_inboxes)})
    </h3>
    <table width="100%" cellpadding="0" cellspacing="0"
           style="background:{CARD2};border-radius:8px;border:1px solid {BORDER};margin-bottom:4px;">
      <thead><tr style="border-bottom:1px solid {BORDER};">
        <th style="padding:8px 14px;text-align:left;font-size:10px;color:{MUTED};text-transform:uppercase;">Inbox</th>
        <th style="padding:8px 14px;text-align:left;font-size:10px;color:{MUTED};text-transform:uppercase;">Threats</th>
      </tr></thead>
      <tbody>{inbox_rows if inbox_rows else f'<tr><td colspan="2" style="padding:14px;text-align:center;color:{MUTED};font-size:12px;">No inboxes targeted</td></tr>'}</tbody>
    </table>""" if top_inboxes else ""

    country_section = f"""
    <h3 style="color:{MUTED};font-size:10px;text-transform:uppercase;letter-spacing:.1em;margin:24px 0 10px;">
      Threat Origin Countries (by Sender Domain)
    </h3>
    <table width="100%" cellpadding="0" cellspacing="0"
           style="background:{CARD2};border-radius:8px;border:1px solid {BORDER};margin-bottom:4px;">
      <thead><tr style="border-bottom:1px solid {BORDER};">
        <th style="padding:8px 14px;text-align:left;font-size:10px;color:{MUTED};text-transform:uppercase;">Country</th>
        <th style="padding:8px 14px;text-align:left;font-size:10px;color:{MUTED};text-transform:uppercase;">Threats</th>
      </tr></thead>
      <tbody>{country_rows}</tbody>
    </table>""" if top_countries else ""

    url_section = f"""
    <h3 style="color:{MUTED};font-size:10px;text-transform:uppercase;letter-spacing:.1em;margin:24px 0 10px;">
      IOCs — Suspicious &amp; Malicious Links ({len(discovered_urls)})
    </h3>
    <table width="100%" cellpadding="0" cellspacing="0"
           style="background:{CARD2};border-radius:8px;border:1px solid {BORDER};margin-bottom:4px;">
      <tbody>{url_items}</tbody>
    </table>""" if discovered_urls else ""

    # IP ranges section
    ip_rows = ""
    for ip, count, country in top_ips:
        ip_rows += f"""
        <tr style="border-bottom:1px solid {BORDER};">
          <td style="padding:7px 14px;font-size:11px;color:{WHITE};font-family:monospace;">{ip}</td>
          <td style="padding:7px 14px;font-size:11px;color:{MUTED};">{country}</td>
          <td style="padding:7px 14px;font-size:11px;font-weight:700;color:{ORANGE};">{count}</td>
        </tr>"""
    ip_section = f"""
    <h3 style="color:{MUTED};font-size:10px;text-transform:uppercase;letter-spacing:.1em;margin:24px 0 10px;">
      Top Sender IPs ({len(top_ips)})
    </h3>
    <table width="100%" cellpadding="0" cellspacing="0"
           style="background:{CARD2};border-radius:8px;border:1px solid {BORDER};margin-bottom:4px;">
      <thead><tr style="border-bottom:1px solid {BORDER};">
        <th style="padding:7px 14px;text-align:left;font-size:10px;color:{MUTED};text-transform:uppercase;">IP Address</th>
        <th style="padding:7px 14px;text-align:left;font-size:10px;color:{MUTED};text-transform:uppercase;">Country</th>
        <th style="padding:7px 14px;text-align:left;font-size:10px;color:{MUTED};text-transform:uppercase;">Threats</th>
      </tr></thead>
      <tbody>{ip_rows}</tbody>
    </table>""" if top_ips else ""

    # Suspicious attachments section
    att_items = "".join(
        f'<tr style="border-bottom:1px solid {BORDER};"><td style="padding:7px 14px;font-size:11px;'
        f'color:{RED};font-family:monospace;">{a}</td></tr>'
        for a in unique_suspicious_attachments[:15]
    )
    suspicious_att_section = f"""
    <h3 style="color:{MUTED};font-size:10px;text-transform:uppercase;letter-spacing:.1em;margin:24px 0 10px;">
      IOCs — Suspicious Attachments ({len(unique_suspicious_attachments)})
    </h3>
    <table width="100%" cellpadding="0" cellspacing="0"
           style="background:{CARD2};border-radius:8px;border:1px solid {BORDER};margin-bottom:4px;">
      <tbody>{att_items}</tbody>
    </table>""" if unique_suspicious_attachments else ""

    # Attachment type breakdown
    att_type_rows = "".join(
        f'<tr style="border-bottom:1px solid {BORDER};"><td style="padding:7px 14px;font-size:11px;color:{WHITE};">'
        f'{ext}</td><td style="padding:7px 14px;font-size:11px;font-weight:700;color:{ORANGE};">{cnt}</td></tr>'
        for ext, cnt in sorted(attachment_type_counts.items(), key=lambda x: -x[1])[:10]
    )
    att_type_section = f"""
    <h3 style="color:{MUTED};font-size:10px;text-transform:uppercase;letter-spacing:.1em;margin:24px 0 10px;">
      Attachment Type Distribution
    </h3>
    <table width="100%" cellpadding="0" cellspacing="0"
           style="background:{CARD2};border-radius:8px;border:1px solid {BORDER};margin-bottom:4px;">
      <thead><tr style="border-bottom:1px solid {BORDER};">
        <th style="padding:7px 14px;text-align:left;font-size:10px;color:{MUTED};text-transform:uppercase;">Type</th>
        <th style="padding:7px 14px;text-align:left;font-size:10px;color:{MUTED};text-transform:uppercase;">Count</th>
      </tr></thead>
      <tbody>{att_type_rows}</tbody>
    </table>""" if attachment_type_counts else ""

    type_section = f"""
    <h3 style="color:{MUTED};font-size:10px;text-transform:uppercase;letter-spacing:.1em;margin:24px 0 10px;">
      Threat Type Breakdown
    </h3>
    <table width="100%" cellpadding="0" cellspacing="0"
           style="background:{CARD2};border-radius:8px;border:1px solid {BORDER};margin-bottom:4px;">
      <thead><tr style="border-bottom:1px solid {BORDER};">
        <th style="padding:8px 14px;text-align:left;font-size:10px;color:{MUTED};text-transform:uppercase;">Type</th>
        <th style="padding:8px 14px;text-align:left;font-size:10px;color:{MUTED};text-transform:uppercase;">Count</th>
      </tr></thead>
      <tbody>{type_rows}</tbody>
    </table>""" if top_types else ""

    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:{BG};font-family:{FONT};">
<table width="100%" cellpadding="0" cellspacing="0" style="background:{BG};padding:40px 16px;">
  <tr><td align="center">
    <table width="620" cellpadding="0" cellspacing="0"
           style="max-width:620px;background:{CARD};border-radius:16px;border:1px solid {BORDER};overflow:hidden;">

      <!-- Header -->
      <tr><td style="padding:28px 36px 22px;border-bottom:1px solid {BORDER};">
        <table width="100%" cellpadding="0" cellspacing="0">
          <tr>
            <td>
              <!-- Himaya logo — table-cell backdrop (email-client safe, no div stripping) -->
              <table cellpadding="0" cellspacing="0" style="border-radius:10px;">
                <tr>
                  <td bgcolor="#1a1f3c" style="padding:8px 18px;border-radius:10px;
                      background:#1a1f3c;border:1px solid #2a3f80;">
                    <img src="https://app.himaya.ai/himaya-logo.png"
                         alt="Himaya" width="130" height="29"
                         style="display:block;border:0;outline:0;height:auto;" />
                  </td>
                </tr>
              </table>
              <div style="color:{MUTED};font-size:11px;margin-top:8px;letter-spacing:.05em;">
                WEEKLY SECURITY DIGEST
              </div>
            </td>
            <td align="right" style="vertical-align:middle;">
              <span style="color:{MUTED};font-size:11px;">{week_start} – {week_end}</span>
            </td>
          </tr>
        </table>
      </td></tr>

      <!-- Summary Banner -->
      <tr><td style="padding:20px 36px 0;">
        <div style="background:{CARD2};border-radius:10px;padding:16px 20px;
                    border-left:4px solid {summary_color};">
          <div style="color:{WHITE};font-size:14px;font-weight:600;">{org_name}</div>
          <div style="color:{summary_color};font-size:13px;margin-top:4px;">{summary_msg}</div>
        </div>
      </td></tr>

      <!-- Stat Grid -->
      <tr><td style="padding:20px 36px 0;">
        <table width="100%" cellpadding="0" cellspacing="0">
          <tr>
            <td width="30%" style="text-align:center;padding:16px 10px;background:{CARD2};
                                   border-radius:10px;border:1px solid {BORDER};">
              <div style="color:{MUTED};font-size:10px;text-transform:uppercase;letter-spacing:.05em;">Scanned</div>
              <div style="color:{BLUE};font-size:26px;font-weight:800;margin-top:4px;">{total_scanned:,}</div>
            </td>
            <td width="3%"></td>
            <td width="30%" style="text-align:center;padding:16px 10px;background:{CARD2};
                                   border-radius:10px;border:1px solid {BORDER};">
              <div style="color:{MUTED};font-size:10px;text-transform:uppercase;letter-spacing:.05em;">Threats</div>
              <div style="color:{RED};font-size:26px;font-weight:800;margin-top:4px;">{threat_count:,}</div>
            </td>
            <td width="3%"></td>
            <td width="34%" style="text-align:center;padding:16px 10px;background:{CARD2};
                                   border-radius:10px;border:1px solid {BORDER};">
              <div style="color:{MUTED};font-size:10px;text-transform:uppercase;letter-spacing:.05em;">vs Last Week</div>
              <div style="color:{trend_color};font-size:26px;font-weight:800;margin-top:4px;">
                {trend_icon} {abs(threat_count - prior_count):,}
              </div>
            </td>
          </tr>
        </table>
      </td></tr>

      <!-- Sections -->
      <tr><td style="padding:8px 36px 32px;">
        {inbox_section}
        {country_section}
        {ip_section}
        {type_section}
        {url_section}
        
        {suspicious_att_section}
        {att_type_section}

        <!-- CTA -->
        <div style="text-align:center;margin-top:28px;">
          <a href="https://app.himaya.ai/threats"
             style="display:inline-block;background:{BLUE};color:white;text-decoration:none;
                    padding:12px 32px;border-radius:10px;font-size:13px;font-weight:700;">
            View Full Threat Log →
          </a>
        </div>
      </td></tr>

      <!-- Footer -->
      <tr><td style="background:#0d0d12;padding:16px 36px;border-top:1px solid {BORDER};">
        <p style="color:#475569;font-size:11px;margin:0;">
          Helios by Himaya Technologies ·
          <a href="https://app.himaya.ai" style="color:{BLUE};">app.himaya.ai</a>
          · To manage email preferences visit Settings → Alerts
        </p>
      </td></tr>

    </table>
  </td></tr>
</table>
</body></html>"""
