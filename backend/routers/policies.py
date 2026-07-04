from datetime import datetime
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import uuid

from backend.database import get_db
from backend.models.db_models import Policy
from backend.routers.auth import get_current_user
from backend.schemas.api_schemas import PolicyCreate, PolicyUpdate
from backend.services.m365_policy_push import M365PolicyPusher

router = APIRouter(prefix="/api/policies", tags=["policies"])

GULF_TEMPLATES = [
    {
        "id": "tpl-bec-high-risk",
        "name": "BEC High Risk Block",
        "description": "Quarantine Business Email Compromise attempts with risk ≥ 75",
        "conditions": {"threat_type": "BEC", "risk_score_min": 75},
        "action": "QUARANTINE",
        "action_config": {"notify_admin": True, "create_evidence": True},
        "frameworks": ["SAMA_CSF", "NCA_ECC"],
    },
    {
        "id": "tpl-gov-impersonation",
        "name": "Government Impersonation Block",
        "description": "Block emails impersonating Saudi government entities (SAMA, ZATCA, MOCI)",
        "conditions": {"threat_type": "GOV_IMPERSONATION", "risk_score_min": 50},
        "action": "BLOCK_DELETE",
        "action_config": {"notify_admin": True, "create_evidence": True, "alert_compliance": True},
        "frameworks": ["NCA_ECC", "SAMA_CSF"],
    },
    {
        "id": "tpl-phishing-banner",
        "name": "Phishing Warning Banner",
        "description": "Add warning banner to suspected phishing (risk 40–74)",
        "conditions": {"threat_type": "PHISHING", "risk_score_min": 40, "risk_score_max": 74},
        "action": "DELIVER_WITH_BANNER",
        "action_config": {"banner_ar": True, "banner_en": True},
        "frameworks": ["SAMA_CSF"],
    },
    {
        "id": "tpl-lookalike-hold",
        "name": "Lookalike Domain Hold",
        "description": "Hold emails from lookalike/typosquat domains for manual review",
        "conditions": {"threat_type": "LOOKALIKE_DOMAIN"},
        "action": "HOLD_FOR_REVIEW",
        "action_config": {"reviewer_role": "analyst"},
        "frameworks": ["NCA_ECC", "UAE_NESA"],
    },
    {
        "id": "tpl-supply-chain",
        "name": "Supply Chain Threat Quarantine",
        "description": "Quarantine suspected supply chain compromise for compliance review",
        "conditions": {"threat_type": "SUPPLY_CHAIN", "risk_score_min": 60},
        "action": "QUARANTINE",
        "action_config": {"create_evidence": True, "alert_compliance": True},
        "frameworks": ["SAMA_CSF", "NCA_ECC", "CBUAE"],
    },
    {
        "id": "tpl-account-takeover",
        "name": "Account Takeover Alert",
        "description": "Quarantine and alert on account takeover indicators",
        "conditions": {"threat_type": "ACCOUNT_TAKEOVER", "risk_score_min": 65},
        "action": "QUARANTINE",
        "action_config": {"notify_admin": True, "notify_soc": True, "create_evidence": True},
        "frameworks": ["SAMA_CSF", "NCA_ECC", "CBUAE", "UAE_NESA"],
    },
    {
        "id": "tpl-ioc-block",
        "name": "IOC-Based Sender Block",
        "description": "Block emails from known malicious IPs/domains pulled from public OSINT feeds (abuse.ch, PhishTank, URLhaus). IOCs are checked at scan time via the threat intelligence pipeline.",
        "conditions": {"ioc_match": True, "risk_score_min": 50},
        "action": "BLOCK_DELETE",
        "action_config": {"notify_admin": True, "create_evidence": True, "ioc_source": "public_feeds"},
        "frameworks": ["NCA_ECC", "SAMA_CSF", "CBUAE"],
    },
    {
        "id": "tpl-threat-feed-malware-urls",
        "name": "Block Known Malware URLs (URLhaus + OpenPhish)",
        "description": "Block emails containing URLs found in URLhaus malware feed or OpenPhish active phishing feed.",
        "conditions": {"threat_feed_match": {"url_match": ["ioc_urlhaus", "ioc_openphish"]}},
        "action": "QUARANTINE",
        "priority": 2,
        "action_config": {"notify_admin": True, "create_evidence": True},
        "tags": ["threat-intel", "malware", "phishing"],
        "frameworks": ["NCA_ECC", "SAMA_CSF", "CBUAE"],
    },
    {
        "id": "tpl-threat-feed-malicious-ips",
        "name": "Block High-Confidence Malicious IPs (IPsum + Feodo + CINS)",
        "description": "Quarantine emails from IPs on 3+ threat intel blacklists or known botnet C2 servers.",
        "conditions": {"threat_feed_match": {"ip_match": ["ioc_ipsum", "ioc_feodo", "ioc_cins"]}},
        "action": "QUARANTINE",
        "priority": 3,
        "action_config": {"notify_admin": True, "create_evidence": True},
        "tags": ["threat-intel", "ip-reputation"],
        "frameworks": ["NCA_ECC", "SAMA_CSF"],
    },
    {
        "id": "tpl-malicious-attachment",
        "name": "Malicious Attachment Block",
        "description": "Block emails with executable or macro-enabled attachments (.exe, .vbs, .ps1, .docm, .xlsm)",
        "conditions": {"attachment_types": [".exe", ".vbs", ".ps1", ".bat", ".cmd", ".msi", ".docm", ".xlsm", ".pptm", ".jar"]},
        "action": "BLOCK_DELETE",
        "action_config": {"notify_admin": True, "create_evidence": True},
        "frameworks": ["NCA_ECC", "SAMA_CSF"],
    },
    {
        "id": "tpl-credential-harvest",
        "name": "Credential Harvesting Block",
        "description": "Block credential phishing and login-page spoofing attempts",
        "conditions": {"threat_type": "CREDENTIAL_HARVESTING", "risk_score_min": 55},
        "action": "BLOCK_DELETE",
        "action_config": {"notify_admin": True, "create_evidence": True},
        "frameworks": ["NCA_ECC", "SAMA_CSF", "CBUAE"],
    },
    {
        "name": "Strip High-Risk Attachments",
        "description": "Remove dangerous attachment types from inbound email before delivery — executables, scripts, encrypted archives, and macro-enabled documents.",
        "conditions": {
            "has_attachment": True,
            "attachment_types": ["exe","bat","cmd","ps1","vbs","js","hta","msi","docm","xlsm","pptm","dotm","xltm","jar","scr","com","pif","iso","img","zip_encrypted","rar_encrypted","7z_encrypted"]
        },
        "action": "STRIP_ATTACHMENTS",
        "action_config": {
            "notify_recipient": True,
            "notify_sender": True,
            "replacement_message": "An attachment was removed from this email by Helios security policy because it contained a potentially dangerous file type."
        },
        "priority": 5,
        "tags": ["attachment", "malware-prevention", "gulf"],
    },
]

EU_TEMPLATES = [
    {
        "id": "tpl-gdpr-data-leak",
        "name": "GDPR Data Exfiltration Alert",
        "description": "Alert on outbound emails with potential personal data leakage (GDPR Art. 33)",
        "conditions": {"threat_type": "DATA_LEAK", "risk_score_min": 50},
        "action": "ALERT",
        "action_config": {"notify_admin": True, "create_evidence": True, "alert_compliance": True},
        "frameworks": ["GDPR", "NIS2"],
    },
    {
        "id": "tpl-dora-supply-chain",
        "name": "DORA Supply Chain Resilience",
        "description": "Quarantine third-party vendor emails with supply chain threat indicators (DORA Art. 28)",
        "conditions": {"threat_type": "SUPPLY_CHAIN", "risk_score_min": 55},
        "action": "QUARANTINE",
        "action_config": {"create_evidence": True, "alert_compliance": True},
        "frameworks": ["DORA", "NIS2"],
    },
    {
        "id": "tpl-nis2-critical-infra",
        "name": "NIS2 Critical Infrastructure Protection",
        "description": "Block high-risk threats targeting critical infrastructure operators (NIS2 Art. 21)",
        "conditions": {"risk_score_min": 80},
        "action": "BLOCK_DELETE",
        "action_config": {"notify_admin": True, "notify_soc": True, "create_evidence": True, "alert_compliance": True},
        "frameworks": ["NIS2", "DORA"],
    },
    {
        "id": "tpl-iso27001-incident",
        "name": "ISO 27001 Incident Response",
        "description": "Quarantine and evidence-collect all high-risk threats for ISO 27001 A.16 incident management",
        "conditions": {"risk_score_min": 70},
        "action": "QUARANTINE",
        "action_config": {"create_evidence": True, "alert_compliance": True, "notify_admin": True},
        "frameworks": ["ISO_27001"],
    },
]

US_TEMPLATES = [
    {
        "id": "tpl-nist-high-risk",
        "name": "NIST High-Risk Block",
        "description": "Block high-risk threats per NIST CSF DE.CM-1 continuous monitoring",
        "conditions": {"risk_score_min": 80},
        "action": "BLOCK_DELETE",
        "action_config": {"notify_admin": True, "create_evidence": True},
        "frameworks": ["NIST_CSF"],
    },
    {
        "id": "tpl-soc2-credential",
        "name": "SOC 2 Credential Harvest Block",
        "description": "Block credential harvesting per SOC 2 CC6.6 logical access controls",
        "conditions": {"threat_type": "CREDENTIAL_HARVESTING", "risk_score_min": 60},
        "action": "BLOCK_DELETE",
        "action_config": {"notify_admin": True, "create_evidence": True},
        "frameworks": ["SOC2"],
    },
    {
        "id": "tpl-ccpa-pii-alert",
        "name": "CCPA PII Leakage Alert",
        "description": "Alert on outbound emails with potential PII exposure",
        "conditions": {"threat_type": "DATA_LEAK", "risk_score_min": 50},
        "action": "ALERT",
        "action_config": {"notify_admin": True, "create_evidence": True, "alert_compliance": True},
        "frameworks": ["CCPA"],
    },
    {
        "id": "tpl-ransomware-zero",
        "name": "Ransomware Zero-Tolerance",
        "description": "Block all ransomware delivery attempts immediately",
        "conditions": {"threat_type": "RANSOMWARE", "risk_score_min": 50},
        "action": "BLOCK_DELETE",
        "action_config": {"notify_admin": True, "notify_soc": True, "create_evidence": True},
        "frameworks": ["NIST_CSF", "SOC2"],
    },
    {
        "id": "tpl-bec-us",
        "name": "BEC Financial Fraud (US)",
        "description": "Quarantine BEC targeting finance and payroll",
        "conditions": {"threat_type": "BEC", "risk_score_min": 70},
        "action": "QUARANTINE",
        "action_config": {"notify_admin": True, "create_evidence": True},
        "frameworks": ["NIST_CSF", "SOC2"],
    },
    {
        "id": "tpl-ioc-block-us",
        "name": "IOC Threat Intelligence Block",
        "description": "Block senders matching IOCs from abuse.ch, URLhaus, and PhishTank public feeds",
        "conditions": {"ioc_match": True, "risk_score_min": 45},
        "action": "BLOCK_DELETE",
        "action_config": {"notify_admin": True, "create_evidence": True, "ioc_source": "public_feeds"},
        "frameworks": ["NIST_CSF", "SOC2", "CCPA"],
    },
]


def policy_to_dict(p: Policy) -> dict:
    return {
        "id": str(p.id),
        "org_id": str(p.org_id),
        "name": p.name,
        "description": p.description,
        "priority": p.priority,
        "status": p.status,
        "conditions": p.conditions,
        "action": p.action,
        "action_config": p.action_config,
        "hit_count": getattr(p, "hit_count", 0) or 0,
        "m365_rule_id": p.m365_rule_id,
        "created_by": str(p.created_by) if p.created_by else None,
        "created_at": p.created_at.isoformat() if p.created_at else None,
        "updated_at": p.updated_at.isoformat() if p.updated_at else None,
    }


CERT_CN_PACK_TEMPLATES = [
    {
        "id": "tpl-cert-cn-malicious-ips",
        "name": "CERT-CN Malicious IP Quarantine",
        "description": (
            "Quarantine emails where the sender IP matches China's National CERT (CNVD/CERT-CN) "
            "daily threat reports. IPs are extracted from published incident reports and refreshed every 6 hours. "
            "Covers APT infrastructure, phishing hosts, malware C2s, and exploit servers reported by CERT-CN."
        ),
        "conditions": {"threat_feed_match": {"ip_match": ["cert_cn_ips"]}},
        "action": "QUARANTINE",
        "action_config": {"notify_admin": True, "create_evidence": True, "ioc_source": "cert_cn_ips"},
        "frameworks": ["CERT-CN", "China NCSA", "Threat Intelligence"],
        "pack_id": "cert_cn_ips",
        "live_feed": True,
    },
    {
        "id": "tpl-cert-cn-malicious-urls",
        "name": "CERT-CN Malicious URL/Domain Quarantine",
        "description": (
            "Quarantine emails containing links or domains matching China CERT daily threat intel reports. "
            "URLs and domains are extracted from CERT-CN incident bulletins covering phishing campaigns, "
            "malware distribution, and APT command-and-control infrastructure. Refreshed every 6 hours."
        ),
        "conditions": {"threat_feed_match": {"url_match": ["cert_cn_urls"]}},
        "action": "QUARANTINE",
        "action_config": {"notify_admin": True, "create_evidence": True, "ioc_source": "cert_cn_urls"},
        "frameworks": ["CERT-CN", "China NCSA", "Threat Intelligence"],
        "pack_id": "cert_cn_urls",
        "live_feed": True,
    },
]

OPENDBL_PACK_TEMPLATES = [
    {
        "id": "tpl-opendbl-emerging-threats",
        "name": "Emerging Threats IP Blocklist",
        "description": (
            "Quarantine emails where the sender IP or any link IP matches the live Emerging Threats "
            "OpenDBL feed — automatically refreshed every 6 hours. Matches sender IP, originating IP "
            "from headers, and IPs resolved from links found in the email body."
        ),
        "conditions": {"opendbl_pack": ["emerging_threats"]},
        "action": "QUARANTINE",
        "action_config": {"notify_admin": True, "create_evidence": True, "ioc_source": "opendbl_emerging_threats"},
        "frameworks": ["OpenDBL", "Threat Intelligence"],
        "pack_id": "emerging_threats",
        "live_feed": True,
    },
    {
        "id": "tpl-opendbl-tor-exits",
        "name": "TOR Exit Node Quarantine",
        "description": (
            "Quarantine emails relayed through TOR exit nodes. Anonymised sender infrastructure "
            "is a strong indicator of evasion intent. Feed refreshed every 6 hours from opendbl.net."
        ),
        "conditions": {"opendbl_pack": ["tor_exits"]},
        "action": "QUARANTINE",
        "action_config": {"notify_admin": True, "create_evidence": True, "ioc_source": "opendbl_tor_exits"},
        "frameworks": ["OpenDBL", "Threat Intelligence"],
        "pack_id": "tor_exits",
        "live_feed": True,
    },
    {
        "id": "tpl-opendbl-brute-force",
        "name": "Brute Force Source Quarantine",
        "description": (
            "Quarantine emails from IPs flagged in the Brute Force Blocker list — sources actively "
            "conducting credential stuffing and password spray attacks. Refreshed every 6 hours."
        ),
        "conditions": {"opendbl_pack": ["brute_force"]},
        "action": "QUARANTINE",
        "action_config": {"notify_admin": True, "create_evidence": True, "ioc_source": "opendbl_brute_force"},
        "frameworks": ["OpenDBL", "Threat Intelligence"],
        "pack_id": "brute_force",
        "live_feed": True,
    },
    {
        "id": "tpl-opendbl-blocklistde",
        "name": "Blocklist.de Combined Feed Quarantine",
        "description": (
            "Quarantine emails from IPs in the Blocklist.de all-in-one feed — covers attacks, "
            "spam sources, SSH abuse, and generic bad actors. Refreshed every 6 hours."
        ),
        "conditions": {"opendbl_pack": ["blocklistde"]},
        "action": "QUARANTINE",
        "action_config": {"notify_admin": True, "create_evidence": True, "ioc_source": "opendbl_blocklistde"},
        "frameworks": ["OpenDBL", "Threat Intelligence"],
        "pack_id": "blocklistde",
        "live_feed": True,
    },
]


@router.get("/templates")
async def get_templates():
    return {
        "gulf": GULF_TEMPLATES,
        "us": US_TEMPLATES,
        "eu": EU_TEMPLATES,
        "all": GULF_TEMPLATES + US_TEMPLATES + EU_TEMPLATES,
        "threat_intel": CERT_CN_PACK_TEMPLATES + OPENDBL_PACK_TEMPLATES,
    }


@router.get("/opendbl/status")
async def get_opendbl_status(current_user=Depends(get_current_user)):
    """Return live OpenDBL pack metadata (IP counts, last refresh time)."""
    try:
        import redis.asyncio as aioredis
        from backend.config import settings as _cfg
        from backend.services.opendbl_service import get_all_pack_meta
        _redis = aioredis.from_url(_cfg.REDIS_URL, decode_responses=True)
        try:
            meta = await get_all_pack_meta(_redis)
        finally:
            await _redis.aclose()
        return {"packs": meta}
    except Exception as e:
        return {"packs": {}, "error": str(e)}


@router.post("/opendbl/test")
async def test_opendbl_pack(
    req: dict,
    current_user=Depends(get_current_user),
):
    """
    Simulate/validate an IOC match against cached OpenDBL packs.

    Body:
      ip        (str)        – raw IPv4 address to test
      domain    (str)        – domain to resolve → IP then test
      pack_ids  (list[str])  – which packs to check; omit to test ALL packs

    Returns per-pack match results so analysts can verify packs are loaded and
    producing expected hits (e.g., enter a known bad IP from the feed to confirm
    the pack is active and matching correctly).
    """
    import time
    from backend.services.opendbl_service import (
        check_ip_in_any_pack,
        check_ip_in_pack,
        resolve_domain_to_ip,
        get_all_pack_meta,
        OPENDBL_PACKS,
        _IP_RE,
    )

    test_ip: str = (req.get("ip") or "").strip()
    test_domain: str = (req.get("domain") or "").strip()
    pack_ids: list[str] = req.get("pack_ids") or list(OPENDBL_PACKS.keys())

    # Validate / resolve
    resolved_ip: str | None = None
    resolution_note: str = ""

    if test_ip and _IP_RE.match(test_ip):
        resolved_ip = test_ip
    elif test_domain:
        resolved_ip = resolve_domain_to_ip(test_domain)
        if resolved_ip:
            resolution_note = f"Resolved {test_domain} → {resolved_ip}"
        else:
            return {
                "error": f"Could not resolve domain '{test_domain}' to an IP address",
                "ip_tested": None,
                "results": {},
            }
    else:
        return {
            "error": "Provide either 'ip' (IPv4 address) or 'domain' to test",
            "ip_tested": None,
            "results": {},
        }

    try:
        import redis.asyncio as aioredis
        from backend.config import settings as _cfg
        _redis = aioredis.from_url(_cfg.REDIS_URL, decode_responses=True)
        try:
            per_pack: dict[str, dict] = {}
            any_match = False
            for pid in pack_ids:
                if pid not in OPENDBL_PACKS:
                    per_pack[pid] = {"matched": False, "error": "Unknown pack_id"}
                    continue
                matched = await check_ip_in_pack(_redis, resolved_ip, pid)
                pack_info = OPENDBL_PACKS[pid]
                per_pack[pid] = {
                    "matched": matched,
                    "label": pack_info["label"],
                    "url": pack_info["url"],
                }
                if matched:
                    any_match = True

            # Also surface pack cache state so caller can tell if a pack has no IPs
            meta = await get_all_pack_meta(_redis)
            for pid in per_pack:
                if pid in meta:
                    per_pack[pid]["ip_count"] = meta[pid].get("ip_count", 0)
                    per_pack[pid]["last_refresh"] = meta[pid].get("last_refresh")

        finally:
            await _redis.aclose()

        return {
            "ip_tested": resolved_ip,
            "domain_tested": test_domain or None,
            "resolution_note": resolution_note or None,
            "any_match": any_match,
            "matched_packs": [pid for pid, r in per_pack.items() if r.get("matched")],
            "results": per_pack,
            "tested_at": time.time(),
        }

    except Exception as e:
        return {"error": str(e), "ip_tested": resolved_ip, "results": {}}


@router.post("/validate/gmail-tag")
async def validate_gmail_tag(
    req: dict,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Validate that Gmail label tagging is working end-to-end for a given mailbox.

    Body:
      user_email        (str)  – the Gmail address to test against
      gmail_message_id  (str)  – a real Gmail message ID to apply the test label to
      label_type        (str)  – "tag" (Himaya-Flagged) | "alert" (Helios-Alert)
                                  | "review" (Helios-Review).  Defaults to "tag".

    Returns success/failure with diagnostic details from the Gmail API so you can
    confirm the label was actually applied in the mailbox.
    """
    user_email: str = (req.get("user_email") or "").strip()
    gmail_message_id: str = (req.get("gmail_message_id") or "").strip()
    label_type: str = (req.get("label_type") or "tag").strip().lower()

    if not user_email or not gmail_message_id:
        raise HTTPException(
            status_code=400,
            detail="Both 'user_email' and 'gmail_message_id' are required",
        )

    # Resolve org OAuth token as fallback (SA preferred)
    fallback_token: str | None = None
    try:
        from backend.models.db_models import OrgIntegration as _OI
        from backend.services.baseline_ingestion import _decrypt
        int_res = await db.execute(
            select(_OI).where(
                _OI.org_id == current_user.org_id,
                _OI.provider == "google",
                _OI.status == "active",
            )
        )
        integration = int_res.scalar_one_or_none()
        if integration and integration.access_token_enc:
            fallback_token = _decrypt(integration.access_token_enc)
    except Exception as _te:
        pass  # non-fatal — SA will be tried first

    try:
        if label_type == "alert":
            from backend.services.quarantine_service import apply_alert_label_gmail
            ok = await apply_alert_label_gmail(
                user_email=user_email,
                gmail_message_id=gmail_message_id,
                fallback_access_token=fallback_token,
            )
            label_name = "Helios-Alert"
        elif label_type == "review":
            from backend.services.quarantine_service import apply_review_label_gmail
            ok = await apply_review_label_gmail(
                user_email=user_email,
                gmail_message_id=gmail_message_id,
                fallback_access_token=fallback_token,
            )
            label_name = "Helios-Review"
        else:
            from backend.services.quarantine_service import apply_flagged_label_gmail
            ok = await apply_flagged_label_gmail(
                user_email=user_email,
                gmail_message_id=gmail_message_id,
                fallback_access_token=fallback_token,
            )
            label_name = "Himaya-Flagged"

        return {
            "success": ok,
            "label_applied": label_name if ok else None,
            "user_email": user_email,
            "gmail_message_id": gmail_message_id,
            "has_service_account": True,  # if we got this far without error, SA tried
            "has_oauth_fallback": fallback_token is not None,
            "message": (
                f"✓ '{label_name}' label successfully applied to message {gmail_message_id}"
                if ok else
                f"✗ Failed to apply '{label_name}' label — check backend logs for Gmail API response details"
            ),
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "user_email": user_email,
            "gmail_message_id": gmail_message_id,
        }


@router.post("/opendbl/refresh")
async def trigger_opendbl_refresh(
    background_tasks: BackgroundTasks,
    current_user=Depends(get_current_user),
):
    """Manually trigger an OpenDBL refresh (admin action)."""
    async def _do_refresh():
        import redis.asyncio as aioredis
        from backend.config import settings as _cfg
        from backend.services.opendbl_service import refresh_all_packs
        _redis = aioredis.from_url(_cfg.REDIS_URL, decode_responses=True)
        try:
            await refresh_all_packs(_redis)
        finally:
            await _redis.aclose()

    background_tasks.add_task(_do_refresh)
    return {"message": "OpenDBL refresh triggered — packs will update within 30 seconds."}


@router.get("/anva/status")
async def get_anva_status(current_user=Depends(get_current_user)):
    """Return ANVA pack metadata (IOC counts, last refresh, status)."""
    import redis.asyncio as aioredis
    from backend.config import settings as _cfg
    from backend.services.anva_service import get_all_anva_pack_meta
    _redis = aioredis.from_url(_cfg.REDIS_URL, decode_responses=True)
    try:
        meta = await get_all_anva_pack_meta(_redis)
        return {"packs": meta}
    finally:
        await _redis.aclose()


@router.post("/anva/refresh")
async def trigger_anva_refresh(
    background_tasks: BackgroundTasks,
    current_user=Depends(get_current_user),
):
    """Manually trigger an ANVA pack refresh (admin action)."""
    async def _do_refresh():
        import redis.asyncio as aioredis
        from backend.config import settings as _cfg
        from backend.services.anva_service import refresh_all_anva_packs
        _redis = aioredis.from_url(_cfg.REDIS_URL, decode_responses=True)
        try:
            await refresh_all_anva_packs(_redis)
        finally:
            await _redis.aclose()

    background_tasks.add_task(_do_refresh)
    return {"message": "ANVA refresh triggered — packs will update in background (requires ANVA_USERNAME/ANVA_PASSWORD env vars)."}


@router.get("/cert-cn/status")
async def get_cert_cn_status(current_user=Depends(get_current_user)):
    """Return CERT-CN feed metadata from Redis."""
    import redis.asyncio as aioredis, json as _j
    from backend.config import settings as _cfg
    _redis = aioredis.from_url(_cfg.REDIS_URL, decode_responses=True)
    try:
        meta_raw = await _redis.get("cert_cn:meta")
        ip_count = await _redis.scard("cert_cn:ips")
        url_count = await _redis.scard("cert_cn:urls")
        meta = _j.loads(meta_raw) if meta_raw else {}
        return {
            "ips": ip_count or 0,
            "urls": url_count or 0,
            "last_refresh": meta.get("last_refresh"),
            "reports_scraped": meta.get("reports_scraped", 0),
        }
    except Exception:
        return {"ips": 0, "urls": 0, "last_refresh": None}
    finally:
        await _redis.aclose()


@router.post("/cert-cn/refresh")
async def trigger_cert_cn_refresh(
    background_tasks: BackgroundTasks,
    current_user=Depends(get_current_user),
):
    """Manually trigger a CERT-CN IOC scrape."""
    async def _do_scrape():
        from backend.services.cert_cn_service import refresh_cert_cn_feeds
        await refresh_cert_cn_feeds()
    background_tasks.add_task(_do_scrape)
    return {"message": "CERT-CN scrape triggered — collecting IOCs from cert.org.cn in background."}


@router.get("/next-priority")
async def get_next_priority(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return the next available priority number that doesn't collide with existing policies."""
    from sqlalchemy import func as _func
    result = await db.execute(
        select(Policy.priority)
        .where(Policy.org_id == current_user.org_id)
        .order_by(Policy.priority.asc())
    )
    used = {row[0] for row in result.fetchall()}
    # Start at 10, increment by 10 to leave gaps, find first unused multiple of 10
    candidate = 10
    while candidate in used:
        candidate += 10
    return {"priority": candidate, "used_priorities": sorted(used)}


@router.get("")
async def list_policies(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Policy)
        .where(Policy.org_id == current_user.org_id)
        .order_by(Policy.priority.asc())
    )
    policies = result.scalars().all()
    return {"items": [policy_to_dict(p) for p in policies], "total": len(policies)}


@router.post("")
async def create_policy(
    req: PolicyCreate,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    policy = Policy(
        org_id=current_user.org_id,
        name=req.name,
        description=req.description,
        priority=req.priority,
        conditions=req.conditions,
        action=req.action,
        action_config=req.action_config,
        status="draft",
        created_by=current_user.id,
    )
    db.add(policy)
    await db.flush()
    return policy_to_dict(policy)


@router.put("/{policy_id}")
async def update_policy(
    policy_id: str,
    req: PolicyUpdate,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Policy).where(
            Policy.id == uuid.UUID(policy_id),
            Policy.org_id == current_user.org_id,
        )
    )
    policy = result.scalar_one_or_none()
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")

    for field, value in req.model_dump(exclude_none=True).items():
        setattr(policy, field, value)
    policy.updated_at = datetime.utcnow()
    await db.flush()
    return policy_to_dict(policy)


@router.post("/{policy_id}/activate")
async def activate_policy(
    policy_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Policy).where(
            Policy.id == uuid.UUID(policy_id),
            Policy.org_id == current_user.org_id,
        )
    )
    policy = result.scalar_one_or_none()
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    policy.status = "active"
    policy.updated_at = datetime.utcnow()

    # Push to M365
    pusher = M365PolicyPusher()
    m365_result = await pusher.create_transport_rule(policy_to_dict(policy), str(current_user.org_id))
    if m365_result.get("m365_rule_id"):
        policy.m365_rule_id = m365_result["m365_rule_id"]

    await db.flush()
    return {"message": "Policy activated", "policy_id": policy_id, "status": "active", "m365": m365_result}


@router.post("/{policy_id}/pause")
async def pause_policy(
    policy_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Policy).where(
            Policy.id == uuid.UUID(policy_id),
            Policy.org_id == current_user.org_id,
        )
    )
    policy = result.scalar_one_or_none()
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    # Remove from M365 if rule exists
    pusher = M365PolicyPusher()
    m365_result = None
    if policy.m365_rule_id:
        m365_result = await pusher.remove_transport_rule(policy.m365_rule_id)
        policy.m365_rule_id = None

    policy.status = "paused"
    policy.updated_at = datetime.utcnow()
    await db.flush()
    return {"message": "Policy paused", "policy_id": policy_id, "status": "paused", "m365": m365_result}


@router.post("/apply-retroactive")
async def apply_policies_retroactively(
    background_tasks: BackgroundTasks,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Kick off retroactive policy application across ALL threats for this org.
    Runs as a background task so the response returns immediately (no timeout).
    """
    from backend.services.policy_engine import retroactive_apply
    from backend.database import AsyncSessionLocal
    import asyncio

    org_id = current_user.org_id

    async def _run():
        async with AsyncSessionLocal() as bg_db:
            try:
                await retroactive_apply(org_id=org_id, db=bg_db, limit=0)
            except Exception as e:
                import logging
                logging.getLogger(__name__).error(f"Background retroactive apply failed: {e}")

    # FIX: pass _run directly — BackgroundTasks detects coroutine functions and awaits them
    # correctly. The previous `asyncio.ensure_future` approach ran in a thread (no event loop)
    # so _run() coroutine was created but never awaited, silently doing nothing.
    background_tasks.add_task(_run)
    return {"message": "Policy application started — emails are being processed in the background.", "status": "processing"}


@router.delete("/{policy_id}")
async def delete_policy(
    policy_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Policy).where(
            Policy.id == uuid.UUID(policy_id),
            Policy.org_id == current_user.org_id,
        )
    )
    policy = result.scalar_one_or_none()
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    # Remove from M365 if rule exists
    if policy.m365_rule_id:
        pusher = M365PolicyPusher()
        await pusher.remove_transport_rule(policy.m365_rule_id)
    await db.delete(policy)
    await db.flush()
    return {"message": "Policy deleted", "policy_id": policy_id}


@router.get("/m365-sync-status")
async def m365_sync_status(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Policy).where(
            Policy.org_id == current_user.org_id,
            Policy.status == "active",
        )
    )
    active_policies = result.scalars().all()
    pusher = M365PolicyPusher()
    reconcile_result = await pusher.reconcile(
        [policy_to_dict(p) for p in active_policies],
        str(current_user.org_id),
    )
    return reconcile_result
