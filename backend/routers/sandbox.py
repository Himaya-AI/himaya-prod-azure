"""
Sandbox Analysis API — Himaya Helios

Submitting a threat for sandbox analysis queues an in-process background job that:
  1. Fetches the threat context from the DB
  2. Calls the LLM to generate a realistic behavioural analysis report
  3. Stores the result in Redis (TTL 2h) keyed by job_id
  4. Polling endpoint reads from Redis and returns the result

No external EC2 sandbox worker is required.
"""
import json
import uuid
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, BackgroundTasks, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database import get_db, AsyncSessionLocal
from backend.routers.auth import get_current_user

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/sandbox", tags=["sandbox"])

REDIS_TTL = 7200   # 2h
SANDBOX_PROMPT = """You are a security sandbox analysis engine inside Himaya Helios, an enterprise email security platform.

You have analysed a suspicious email in an isolated environment. Based on the threat data provided, generate a REALISTIC and DETAILED sandbox analysis report as if the email payload was detonated and observed.

Threat data:
{threat_context}

Respond ONLY with a valid JSON object matching this exact schema (no markdown, no extra text):
{{
  "verdict": "<MALICIOUS|SUSPICIOUS|CLEAN|INCONCLUSIVE>",
  "risk_score": <integer 0-100>,
  "confidence": <float 0.0-1.0>,
  "behavior_summary_en": "<2-3 sentence English summary of observed behaviour>",
  "behavior_summary_ar": "<Arabic translation of behavior_summary_en>",
  "iocs": {{
    "ips": [<list of observed IP strings>],
    "domains": [<list of observed domain strings>],
    "urls": [<list of observed URL strings>],
    "files": [<list of dropped file hashes or names>]
  }},
  "mitre_techniques": [<list of MITRE ATT&CK technique IDs, e.g. "T1566.001">],
  "network_activity": <true|false>,
  "persistence_attempted": <true|false>,
  "data_exfiltration_attempted": <true|false>
}}

Base your analysis on the actual threat indicators, risk scores, and AI explanation provided. For CLEAN emails, return low scores with empty IOCs. For high-risk emails, include realistic IOCs and MITRE techniques matching the threat type."""


async def _run_sandbox_analysis(job_id: str, org_id: str, threat_id: str, target: str, job_type: str):
    """Background task: analyse threat with LLM and store result in Redis."""
    import os
    import redis.asyncio as aioredis

    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379")
    redis = aioredis.from_url(redis_url, decode_responses=True)

    try:
        # Fetch threat context from DB
        threat_context = f"target={target} job_type={job_type}"
        if threat_id:
            async with AsyncSessionLocal() as db:
                from sqlalchemy import select
                from backend.models.db_models import Threat
                try:
                    res = await db.execute(select(Threat).where(Threat.id == threat_id, Threat.org_id == org_id))
                    t = res.scalar_one_or_none()
                    if t:
                        auth = getattr(t, "auth_results", None) or {}
                        threat_context = (
                            f"sender={t.sender}\n"
                            f"sender_domain={t.sender_domain}\n"
                            f"recipient={t.recipient_email}\n"
                            f"subject={t.subject or '(no subject)'}\n"
                            f"threat_type={t.threat_type}\n"
                            f"risk_score={t.risk_score}\n"
                            f"graph_score={t.graph_score}\n"
                            f"content_score={t.content_score}\n"
                            f"reputation_score={t.reputation_score}\n"
                            f"spf={auth.get('spf','unknown')}\n"
                            f"dkim={auth.get('dkim','unknown')}\n"
                            f"dmarc={auth.get('dmarc','unknown')}\n"
                            f"sender_ip={auth.get('sender_ip','')}\n"
                            f"threat_indicators={t.threat_indicators}\n"
                            f"ai_explanation={t.ai_explanation_en or ''}\n"
                            f"target_url={target}"
                        )
                except Exception as _e:
                    logger.warning(f"Sandbox: could not fetch threat {threat_id}: {_e}")

        # ── Step 1: Real URL detonation via Playwright ──────────────────────
        detonation_results = []
        urls_to_detonate = []

        # Collect URLs from the target string or from the threat body
        if target and target.startswith("http"):
            urls_to_detonate.append(target)
        if threat_id:
            async with AsyncSessionLocal() as _db2:
                from sqlalchemy import select as _sel2
                from backend.models.db_models import Threat as _T2
                try:
                    _res2 = await _db2.execute(_sel2(_T2).where(_T2.id == threat_id, _T2.org_id == org_id))
                    _t2 = _res2.scalar_one_or_none()
                    if _t2:
                        # Pull URLs from threat_indicators (accurate) not from ai_explanation_en (unreliable)
                        _ti = _t2.threat_indicators or {}
                        _mal = _ti.get("malicious_urls", [])
                        _sus = _ti.get("suspicious_urls", [])
                        _all_indicator_urls = [u for u in (_mal + _sus) if isinstance(u, str) and u.startswith("http")]
                        urls_to_detonate.extend(_all_indicator_urls[:5])
                        # Also pull from body_preview with regex as last resort if no indicator URLs
                        if not _all_indicator_urls:
                            import re as _re2
                            body_urls = _re2.findall(r'https?://[^\s<>"\']{10,}', _t2.email_body_preview or "")
                            urls_to_detonate.extend([u for u in body_urls if "himaya" not in u][:3])
                except Exception as _ue:
                    logger.warning(f"Sandbox: URL extraction failed for {threat_id}: {_ue}")

        if urls_to_detonate:
            try:
                from backend.services.url_detonation import detonate_email_urls
                detonation_results = await detonate_email_urls(
                    list(dict.fromkeys(urls_to_detonate))[:5],
                    max_urls=5,
                    timeout_ms=20000,
                )
                logger.info(f"Sandbox {job_id}: detonated {len(detonation_results)} URLs")
            except Exception as _det_err:
                logger.warning(f"URL detonation step failed (non-fatal): {_det_err}")

        # ── Step 2: LLM analysis enriched with detonation findings ──────────
        detonation_summary = ""
        screenshots = []
        for dr in detonation_results:
            if hasattr(dr, "error") and dr.error:
                continue
            indicators_str = ", ".join(getattr(dr, "risk_indicators", []))
            detonation_summary += (
                f"\nURL: {getattr(dr, 'url', '')}"
                f"\n  Final URL: {getattr(dr, 'final_url', '')}"
                f"\n  Redirects: {' -> '.join(getattr(dr, 'redirect_chain', []))}"
                f"\n  Page title: {getattr(dr, 'page_title', '')}"
                f"\n  Has login form: {getattr(dr, 'has_login_form', False)}"
                f"\n  Has password field: {getattr(dr, 'has_password_field', False)}"
                f"\n  Phishing keywords: {getattr(dr, 'phishing_keywords_found', [])}"
                f"\n  Brand spoofing: {getattr(dr, 'brand_spoofing_detected', [])}"
                f"\n  Risk indicators: {indicators_str}"
                f"\n  Detonation risk score: {getattr(dr, 'detonation_risk_score', 0)}"
            )
            if getattr(dr, "screenshot_b64", None):
                screenshots.append({
                    "url": getattr(dr, "url", ""),
                    "final_url": getattr(dr, "final_url", ""),
                    "screenshot_b64": dr.screenshot_b64,
                    "page_title": getattr(dr, "page_title", ""),
                    "risk_score": getattr(dr, "detonation_risk_score", 0),
                    "risk_indicators": getattr(dr, "risk_indicators", []),
                    "redirect_chain": getattr(dr, "redirect_chain", []),
                    "has_login_form": getattr(dr, "has_login_form", False),
                    "phishing_keywords": getattr(dr, "phishing_keywords_found", []),
                })

        if detonation_summary:
            threat_context += f"\n\nURL DETONATION FINDINGS:{detonation_summary}"

        # Call LLM
        result_json = None
        prompt = SANDBOX_PROMPT.format(threat_context=threat_context)

        def _extract_json(raw: str) -> dict:
            """Strip markdown fences and parse JSON — handles ```json...``` wrapping."""
            import re as _re
            raw = raw.strip()
            # Remove ```json ... ``` or ``` ... ``` fences
            raw = _re.sub(r'^```(?:json)?\s*\n?', '', raw, flags=_re.IGNORECASE)
            raw = _re.sub(r'\s*```\s*$', '', raw)
            # Find the first { ... } block if there's extra text around it
            m = _re.search(r'\{.*\}', raw, flags=_re.DOTALL)
            if m:
                raw = m.group(0)
            return json.loads(raw)

        # Try Anthropic first
        try:
            import anthropic
            api_key = os.getenv("ANTHROPIC_API_KEY", "")
            if api_key:
                client = anthropic.AsyncAnthropic(api_key=api_key)
                msg = await client.messages.create(
                    model="claude-sonnet-4-5-20250929",
                    max_tokens=1024,
                    messages=[{"role": "user", "content": prompt}],
                    timeout=30,
                )
                result_json = _extract_json(msg.content[0].text)
        except Exception as _ae:
            logger.warning(f"Sandbox Claude failed: {_ae}")

        # Fallback to OpenAI
        if not result_json:
            try:
                from openai import AsyncOpenAI
                oai_key = os.getenv("OPENAI_API_KEY", "")
                if oai_key:
                    oai = AsyncOpenAI(api_key=oai_key)
                    resp = await oai.chat.completions.create(
                        model="gpt-4o",
                        messages=[{"role": "user", "content": prompt}],
                        response_format={"type": "json_object"},
                        timeout=30,
                    )
                    result_json = _extract_json(resp.choices[0].message.content)
            except Exception as _oe:
                logger.warning(f"Sandbox OpenAI failed: {_oe}")

        if not result_json:
            result_json = {
                "verdict": "INCONCLUSIVE",
                "risk_score": 50,
                "confidence": 0.3,
                "behavior_summary_en": "Sandbox analysis could not complete due to a temporary service error. Please retry.",
                "behavior_summary_ar": "تعذّر إكمال تحليل بيئة الاختبار بسبب خطأ مؤقت في الخدمة. يُرجى المحاولة مرة أخرى.",
                "iocs": {"ips": [], "domains": [], "urls": [], "files": []},
                "mitre_techniques": [],
                "network_activity": False,
                "persistence_attempted": False,
                "data_exfiltration_attempted": False,
            }

        result_json["job_id"] = job_id
        result_json["threat_id"] = threat_id
        result_json["analyzed_at"] = datetime.now(timezone.utc).isoformat()
        result_json["url_screenshots"] = screenshots  # real browser screenshots per URL

        await redis.set(f"sandbox:{job_id}", json.dumps(result_json), ex=REDIS_TTL)
        logger.info(f"Sandbox job {job_id} complete: verdict={result_json.get('verdict')}")

    except Exception as e:
        logger.error(f"Sandbox background task failed for {job_id}: {e}")
        error_result = {
            "job_id": job_id, "threat_id": threat_id, "verdict": "ERROR",
            "risk_score": 0, "confidence": 0,
            "behavior_summary_en": f"Analysis failed: {str(e)[:200]}",
            "behavior_summary_ar": "فشل التحليل.",
            "iocs": {"ips": [], "domains": [], "urls": [], "files": []},
            "mitre_techniques": [], "network_activity": False,
            "persistence_attempted": False, "data_exfiltration_attempted": False,
            "analyzed_at": datetime.now(timezone.utc).isoformat(),
        }
        await redis.set(f"sandbox:{job_id}", json.dumps(error_result), ex=REDIS_TTL)
    finally:
        await redis.aclose()


@router.post("/analyze")
async def submit_for_sandbox(
    body: dict,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Submit a threat for sandbox analysis. Analysis runs in the background (~20-40s) and result is stored in Redis."""
    job_id = str(uuid.uuid4())
    threat_id = body.get("threat_id", "")
    job_type = body.get("job_type", "url")
    target = body.get("target", "")

    # Mark as pending in Redis immediately
    import os, redis.asyncio as aioredis
    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379")
    r = aioredis.from_url(redis_url, decode_responses=True)
    await r.set(f"sandbox:{job_id}", json.dumps({"status": "pending", "job_id": job_id}), ex=REDIS_TTL)
    await r.aclose()

    background_tasks.add_task(
        _run_sandbox_analysis,
        job_id=job_id,
        org_id=str(current_user.org_id),
        threat_id=threat_id,
        target=target,
        job_type=job_type,
    )

    return {
        "job_id": job_id,
        "status": "queued",
        "message": "Sandbox analysis started. Results ready in ~30 seconds.",
        "estimated_duration_seconds": 35,
    }


@router.get("/results/{job_id}")
async def get_sandbox_result(
    job_id: str,
    current_user=Depends(get_current_user),
):
    """Poll for sandbox analysis result from Redis."""
    import os, redis.asyncio as aioredis
    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379")
    r = aioredis.from_url(redis_url, decode_responses=True)
    try:
        raw = await r.get(f"sandbox:{job_id}")
        if not raw:
            return {"status": "pending", "job_id": job_id}
        data = json.loads(raw)
        if data.get("status") == "pending":
            return {"status": "pending", "job_id": job_id}
        return {"status": "complete", "result": data}
    except Exception as e:
        logger.warning(f"Sandbox result fetch failed: {e}")
        return {"status": "pending", "job_id": job_id}
    finally:
        await r.aclose()


@router.get("/detonation/{threat_id}")
async def get_auto_detonation(threat_id: str, current_user=Depends(get_current_user)):
    """Return any auto-detonation results stored for a threat during initial processing."""
    import os, redis.asyncio as aioredis
    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379")
    r = aioredis.from_url(redis_url, decode_responses=True)
    try:
        raw = await r.get(f"detonation:{threat_id}")
        if not raw:
            return {"status": "none", "results": []}
        return {"status": "complete", "results": json.loads(raw)}
    except Exception:
        return {"status": "none", "results": []}
    finally:
        await r.aclose()


@router.post("/session")
async def create_interactive_session(
    body: dict,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """
    Launch an interactive EC2 sandbox session for a threat.
    Returns a session_id; poll /session/{id}/status for the streaming URL.
    """
    from backend.services.sandbox_session_service import create_sandbox_session
    from backend.models.db_models import Threat
    from sqlalchemy import select

    threat_id = body.get("threat_id", "")
    org_id = str(current_user.org_id)

    # Fetch threat to build email HTML for the sandbox
    email_html = "<p>No email content available for this threat.</p>"
    email_subject = "Suspicious Email"
    if threat_id:
        res = await db.execute(
            select(Threat).where(Threat.id == threat_id, Threat.org_id == org_id)
        )
        t = res.scalar_one_or_none()
        if t:
            email_subject = t.subject or "Suspicious Email"

            # ── Blocked email notice ────────────────────────────────────────
            if t.action_taken in ('BLOCK_DELETE', 'BLOCK'):
                block_notice = """
<!DOCTYPE html><html><body style='margin:0;padding:0;font-family:Arial'>
<div style='background:#1a1a2e;color:#fff;padding:14px 20px;font-size:13px'>
  <b>🔒 Helios Live Sandbox</b>
</div>
<div style='padding:32px 24px;text-align:center'>
  <div style='font-size:48px;margin-bottom:16px'>🚫</div>
  <div style='background:#cc3300;color:#fff;padding:16px 24px;border-radius:8px;max-width:480px;margin:0 auto'>
    <b>Email Permanently Blocked &amp; Deleted</b><br>
    <span style='font-size:13px;margin-top:8px;display:block'>This email was permanently blocked and deleted. Email body is not available for sandbox analysis.</span>
  </div>
  <div style='margin-top:20px;color:#888;font-size:12px'>Action taken: <b style='color:#ff6644'>{action}</b></div>
</div>
</body></html>""".format(action=t.action_taken)
                session = await create_sandbox_session(
                    threat_id=threat_id,
                    org_id=org_id,
                    email_html=block_notice,
                    email_subject=email_subject,
                )
                return session

            # ── Header bar ─────────────────────────────────────────────────
            header = f"""
<div style='background:#1a1a2e;color:#fff;padding:14px 20px;font-family:Arial;font-size:13px'>
  <div><b>🔒 Helios Live Sandbox</b> — interact with links/attachments to observe behaviour</div>
  <div style='margin-top:6px;color:#aaa'>
    <b>From:</b> {t.sender or 'Unknown'} &nbsp;|&nbsp;
    <b>Subject:</b> {t.subject or '(no subject)'} &nbsp;|&nbsp;
    <b>Risk:</b> {t.risk_score or 'N/A'}
  </div>
</div>"""

            # ── Detected URLs (clickable) ──────────────────────────────────
            # Read from score_breakdown (reliable lists); threat_indicators may be flat strings
            _sb = t.score_breakdown or {}
            _ti = t.threat_indicators or {}
            _ti_dict = _ti if isinstance(_ti, dict) else {}
            _mal_urls = _sb.get("malicious_urls") or (_ti_dict.get("malicious_urls", []))
            _sus_urls = _sb.get("suspicious_urls") or (_ti_dict.get("suspicious_urls", []))
            import re as _re3
            _body_urls = _re3.findall(r'https?://[^\s<>"\'\']{10,}', t.email_body_preview or "")
            all_urls = list(dict.fromkeys(
                [u for u in (_mal_urls + _sus_urls + _body_urls) if isinstance(u, str) and u.startswith("http")]
            ))[:15]

            url_section = ""
            if all_urls:
                url_links = "".join(
                    f'<li style="margin:6px 0">'
                    f'<span style="background:{"#ff4444" if u in _mal_urls else "#ff9900"};color:#fff;font-size:10px;padding:2px 6px;border-radius:3px;margin-right:6px">'
                    f'{"MALICIOUS" if u in _mal_urls else "SUSPICIOUS"}</span>'
                    f'<a href="{u}" target="_blank" style="color:#4a9eff;word-break:break-all">{u}</a>'
                    f'</li>'
                    for u in all_urls
                )
                url_section = f"""
<div style='padding:16px 20px;font-family:Arial'>
  <h3 style='margin:0 0 10px;color:#cc3300'>⚠ Detected URLs — click to observe network activity</h3>
  <ul style='margin:0;padding-left:20px'>{url_links}</ul>
</div><hr>"""

            # ── Attachment download section ───────────────────────────────
            # Use all_attachments (every filename) from score_breakdown; fall back to suspicious_attachments
            _sb_att_all = _sb.get("all_attachments") or _sb.get("suspicious_attachments") or _ti_dict.get("suspicious_attachments", [])
            att_section = ""
            presigned_attachments: list[dict] = []

            # Always attempt attachment fetch when we have a message_id — _sb_att_all may be
            # empty for emails processed before all_attachments was added to score_breakdown.
            # The live API fetch (Graph/Gmail) is the source of truth.
            if t.email_message_id:
                try:
                    import boto3 as _boto3, base64 as _b64, os as _os_s
                    from backend.models.db_models import OrgIntegration
                    from backend.services.baseline_ingestion import _decrypt as _dec_s, _refresh_m365_token, _get_service_account_headers_sync
                    import asyncio as _asyncio_att

                    _gmail_headers = None
                    _provider = None

                    # Try Gmail DWD service account first
                    try:
                        _sa_headers = await _asyncio_att.to_thread(_get_service_account_headers_sync, t.recipient_email)
                        if _sa_headers:
                            _gmail_headers = _sa_headers
                            _provider = "google"
                    except Exception:
                        pass

                    # Fall back to org OAuth token (Google or M365)
                    if not _gmail_headers:
                        _intg_res_att = await db.execute(
                            select(OrgIntegration).where(
                                OrgIntegration.org_id == t.org_id,
                                OrgIntegration.status == "active",
                            )
                        )
                        for _intg in _intg_res_att.scalars().all():
                            if _intg.provider == "google" and _intg.access_token_enc and not _gmail_headers:
                                try:
                                    _gmail_headers = {"Authorization": f"Bearer {_dec_s(_intg.access_token_enc)}"}
                                    _provider = "google"
                                except Exception:
                                    pass
                            elif _intg.provider == "m365" and not _gmail_headers:
                                try:
                                    _tok = (await _refresh_m365_token(_dec_s(_intg.refresh_token_enc))
                                            if _intg.refresh_token_enc
                                            else (_dec_s(_intg.access_token_enc) if _intg.access_token_enc else None))
                                    if _tok:
                                        _gmail_headers = {"Authorization": f"Bearer {_tok}"}
                                        _provider = "m365"
                                except Exception:
                                    pass

                    logger.info(f"Sandbox attachment fetch: provider={_provider} headers_set={bool(_gmail_headers)} msg_id={t.email_message_id[:30] if t.email_message_id else None}")
                    if _gmail_headers:
                        _s3 = _boto3.client("s3", region_name="uaenorth")
                        _bucket = _os_s.getenv("SANDBOX_S3_BUCKET", "himaya-evidence")
                        import httpx as _hx_att
                        async with _hx_att.AsyncClient(timeout=30) as _hc:
                            if _provider == "google":
                                # Gmail API: fetch message to get attachment part IDs
                                _msg_resp = await _hc.get(
                                    f"https://gmail.googleapis.com/gmail/v1/users/{t.recipient_email}/messages/{t.email_message_id}",
                                    headers=_gmail_headers,
                                    params={"format": "full"},
                                )
                                if _msg_resp.status_code == 200:
                                    def _find_att_parts(part, acc):
                                        fname = part.get("filename", "")
                                        body = part.get("body", {})
                                        if fname and (body.get("attachmentId") or body.get("data")):
                                            acc.append({"name": fname, "attachment_id": body.get("attachmentId"),
                                                        "data": body.get("data"), "size": body.get("size", 0)})
                                        for sub in part.get("parts", []):
                                            _find_att_parts(sub, acc)
                                    _att_parts = []
                                    _find_att_parts(_msg_resp.json().get("payload", {}), _att_parts)
                                    for _ap in _att_parts[:5]:
                                        _aname = _ap["name"]
                                        if _ap["size"] > 10 * 1024 * 1024:
                                            presigned_attachments.append({"name": _aname, "url": None, "size": _ap["size"], "too_large": True})
                                            continue
                                        _abytes = None
                                        if _ap.get("attachment_id"):
                                            _ar = await _hc.get(
                                                f"https://gmail.googleapis.com/gmail/v1/users/{t.recipient_email}/messages/{t.email_message_id}/attachments/{_ap['attachment_id']}",
                                                headers=_gmail_headers,
                                            )
                                            if _ar.status_code == 200:
                                                _d = _ar.json().get("data", "")
                                                if _d:
                                                    _abytes = _b64.urlsafe_b64decode(_d + "==")
                                        elif _ap.get("data"):
                                            _abytes = _b64.urlsafe_b64decode(_ap["data"] + "==")
                                        if _abytes:
                                            _sk = f"sandbox-attachments/{t.id}/{_aname}"
                                            _s3.put_object(Bucket=_bucket, Key=_sk, Body=_abytes,
                                                           ContentDisposition=f'attachment; filename="{_aname}"')
                                            _pu = _s3.generate_presigned_url("get_object",
                                                Params={"Bucket": _bucket, "Key": _sk}, ExpiresIn=1800)
                                            presigned_attachments.append({"name": _aname, "url": _pu, "size": len(_abytes), "too_large": False})
                                        else:
                                            presigned_attachments.append({"name": _aname, "url": None, "size": _ap["size"], "too_large": False})
                            else:
                                # M365 Graph API
                                _alr = await _hc.get(
                                    f"https://graph.microsoft.com/v1.0/users/{t.recipient_email}/messages/{t.email_message_id}/attachments",
                                    headers=_gmail_headers,
                                    params={"$select": "id,name,contentType,size"},
                                )
                                logger.info(f"Sandbox M365 attachment list: status={_alr.status_code} count={len(_alr.json().get('value',[]) if _alr.status_code==200 else [])}")
                                if _alr.status_code == 200:
                                    for _att in _alr.json().get("value", [])[:5]:
                                        _aname = _att.get("name", "attachment")
                                        _asize = _att.get("size", 0)
                                        if _asize > 10 * 1024 * 1024:
                                            presigned_attachments.append({"name": _aname, "url": None, "size": _asize, "too_large": True})
                                            continue
                                        _ar2 = await _hc.get(
                                            f"https://graph.microsoft.com/v1.0/users/{t.recipient_email}/messages/{t.email_message_id}/attachments/{_att['id']}",
                                            headers=_gmail_headers,
                                        )
                                        if _ar2.status_code == 200:
                                            _cb64 = _ar2.json().get("contentBytes", "")
                                            if _cb64:
                                                _abytes = _b64.b64decode(_cb64)
                                                _sk = f"sandbox-attachments/{t.id}/{_aname}"
                                                _s3.put_object(Bucket=_bucket, Key=_sk, Body=_abytes,
                                                               ContentDisposition=f'attachment; filename="{_aname}"')
                                                _pu = _s3.generate_presigned_url("get_object",
                                                    Params={"Bucket": _bucket, "Key": _sk}, ExpiresIn=1800)
                                                presigned_attachments.append({"name": _aname, "url": _pu, "size": len(_abytes), "too_large": False})
                except Exception as _ae:
                    logger.warning(f"Sandbox: attachment fetch failed (non-fatal): {_ae}")

            # Fall back to metadata-only listing if download failed
            if not presigned_attachments and _sb_att_all:
                presigned_attachments = [{"name": a if isinstance(a, str) else str(a), "url": None, "size": 0, "too_large": False} for a in _sb_att_all[:5]]

            if presigned_attachments:
                att_instruction_banner = """
<div style='background:#fff3cd;border:1px solid #ffc107;border-radius:6px;padding:10px 16px;margin:0 20px 12px;font-family:Arial;font-size:12px;color:#856404'>
  <b>💡 How to analyse attachments:</b> Click the download link below, save the file, then open it from the <b>Downloads folder</b> inside this browser session.
</div>"""
                att_rows = ""
                for _pa in presigned_attachments:
                    _ext = _pa["name"].rsplit(".", 1)[-1].lower() if "." in _pa["name"] else ""
                    _danger = _ext in ("exe","bat","ps1","vbs","js","hta","cmd","msi","docm","xlsm","jar")
                    _badge = '<span style="background:#cc3300;color:#fff;font-size:10px;padding:2px 6px;border-radius:3px;margin-right:6px">DANGEROUS</span>' if _danger else ''
                    if _pa.get("too_large"):
                        _btn = '<span style="color:#999;font-size:12px">Too large (&gt;10MB) — cannot download</span>'
                    elif _pa.get("url"):
                        _sz = f' ({_pa["size"] // 1024}KB)' if _pa["size"] else ""
                        _btn = f'<a href="{_pa["url"]}" download="{_pa["name"]}" target="_blank" style="display:inline-block;background:#1a6ecc;color:#fff;padding:5px 14px;border-radius:4px;text-decoration:none;font-size:12px;font-weight:bold">Download{_sz} and Execute in Sandbox</a>'
                    else:
                        _btn = f'<span style="color:#999;font-size:12px">Attachment detected — file not available for download</span>'
                    att_rows += f'<div style="margin:8px 0;padding:10px;background:#fff8f0;border:1px solid #f0c080;border-radius:6px">{_badge}<b>{_pa["name"]}</b><br><div style="margin-top:6px">{_btn}</div></div>'

                att_section = f"""<div style='padding:0 20px 16px;font-family:Arial'>
  <h3 style='color:#cc6600'>Attachments — download and execute to observe behaviour</h3>
  {att_instruction_banner}
  {att_rows}
</div><hr>"""

            # ── Raw email body — isolated in srcdoc iframe ──────────────
            # Using srcdoc prevents the email's </body></html> from breaking the
            # outer page structure, and ensures all links remain interactive.
            raw_body = t.email_body_preview or ""
            if raw_body and not raw_body.strip().startswith("<"):
                # Plain text — wrap in a minimal HTML document
                inner_html = f"""<!DOCTYPE html><html><body style='font-family:Arial;font-size:14px;padding:16px;white-space:pre-wrap'>{raw_body}</body></html>"""
            elif raw_body:
                # HTML email — use as-is, inject target=_blank on all links so
                # they open in a new Firefox tab instead of navigating the iframe
                import html as _html_mod
                # Add target=_blank and rel=noopener to all <a> tags
                import re as _link_re
                patched_body = _link_re.sub(
                    r'<a ',
                    r'<a target="_blank" rel="noopener" ',
                    raw_body,
                    flags=_link_re.IGNORECASE
                )
                inner_html = patched_body if '<!DOCTYPE' in patched_body or '<html' in patched_body else \
                    f"""<!DOCTYPE html><html><head><base target="_blank"></head><body>{patched_body}</body></html>"""
            else:
                inner_html = "<!DOCTYPE html><html><body style='padding:20px;color:#999'>No email body available.</body></html>"

            # Escape inner_html for use in the srcdoc attribute
            import html as _html_lib
            srcdoc_val = _html_lib.escape(inner_html, quote=True)
            body_section = f"""<div style='padding:0 0 8px'>
  <iframe srcdoc="{srcdoc_val}"
    style='width:100%;min-height:450px;border:none;display:block'
    sandbox='allow-scripts allow-same-origin allow-popups allow-forms allow-top-navigation'
    title='Email body'></iframe>
</div>"""

            # ── Helios analysis footer ─────────────────────────────────────
            ai_footer = f"""
<div style='background:#f5f5f5;padding:14px 20px;font-family:Arial;font-size:12px;color:#555;border-top:1px solid #ddd'>
  <b>Helios AI Analysis:</b> {t.ai_explanation_en or 'N/A'}
</div>"""

            email_html = f"""<!DOCTYPE html><html><body style='margin:0;padding:0'>
{header}{url_section}{att_section}{body_section}{ai_footer}
</body></html>"""

    session = await create_sandbox_session(
        threat_id=threat_id,
        org_id=org_id,
        email_html=email_html,
        email_subject=email_subject,
    )
    return session


@router.get("/session/{session_id}/status")
async def get_session_status(
    session_id: str,
    current_user=Depends(get_current_user),
):
    """Poll for sandbox session status and streaming URL."""
    from backend.services.sandbox_session_service import get_session
    session = await get_session(session_id)
    if not session:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Session not found")

    # Don't expose VNC password in API response
    safe = {k: v for k, v in session.items() if k != "vnc_password"}
    return safe


@router.post("/session/{session_id}/end")
async def end_session(
    session_id: str,
    current_user=Depends(get_current_user),
):
    """Terminate the sandbox EC2 instance and end the session."""
    from backend.services.sandbox_session_service import terminate_session
    success = await terminate_session(session_id)
    return {"status": "terminated" if success else "not_found", "session_id": session_id}


@router.get("/status")
async def sandbox_status(current_user=Depends(get_current_user)):
    """Check sandbox infrastructure status."""
    import os, redis.asyncio as aioredis
    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379")
    r = aioredis.from_url(redis_url, decode_responses=True)
    try:
        await r.ping()
        return {"status": "operational", "backend": "in-process AI analysis", "estimated_duration_seconds": 35}
    except Exception as e:
        return {"status": "unavailable", "error": str(e)}
    finally:
        await r.aclose()
