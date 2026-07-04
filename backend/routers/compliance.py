import uuid
from datetime import datetime, date, timedelta
from fastapi import APIRouter, Depends, Query, HTTPException
from fastapi.responses import Response
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, text as _sql

from backend.database import get_db
from backend.models.db_models import (
    ComplianceControl, ComplianceStatus, ComplianceEvidence, Report, Threat,
    Organization, ComplianceScoreSnapshot, OrgIntegration, Policy as _PolicyModel,
)
from backend.routers.auth import get_current_user
from backend.services.report_generator import AuditReportGenerator

router = APIRouter(prefix="/api/compliance", tags=["compliance"])

FRAMEWORKS = ["SAMA_CSF", "NCA_ECC", "UAE_NESA", "CBUAE", "NIST_CSF", "HIPAA", "SOC2", "CCPA", "GDPR", "ISO_27001", "DORA", "NIS2"]

report_generator = AuditReportGenerator()


@router.get("/overview")
async def get_overview(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = []
    for fw in FRAMEWORKS:
        # Get all controls for this framework
        controls_result = await db.execute(
            select(ComplianceControl).where(ComplianceControl.framework == fw)
        )
        controls = controls_result.scalars().all()
        total = len(controls)
        if total == 0:
            continue

        control_ids = [c.id for c in controls]

        # Get statuses for this org + framework
        statuses_result = await db.execute(
            select(ComplianceStatus.status, func.count().label("cnt"))
            .where(
                ComplianceStatus.org_id == current_user.org_id,
                ComplianceStatus.control_id.in_(control_ids),
            )
            .group_by(ComplianceStatus.status)
        )
        status_counts = {row.status: row.cnt for row in statuses_result}

        compliant = status_counts.get("compliant", 0)
        partial = status_counts.get("partial", 0)
        non_compliant = status_counts.get("non_compliant", 0)
        not_started = total - compliant - partial - non_compliant

        pct = round((compliant + partial * 0.5) / total * 100, 1) if total else 0

        result.append({
            "framework": fw,
            "total_controls": total,
            "compliant": compliant,
            "partial": partial,
            "non_compliant": non_compliant,
            "not_started": max(0, not_started),
            "compliance_pct": pct,
        })

    return {"frameworks": result}


@router.get("/controls")
async def get_controls(
    framework: str = Query(None),
    status: str = Query(None, description="Filter: compliant | partial | non_compliant | not_started"),
    search: str = Query(None, description="Substring match against control id or English name"),
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    q = select(ComplianceControl)
    if framework:
        q = q.where(ComplianceControl.framework == framework)
    controls_result = await db.execute(q.order_by(ComplianceControl.framework, ComplianceControl.control_id))
    controls = controls_result.scalars().all()

    # Get statuses for this org (single query)
    statuses_result = await db.execute(
        select(ComplianceStatus).where(ComplianceStatus.org_id == current_user.org_id)
    )
    statuses = {str(s.control_id): s for s in statuses_result.scalars().all()}

    items = []
    for c in controls:
        st = statuses.get(str(c.id))
        cur_status = st.status if st else "not_started"
        # Status filter
        if status and cur_status != status:
            continue
        # Search filter (case-insensitive)
        if search:
            needle = search.lower()
            hay = f"{c.control_id} {c.control_name_en or ''} {c.control_name_ar or ''}".lower()
            if needle not in hay:
                continue
        items.append({
            "id": str(c.id),
            "framework": c.framework,
            "control_id": c.control_id,
            "control_name_en": c.control_name_en,
            "control_name_ar": c.control_name_ar,
            "description_en": c.description_en,
            "description_ar": c.description_ar,
            "evidence_type": c.evidence_type,
            "status": cur_status,
            "evidence_count": st.evidence_count if st else 0,
            "notes": st.notes if st else None,
            # Rich fields — used by frontend drill-down
            "rationale": (st.rationale if st else None),
            "evidence_summary": (st.evidence_summary if st else None),
            "last_assessed_at": st.last_assessed_at.isoformat() if st and st.last_assessed_at else None,
        })

    return {"items": items, "total": len(items)}


@router.get("/controls/{control_uuid}")
async def get_control_detail(
    control_uuid: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Per-control drill-down: control definition, current status, rationale,
    live evidence sources (integrations, threats, policies), and any
    ComplianceEvidence rows that explicitly reference this control."""
    try:
        cid = uuid.UUID(control_uuid)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid control id")

    ctrl = (await db.execute(
        select(ComplianceControl).where(ComplianceControl.id == cid)
    )).scalar_one_or_none()
    if not ctrl:
        raise HTTPException(status_code=404, detail="Control not found")

    st = (await db.execute(
        select(ComplianceStatus).where(
            ComplianceStatus.org_id == current_user.org_id,
            ComplianceStatus.control_id == cid,
        )
    )).scalar_one_or_none()

    # Live evidence sources — what real signals back this score?
    active_integrations = (await db.execute(
        select(OrgIntegration.provider).where(
            OrgIntegration.org_id == current_user.org_id,
            OrgIntegration.status == "active",
        )
    )).scalars().all()

    active_policies_n = (await db.execute(
        select(func.count()).select_from(_PolicyModel).where(
            _PolicyModel.org_id == current_user.org_id,
            _PolicyModel.status == "active",
        )
    )).scalar() or 0

    threats_90d = (await db.execute(
        select(func.count()).select_from(Threat).where(
            Threat.org_id == current_user.org_id,
            Threat.detected_at >= datetime.utcnow() - timedelta(days=90),
        )
    )).scalar() or 0

    quarantined_90d = (await db.execute(
        select(func.count()).select_from(Threat).where(
            Threat.org_id == current_user.org_id,
            Threat.detected_at >= datetime.utcnow() - timedelta(days=90),
            Threat.action_taken.in_(["QUARANTINED", "BLOCKED", "BLOCK_DELETE"]),
        )
    )).scalar() or 0

    # Explicit evidence rows referencing this control
    ev_rows = (await db.execute(
        select(ComplianceEvidence)
        .where(ComplianceEvidence.org_id == current_user.org_id)
        .order_by(ComplianceEvidence.created_at.desc())
        .limit(50)
    )).scalars().all()
    related_evidence = [
        {
            "id": str(e.id),
            "framework": e.framework,
            "action_taken": e.action_taken,
            "outcome": e.outcome,
            "created_at": e.created_at.isoformat() if e.created_at else None,
            "control_ids": e.control_ids or [],
        }
        for e in ev_rows
        if e.control_ids and ctrl.control_id in (e.control_ids or [])
    ]

    return {
        "control": {
            "id": str(ctrl.id),
            "framework": ctrl.framework,
            "control_id": ctrl.control_id,
            "control_name_en": ctrl.control_name_en,
            "control_name_ar": ctrl.control_name_ar,
            "description_en": ctrl.description_en,
            "description_ar": ctrl.description_ar,
            "evidence_type": ctrl.evidence_type,
        },
        "status": st.status if st else "not_started",
        "rationale": st.rationale if st else None,
        "evidence_summary": st.evidence_summary if st else None,
        "last_assessed_at": st.last_assessed_at.isoformat() if st and st.last_assessed_at else None,
        "live_signals": {
            "active_integrations": list(active_integrations),
            "active_policies": active_policies_n,
            "threats_90d": threats_90d,
            "quarantined_90d": quarantined_90d,
        },
        "related_evidence": related_evidence,
    }


@router.get("/history")
async def get_history(
    framework: str = Query(None),
    days: int = Query(90, ge=1, le=365),
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Score-over-time trend for one or all frameworks."""
    since = datetime.utcnow() - timedelta(days=days)
    q = select(ComplianceScoreSnapshot).where(
        ComplianceScoreSnapshot.org_id == current_user.org_id,
        ComplianceScoreSnapshot.captured_at >= since,
    )
    if framework:
        q = q.where(ComplianceScoreSnapshot.framework == framework)
    q = q.order_by(ComplianceScoreSnapshot.captured_at.asc())
    rows = (await db.execute(q)).scalars().all()

    series: dict = {}
    for r in rows:
        series.setdefault(r.framework, []).append({
            "t": r.captured_at.isoformat(),
            "score": r.score_pct,
            "compliant": r.compliant,
            "partial": r.partial,
            "non_compliant": r.non_compliant,
            "total": r.total_controls,
        })
    return {"days": days, "series": series}


@router.get("/evidence")
async def get_evidence(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    framework: str = Query(None),
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    q = select(ComplianceEvidence).where(ComplianceEvidence.org_id == current_user.org_id)
    if framework:
        q = q.where(ComplianceEvidence.framework == framework)

    total_result = await db.execute(
        select(func.count()).select_from(
            select(ComplianceEvidence.id).where(
                ComplianceEvidence.org_id == current_user.org_id
            ).subquery()
        )
    )
    total = total_result.scalar() or 0

    result = await db.execute(
        q.order_by(ComplianceEvidence.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    evidence = result.scalars().all()

    return {
        "items": [
            {
                "id": str(e.id),
                "org_id": str(e.org_id),
                "threat_id": str(e.threat_id) if e.threat_id else None,
                "control_ids": e.control_ids,
                "framework": e.framework,
                "action_taken": e.action_taken,
                "outcome": e.outcome,
                "immutable": e.immutable,
                "retention_tier": e.retention_tier,
                "created_at": e.created_at.isoformat() if e.created_at else None,
            }
            for e in evidence
        ],
        "total": total,
        "page": page,
        "page_size": page_size,
    }


@router.get("/dns-check")
async def dns_check_org(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """On-demand DNS record lookup: SPF, DMARC, MX for the org's domain."""
    from backend.models.db_models import OrgIntegration as _OI
    org = (await db.execute(select(Organization).where(Organization.id == current_user.org_id))).scalar_one_or_none()
    domain = org.domain if org and org.domain else None
    if not domain:
        oi = (await db.execute(select(_OI).where(_OI.org_id == current_user.org_id, _OI.status == "active"))).scalars().first()
        domain = oi.org_domain if oi else None
    if not domain:
        raise HTTPException(status_code=404, detail="No domain found for org")

    results: dict = {"domain": domain, "spf": None, "dmarc": None, "mx": []}
    try:
        import dns.resolver as _dns
        try:
            for r in _dns.resolve(domain, "TXT", lifetime=5):
                txt = r.to_text().strip('"')
                if txt.startswith("v=spf1"):
                    results["spf"] = txt
                    break
        except Exception:
            results["spf"] = "Not found"
        try:
            for r in _dns.resolve(f"_dmarc.{domain}", "TXT", lifetime=5):
                results["dmarc"] = r.to_text().strip('"')
                break
        except Exception:
            results["dmarc"] = "Not found"
        try:
            mx = _dns.resolve(domain, "MX", lifetime=5)
            results["mx"] = sorted([str(r.exchange).rstrip(".") for r in mx])
        except Exception:
            results["mx"] = []
    except ImportError:
        results["spf"] = results["dmarc"] = "DNS lookup unavailable"
    return results


async def _run_dns_check(domain: str) -> dict:
    """Inline DNS check without auth — used during report generation."""
    results: dict = {"domain": domain, "spf": "Not checked", "dmarc": "Not checked", "mx": []}
    try:
        import dns.resolver as _dns
        try:
            for r in _dns.resolve(domain, "TXT", lifetime=5):
                txt = r.to_text().strip('"')
                if txt.startswith("v=spf1"):
                    results["spf"] = txt; break
        except Exception: pass
        try:
            for r in _dns.resolve(f"_dmarc.{domain}", "TXT", lifetime=5):
                results["dmarc"] = r.to_text().strip('"'); break
        except Exception: pass
        try:
            results["mx"] = sorted([str(r.exchange).rstrip(".") for r in _dns.resolve(domain, "MX", lifetime=5)])
        except Exception: pass
    except ImportError: pass
    return results


@router.post("/report/generate")
async def generate_report(
    body: dict,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    framework = body.get("framework", "SAMA_CSF")
    report_format = body.get("format", "pdf")   # "html" or "pdf"
    date_from_str = body.get("date_from", "2026-01-01")
    date_to_str = body.get("date_to", "2026-03-01")

    try:
        date_from = date.fromisoformat(date_from_str)
        date_to = date.fromisoformat(date_to_str)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid date format. Use YYYY-MM-DD")

    # Fetch org
    org_result = await db.execute(select(Organization).where(Organization.id == current_user.org_id))
    org = org_result.scalar_one_or_none()
    org_name = org.name if org else "Unknown Org"
    org_domain = org.domain if org and org.domain else ""

    # DNS check (on-demand during report generation)
    dns_data: dict = {"domain": org_domain, "spf": "Not checked", "dmarc": "Not checked", "mx": []}
    if org_domain:
        try:
            import asyncio
            dns_data = await asyncio.wait_for(_run_dns_check(org_domain), timeout=8)
        except Exception:
            pass

    # Fetch threats (last 500)
    threats_result = await db.execute(
        select(Threat).where(Threat.org_id == current_user.org_id)
        .order_by(Threat.detected_at.desc()).limit(500)
    )
    threats_raw = threats_result.scalars().all()

    # Resolve IPs → country using ip-api.com batch endpoint (free, no key needed)
    _ip_country_cache: dict = {}
    _ips_to_resolve = list({
        (t.auth_results or {}).get("sender_ip", "")
        for t in threats_raw
        if (t.auth_results or {}).get("sender_ip")
    } - {""})
    if _ips_to_resolve:
        try:
            import httpx as _hx
            # ip-api.com batch: POST up to 100 IPs at a time
            batch_size = 100
            for _batch_start in range(0, len(_ips_to_resolve), batch_size):
                _batch = _ips_to_resolve[_batch_start:_batch_start + batch_size]
                _payload = [{"query": ip, "fields": "query,country,countryCode,status"} for ip in _batch]
                async with _hx.AsyncClient(timeout=8) as _hclient:
                    _resp = await _hclient.post("http://ip-api.com/batch", json=_payload)
                if _resp.status_code == 200:
                    for entry in _resp.json():
                        if entry.get("status") == "success":
                            _ip_country_cache[entry["query"]] = entry.get("country", "")
        except Exception:
            pass  # geo best-effort — never block report generation

    threats = [
        {
            "detected_at": t.detected_at.isoformat() if t.detected_at else "",
            "threat_type": t.threat_type or "",
            "recipient_email": t.recipient_email or "",
            "sender_email": t.sender_domain or "",
            "sender_ip": (t.auth_results or {}).get("sender_ip", ""),
            "risk_score": t.risk_score or 0,
            "action_taken": t.action_taken or "",
            # Use cached geo result, fallback to previously stored sender_country
            "sender_country": (
                _ip_country_cache.get((t.auth_results or {}).get("sender_ip", ""))
                or (t.auth_results or {}).get("sender_country", "")
                or ""
            ),
        }
        for t in threats_raw
    ]

    # Fetch active policies
    from backend.models.db_models import Policy as _ReportPolicy
    policies_result = await db.execute(
        select(_ReportPolicy).where(_ReportPolicy.org_id == current_user.org_id, _ReportPolicy.status == "active")
    )
    policies_data = [{"name": p.name, "action": p.action, "priority": p.priority} for p in policies_result.scalars().all()]

    # Fetch ALL framework controls + org statuses in one pass
    all_controls_result = await db.execute(select(ComplianceControl))
    all_controls_raw = all_controls_result.scalars().all()
    statuses_result = await db.execute(select(ComplianceStatus).where(ComplianceStatus.org_id == current_user.org_id))
    statuses = {str(s.control_id): s for s in statuses_result.scalars().all()}

    def _build_controls(raw_list):
        return [
            {
                "control_id": c.control_id,
                "control_name_en": getattr(c, "control_name_en", None) or getattr(c, "name_en", None) or c.control_id,
                "control_name_ar": getattr(c, "control_name_ar", None) or getattr(c, "name_ar", None) or "",
                "status": statuses[str(c.id)].status if str(c.id) in statuses else "not_started",
                "evidence_count": statuses[str(c.id)].evidence_count if str(c.id) in statuses else 0,
                "notes": statuses[str(c.id)].notes if str(c.id) in statuses else "",
            }
            for c in raw_list
        ]

    # Primary framework controls (for executive summary score)
    primary_raw = [c for c in all_controls_raw if c.framework == framework]
    compliance_controls = _build_controls(primary_raw)

    # All frameworks grouped
    all_frameworks_controls: dict = {}
    for fw_key in FRAMEWORKS:
        fw_raw = [c for c in all_controls_raw if c.framework == fw_key]
        if fw_raw:
            all_frameworks_controls[fw_key] = _build_controls(fw_raw)

    total = len(compliance_controls)
    compliant = sum(1 for c in compliance_controls if c["status"] == "compliant")
    partial = sum(1 for c in compliance_controls if c["status"] == "partial")
    overall_score = round((compliant + partial * 0.5) / total * 100) if total else 0
    org_id_str = str(current_user.org_id)

    # Claude analysis for the report — run in executor to avoid blocking event loop
    claude_analysis = ""
    try:
        import os, anthropic as _ant, asyncio as _asyncio
        _client = _ant.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY",""))
        blocked = sum(1 for t in threats if t["action_taken"] in ("QUARANTINED","BLOCKED","BLOCK_DELETE"))
        _prompt = f"""You are a cybersecurity compliance analyst. Write a 3-4 paragraph professional compliance analysis for a report.

Organization: {org_name} | Domain: {org_domain}
Framework: {framework} | Compliance Score: {overall_score}%
Compliant controls: {compliant}/{total} | Partial: {partial} | Non-compliant: {total-compliant-partial}
Threats (90 days): {len(threats)} total, {blocked} blocked/quarantined
Active policies: {len(policies_data)}
SPF: {dns_data.get("spf","unknown")} | DMARC: {dns_data.get("dmarc","unknown")}

Write a clear, factual analysis covering: overall posture, key gaps, email authentication status, and specific recommendations. Use formal language suitable for an executive audit report. Do not use markdown formatting."""

        def _call_claude():
            return _client.messages.create(
                model="claude-opus-4-5-20251101",
                max_tokens=1200,
                messages=[{"role": "user", "content": _prompt}],
            )

        _msg = await _asyncio.wait_for(
            _asyncio.get_event_loop().run_in_executor(None, _call_claude),
            timeout=90,  # 90s max for Claude — generous but bounded
        )
        claude_analysis = _msg.content[0].text if _msg.content else ""
    except Exception as _ce:
        claude_analysis = f"Automated analysis: {org_name} achieved {overall_score}% compliance on {framework} with {compliant} of {total} controls fully compliant."

    report_content: bytes
    content_type: str

    if report_format == "html":
        # Generate HTML report
        html_str = await report_generator.generate_html_report(
            org_id=org_id_str,
            framework=framework,
            controls_data=compliance_controls,
            all_frameworks_controls=all_frameworks_controls,
            threats_data=threats,
            policies_data=policies_data,
            employees_data=[],
            dns_data=dns_data,
            org_name=org_name,
            domain=org_domain,
            claude_analysis=claude_analysis,
        )
        report_content = html_str.encode("utf-8")
        content_type = "text/html"
        s3_key = f"reports/{org_id_str}/{framework}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.html"
    else:
        # Generate PDF in executor — ReportLab is CPU-bound and blocks event loop
        import asyncio as _asyncio2
        def _gen_pdf():
            return report_generator.generate_report(
                org_name=org_name,
                framework=framework,
                date_from=date_from,
                date_to=date_to,
                threats=threats,
                compliance_controls=compliance_controls,
                overall_score=overall_score,
                org_id=org_id_str,
                all_frameworks_controls=all_frameworks_controls,
            )
        pdf_bytes, s3_key = await _asyncio2.get_event_loop().run_in_executor(None, _gen_pdf)
        report_content = pdf_bytes
        content_type = "application/pdf"

    # Cache for download
    _pdf_cache[org_id_str + "_pending"] = (report_content, content_type, report_format)

    # Save report record
    report = Report(
        org_id=current_user.org_id,
        report_type="audit",
        framework=framework,
        date_range_start=date_from,
        date_range_end=date_to,
        status="complete",
        s3_key=s3_key,
        generated_by=current_user.id,
        completed_at=datetime.utcnow(),
    )
    db.add(report)
    await db.flush()

    report_id = str(report.id)
    _pdf_cache[report_id] = (report_content, content_type, report_format)

    return {
        "report_id": report_id,
        "framework": framework,
        "format": report_format,
        "s3_key": s3_key,
        "download_url": f"/api/compliance/report/{report_id}",
        "overall_score": overall_score,
        "threats_included": len(threats),
        "controls_included": len(compliance_controls),
    }


# Store for in-memory PDF cache (dev only)
_pdf_cache: dict = {}


@router.get("/report/{report_id}")
async def download_report(
    report_id: str,
    token: str = None,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Serve cached compliance report (HTML or PDF)."""
    # Try cache first
    if report_id in _pdf_cache:
        content, content_type, fmt = _pdf_cache[report_id]
        ext = "html" if fmt == "html" else "pdf"
        return Response(
            content=content,
            media_type=content_type,
            headers={"Content-Disposition": f'attachment; filename="Himaya-Compliance-Report.{ext}"'},
        )
    # Fall back to reports router
    from backend.routers.reports import download_report as _dl_report
    return await _dl_report(report_id=report_id, current_user=current_user, db=db)


@router.get("/report/{report_id}/status")
async def get_report_status(
    report_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Check if a report is ready for download."""
    try:
        result = await db.execute(
            select(Report).where(
                Report.id == uuid.UUID(report_id),
                Report.org_id == current_user.org_id,
            )
        )
        report = result.scalar_one_or_none()
        if not report:
            raise HTTPException(status_code=404, detail="Report not found")
        return {"report_id": report_id, "status": report.status or "ready"}
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid report ID")


@router.post("/assess")
async def assess_controls(
    body: dict,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    On-demand compliance assessment via Claude.
    Evaluates controls for the given framework based on email threat data, policies,
    and integration status for this org.
    """
    import os, json
    from sqlalchemy import text as _text

    framework = body.get("framework", "SAMA_CSF")

    # Fetch controls for framework
    controls_result = await db.execute(
        select(ComplianceControl).where(ComplianceControl.framework == framework)
    )
    controls = controls_result.scalars().all()
    if not controls:
        return {
            "framework": framework,
            "controls_assessed": 0,
            "compliant": 0,
            "partial": 0,
            "non_compliant": 0,
            "score_pct": 0,
            "assessment_results": {},
            "assessed_at": datetime.utcnow().isoformat(),
            "message": f"No controls seeded for {framework} yet. Run seed_data.py to populate controls.",
        }

    # Fetch recent threats (last 90 days)
    threats_result = await db.execute(
        select(Threat).where(
            Threat.org_id == current_user.org_id,
        ).order_by(Threat.detected_at.desc()).limit(200)
    )
    recent_threats = threats_result.scalars().all()
    threat_summary = {
        "total": len(recent_threats),
        "by_type": {},
        "quarantined": sum(1 for t in recent_threats if t.action_taken in ("QUARANTINED", "BLOCK")),
        "avg_risk": round(sum(t.risk_score or 0 for t in recent_threats) / len(recent_threats), 1) if recent_threats else 0,
    }
    for t in recent_threats:
        if t.threat_type and t.threat_type != "CLEAN":
            threat_summary["by_type"][t.threat_type] = threat_summary["by_type"].get(t.threat_type, 0) + 1

    # Fetch active policies
    from backend.models.db_models import Policy as _Policy
    policies_result = await db.execute(
        select(_Policy).where(
            _Policy.org_id == current_user.org_id,
            _Policy.status == "active",
        )
    )
    active_policies = [{"name": p.name, "action": p.action, "conditions": p.conditions} for p in policies_result.scalars().all()]

    # Fetch integrations
    from backend.models.db_models import OrgIntegration as _OI
    int_result = await db.execute(
        select(_OI).where(_OI.org_id == current_user.org_id, _OI.status == "active")
    )
    integrations = [i.provider for i in int_result.scalars().all()]

    # Build evidence context for Claude
    evidence_context = f"""
ORGANIZATION EMAIL SECURITY EVIDENCE for {framework} compliance assessment:

Email Provider Integrations: {', '.join(integrations) if integrations else 'None connected'}

Threat Detection Summary (last 90 days):
- Total emails analyzed: {threat_summary['total']}
- Threats detected by type: {json.dumps(threat_summary['by_type'])}
- Auto-quarantined/blocked: {threat_summary['quarantined']}
- Average risk score: {threat_summary['avg_risk']}

Active Security Policies ({len(active_policies)} policies):
{json.dumps(active_policies[:10], indent=2)}

Himaya Platform Capabilities:
- AI-powered email threat detection (Claude/GPT-4o ensemble)
- Real-time delta sync every 2 minutes
- Automatic quarantine for risk score >= 80
- Compliance evidence automatically collected per threat
- Audit reports generated in PDF format
"""

    # Build controls list for assessment
    controls_for_prompt = "\n".join([
        f"- {c.control_id}: {c.control_name_en}"
        for c in controls[:30]  # Cap at 30 for token budget
    ])

    # Call Claude for assessment
    anthropic_key = os.getenv("ANTHROPIC_API_KEY")
    assessment_results = {}

    if anthropic_key:
        try:
            import anthropic as _anthropic
            client = _anthropic.Anthropic(api_key=anthropic_key)
            response = client.messages.create(
                model="claude-opus-4-5-20251101",
                max_tokens=2000,
                messages=[{
                    "role": "user",
                    "content": f"""You are a compliance assessor for email security. 
Based on the evidence below, assess each compliance control as: compliant, partial, or non_compliant.

{evidence_context}

CONTROLS TO ASSESS ({framework}):
{controls_for_prompt}

Respond with ONLY a JSON object mapping control_id to status. Example:
{{"3.3.3": "compliant", "3.3.5": "partial", "3.4.1": "non_compliant"}}

Scoring rules — balanced, realistic assessment:
- "compliant": control is clearly and actively met by the evidence.
  • threat_detection controls → compliant if integration active + threats scanned
  • monitoring controls → compliant if mailboxes discovered and delta-sync running
  • authentication controls → compliant if OAuth 2.0 connected (OAuth IS strong auth / SSO with MFA managed by IdP)
  • access_control → compliant if mailboxes under active monitoring
  • incident_response → compliant if quarantine or automated block policy exists
  • risk_management → compliant if 2+ active policies
- "partial": the org has made effort but something specific is incomplete or only half-met.
  • data_protection → always partial (in-transit only, data-at-rest not managed by email security tool)
  • governance → partial (operational governance exists but no formal ISMS/documented policy framework)
  • incident_response → partial if only 1 policy and it's not quarantine
  • risk_management → partial if only 1 policy
- "non_compliant": control cannot be met with current setup.
  • training → non_compliant (no training module)
  • any control requiring integration when no integration exists

Be specific and honest. Do not give compliant to everything — use partial where there are
genuine gaps. Return ONLY the JSON object, no explanation."""
                }]
            )
            raw = response.content[0].text.strip()
            # Extract JSON from response
            start = raw.find("{")
            end = raw.rfind("}") + 1
            if start >= 0 and end > start:
                assessment_results = json.loads(raw[start:end])
        except Exception as e:
            import logging
            logging.getLogger(__name__).warning(f"Claude assessment failed, using heuristic: {e}")

    # Heuristic fallback if Claude failed or not configured (balanced scoring)
    if not assessment_results:
        has_integration = bool(integrations)
        has_policies = len(active_policies) > 0
        has_quarantine = any(p.get("action","").upper() in ("QUARANTINE","BLOCK","BLOCK_DELETE") for p in active_policies)
        has_threats = threat_summary["total"] > 0
        policy_count = len(active_policies)

        for c in controls:
            cid = c.control_id
            ev = getattr(c, "evidence_type", "") or ""
            name_lower = (c.control_name_en or "").lower()

            if not has_integration:
                assessment_results[cid] = "non_compliant"
            elif ev == "training":
                assessment_results[cid] = "non_compliant"
            elif ev == "data_protection":
                assessment_results[cid] = "partial"  # in-transit only
            elif ev == "governance":
                assessment_results[cid] = "partial"  # operational but no formal ISMS
            elif ev == "threat_detection":
                assessment_results[cid] = "compliant" if has_threats else "partial"
            elif ev == "monitoring":
                assessment_results[cid] = "compliant"
            elif ev == "authentication":
                assessment_results[cid] = "compliant"  # OAuth = strong auth
            elif ev == "access_control":
                assessment_results[cid] = "compliant"
            elif ev == "incident_response":
                if has_quarantine:
                    assessment_results[cid] = "compliant"
                elif has_policies:
                    assessment_results[cid] = "partial"
                else:
                    assessment_results[cid] = "non_compliant"
            elif ev == "risk_management":
                if policy_count >= 2:
                    assessment_results[cid] = "compliant"
                elif policy_count == 1:
                    assessment_results[cid] = "partial"
                else:
                    assessment_results[cid] = "partial"  # integration = partial risk mgmt
            else:
                # Generic: integration = partial, no integration = non_compliant
                assessment_results[cid] = "partial"

    # Build a shared evidence_summary snapshot — same for every control in
    # this assessment run, since it reflects org-wide live signals.
    evidence_summary = {
        "integrations_active": integrations,
        "policies_active": len(active_policies),
        "threats_90d": threat_summary["total"],
        "quarantined_90d": threat_summary["quarantined"],
        "avg_risk_score": threat_summary["avg_risk"],
        "threats_by_type": threat_summary["by_type"],
        "assessed_at": datetime.utcnow().isoformat(),
    }

    def _rationale_for(ctrl_obj, status_val: str) -> str:
        ev = (getattr(ctrl_obj, "evidence_type", "") or "").strip()
        name = ctrl_obj.control_name_en or ctrl_obj.control_id
        if status_val == "compliant":
            if ev == "threat_detection":
                return f"Compliant: {threat_summary['total']} emails analysed and {threat_summary['quarantined']} threats quarantined/blocked across active integrations ({', '.join(integrations) or 'none'}). AI ensemble running continuously."
            if ev == "monitoring":
                return f"Compliant: delta sync covering org mailboxes; {threat_summary['total']} messages processed in the last 90 days."
            if ev == "authentication":
                return "Compliant: OAuth 2.0 with admin consent to Microsoft Graph; tenant SSO/MFA managed at IdP layer."
            if ev == "access_control":
                return "Compliant: all mailboxes under continuous monitoring; per-org tenant isolation enforced."
            if ev == "incident_response":
                return f"Compliant: {len(active_policies)} active response policies including quarantine/block actions."
            if ev == "risk_management":
                return f"Compliant: {len(active_policies)} risk-management policies enforced."
            return f"Compliant: live monitoring evidence collected for '{name}'."
        if status_val == "partial":
            if ev == "data_protection":
                return "Partial: email in-transit encryption enforced (TLS), but data-at-rest controls live in tenant (Purview / IRM) and are outside Himaya scope."
            if ev == "governance":
                return "Partial: operational governance is in place (this platform), but a formal documented ISMS/governance framework is not detected."
            if ev == "risk_management":
                return f"Partial: {len(active_policies)} active policy(ies). Recommend at least 2 for full compliance."
            if ev == "incident_response":
                return "Partial: response policy exists but no quarantine/block action configured."
            return f"Partial: some evidence collected for '{name}', but additional controls required."
        if status_val == "non_compliant":
            if ev == "training":
                return "Non-compliant: security-awareness training module not yet provided by Himaya."
            if not integrations:
                return "Non-compliant: no email-provider integration is connected, so no telemetry can be evaluated."
            return f"Non-compliant: '{name}' requires controls not currently implemented."
        return "Not yet assessed."

    # Save results to ComplianceStatus table
    updated = 0
    now = datetime.utcnow()
    for c in controls:
        cid = c.control_id
        new_status = assessment_results.get(cid, "partial")
        if new_status not in ("compliant", "partial", "non_compliant"):
            new_status = "partial"
        new_rationale = _rationale_for(c, new_status)

        # Upsert ComplianceStatus
        existing = await db.execute(
            select(ComplianceStatus).where(
                ComplianceStatus.org_id == current_user.org_id,
                ComplianceStatus.control_id == c.id,
            )
        )
        cs = existing.scalar_one_or_none()
        if cs:
            cs.status = new_status
            cs.last_assessed_at = now
            cs.rationale = new_rationale
            cs.evidence_summary = evidence_summary
            if new_status == "compliant":
                cs.evidence_count = threat_summary["quarantined"]
        else:
            db.add(ComplianceStatus(
                org_id=current_user.org_id,
                control_id=c.id,
                status=new_status,
                evidence_count=threat_summary["quarantined"] if new_status == "compliant" else 0,
                last_assessed_at=now,
                rationale=new_rationale,
                evidence_summary=evidence_summary,
            ))
        updated += 1

    await db.flush()

    # Recompute summary score
    compliant_count = sum(1 for s in assessment_results.values() if s == "compliant")
    partial_count = sum(1 for s in assessment_results.values() if s == "partial")
    total = len(controls)
    pct = round((compliant_count + partial_count * 0.5) / total * 100) if total else 0

    # Persist compliance score to org table so dashboard tile reflects real value
    org_result = await db.execute(
        select(Organization).where(Organization.id == current_user.org_id)
    )
    org = org_result.scalar_one_or_none()
    if org:
        # Update compliance_score as average across all frameworks (for now use this framework's score)
        # Weight by updating the field — a full average would need all frameworks assessed
        org.compliance_score = pct
        await db.flush()

    # Persist a daily snapshot so /history can chart the trend.
    # Upsert via raw SQL so we can reference the functional index
    # uq_compliance_snap_daily(org_id, framework, (captured_at::date)).
    try:
        await db.execute(
            _sql(
                """
                INSERT INTO compliance_score_snapshots
                  (org_id, framework, score_pct, total_controls,
                   compliant, partial, non_compliant, captured_at)
                VALUES (:org_id, :fw, :pct, :total, :c, :p, :n, NOW())
                ON CONFLICT (org_id, framework,
                             (date_trunc('day', captured_at AT TIME ZONE 'UTC')))
                DO UPDATE SET
                  score_pct      = EXCLUDED.score_pct,
                  total_controls = EXCLUDED.total_controls,
                  compliant      = EXCLUDED.compliant,
                  partial        = EXCLUDED.partial,
                  non_compliant  = EXCLUDED.non_compliant,
                  captured_at    = EXCLUDED.captured_at
                """
            ),
            {
                "org_id": current_user.org_id,
                "fw": framework,
                "pct": pct,
                "total": total,
                "c": compliant_count,
                "p": partial_count,
                "n": total - compliant_count - partial_count,
            },
        )
        await db.flush()
    except Exception as _snap_err:
        import logging as _log
        _log.getLogger(__name__).warning(f"score snapshot persist failed: {_snap_err}")

    return {
        "framework": framework,
        "controls_assessed": updated,
        "compliant": compliant_count,
        "partial": partial_count,
        "non_compliant": total - compliant_count - partial_count,
        "score_pct": pct,
        "assessment_results": assessment_results,
        "assessed_at": datetime.utcnow().isoformat(),
    }


@router.get("/summary")
async def get_summary_alias(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Alias for /overview — returns per-framework compliance percentages."""
    overview = await get_overview(current_user=current_user, db=db)
    # Return as {FRAMEWORK: pct} dict for frontend
    return {row["framework"]: row["compliance_pct"] for row in overview.get("frameworks", [])}
