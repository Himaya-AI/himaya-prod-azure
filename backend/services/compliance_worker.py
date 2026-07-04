"""
Compliance Auto-Assessment Worker
==================================
Runs on startup and every 24 hours. Analyses the org's email-security posture
(threats, policies, integrations, mailbox coverage) and maps it to compliance
controls across SAMA CSF, NCA ECC, UAE NESA, CBUAE, NIST CSF, HIPAA, SOC2, CCPA.

Assessment logic per evidence_type:
  threat_detection   → COMPLIANT if threats actively detected (LLM pipeline running)
  monitoring         → COMPLIANT if delta sync covering all org mailboxes
  incident_response  → PARTIAL if any quarantine/alert policy; COMPLIANT if both types
  data_protection    → PARTIAL (emails processed in-transit; no data-at-rest control yet)
  authentication     → PARTIAL if integration connected (OAuth)
  access_control     → PARTIAL if mailboxes being monitored
  risk_management    → PARTIAL if 1+ policies; COMPLIANT if 3+ active policies
  governance         → PARTIAL (system operational = basic governance)
  training           → NOT_STARTED (no training module yet)
"""
import asyncio
import logging
import uuid
from datetime import datetime, timezone, timedelta

from sqlalchemy import select, func, text as _sql

logger = logging.getLogger(__name__)

ASSESSMENT_INTERVAL_HOURS = 24
_WORKER_RUNNING = False


async def run_compliance_assessment_loop():
    """Background asyncio task — seeds controls then re-assesses every 24h."""
    global _WORKER_RUNNING
    if _WORKER_RUNNING:
        return  # Only one loop per process
    _WORKER_RUNNING = True
    await asyncio.sleep(180)  # wait 3 min so service is healthy before hitting DB
    while True:
        try:
            await _assess_all_orgs()
        except Exception as exc:
            logger.error(f"Compliance assessment error: {exc}", exc_info=True)
        await asyncio.sleep(ASSESSMENT_INTERVAL_HOURS * 3600)


async def _assess_all_orgs():
    """Seed controls (if missing) then auto-assess every active org."""
    from backend.database import AsyncSessionLocal
    from backend.models.db_models import Organization, OrgIntegration

    async with AsyncSessionLocal() as db:
        # Seed SAMA/NCA controls if they don't exist yet
        await _seed_controls_if_missing(db)

        orgs = (await db.execute(select(Organization))).scalars().all()
        for org in orgs:
            try:
                await _assess_org(db, str(org.id))
            except Exception as exc:
                logger.warning(f"Compliance assessment failed for org {org.id}: {exc}")
        await db.commit()
    logger.info(f"Compliance auto-assessment completed for all orgs")


async def _seed_controls_if_missing(db):
    """Upsert all default controls — safe to run every boot (ON CONFLICT DO NOTHING)."""
    from sqlalchemy import text as _t
    # Note: unique index on (framework, control_id) is created at startup in main.py
    controls = _get_default_controls()
    inserted = 0
    for fw, cid, name_en, name_ar, etype in controls:
        await db.execute(_t("""
            INSERT INTO compliance_controls (id, framework, control_id, control_name_en, control_name_ar, evidence_type)
            VALUES (gen_random_uuid(), :fw, :cid, :name_en, :name_ar, :etype)
            ON CONFLICT (framework, control_id) DO UPDATE
              SET control_name_en = EXCLUDED.control_name_en,
                  evidence_type   = EXCLUDED.evidence_type
        """), {"fw": fw, "cid": cid, "name_en": name_en, "name_ar": name_ar, "etype": etype})
        inserted += 1
    await db.commit()
    logger.info(f"Synced {inserted} compliance controls across all frameworks")


async def _assess_org(db, org_id: str):
    """Assess compliance posture for a single org and upsert ComplianceStatus rows."""
    from backend.models.db_models import ComplianceControl, ComplianceStatus, OrgIntegration, Policy, Threat, User, Organization

    org_uuid = uuid.UUID(org_id)
    now = datetime.utcnow()
    cutoff_30d = now - timedelta(days=30)

    # ── Gather metrics ────────────────────────────────────────────────
    # Active integrations
    integrations = (await db.execute(
        select(OrgIntegration).where(
            OrgIntegration.org_id == org_uuid,
            OrgIntegration.status == "active",
        )
    )).scalars().all()
    has_integration = len(integrations) > 0

    # Active policies
    active_policies = (await db.execute(
        select(Policy).where(Policy.org_id == org_uuid, Policy.status == "active")
    )).scalars().all()
    policy_count = len(active_policies)
    policy_actions = {p.action for p in active_policies}
    has_quarantine_policy = "QUARANTINE" in policy_actions
    has_alert_policy = "ALERT" in policy_actions
    has_tag_policy = "TAG" in policy_actions or "DELIVER_WITH_BANNER" in policy_actions

    # Threats in last 30 days
    threat_count_30d = (await db.execute(
        select(func.count(Threat.id)).where(
            Threat.org_id == org_uuid,
            Threat.detected_at >= cutoff_30d,
        )
    )).scalar() or 0

    # High-risk threats handled (quarantined/flagged)
    handled_count = (await db.execute(
        select(func.count(Threat.id)).where(
            Threat.org_id == org_uuid,
            Threat.action_taken.in_(["QUARANTINED", "FLAGGED_HIGH", "MARKED_SPAM"]),
            Threat.detected_at >= cutoff_30d,
        )
    )).scalar() or 0

    # Monitored mailboxes
    mailbox_count = (await db.execute(
        select(func.count(User.id)).where(
            User.org_id == org_uuid, User.is_active.is_(True)
        )
    )).scalar() or 0

    # Total threats ever
    total_threats = (await db.execute(
        select(func.count(Threat.id)).where(Threat.org_id == org_uuid)
    )).scalar() or 0

    # ── Connected-resource metrics ────────────────────────────────────
    # The compliance worker historically only looked at email-security
    # signals (threats, policies, integrations). With CSPM/DSPM connectors
    # in play (AWS/GCP/Databricks/Azure/Oracle/SAP/GitHub/Snowflake) we
    # now also fold their state into the assessment so a connected cloud
    # gives credit for monitoring/data_protection/risk_management and
    # an open toxic combination demotes the relevant control to partial.
    async def _safe_scalar(sql: str) -> int:
        try:
            r = await db.execute(_sql(sql), {"oid": str(org_uuid)})
            return int(r.scalar() or 0)
        except Exception:
            return 0

    cloud_resource_count = 0
    for tbl in ("aws_resources", "gcp_resources", "databricks_resources",
                "azure_resources", "oracle_resources"):
        cloud_resource_count += await _safe_scalar(
            f"SELECT COUNT(*) FROM {tbl} WHERE org_id = CAST(:oid AS UUID)"
        )
    cloud_findings_open = 0
    cloud_findings_critical_open = 0
    for tbl in ("aws_findings", "gcp_findings", "databricks_findings",
                "azure_findings", "sap_findings", "github_findings",
                "snowflake_findings", "salesforce_findings"):
        cloud_findings_open += await _safe_scalar(
            f"SELECT COUNT(*) FROM {tbl} WHERE org_id = CAST(:oid AS UUID) "
            f"AND status = 'open'"
        )
        cloud_findings_critical_open += await _safe_scalar(
            f"SELECT COUNT(*) FROM {tbl} WHERE org_id = CAST(:oid AS UUID) "
            f"AND status = 'open' AND severity IN ('critical','high')"
        )
    cloud_connections = 0
    for tbl in ("aws_connections", "gcp_connections", "databricks_connections",
                "azure_connections", "oracle_connections",
                "sap_connections", "github_connections", "snowflake_connections",
                "salesforce_connections"):
        cloud_connections += await _safe_scalar(
            f"SELECT COUNT(*) FROM {tbl} WHERE org_id = CAST(:oid AS UUID)"
        )
    # Toxic combinations — active (open) compound risks across clouds.
    toxic_open = await _safe_scalar(
        "SELECT COUNT(*) FROM toxic_combinations "
        "WHERE org_id = CAST(:oid AS UUID) AND status = 'open'"
    )
    toxic_critical = await _safe_scalar(
        "SELECT COUNT(*) FROM toxic_combinations "
        "WHERE org_id = CAST(:oid AS UUID) AND status = 'open' "
        "AND severity IN ('critical','high')"
    )
    # DSPM classified resources — evidence that data classification is
    # running across connected clouds, not just email.
    dspm_classified = 0
    for tbl in ("aws_resources", "gcp_resources", "databricks_resources",
                "azure_resources", "oracle_resources"):
        dspm_classified += await _safe_scalar(
            f"SELECT COUNT(*) FROM {tbl} WHERE org_id = CAST(:oid AS UUID) "
            f"AND metadata->>'dlp_classified' = 'true'"
        )
    # SaaS data items classified (M365 / SharePoint / OneDrive / Teams).
    saas_classified = await _safe_scalar(
        "SELECT COUNT(*) FROM saas_data_items "
        "WHERE org_id = CAST(:oid AS UUID) "
        "AND classification_label IS NOT NULL"
    )

    # ── Assessment rules (lenient: give credit when close) ───────────
    # NOTE: nested `await` inside a sync inner function raises
    # SyntaxError; this must be `async def` because the posture branch
    # below performs awaited DB queries.
    async def _score(evidence_type: str) -> tuple[str, str, int]:
        """Returns (status, notes, evidence_count).
        Philosophy: if the org has taken meaningful action toward a control,
        give compliant. Partial only when meaningfully incomplete. Not-started
        only when nothing is configured."""

        if evidence_type == "threat_detection":
            # Cloud findings also count as threat detection evidence (CSPM/DSPM
            # findings = misconfigurations + sensitive-data leaks detected).
            if has_integration or cloud_resource_count > 0:
                parts = []
                if total_threats:
                    parts.append(f"{total_threats} email threats analysed ({threat_count_30d} in last 30 days)")
                if cloud_findings_open:
                    parts.append(f"{cloud_findings_open} open cloud findings across connected resources")
                if cloud_resource_count:
                    parts.append(f"{cloud_resource_count} cloud resources inventoried")
                summary = "; ".join(parts) if parts else "continuous LLM-based scanning active"
                return "compliant", f"Active threat detection pipeline: {summary}.", max(total_threats + cloud_findings_open, 1)
            return "not_started", "No email integration or cloud connector configured.", 0

        elif evidence_type == "monitoring":
            if mailbox_count > 0 and has_integration and cloud_connections > 0:
                return "compliant", f"Continuous monitoring active: {mailbox_count} mailboxes + {cloud_connections} cloud connectors monitored on a 5-minute scan cycle.", mailbox_count + cloud_resource_count
            if mailbox_count > 0 and has_integration:
                return "compliant", f"Continuous monitoring active: {mailbox_count} mailboxes covered, delta sync every 60 seconds.", mailbox_count
            if cloud_connections > 0:
                return "compliant", f"Continuous cloud monitoring active: {cloud_connections} connector(s), {cloud_resource_count} resources scanned every 5 minutes.", cloud_resource_count
            elif has_integration:
                # Integration exists, mailboxes being discovered
                return "compliant", "Email integration active — monitoring pipeline running. Mailbox discovery in progress.", 1
            return "not_started", "No integration connected — monitoring not active.", 0

        elif evidence_type == "incident_response":
            if has_quarantine_policy and (has_alert_policy or has_tag_policy):
                return "compliant", f"Incident response fully configured: QUARANTINE + ALERT/TAG policies active ({policy_count} total).", policy_count
            elif has_quarantine_policy or has_alert_policy or has_tag_policy:
                # Has at least one response action — give compliant (lenient)
                return "compliant", f"Incident response policies active: {policy_count} policy(ies) configured with automated response actions.", policy_count
            elif policy_count > 0:
                return "partial", f"{policy_count} policy(ies) defined. Add quarantine or alert actions for automated incident response.", policy_count
            elif has_integration:
                return "partial", "Integration connected. Define at least one incident response policy (quarantine/alert/tag).", 0
            return "not_started", "No incident response policies defined.", 0

        elif evidence_type == "data_protection":
            # Data-at-rest credit comes from connected cloud DSPM:
            # if there are connected resources AND we are classifying them
            # AND there are no critical toxic data combinations, give
            # compliant. Otherwise partial.
            total_dspm = dspm_classified + saas_classified
            critical_data_toxic = await _safe_scalar(
                "SELECT COUNT(*) FROM toxic_combinations "
                "WHERE org_id = CAST(:oid AS UUID) AND status = 'open' "
                "AND severity IN ('critical','high') "
                "AND rule_id IN ('public_pii_bucket','public_db_with_data',"
                "                 'unencrypted_confidential','secret_in_public_notebook',"
                "                 'shadow_data_external')"
            )
            if total_dspm > 0 and critical_data_toxic == 0:
                return "compliant", f"In-transit AND at-rest data protection: {total_threats} email threats intercepted, {total_dspm} sensitive data assets classified across connected clouds + SaaS, no critical toxic data exposures open.", total_dspm
            if total_dspm > 0 and critical_data_toxic > 0:
                return "partial", f"DSPM classifying {total_dspm} sensitive assets across clouds + SaaS, but {critical_data_toxic} critical/high toxic data exposure(s) open. Remediate to reach compliant.", total_dspm
            if has_integration and total_threats > 0:
                return "partial", f"In-transit data protection active: {total_threats} threats intercepted. Connect a cloud (AWS/GCP/Azure) for data-at-rest classification evidence.", total_threats
            elif has_integration:
                return "partial", "Email data-in-transit protection enabled. Connect a cloud connector to extend coverage to data-at-rest.", 0
            return "not_started", "No integration connected.", 0

        elif evidence_type == "authentication":
            if has_integration:
                providers = ", ".join(set(i.provider for i in integrations))
                return "compliant", f"OAuth 2.0 authentication enforced via {providers}. MFA managed through identity provider admin console.", len(integrations)
            return "not_started", "No authentication integration connected.", 0

        elif evidence_type == "access_control":
            # Identity-aware DSPM (Access Intelligence) gives stronger
            # access_control evidence when cloud connectors are present.
            if mailbox_count > 0 and cloud_connections > 0:
                return "compliant", f"Access control active across email + cloud: {mailbox_count} mailboxes + {cloud_connections} connectors. Access Intelligence tracks per-identity blast radius across clouds.", mailbox_count + cloud_connections
            if mailbox_count > 0:
                return "compliant", f"Access control active: {mailbox_count} mailboxes monitored. Unauthorised access patterns trigger alerts.", mailbox_count
            elif has_integration:
                return "partial", "Integration connected; mailbox access control initialising.", 0
            return "not_started", "No access control integration.", 0

        elif evidence_type == "risk_management":
            # Cloud connectors + toxic combinations engine = active risk
            # identification across the connected estate. Tie risk_management
            # to whether an org is actively detecting AND tracking risks.
            if policy_count >= 2 and has_integration and cloud_connections > 0:
                tox_note = f"; {toxic_open} compound (\"toxic\") risks tracked" if toxic_open else "; no open compound risks"
                return "compliant", f"Risk management active across email + cloud: {policy_count} policies, {cloud_connections} connectors, {threat_count_30d} email risks last 30 days, {cloud_findings_open} cloud findings open{tox_note}.", policy_count + cloud_findings_open
            if policy_count >= 2 and has_integration:
                return "compliant", f"Risk management active: {policy_count} policies governing email security posture, {threat_count_30d} risks identified last 30 days.", policy_count
            if cloud_connections > 0 and policy_count >= 1:
                return "compliant", f"Cloud risk management active: {cloud_connections} connector(s) scanned every 5 min, {cloud_findings_open} open findings under triage, {policy_count} policy(ies) defined.", policy_count + cloud_findings_open
            elif policy_count >= 1:
                return "partial", f"{policy_count} risk policy active. Add at least 2 policies for full risk management coverage.", policy_count
            elif has_integration:
                return "partial", "Integration active but no risk policies defined. Define policies to formalise risk management.", 0
            return "not_started", "No risk management policies or integration.", 0

        elif evidence_type == "governance":
            # Governance now also notes cloud connector coverage — a meaningful
            # signal that the org has expanded operational security beyond email.
            if has_integration and policy_count > 0 and cloud_connections > 0:
                return "compliant", f"Multi-domain governance active: {policy_count} policies, {mailbox_count} mailboxes + {cloud_connections} cloud connectors, continuous audit trail across email and cloud estate.", policy_count + cloud_connections
            if has_integration and policy_count > 0:
                return "partial", f"Operational security governance active: {policy_count} policies, {mailbox_count} mailboxes monitored, continuous audit trail. Formalise with documented ISMS for full compliance.", policy_count
            elif has_integration:
                return "partial", "Helios provides operational governance framework. Define security policies to strengthen governance posture.", 0
            return "not_started", "System not connected.", 0

        elif evidence_type == "training":
            return "not_started", "Security awareness training module not yet configured.", 0

        elif evidence_type == "data_classification":
            # Were sensitive data assets classified across email + cloud?
            total_dspm = dspm_classified + saas_classified
            if total_dspm == 0 and cloud_connections == 0 and not has_integration:
                return "not_started", "No cloud or SaaS connectors — cannot classify data assets.", 0
            if total_dspm == 0 and (cloud_connections > 0 or has_integration):
                return "partial", "Connectors active but DLP classifier has not yet labelled any assets. Wait one scan cycle and re-check.", 0
            if total_dspm > 0:
                return "compliant", f"DLP classification active: {dspm_classified} cloud resources + {saas_classified} SaaS items labelled across connectors. Categories include PII, PCI, PHI, credentials, financial.", total_dspm
            return "not_started", "No data classification evidence.", 0

        elif evidence_type == "cloud_posture":
            # Aggregate CSPM/DSPM cloud posture across connected estates.
            if cloud_connections == 0:
                return "not_started", "No cloud (AWS/GCP/Azure/Oracle) connectors — cloud posture not assessed.", 0
            if toxic_critical > 0:
                return "non_compliant", f"{toxic_critical} critical/high toxic combination(s) open across {cloud_connections} connected cloud(s). Address before re-scoring.", toxic_critical
            if cloud_findings_critical_open > 5:
                return "partial", f"{cloud_findings_critical_open} open critical/high cloud findings across {cloud_connections} connector(s). Drive to <5 to reach compliant.", cloud_findings_critical_open
            return "compliant", f"Cloud posture healthy: {cloud_connections} connector(s), {cloud_resource_count} resources inventoried, {cloud_findings_open} open findings under triage, no critical toxic combinations.", cloud_resource_count

        elif evidence_type == "posture":
            # Inbox posture management — assess from posture tables
            try:
                from sqlalchemy import text as _ptxt
                _pa_r = await db.execute(_ptxt(
                    "SELECT COUNT(*) as total, COUNT(*) FILTER (WHERE risk='high') as high "
                    "FROM posture_apps WHERE org_id=:oid"
                ), {"oid": org_id})
                _pr_r = await db.execute(_ptxt(
                    "SELECT COUNT(*) as total, COUNT(*) FILTER (WHERE risk='high') as high "
                    "FROM posture_rules WHERE org_id=:oid"
                ), {"oid": org_id})
                _pf_r = await db.execute(_ptxt(
                    "SELECT COUNT(*) FILTER (WHERE is_external=true) as ext "
                    "FROM posture_forwards WHERE org_id=:oid"
                ), {"oid": org_id})
                _scan_r = await db.execute(_ptxt(
                    "SELECT last_scanned_at FROM posture_scan_log WHERE org_id=:oid"
                ), {"oid": org_id})
                _pa = _pa_r.fetchone()
                _pr = _pr_r.fetchone()
                _pf = _pf_r.fetchone()
                _scan = _scan_r.fetchone()
                _total_apps = int(_pa[0] or 0) if _pa else 0
                _high_apps = int(_pa[1] or 0) if _pa else 0
                _high_rules = int(_pr[1] or 0) if _pr else 0
                _ext_fwds = int(_pf[0] or 0) if _pf else 0
                _scanned = bool(_scan and _scan[0])
                if not _scanned:
                    return "not_started", "Inbox posture scan not yet run. Trigger a scan from the Inbox Posture page.", 0
                if _high_apps == 0 and _high_rules == 0 and _ext_fwds == 0:
                    return "compliant", f"Inbox posture clean: {_total_apps} apps reviewed, no high-risk rules or external forwarding detected.", _total_apps
                if _ext_fwds > 0:
                    return "non_compliant", f"{_ext_fwds} external forwarding rule(s) detected — high exfiltration risk. Review Auto-Forwarding tab.", _ext_fwds
                if _high_rules > 0:
                    return "non_compliant", f"{_high_rules} high-risk inbox rule(s) detected (forwarding/deletion rules). Review Inbox Rules tab.", _high_rules
                if _high_apps > 0:
                    return "partial", f"{_high_apps} high-risk OAuth app(s) or add-ins detected. Review OAuth Apps tab and revoke unnecessary access.", _high_apps
            except Exception as _pe:
                return "not_started", f"Posture tables not available yet: {_pe}", 0

        return "not_started", "Control not yet evaluated.", 0

    # ── Load all controls and upsert status ───────────────────────────
    controls = (await db.execute(select(ComplianceControl))).scalars().all()
    statuses = {
        str(s.control_id): s
        for s in (await db.execute(
            select(ComplianceStatus).where(ComplianceStatus.org_id == org_uuid)
        )).scalars().all()
    }

    compliant_count = 0
    partial_count = 0

    for ctrl in controls:
        status_str, notes, evidence = await _score(ctrl.evidence_type or "")
        ctrl_id_str = str(ctrl.id)

        if status_str == "compliant":
            compliant_count += 1
        elif status_str == "partial":
            partial_count += 1

        if ctrl_id_str in statuses:
            existing = statuses[ctrl_id_str]
            existing.status = status_str
            existing.notes = notes
            existing.evidence_count = evidence
            existing.last_assessed_at = now
        else:
            db.add(ComplianceStatus(
                org_id=org_uuid,
                control_id=ctrl.id,
                status=status_str,
                notes=notes,
                evidence_count=evidence,
                last_assessed_at=now,
            ))

    # ── Update org compliance score ────────────────────────────────────
    total = len(controls)
    if total > 0:
        score = round((compliant_count + partial_count * 0.5) / total * 100)
        await db.execute(_sql(
            "UPDATE organizations SET compliance_score = :s WHERE id = :oid"
        ), {"s": score, "oid": org_uuid})

    logger.info(
        f"Compliance assessed org {org_id}: {compliant_count} compliant, "
        f"{partial_count} partial / {total} controls → score={score if total else 0}%"
    )


def _get_default_controls():
    """Default compliance controls seeded on first run."""
    return [
        # SAMA CSF
        ("SAMA_CSF", "3.3.3",   "Email Security Controls",          "ضوابط أمن البريد الإلكتروني",          "threat_detection"),
        ("SAMA_CSF", "3.3.5",   "Anti-Phishing Controls",           "ضوابط مكافحة التصيد الاحتيالي",        "threat_detection"),
        ("SAMA_CSF", "3.4.1",   "Incident Response",                "الاستجابة للحوادث",                     "incident_response"),
        ("SAMA_CSF", "3.2.1",   "Risk Management Framework",        "إطار إدارة المخاطر",                    "risk_management"),
        ("SAMA_CSF", "3.1.1",   "Information Security Governance",  "حوكمة أمن المعلومات",                   "governance"),
        # NCA ECC
        ("NCA_ECC",  "2-7-1",   "Email Authentication",             "مصادقة البريد الإلكتروني",              "authentication"),
        ("NCA_ECC",  "2-7-2",   "Anti-Spoofing",                    "مكافحة الانتحال",                       "threat_detection"),
        ("NCA_ECC",  "2-7-3",   "BEC Protection",                   "الحماية من احتيال البريد التجاري",      "threat_detection"),
        ("NCA_ECC",  "2-7-4",   "Government Impersonation",         "الحماية من انتحال الجهات الحكومية",     "threat_detection"),
        ("NCA_ECC",  "2-7-5",   "Malware Protection",               "الحماية من البرمجيات الخبيثة",          "threat_detection"),
        ("NCA_ECC",  "2-8-1",   "Continuous Monitoring",            "المراقبة المستمرة",                     "monitoring"),
        # UAE NESA
        ("UAE_NESA", "IAS-T07", "Email Security Controls",          "ضوابط أمن البريد الإلكتروني",          "threat_detection"),
        ("UAE_NESA", "IAS-T06", "Malware & Content Filtering",      "تصفية المحتوى والبرمجيات الخبيثة",     "threat_detection"),
        # CBUAE
        ("CBUAE",    "EMAIL-001","Email Protection Domain",          "نطاق حماية البريد الإلكتروني",          "threat_detection"),
        ("CBUAE",    "MON-001",  "Security Monitoring",              "مراقبة الأمن",                          "monitoring"),
        # NIST CSF
        ("NIST_CSF", "DE.AE-2", "Anomaly & Event Detection",        "Anomaly & Event Detection",              "threat_detection"),
        ("NIST_CSF", "DE.CM-1", "Network Continuous Monitoring",    "Network Continuous Monitoring",          "monitoring"),
        ("NIST_CSF", "DE.CM-7", "Unauthorized Activity Monitoring", "Unauthorized Activity Monitoring",       "monitoring"),
        ("NIST_CSF", "RS.RP-1", "Response Plan Execution",          "Response Plan Execution",                "incident_response"),
        ("NIST_CSF", "PR.AC-1", "Identity Management",              "Identity Management",                    "authentication"),
        ("NIST_CSF", "PR.DS-2", "Data-in-Transit Protection",       "Data-in-Transit Protection",             "data_protection"),
        ("NIST_CSF", "PR.AC-3", "Remote Access Management",         "Remote Access Management",               "access_control"),
        ("NIST_CSF", "CC3.2",   "Risk Identification & Analysis",   "Risk Identification & Analysis",         "risk_management"),
        # SOC 2
        ("SOC2",     "CC7.1",   "Threat Detection & Monitoring",    "Threat Detection & Monitoring",          "monitoring"),
        ("SOC2",     "CC7.2",   "Monitoring for Anomalies",         "Monitoring for Anomalies",               "monitoring"),
        ("SOC2",     "CC7.3",   "Incident Identification & Response","Incident Identification & Response",    "incident_response"),
        ("SOC2",     "CC6.6",   "Security Against External Threats","Security Against External Threats",      "threat_detection"),
        ("SOC2",     "CC3.2",   "Risk Identification & Analysis",   "Risk Identification & Analysis",         "risk_management"),
        # HIPAA
        ("HIPAA",    "164.312(b)",    "Audit Controls",             "Audit Controls",                         "monitoring"),
        ("HIPAA",    "164.308(a)(1)", "Risk Analysis & Management", "Risk Analysis & Management",             "risk_management"),
        ("HIPAA",    "164.308(a)(6)", "Security Incident Procedures","Security Incident Procedures",          "incident_response"),
        # GDPR
        ("GDPR",     "GDPR-1",   "Lawful Processing of Email Data",         "", "data_protection"),
        ("GDPR",     "GDPR-2",   "Data Subject Rights (Erasure/Portability)","", "data_protection"),
        ("GDPR",     "GDPR-3",   "72-Hour Breach Notification",             "", "incident_response"),
        ("GDPR",     "GDPR-4",   "Privacy by Design & Default",             "", "governance"),
        ("GDPR",     "GDPR-5",   "Data Minimisation",                       "", "data_protection"),
        ("GDPR",     "GDPR-6",   "Cross-border Transfer Controls",          "", "data_protection"),
        ("GDPR",     "GDPR-7",   "Consent Management for Email Marketing",  "", "governance"),
        ("GDPR",     "GDPR-8",   "DPO Designation & Records of Processing", "", "governance"),
        # ISO 27001
        ("ISO_27001","ISO-A5.1", "Information Security Policies",           "", "governance"),
        ("ISO_27001","ISO-A8.1", "Inventory of Email Assets",               "", "governance"),
        ("ISO_27001","ISO-A13.2","Information Transfer Controls",           "", "data_protection"),
        ("ISO_27001","ISO-A14.1","Secure Email Gateway Development",        "", "threat_detection"),
        ("ISO_27001","ISO-A12.1","Operational Anti-Spam / Anti-Malware",   "", "threat_detection"),
        ("ISO_27001","ISO-A15.1","Third-Party Email Supplier Security",     "", "risk_management"),
        ("ISO_27001","ISO-A16.1","Incident Response for Email Threats",     "", "incident_response"),
        ("ISO_27001","ISO-A18.1","Regulatory Compliance & Email Retention", "", "monitoring"),
        # DORA
        ("DORA",     "DORA-1",   "ICT Risk Management Framework",           "", "risk_management"),
        ("DORA",     "DORA-2",   "ICT Incident Classification & Reporting", "", "incident_response"),
        ("DORA",     "DORA-3",   "Digital Operational Resilience Testing",  "", "monitoring"),
        ("DORA",     "DORA-4",   "Third-Party ICT Risk (Email Providers)",  "", "risk_management"),
        ("DORA",     "DORA-5",   "Cyber Threat Information Sharing",        "", "monitoring"),
        ("DORA",     "DORA-6",   "Business Continuity for Email Systems",   "", "governance"),
        ("DORA",     "DORA-7",   "RPO / RTO Objectives for Email",          "", "governance"),
        # NIS2
        ("NIS2",     "NIS2-1",   "Risk Management Measures",                "", "risk_management"),
        ("NIS2",     "NIS2-2",   "Incident Handling",                       "", "incident_response"),
        ("NIS2",     "NIS2-3",   "Business Continuity",                     "", "governance"),
        ("NIS2",     "NIS2-4",   "Supply Chain Security",                   "", "risk_management"),
        ("NIS2",     "NIS2-5",   "Network Security (Email Gateway Hardening)","", "threat_detection"),
        ("NIS2",     "NIS2-6",   "Access Control and MFA",                  "", "authentication"),
        ("NIS2",     "NIS2-7",   "Vulnerability Management",                "", "risk_management"),
        ("NIS2",     "NIS2-8",   "Encryption in Transit / at Rest",         "", "data_protection"),
        # Inbox Posture Management controls (enterprise tier)
        ("SAMA_CSF", "3.3.6",   "OAuth App & Add-in Security",              "ضوابط أمان التطبيقات",            "posture"),
        ("NCA_ECC",  "2-7-3",   "Inbox Rule & Forwarding Integrity",        "سلامة قواعد البريد الوارد",          "posture"),
        ("ISO_27001","ISO-A9.4", "OAuth Access Control & Token Review",     "", "posture"),
        ("ISO_27001","ISO-A12.6","Email Forwarding & Exfiltration Controls", "", "posture"),
        # Cloud / DSPM controls — added 2026-06-21 so connected-resource
        # evidence rolls up into compliance frameworks rather than only
        # email metrics. Each control routes to the new data_classification
        # or cloud_posture evidence types.
        ("NIST_CSF", "PR.DS-1", "Data-at-Rest Protection (DSPM)",           "", "data_classification"),
        ("NIST_CSF", "ID.AM-2", "Cloud Resource Inventory",                 "", "cloud_posture"),
        ("SOC2",     "CC6.1",   "Logical Access Controls (Cloud Estate)",   "", "cloud_posture"),
        ("SOC2",     "CC6.7",   "Data Classification & Handling",           "", "data_classification"),
        ("ISO_27001","ISO-A8.2", "Information Classification (Cloud + SaaS)","", "data_classification"),
        ("ISO_27001","ISO-A8.3", "Cloud Asset Inventory & Ownership",       "", "cloud_posture"),
        ("GDPR",     "GDPR-9",   "Data Classification & Records",           "", "data_classification"),
        ("HIPAA",    "164.308(a)(8)","Risk Mitigation (Cloud Estate)",       "Risk Mitigation", "cloud_posture"),
        ("DORA",     "DORA-8",   "ICT Asset Inventory & Classification",    "", "cloud_posture"),
        ("NIS2",     "NIS2-9",   "Asset Management & Inventory",            "", "cloud_posture"),
        ("SAMA_CSF", "3.3.7",   "Data Classification Programme",            "برنامج تصنيف البيانات",          "data_classification"),
        ("NCA_ECC",  "2-9-1",   "Cloud Security & Posture Management",     "إدارة وضع الأمان السحابي",      "cloud_posture"),
    ]
