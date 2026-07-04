"""
Seed script for Himaya Helios demo data.
Run from himaya-helios/ root: python -m backend.seed_data
or from backend/: python seed_data.py
"""
import asyncio
import hashlib
import random
import sys
import os
from datetime import datetime, timedelta
from pathlib import Path

# Ensure imports work whether run from root or backend/
sys.path.insert(0, str(Path(__file__).parent.parent))

from dotenv import load_dotenv
load_dotenv(Path(__file__).parent.parent / ".env")

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy import select, text

from backend.config import settings
from backend.models.db_models import (
    Organization, User, Threat, ComplianceEvidence, ComplianceControl, Policy
)
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

THREAT_TYPES = ["BEC", "PHISHING", "GOV_IMPERSONATION", "MALWARE", "LOOKALIKE_DOMAIN", "ACCOUNT_TAKEOVER", "SUPPLY_CHAIN"]
STATUSES = ["open", "resolved", "quarantined", "false_positive"]
ACTIONS = ["DELIVER", "DELIVER_WITH_BANNER", "HOLD_FOR_REVIEW", "QUARANTINE", "BLOCK_DELETE"]

SENDERS = [
    "ceo-fraud@acme-c0rp.com",
    "billing@acmefintech-invoice.net",
    "zatca-support@g0v-sa.com",
    "hr@acmefintech-payroll.co",
    "vendor@trusted-supplier1.com",
    "noreply@microsft-365.com",
    "admin@acmef1ntech.com",
    "security@paypal-alert.net",
    "support@amaz0n-aws.com",
    "cfo@acme-corp-intl.com",
]

DEPARTMENTS = ["Finance", "IT", "HR", "Operations", "Compliance", "Legal", "Executive"]


async def seed():
    engine = create_async_engine(settings.DATABASE_URL, echo=False)
    SessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with SessionLocal() as db:
        print("🌱 Starting seed...")

        # Check if already seeded
        existing = await db.execute(select(Organization).where(Organization.domain == "acmefintech.com"))
        if existing.scalar_one_or_none():
            print("⚠️  Demo data already exists. Skipping.")
            return

        # ── Organization ──────────────────────────────────────────────────────
        org = Organization(
            name="Acme Fintech",
            domain="acmefintech.com",
            plan="enterprise",
            country="Saudi Arabia",
            mailbox_count=250,
            risk_score=62,
            compliance_score=74,
            timezone="Asia/Riyadh",
            language="en",
            mfa_enforced=True,
        )
        db.add(org)
        await db.flush()
        print(f"✓ Created organization: {org.name} ({org.id})")

        # ── Users ─────────────────────────────────────────────────────────────
        users_data = [
            {
                "email": "admin@acmefintech.com",
                "name": "Ahmed Al-Rashid",
                "role": "admin",
                "department": "IT",
                "job_title": "CISO",
                "password": "SentinelDemo123!",
            },
            {
                "email": "analyst@acmefintech.com",
                "name": "Sara Al-Otaibi",
                "role": "analyst",
                "department": "IT",
                "job_title": "Security Analyst",
                "password": "SentinelDemo123!",
            },
            {
                "email": "compliance@acmefintech.com",
                "name": "Mohammed Al-Ghamdi",
                "role": "compliance",
                "department": "Compliance",
                "job_title": "Compliance Officer",
                "password": "SentinelDemo123!",
            },
        ]

        created_users = []
        for ud in users_data:
            user = User(
                org_id=org.id,
                email=ud["email"],
                name=ud["name"],
                role=ud["role"],
                department=ud["department"],
                job_title=ud["job_title"],
                password_hash=pwd_context.hash(ud["password"]),
                is_active=True,
                is_vip=(ud["role"] == "admin"),
                risk_score=random.randint(5, 30),
            )
            db.add(user)
            created_users.append(user)

        # Extra employees (targets for threats)
        extra_employees = [
            ("cfo@acmefintech.com", "Khalid Al-Harbi", "Finance", "CFO", 75, True),
            ("finance1@acmefintech.com", "Nora Al-Qahtani", "Finance", "Finance Manager", 60, False),
            ("finance2@acmefintech.com", "Abdullah Al-Dosari", "Finance", "Accountant", 45, False),
            ("hr@acmefintech.com", "Fatima Al-Zahrani", "HR", "HR Manager", 30, False),
            ("it@acmefintech.com", "Omar Al-Mutairi", "IT", "SysAdmin", 25, False),
        ]
        for email, name, dept, title, risk, vip in extra_employees:
            emp = User(
                org_id=org.id,
                email=email,
                name=name,
                role="readonly",
                department=dept,
                job_title=title,
                password_hash=pwd_context.hash("Employee123!"),
                is_active=True,
                is_vip=vip,
                risk_score=risk,
            )
            db.add(emp)
            created_users.append(emp)

        await db.flush()
        print(f"✓ Created {len(created_users)} users")

        # ── Policies ──────────────────────────────────────────────────────────
        policies_data = [
            {
                "name": "BEC High Risk Block",
                "conditions": {"threat_type": "BEC", "risk_score_min": 75},
                "action": "QUARANTINE",
                "status": "active",
                "priority": 10,
            },
            {
                "name": "Government Impersonation Block",
                "conditions": {"threat_type": "GOV_IMPERSONATION"},
                "action": "BLOCK_DELETE",
                "status": "active",
                "priority": 5,
            },
            {
                "name": "Phishing Warning Banner",
                "conditions": {"threat_type": "PHISHING", "risk_score_min": 40},
                "action": "DELIVER_WITH_BANNER",
                "status": "active",
                "priority": 20,
            },
        ]
        for pd in policies_data:
            policy = Policy(
                org_id=org.id,
                name=pd["name"],
                conditions=pd["conditions"],
                action=pd["action"],
                status=pd["status"],
                priority=pd["priority"],
                created_by=created_users[0].id,
            )
            db.add(policy)

        await db.flush()
        print("✓ Created 3 policies")

        # ── Threats (50 records, 30 days) ─────────────────────────────────────
        compliance_controls_result = await db.execute(select(ComplianceControl))
        all_controls = compliance_controls_result.scalars().all()

        threat_count = 0
        target_users = [u for u in created_users if u.department in ("Finance", "HR", "IT", "Executive")]

        for i in range(50):
            days_ago = random.randint(0, 30)
            hours_ago = random.randint(0, 23)
            detected = datetime.utcnow() - timedelta(days=days_ago, hours=hours_ago)

            threat_type = random.choice(THREAT_TYPES)
            risk_score = random.randint(20, 98)
            content_score = random.randint(20, 100)
            graph_score = random.randint(0, 80)
            reputation_score = random.randint(10, 90)

            status = random.choices(
                STATUSES, weights=[50, 25, 15, 10]
            )[0]

            if risk_score >= 80:
                action = "QUARANTINE" if threat_type != "GOV_IMPERSONATION" else "BLOCK_DELETE"
            elif risk_score >= 60:
                action = "QUARANTINE"
            elif risk_score >= 40:
                action = "DELIVER_WITH_BANNER"
            else:
                action = "DELIVER"

            sender = random.choice(SENDERS)
            target_user = random.choice(target_users)

            sama_map = {
                "BEC": ["3.3.3", "3.4.1"],
                "PHISHING": ["3.3.5", "3.4.1"],
                "GOV_IMPERSONATION": ["3.3.3", "3.3.5"],
                "MALWARE": ["3.3.3"],
                "LOOKALIKE_DOMAIN": ["3.3.5"],
                "ACCOUNT_TAKEOVER": ["3.4.1"],
                "SUPPLY_CHAIN": ["3.3.3", "3.4.1"],
            }
            nca_map = {
                "BEC": ["2-7-3"],
                "PHISHING": ["2-7-2", "2-7-5"],
                "GOV_IMPERSONATION": ["2-7-4"],
                "MALWARE": ["2-7-5"],
                "LOOKALIKE_DOMAIN": ["2-7-2"],
                "ACCOUNT_TAKEOVER": ["2-7-1"],
                "SUPPLY_CHAIN": ["2-7-3"],
            }

            threat = Threat(
                org_id=org.id,
                email_message_id=f"<msg-{i:04d}@mail.acmefintech.com>",
                sender=sender,
                sender_domain=sender.split("@")[-1],
                recipient_user_id=target_user.id,
                recipient_email=target_user.email,
                subject_hash=hashlib.sha256(f"subject-{i}".encode()).hexdigest()[:64],
                threat_type=threat_type,
                risk_score=risk_score,
                score_breakdown={
                    "content": content_score,
                    "graph": graph_score,
                    "reputation": reputation_score,
                },
                graph_score=graph_score,
                content_score=content_score,
                reputation_score=reputation_score,
                status=status,
                action_taken=action,
                ai_explanation_en=f"This email exhibits {threat_type} characteristics with a risk score of {risk_score}/100. "
                                   f"Key indicators include suspicious sender domain and unusual communication patterns.",
                ai_explanation_ar=f"يُظهر هذا البريد الإلكتروني خصائص {threat_type} بدرجة خطر {risk_score}/100.",
                threat_indicators={
                    "content": ["suspicious_language", "urgency_words"] if risk_score > 60 else [],
                    "reputation": ["domain_age_low"] if reputation_score > 50 else [],
                    "graph": ["first_time_sender"] if graph_score > 30 else [],
                },
                sama_controls=sama_map.get(threat_type, ["3.3.3"]),
                nca_controls=nca_map.get(threat_type, ["2-7-1"]),
                false_positive=(status == "false_positive"),
                detected_at=detected,
                resolved_at=detected + timedelta(hours=random.randint(1, 24)) if status in ("resolved", "quarantined") else None,
                created_at=detected,
            )
            db.add(threat)
            threat_count += 1

            # Create compliance evidence for quarantined/blocked threats
            if action in ("QUARANTINE", "BLOCK_DELETE") and status != "false_positive":
                evidence = ComplianceEvidence(
                    org_id=org.id,
                    threat_id=None,  # Will link after flush
                    control_ids=sama_map.get(threat_type, []) + nca_map.get(threat_type, []),
                    framework="SAMA_CSF",
                    action_taken=action,
                    outcome=f"Threat {threat_type} detected. Action: {action}. Risk: {risk_score}",
                    immutable=True,
                    retention_tier="1_year",
                    created_at=detected,
                )
                db.add(evidence)

        await db.flush()
        print(f"✓ Created {threat_count} threats")

        # ── EU/UK Compliance Controls ─────────────────────────────────────────
        eu_controls = [
            # GDPR
            ("GDPR", "GDPR-1", "Lawful Processing of Email Data", "", "data_protection",
             "Ensure all email data processing has a valid legal basis under GDPR Article 6."),
            ("GDPR", "GDPR-2", "Data Subject Rights (Erasure / Portability)", "", "data_protection",
             "Implement processes for data subjects to exercise rights to erasure and data portability."),
            ("GDPR", "GDPR-3", "72-Hour Breach Notification", "", "incident_response",
             "Establish a procedure to notify supervisory authorities of personal data breaches within 72 hours."),
            ("GDPR", "GDPR-4", "Privacy by Design & Default", "", "governance",
             "Embed data protection principles into email system architecture and default settings."),
            ("GDPR", "GDPR-5", "Data Minimisation", "", "data_protection",
             "Collect and retain only email data that is necessary for the stated processing purpose."),
            ("GDPR", "GDPR-6", "Cross-border Transfer Controls", "", "data_protection",
             "Ensure adequate safeguards exist before transferring email data outside the EEA."),
            ("GDPR", "GDPR-7", "Consent Management for Email Marketing", "", "governance",
             "Obtain and record explicit consent for marketing emails; honour opt-out requests promptly."),
            ("GDPR", "GDPR-8", "DPO Designation & Records of Processing", "", "governance",
             "Designate a Data Protection Officer and maintain records of processing activities for email data."),
            ("GDPR", "GDPR-9", "Data Retention & Deletion Policy", "", "data_protection",
             "Define and enforce retention periods for personal data; securely delete data when no longer needed."),
            ("GDPR", "GDPR-10", "Access Control to Personal Data", "", "authentication",
             "Restrict access to personal data on a need-to-know basis with role-based access controls."),
            ("GDPR", "GDPR-11", "Encryption of Personal Data at Rest & in Transit", "", "data_protection",
             "Encrypt all personal data stored in SaaS systems and in transit using TLS 1.2+."),
            ("GDPR", "GDPR-12", "Data Protection Impact Assessment (DPIA)", "", "governance",
             "Conduct DPIAs for high-risk processing activities involving personal data."),
            ("GDPR", "GDPR-13", "Consent Withdrawal Mechanism", "", "governance",
             "Provide easy mechanisms for data subjects to withdraw consent at any time."),
            ("GDPR", "GDPR-14", "Third-Party Processor Agreements (DPA)", "", "risk_management",
             "Sign Data Processing Agreements with all third-party processors of personal data."),
            ("GDPR", "GDPR-15", "Data Subject Access Request (DSAR) Process", "", "governance",
             "Establish a process to respond to DSARs within 30 days including data extraction from SaaS."),
            ("GDPR", "GDPR-16", "Pseudonymisation of Sensitive Data", "", "data_protection",
             "Apply pseudonymisation or anonymisation techniques where possible to reduce risk."),
            ("GDPR", "GDPR-17", "Audit Logging for Personal Data Access", "", "monitoring",
             "Maintain audit logs of all access to personal data, especially admin and privileged operations."),
            ("GDPR", "GDPR-18", "Cross-border Data Transfer Mechanisms", "", "data_protection",
             "Use SCCs, BCRs, or adequacy decisions for all personal data transfers outside the EEA."),
            ("GDPR", "GDPR-19", "Vendor Risk Assessment for Data Processors", "", "risk_management",
             "Conduct annual security assessments of third-party processors handling personal data."),
            ("GDPR", "GDPR-20", "Children's Data Protection", "", "governance",
             "Implement specific controls and parental consent mechanisms for processing children's data."),
            # SAMA CSF (additional)
            ("SAMA_CSF", "SAMA-CS-1", "Information Security Governance Framework", "", "governance",
             "Establish an Information Security governance framework aligned with SAMA Cyber Security Framework."),
            ("SAMA_CSF", "SAMA-CS-2", "Asset Management & Classification", "", "data_protection",
             "Classify and manage all information assets according to their sensitivity and business value."),
            ("SAMA_CSF", "SAMA-CS-3", "Identity & Access Management", "", "authentication",
             "Implement IAM controls including MFA, least privilege, and regular access reviews."),
            ("SAMA_CSF", "SAMA-CS-4", "Privileged Access Management", "", "authentication",
             "Control and monitor privileged access to critical systems using PAM solutions."),
            ("SAMA_CSF", "SAMA-CS-5", "Network Security Controls", "", "threat_detection",
             "Deploy network segmentation, firewalls, and IDS/IPS to protect critical systems."),
            ("SAMA_CSF", "SAMA-CS-6", "Data Protection & Encryption", "", "data_protection",
             "Encrypt sensitive data at rest and in transit; implement DLP to prevent data exfiltration."),
            ("SAMA_CSF", "SAMA-CS-7", "Cloud Security", "", "risk_management",
             "Apply SAMA cloud security guidelines for all SaaS/IaaS deployments."),
            ("SAMA_CSF", "SAMA-CS-8", "Security Incident Management", "", "incident_response",
             "Establish and test incident response procedures; report major incidents to SAMA within 24h."),
            ("SAMA_CSF", "SAMA-CS-9", "Third-Party Risk Management", "", "risk_management",
             "Assess and monitor security of all third-party vendors with access to organizational data."),
            ("SAMA_CSF", "SAMA-CS-10", "Security Awareness & Training", "", "governance",
             "Conduct mandatory annual security awareness training for all staff."),
            # NCA ECC
            ("NCA_ECC", "ECC-CS-1", "Cybersecurity Governance", "", "governance",
             "Establish cybersecurity governance structure with board-level oversight per NCA ECC."),
            ("NCA_ECC", "ECC-CS-2", "Cybersecurity Risk Management", "", "risk_management",
             "Implement a risk management process to identify, assess, and treat cybersecurity risks."),
            ("NCA_ECC", "ECC-CS-3", "Asset Identification & Classification", "", "data_protection",
             "Maintain a comprehensive inventory of critical assets with appropriate classifications."),
            ("NCA_ECC", "ECC-CS-4", "Identity & Access Management", "", "authentication",
             "Enforce strong authentication including MFA for all users accessing critical systems."),
            ("NCA_ECC", "ECC-CS-5", "Data Protection Controls", "", "data_protection",
             "Implement technical controls to protect data in storage, processing, and transmission."),
            ("NCA_ECC", "ECC-CS-6", "Cybersecurity Incident Management", "", "incident_response",
             "Establish incident detection, response, and reporting capabilities per NCA requirements."),
            ("NCA_ECC", "ECC-CS-7", "Threat Intelligence", "", "threat_detection",
             "Subscribe to and act on threat intelligence relevant to the organization's sector."),
            ("NCA_ECC", "ECC-CS-8", "Compliance Management", "", "governance",
             "Monitor and ensure compliance with NCA ECC and other applicable cybersecurity regulations."),
            # ISO 27001 (additional controls)
            ("ISO_27001", "ISO-A5.2", "Information Security Roles & Responsibilities", "", "governance",
             "Define and assign information security roles including CISO, data owners, and custodians."),
            ("ISO_27001", "ISO-A6.1", "Screening of Personnel", "", "governance",
             "Screen employees and contractors with access to sensitive systems before employment."),
            ("ISO_27001", "ISO-A7.1", "Physical & Environmental Security", "", "governance",
             "Secure data centers and offices against physical threats; implement access controls."),
            ("ISO_27001", "ISO-A9.1", "Access Control Policy", "", "authentication",
             "Define and enforce an access control policy based on least privilege principle."),
            ("ISO_27001", "ISO-A10.1", "Cryptographic Controls", "", "data_protection",
             "Implement cryptographic controls for sensitive data protection per ISO 27001 Annex A.10."),
            ("ISO_27001", "ISO-A11.1", "Clear Desk & Screen Policy", "", "governance",
             "Enforce clear desk and clear screen policies to protect sensitive information."),
            ("ISO_27001", "ISO-A17.1", "IT Continuity Management", "", "governance",
             "Ensure IT continuity requirements are included in business continuity plans."),
            # ISO 27001
            ("ISO_27001", "ISO-A5.1",  "Information Security Policies", "", "governance",
             "Establish and maintain an information security policy set covering email communications."),
            ("ISO_27001", "ISO-A8.1",  "Inventory of Email Assets", "", "governance",
             "Maintain an accurate inventory of email infrastructure assets and associated data classifications."),
            ("ISO_27001", "ISO-A13.2", "Information Transfer Controls", "", "data_protection",
             "Implement controls for transferring information via email, including encryption and DLP policies."),
            ("ISO_27001", "ISO-A14.1", "Secure Email Gateway Development", "", "threat_detection",
             "Apply security requirements to the email gateway throughout its lifecycle."),
            ("ISO_27001", "ISO-A12.1", "Operational Anti-Spam / Anti-Malware", "", "threat_detection",
             "Deploy and maintain anti-spam and anti-malware controls on all email channels."),
            ("ISO_27001", "ISO-A15.1", "Third-Party Email Supplier Security", "", "risk_management",
             "Assess and contractually bind third-party email service providers to security requirements."),
            ("ISO_27001", "ISO-A16.1", "Incident Response for Email Threats", "", "incident_response",
             "Document and rehearse an incident response procedure specifically for email-borne threats."),
            ("ISO_27001", "ISO-A18.1", "Regulatory Compliance & Email Retention", "", "monitoring",
             "Ensure email retention policies align with legal and regulatory requirements."),
            # DORA
            ("DORA", "DORA-1", "ICT Risk Management Framework", "", "risk_management",
             "Establish an ICT risk management framework covering email and communication systems."),
            ("DORA", "DORA-2", "ICT Incident Classification & Reporting", "", "incident_response",
             "Classify and report major ICT incidents affecting email services to regulators within required timeframes."),
            ("DORA", "DORA-3", "Digital Operational Resilience Testing", "", "monitoring",
             "Perform regular resilience testing of email infrastructure including threat-led penetration testing."),
            ("DORA", "DORA-4", "Third-Party ICT Risk (Email Providers)", "", "risk_management",
             "Manage and monitor ICT third-party risks for email cloud providers and managed services."),
            ("DORA", "DORA-5", "Cyber Threat Information Sharing", "", "monitoring",
             "Participate in information-sharing arrangements on email threat intelligence with sector peers."),
            ("DORA", "DORA-6", "Business Continuity for Email Systems", "", "governance",
             "Maintain a tested business continuity plan ensuring email availability during disruptions."),
            ("DORA", "DORA-7", "RPO / RTO Objectives for Email", "", "governance",
             "Define and validate Recovery Point Objectives and Recovery Time Objectives for email services."),
            # NIS2
            ("NIS2", "NIS2-1", "Risk Management Measures", "", "risk_management",
             "Implement appropriate technical and organisational measures to manage cybersecurity risks to email systems."),
            ("NIS2", "NIS2-2", "Incident Handling", "", "incident_response",
             "Establish and exercise an incident handling capability covering email-related security events."),
            ("NIS2", "NIS2-3", "Business Continuity", "", "governance",
             "Maintain email service continuity plans including backup systems and disaster recovery."),
            ("NIS2", "NIS2-4", "Supply Chain Security", "", "risk_management",
             "Assess cybersecurity of email supply chain including third-party providers and software components."),
            ("NIS2", "NIS2-5", "Network Security (Email Gateway Hardening)", "", "threat_detection",
             "Harden email gateway and network perimeter controls against known attack vectors."),
            ("NIS2", "NIS2-6", "Access Control and MFA", "", "authentication",
             "Enforce multi-factor authentication and least-privilege access to email administration interfaces."),
            ("NIS2", "NIS2-7", "Vulnerability Management", "", "risk_management",
             "Identify, assess, and remediate vulnerabilities in email platforms and related components."),
            ("NIS2", "NIS2-8", "Encryption in Transit / at Rest", "", "data_protection",
             "Encrypt email data in transit (TLS) and at rest using approved cryptographic standards."),
        ]

        eu_ctrl_count = 0
        for fw, cid, name_en, name_ar, etype, description in eu_controls:
            existing_ctrl = await db.execute(
                select(ComplianceControl).where(
                    ComplianceControl.framework == fw,
                    ComplianceControl.control_id == cid,
                )
            )
            if existing_ctrl.scalar_one_or_none() is None:
                ctrl = ComplianceControl(
                    framework=fw,
                    control_id=cid,
                    control_name_en=name_en,
                    control_name_ar=name_ar,
                    evidence_type=etype,
                )
                # Store description if the model supports it
                if hasattr(ctrl, 'description'):
                    ctrl.description = description
                db.add(ctrl)
                eu_ctrl_count += 1

        await db.flush()
        print(f"✓ Seeded {eu_ctrl_count} EU/UK compliance controls (GDPR, ISO 27001, DORA, NIS2)")

        await db.commit()

        # ── Vendor Admin Seed Data ──────────────────────────────────────────
        print("\n📊 Seeding vendor admin data (multi-tenant orgs + usage)...")

        demo_orgs = [
            {"name": "Gulf Finance Co", "domain": "gulffinance.sa", "plan": "enterprise", "country": "Saudi Arabia", "mailboxes": 450, "rate": 8.00, "contact_name": "Ahmed Al-Rashid", "contact_email": "ahmed@gulffinance.sa"},
            {"name": "Emirates Trade Bank", "domain": "emiratestrade.ae", "plan": "professional", "country": "UAE", "mailboxes": 180, "rate": 8.00, "contact_name": "Fatima Hassan", "contact_email": "fatima@emiratestrade.ae"},
            {"name": "Kuwait Capital Group", "domain": "kuwaitcapital.kw", "plan": "professional", "country": "Kuwait", "mailboxes": 120, "rate": 8.00, "contact_name": "Khalid Al-Sabah", "contact_email": "khalid@kuwaitcapital.kw"},
            {"name": "Riyadh Fintech Startup", "domain": "riyadhfintech.sa", "plan": "starter", "country": "Saudi Arabia", "mailboxes": 35, "rate": 8.00, "contact_name": "Sara Al-Otaibi", "contact_email": "sara@riyadhfintech.sa"},
            {"name": "Doha Insurance Ltd", "domain": "dohainsurance.qa", "plan": "starter", "country": "Qatar", "mailboxes": 60, "rate": 8.00, "contact_name": "Mohammed Al-Thani", "contact_email": "mo@dohainsurance.qa"},
        ]

        email_volume_by_plan = {"enterprise": (80000, 120000), "professional": (25000, 50000), "starter": (3000, 10000)}
        threat_ratio = 0.08

        now = datetime.utcnow()
        for demo_org_data in demo_orgs:
            # Check if domain already exists
            existing_org = await db.execute(select(Organization).where(Organization.domain == demo_org_data["domain"]))
            if existing_org.scalar_one_or_none():
                print(f"  ↳ Skipping {demo_org_data['name']} (already exists)")
                continue

            demo_org = Organization(
                name=demo_org_data["name"],
                domain=demo_org_data["domain"],
                plan=demo_org_data["plan"],
                country=demo_org_data["country"],
                mailbox_count=demo_org_data["mailboxes"],
            )
            db.add(demo_org)
            await db.flush()

            await db.execute(
                text("""UPDATE organizations SET mailbox_limit = :ml, billing_rate_usd = :br,
                         contact_email = :ce, contact_name = :cn, status = 'active' WHERE id = :oid"""),
                {"ml": demo_org_data["mailboxes"] + 50, "br": demo_org_data["rate"],
                 "ce": demo_org_data["contact_email"], "cn": demo_org_data["contact_name"], "oid": str(demo_org.id)},
            )

            # Create admin user
            demo_user = User(
                org_id=demo_org.id,
                email=f"admin@{demo_org_data['domain']}",
                name=demo_org_data["contact_name"],
                role="admin",
                password_hash=pwd_context.hash("SentinelDemo123!"),
                is_active=True,
            )
            db.add(demo_user)
            await db.flush()

            # Seed monthly usage + billing for last 6 months
            lo, hi = email_volume_by_plan[demo_org_data["plan"]]
            for months_back in range(6, 0, -1):
                target = now - timedelta(days=30 * months_back)
                yr, mo = target.year, target.month
                emails = random.randint(lo, hi)
                threats_cnt = int(emails * threat_ratio)
                quarantined = int(threats_cnt * 0.6)
                blocked = int(threats_cnt * 0.3)
                period = f"{yr}-{str(mo).zfill(2)}"
                base_amount = demo_org_data["mailboxes"] * demo_org_data["rate"]

                await db.execute(
                    text("""
                        INSERT INTO monthly_usage (org_id, year, month, emails_scanned, threats_detected,
                            emails_quarantined, emails_blocked, reports_generated)
                        VALUES (:oid, :yr, :mo, :es, :td, :eq, :eb, :rg)
                        ON CONFLICT (org_id, year, month) DO NOTHING
                    """),
                    {"oid": str(demo_org.id), "yr": yr, "mo": mo, "es": emails, "td": threats_cnt,
                     "eq": quarantined, "eb": blocked, "rg": random.randint(1, 5)},
                )
                await db.execute(
                    text("""
                        INSERT INTO billing_records (org_id, billing_period, plan, mailbox_count, emails_scanned,
                            rate_per_mailbox_usd, base_amount_usd, overage_amount_usd, total_amount_usd, status, invoice_id)
                        VALUES (:oid, :period, :plan, :mc, :es, :rate, :base, 0, :total, 'paid',
                                :inv_id)
                        ON CONFLICT (org_id, billing_period) DO NOTHING
                    """),
                    {"oid": str(demo_org.id), "period": period, "plan": demo_org_data["plan"],
                     "mc": demo_org_data["mailboxes"], "es": emails, "rate": demo_org_data["rate"],
                     "base": base_amount, "total": base_amount,
                     "inv_id": f"INV-{yr}{str(mo).zfill(2)}-{str(demo_org.id)[:8].upper()}"},
                )

            # Current month usage (partial)
            current_emails = random.randint(lo // 3, hi // 2)
            await db.execute(
                text("""
                    INSERT INTO monthly_usage (org_id, year, month, emails_scanned, threats_detected,
                        emails_quarantined, emails_blocked)
                    VALUES (:oid, :yr, :mo, :es, :td, :eq, :eb)
                    ON CONFLICT (org_id, year, month) DO NOTHING
                """),
                {"oid": str(demo_org.id), "yr": now.year, "mo": now.month,
                 "es": current_emails, "td": int(current_emails * threat_ratio),
                 "eq": int(current_emails * threat_ratio * 0.6),
                 "eb": int(current_emails * threat_ratio * 0.3)},
            )

            print(f"  ✓ {demo_org_data['name']} ({demo_org_data['plan']}) — {demo_org_data['mailboxes']} mailboxes")

        await db.commit()
        print("✓ Vendor admin seed data complete")

        print("\n✅ Seed complete!")
        print("\n" + "=" * 50)
        print("DEMO LOGIN CREDENTIALS")
        print("=" * 50)
        print(f"Admin:      admin@acmefintech.com      / SentinelDemo123!")
        print(f"Analyst:    analyst@acmefintech.com    / SentinelDemo123!")
        print(f"Compliance: compliance@acmefintech.com / SentinelDemo123!")
        print(f"\nVendor Admin Portal: http://localhost:3000/admin")
        print(f"Vendor Admin Login:  sentinel-admin@himayahelios.io / SentinelVendor2026!")
        print("=" * 50)
        print(f"\nAPI Docs: http://localhost:8000/docs")
        print(f"Health:   http://localhost:8000/health")

    await engine.dispose()


if __name__ == "__main__":
    asyncio.run(seed())
