-- Organizations
CREATE TABLE IF NOT EXISTS organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    domain VARCHAR(255) NOT NULL UNIQUE,
    plan VARCHAR(50) DEFAULT 'starter',
    country VARCHAR(50),
    mailbox_count INTEGER DEFAULT 0,
    risk_score INTEGER DEFAULT 0,
    compliance_score INTEGER DEFAULT 0,
    timezone VARCHAR(100) DEFAULT 'Asia/Riyadh',
    language VARCHAR(10) DEFAULT 'en',
    mfa_enforced BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Users
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL UNIQUE,
    name VARCHAR(255),
    department VARCHAR(255),
    job_title VARCHAR(255),
    manager_email VARCHAR(255),
    role VARCHAR(50) DEFAULT 'analyst',
    cognito_id VARCHAR(255) UNIQUE,
    password_hash VARCHAR(255),
    is_vip BOOLEAN DEFAULT FALSE,
    is_active BOOLEAN DEFAULT TRUE,
    risk_score INTEGER DEFAULT 0,
    m365_user_id VARCHAR(255),
    last_login TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Org Integrations
CREATE TABLE IF NOT EXISTS org_integrations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    provider VARCHAR(50) NOT NULL,
    access_token_enc TEXT,
    refresh_token_enc TEXT,
    token_expiry TIMESTAMPTZ,
    scope TEXT,
    webhook_subscription_id VARCHAR(255),
    status VARCHAR(50) DEFAULT 'active',
    connected_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Threats
CREATE TABLE IF NOT EXISTS threats (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    email_message_id VARCHAR(500),
    sender VARCHAR(255),
    sender_domain VARCHAR(255),
    recipient_user_id UUID REFERENCES users(id),
    recipient_email VARCHAR(255),
    subject_hash VARCHAR(64),
    threat_type VARCHAR(50),
    risk_score INTEGER,
    score_breakdown JSONB,
    graph_score INTEGER,
    content_score INTEGER,
    reputation_score INTEGER,
    status VARCHAR(50) DEFAULT 'open',
    action_taken VARCHAR(50),
    ai_explanation_ar TEXT,
    ai_explanation_en TEXT,
    threat_indicators JSONB,
    sama_controls TEXT[],
    nca_controls TEXT[],
    policy_id UUID,
    false_positive BOOLEAN DEFAULT FALSE,
    detected_at TIMESTAMPTZ DEFAULT NOW(),
    resolved_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Policies
CREATE TABLE IF NOT EXISTS policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    priority INTEGER DEFAULT 100,
    status VARCHAR(50) DEFAULT 'draft',
    conditions JSONB NOT NULL,
    action VARCHAR(50) NOT NULL,
    action_config JSONB,
    m365_rule_id VARCHAR(255),
    shadow_start TIMESTAMPTZ,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Policy Evaluations
CREATE TABLE IF NOT EXISTS policy_evaluations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_id UUID REFERENCES policies(id),
    threat_id UUID REFERENCES threats(id),
    matched BOOLEAN DEFAULT FALSE,
    action_taken VARCHAR(50),
    shadow_mode BOOLEAN DEFAULT FALSE,
    evaluated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Compliance Controls
CREATE TABLE IF NOT EXISTS compliance_controls (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    framework VARCHAR(50) NOT NULL,
    control_id VARCHAR(50) NOT NULL,
    control_name_en TEXT NOT NULL,
    control_name_ar TEXT NOT NULL,
    description_en TEXT,
    description_ar TEXT,
    evidence_type VARCHAR(100),
    UNIQUE(framework, control_id)
);

-- Compliance Status per org
CREATE TABLE IF NOT EXISTS compliance_status (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    control_id UUID REFERENCES compliance_controls(id),
    status VARCHAR(50) DEFAULT 'not_started',
    evidence_count INTEGER DEFAULT 0,
    last_evidence_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(org_id, control_id)
);

-- Compliance Evidence
CREATE TABLE IF NOT EXISTS compliance_evidence (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    threat_id UUID REFERENCES threats(id),
    control_ids TEXT[],
    framework VARCHAR(50),
    action_taken VARCHAR(255),
    outcome VARCHAR(255),
    s3_key TEXT,
    immutable BOOLEAN DEFAULT TRUE,
    retention_tier VARCHAR(20) DEFAULT '1_year',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Audit Logs
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID REFERENCES organizations(id),
    user_id UUID REFERENCES users(id),
    action VARCHAR(255) NOT NULL,
    resource_type VARCHAR(100),
    resource_id UUID,
    old_value JSONB,
    new_value JSONB,
    ip_address VARCHAR(45),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Generated Reports
CREATE TABLE IF NOT EXISTS reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    report_type VARCHAR(100),
    framework VARCHAR(50),
    date_range_start DATE,
    date_range_end DATE,
    status VARCHAR(50) DEFAULT 'pending',
    s3_key TEXT,
    generated_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_threats_org_id ON threats(org_id);
CREATE INDEX IF NOT EXISTS idx_threats_detected_at ON threats(detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_threats_risk_score ON threats(risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_threats_status ON threats(status);
CREATE INDEX IF NOT EXISTS idx_threats_threat_type ON threats(threat_type);
CREATE INDEX IF NOT EXISTS idx_users_org_id ON users(org_id);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_compliance_evidence_org_id ON compliance_evidence(org_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_org_id ON audit_logs(org_id);

-- Seed compliance controls
INSERT INTO compliance_controls (framework, control_id, control_name_en, control_name_ar, evidence_type) VALUES
('SAMA_CSF', '3.3.3', 'Email Security Controls', 'ضوابط أمن البريد الإلكتروني', 'threat_detection'),
('SAMA_CSF', '3.3.5', 'Anti-Phishing Controls', 'ضوابط مكافحة التصيد الاحتيالي', 'threat_detection'),
('SAMA_CSF', '3.4.1', 'Incident Response', 'الاستجابة للحوادث', 'incident_response'),
('NCA_ECC', '2-7-1', 'Email Authentication', 'مصادقة البريد الإلكتروني', 'authentication'),
('NCA_ECC', '2-7-2', 'Anti-Spoofing', 'مكافحة الانتحال', 'threat_detection'),
('NCA_ECC', '2-7-3', 'BEC Protection', 'الحماية من احتيال البريد التجاري', 'threat_detection'),
('NCA_ECC', '2-7-4', 'Government Impersonation Protection', 'الحماية من انتحال الجهات الحكومية', 'threat_detection'),
('NCA_ECC', '2-7-5', 'Malware Protection', 'الحماية من البرمجيات الخبيثة', 'threat_detection'),
('UAE_NESA', 'IAS-T07', 'Email Security Controls', 'ضوابط أمن البريد الإلكتروني', 'threat_detection'),
('CBUAE', 'EMAIL-001', 'Email Protection Domain', 'نطاق حماية البريد الإلكتروني', 'threat_detection'),
-- NIST CSF (Email Security Controls)
('NIST_CSF', 'PR.AC-1', 'Identity Management & Authentication', 'Identity Management & Authentication', 'authentication'),
('NIST_CSF', 'PR.AC-3', 'Remote Access Management', 'Remote Access Management', 'access_control'),
('NIST_CSF', 'PR.DS-1', 'Data-at-Rest Protection', 'Data-at-Rest Protection', 'data_protection'),
('NIST_CSF', 'PR.DS-2', 'Data-in-Transit Protection', 'Data-in-Transit Protection', 'data_protection'),
('NIST_CSF', 'DE.AE-1', 'Baseline Network Operations', 'Baseline Network Operations', 'threat_detection'),
('NIST_CSF', 'DE.AE-2', 'Anomaly & Event Detection', 'Anomaly & Event Detection', 'threat_detection'),
('NIST_CSF', 'DE.CM-1', 'Network Continuous Monitoring', 'Network Continuous Monitoring', 'monitoring'),
('NIST_CSF', 'DE.CM-7', 'Unauthorized Activity Monitoring', 'Unauthorized Activity Monitoring', 'monitoring'),
('NIST_CSF', 'RS.RP-1', 'Response Plan Execution', 'Response Plan Execution', 'incident_response'),
('NIST_CSF', 'RS.CO-3', 'Information Sharing', 'Information Sharing', 'incident_response'),
-- HIPAA (Email / PHI Protection)
('HIPAA', '164.312(a)(1)', 'Access Control — Unique User Identification', 'Access Control — Unique User Identification', 'authentication'),
('HIPAA', '164.312(a)(2)(i)', 'Emergency Access Procedure', 'Emergency Access Procedure', 'access_control'),
('HIPAA', '164.312(b)', 'Audit Controls', 'Audit Controls', 'monitoring'),
('HIPAA', '164.312(c)(1)', 'Integrity — ePHI Protection', 'Integrity — ePHI Protection', 'data_protection'),
('HIPAA', '164.312(d)', 'Person or Entity Authentication', 'Person or Entity Authentication', 'authentication'),
('HIPAA', '164.312(e)(1)', 'Transmission Security — Encryption', 'Transmission Security — Encryption', 'data_protection'),
('HIPAA', '164.308(a)(1)', 'Risk Analysis & Management', 'Risk Analysis & Management', 'risk_management'),
('HIPAA', '164.308(a)(5)', 'Security Awareness Training', 'Security Awareness Training', 'training'),
('HIPAA', '164.308(a)(6)', 'Security Incident Procedures', 'Security Incident Procedures', 'incident_response'),
('HIPAA', '164.308(a)(7)', 'Contingency Plan', 'Contingency Plan', 'incident_response'),
-- SOC 2 (Trust Services Criteria)
('SOC2', 'CC1.1', 'COSO — Board Oversight of Controls', 'COSO — Board Oversight of Controls', 'governance'),
('SOC2', 'CC2.1', 'Communication of Internal Control Info', 'Communication of Internal Control Info', 'governance'),
('SOC2', 'CC3.1', 'Risk Assessment — Specify Objectives', 'Risk Assessment — Specify Objectives', 'risk_management'),
('SOC2', 'CC3.2', 'Risk Identification & Analysis', 'Risk Identification & Analysis', 'risk_management'),
('SOC2', 'CC6.1', 'Logical & Physical Access Controls', 'Logical & Physical Access Controls', 'access_control'),
('SOC2', 'CC6.6', 'Security Against Threats — External', 'Security Against Threats — External', 'threat_detection'),
('SOC2', 'CC6.7', 'Data Transmission & Movement Controls', 'Data Transmission & Movement Controls', 'data_protection'),
('SOC2', 'CC7.1', 'Threat Detection & Monitoring', 'Threat Detection & Monitoring', 'monitoring'),
('SOC2', 'CC7.2', 'Monitoring for Anomalies', 'Monitoring for Anomalies', 'monitoring'),
('SOC2', 'CC7.3', 'Incident Identification & Response', 'Incident Identification & Response', 'incident_response'),
('SOC2', 'CC7.4', 'Incident Response & Recovery', 'Incident Response & Recovery', 'incident_response'),
('SOC2', 'CC8.1', 'Change Management Controls', 'Change Management Controls', 'governance'),
-- CCPA (Email / PII Protection)
('CCPA', '1798.100', 'Right to Know — Data Access', 'Right to Know — Data Access', 'data_protection'),
('CCPA', '1798.105', 'Right to Delete Personal Information', 'Right to Delete Personal Information', 'data_protection'),
('CCPA', '1798.110', 'Right to Know — Categories Collected', 'Right to Know — Categories Collected', 'data_protection'),
('CCPA', '1798.115', 'Right to Know — Data Sharing', 'Right to Know — Data Sharing', 'governance'),
('CCPA', '1798.120', 'Right to Opt-Out of Sale', 'Right to Opt-Out of Sale', 'governance'),
('CCPA', '1798.135', 'Methods for Submitting Opt-Out', 'Methods for Submitting Opt-Out', 'governance'),
('CCPA', '1798.150', 'Private Right of Action — Data Breach', 'Private Right of Action — Data Breach', 'incident_response'),
('CCPA', '1798.155', 'AG Enforcement & Civil Penalties', 'AG Enforcement & Civil Penalties', 'governance')
ON CONFLICT (framework, control_id) DO NOTHING;
