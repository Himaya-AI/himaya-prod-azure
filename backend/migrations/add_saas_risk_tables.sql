-- Add missing SaaS risk tables
-- Created: 2026-06-04

CREATE TABLE IF NOT EXISTS saas_risky_users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_email VARCHAR(255) NOT NULL,
    user_id VARCHAR(255),
    risk_level VARCHAR(50) NOT NULL,
    risk_state VARCHAR(100),
    risk_detail TEXT,
    risk_last_updated_at TIMESTAMPTZ,
    provider VARCHAR(50) NOT NULL DEFAULT 'microsoft',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT uq_saas_risky_users_org_email UNIQUE (org_id, user_email, provider)
);

CREATE TABLE IF NOT EXISTS saas_admin_actions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    admin_email VARCHAR(255) NOT NULL,
    action_type VARCHAR(255) NOT NULL,
    target_type VARCHAR(100),
    target_id VARCHAR(500),
    target_name TEXT,
    details JSONB,
    provider VARCHAR(50) NOT NULL DEFAULT 'microsoft',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS saas_user_risk_scores (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_email VARCHAR(255) NOT NULL,
    user_id VARCHAR(255),
    display_name VARCHAR(255),
    job_title VARCHAR(255),
    department VARCHAR(255),
    risk_score INTEGER DEFAULT 0,
    risk_factors JSONB DEFAULT '[]',
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT uq_saas_user_risk_scores_org_email UNIQUE (org_id, user_email)
);
