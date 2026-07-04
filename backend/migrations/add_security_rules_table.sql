-- Security Rules Table - stores configurable alert rules per org/provider
-- Created: 2026-06-07

CREATE TABLE IF NOT EXISTS security_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,  -- NULL = global default
    provider VARCHAR(50) NOT NULL,  -- aws, teams, sharepoint, onedrive, m365
    rule_name VARCHAR(255) NOT NULL,
    description TEXT,
    severity VARCHAR(20) DEFAULT 'medium',
    enabled BOOLEAN DEFAULT TRUE,
    conditions JSONB DEFAULT '{}',  -- rule matching conditions
    ai_analysis BOOLEAN DEFAULT FALSE,  -- use AI for analysis
    remediation_steps TEXT[] DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Worker status tracking table (Redis-backed, with DB fallback)
CREATE TABLE IF NOT EXISTS saas_worker_status (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    worker_name VARCHAR(100) NOT NULL,
    status VARCHAR(50) DEFAULT 'running',
    last_run TIMESTAMPTZ,
    next_run TIMESTAMPTZ,
    last_error TEXT,
    run_count INTEGER DEFAULT 0,
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(org_id, worker_name)
);
