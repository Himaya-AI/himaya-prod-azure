-- Migration: Add LLM classifier metadata + analyst feedback columns to threats
-- Run against: sentinel_mail DB on RDS

BEGIN;

ALTER TABLE threats
    ADD COLUMN IF NOT EXISTS llm_classification     VARCHAR(50),
    ADD COLUMN IF NOT EXISTS llm_confidence         REAL,
    ADD COLUMN IF NOT EXISTS llm_model              VARCHAR(100),
    ADD COLUMN IF NOT EXISTS llm_cost_usd           REAL,
    ADD COLUMN IF NOT EXISTS impersonation_detected BOOLEAN DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS impersonation_target   VARCHAR(255),
    ADD COLUMN IF NOT EXISTS urgency_score          INTEGER,
    ADD COLUMN IF NOT EXISTS analyst_verdict        VARCHAR(50),
    ADD COLUMN IF NOT EXISTS analyst_email          VARCHAR(255),
    ADD COLUMN IF NOT EXISTS analyst_notes          TEXT,
    ADD COLUMN IF NOT EXISTS reviewed_at            TIMESTAMPTZ;

CREATE TABLE IF NOT EXISTS org_metrics (
    org_id      UUID PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
    feedback_tp INTEGER DEFAULT 0,
    feedback_fp INTEGER DEFAULT 0,
    feedback_tn INTEGER DEFAULT 0,
    updated_at  TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_threats_analyst_verdict ON threats(org_id, analyst_verdict);
CREATE INDEX IF NOT EXISTS idx_threats_llm_model ON threats(llm_model);

COMMIT;
