-- Compliance score history snapshots — one row per (org, framework, day)
-- Used by /api/compliance/history for trend charts and audit timelines.
CREATE TABLE IF NOT EXISTS compliance_score_snapshots (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    framework VARCHAR(50) NOT NULL,
    score_pct INTEGER NOT NULL,
    total_controls INTEGER NOT NULL DEFAULT 0,
    compliant INTEGER NOT NULL DEFAULT 0,
    partial INTEGER NOT NULL DEFAULT 0,
    non_compliant INTEGER NOT NULL DEFAULT 0,
    captured_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_compliance_snap_org_fw_time
    ON compliance_score_snapshots (org_id, framework, captured_at DESC);

-- One snapshot per org+framework+day (rolling).
-- We can't index `(captured_at::date)` directly because PostgreSQL
-- considers the cast STABLE, not IMMUTABLE, and refuses to build a
-- functional index from it. `date_trunc('day', timestamptz, 'UTC')` is
-- explicitly IMMUTABLE when the time zone is a literal.
CREATE UNIQUE INDEX IF NOT EXISTS uq_compliance_snap_daily
    ON compliance_score_snapshots (org_id, framework, (date_trunc('day', captured_at AT TIME ZONE 'UTC')));

-- Add rationale and evidence_summary to ComplianceStatus for per-control "why"
ALTER TABLE compliance_status ADD COLUMN IF NOT EXISTS rationale TEXT;
ALTER TABLE compliance_status ADD COLUMN IF NOT EXISTS evidence_summary JSONB;
