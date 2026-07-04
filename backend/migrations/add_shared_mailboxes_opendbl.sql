-- Migration: Add shared mailbox tracking + OpenDBL support
-- Run: idempotent (IF NOT EXISTS guards throughout)

-- shared_count on org_integrations (tracks discovered M365 shared mailboxes)
ALTER TABLE org_integrations
    ADD COLUMN IF NOT EXISTS shared_count INTEGER DEFAULT 0;

-- Ensure email_groups has all columns needed for shared mailbox upsert
ALTER TABLE email_groups
    ADD COLUMN IF NOT EXISTS description TEXT;

ALTER TABLE email_groups
    ADD COLUMN IF NOT EXISTS last_synced_at TIMESTAMPTZ DEFAULT NOW();

-- Index for fast org-level group lookups
CREATE INDEX IF NOT EXISTS idx_email_groups_org_id ON email_groups(org_id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_email_groups_org_email ON email_groups(org_id, group_email);
