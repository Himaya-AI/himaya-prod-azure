-- Migration: Add missing columns to billing_records
-- Safe to run multiple times (uses IF NOT EXISTS / DO NOTHING)

ALTER TABLE billing_records
    ADD COLUMN IF NOT EXISTS plan                VARCHAR(50)   DEFAULT 'starter',
    ADD COLUMN IF NOT EXISTS mailbox_count       INTEGER       DEFAULT 0,
    ADD COLUMN IF NOT EXISTS emails_scanned      INTEGER       DEFAULT 0,
    ADD COLUMN IF NOT EXISTS rate_per_mailbox_usd NUMERIC(10,2) DEFAULT 8.00,
    ADD COLUMN IF NOT EXISTS base_amount_usd     NUMERIC(10,2) DEFAULT 0,
    ADD COLUMN IF NOT EXISTS overage_amount_usd  NUMERIC(10,2) DEFAULT 0,
    ADD COLUMN IF NOT EXISTS paid_at             TIMESTAMPTZ;
