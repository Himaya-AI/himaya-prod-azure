-- Comprehensive migration: add all missing columns
-- Safe to run multiple times

ALTER TABLE organizations
    ADD COLUMN IF NOT EXISTS status           VARCHAR(50)    DEFAULT 'active',
    ADD COLUMN IF NOT EXISTS mailbox_limit    INTEGER        DEFAULT 100,
    ADD COLUMN IF NOT EXISTS billing_rate_usd NUMERIC(10,2)  DEFAULT 8.00,
    ADD COLUMN IF NOT EXISTS contact_email    VARCHAR(255),
    ADD COLUMN IF NOT EXISTS contact_name     VARCHAR(255),
    ADD COLUMN IF NOT EXISTS suspended_at     TIMESTAMPTZ;

ALTER TABLE billing_records
    ADD COLUMN IF NOT EXISTS plan                VARCHAR(50)    DEFAULT 'starter',
    ADD COLUMN IF NOT EXISTS mailbox_count       INTEGER        DEFAULT 0,
    ADD COLUMN IF NOT EXISTS emails_scanned      INTEGER        DEFAULT 0,
    ADD COLUMN IF NOT EXISTS rate_per_mailbox_usd NUMERIC(10,2) DEFAULT 8.00,
    ADD COLUMN IF NOT EXISTS base_amount_usd     NUMERIC(10,2)  DEFAULT 0,
    ADD COLUMN IF NOT EXISTS overage_amount_usd  NUMERIC(10,2)  DEFAULT 0,
    ADD COLUMN IF NOT EXISTS paid_at             TIMESTAMPTZ;

-- Add plaintext subject to threats for searchability
ALTER TABLE threats ADD COLUMN IF NOT EXISTS subject TEXT;

-- Add subject to email_processor output
