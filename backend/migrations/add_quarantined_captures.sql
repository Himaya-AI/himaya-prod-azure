-- Encrypted copies of quarantined mail that was pulled fully OUT of the user's
-- mailbox (hard-capture quarantine). Himaya holds the copy so the end user
-- cannot see it anywhere; an admin release re-injects it into the inbox.
-- See backend/services/mailbox_capture_service.py. This is also created
-- idempotently at startup in backend/main.py; this file documents the schema.

CREATE TABLE IF NOT EXISTS quarantined_captures (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    threat_id UUID REFERENCES threats(id) ON DELETE SET NULL,
    provider VARCHAR(20) NOT NULL,              -- 'google' | 'm365'
    user_email VARCHAR(255) NOT NULL,           -- recipient mailbox
    original_message_id TEXT NOT NULL,          -- provider message id pre-delete
    internet_message_id TEXT,                   -- RFC822 Message-ID
    raw_encrypted TEXT NOT NULL,                -- base64(fernet(gzip(mime)))
    size_bytes INTEGER DEFAULT 0,
    status VARCHAR(20) DEFAULT 'held',          -- 'held' | 'released'
    captured_at TIMESTAMPTZ DEFAULT NOW(),
    released_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS ix_quarantined_captures_lookup
    ON quarantined_captures (org_id, user_email, original_message_id);
