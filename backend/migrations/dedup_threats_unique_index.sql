-- Deduplication: prevent duplicate threat rows for same message_id + recipient + org
-- This races condition between concurrent delta sync cycles inserting the same email twice.
-- Using a partial unique index so NULL email_message_id rows are excluded.
-- The index is CONCURRENTLY so it doesn't lock the table in production.

CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS uq_threats_msg_recipient_org
  ON threats (email_message_id, org_id, recipient_email)
  WHERE email_message_id IS NOT NULL
    AND email_message_id != ''
    AND recipient_email IS NOT NULL;
