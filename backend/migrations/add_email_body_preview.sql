-- Migration: add email_body_preview to threats table
-- Stores first 1500 chars of plain-text body at detection time
-- Used for ThreatDetail UI preview and richer notification emails

ALTER TABLE threats
  ADD COLUMN IF NOT EXISTS email_body_preview TEXT;
