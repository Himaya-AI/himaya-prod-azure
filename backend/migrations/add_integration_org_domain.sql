-- Migration: add org_domain to org_integrations
-- Stores the domain discovered from each provider's OAuth separately,
-- so M365 and Google can each have their own domain without overwriting each other.
ALTER TABLE org_integrations
  ADD COLUMN IF NOT EXISTS org_domain VARCHAR(255);
