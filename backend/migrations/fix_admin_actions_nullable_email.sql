-- 2026-06-17 audit fix #3
--
-- Microsoft Graph directoryAudits returns system-initiated events
-- (Group lifecycle policies, automated mailbox processes, etc.) where
-- initiatedBy.user is present but userPrincipalName is null. Our scanner
-- coerces these to "System" now, but pre-existing rows / old code paths
-- can still hit the NOT NULL constraint. Relax the column so the fallback
-- chain works even in transient states.
ALTER TABLE saas_admin_actions
    ALTER COLUMN admin_email DROP NOT NULL;
