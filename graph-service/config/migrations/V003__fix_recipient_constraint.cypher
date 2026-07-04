// V003 — Replace V001 unique constraint on Recipient.email with org-scoped composite index.
//
// V001 created FOR (r:Recipient) REQUIRE r.email IS UNIQUE — this blocks multi-tenant
// scenarios where two orgs share a recipient email address (e.g. admin@acme.com).
// V002 added the composite index (email, org_id) which is the correct lookup key for
// all MERGE and MATCH calls in write.py and query.py, but never dropped the V001 constraint.
//
// Safe to re-run — DROP CONSTRAINT is idempotent when the constraint name is stable.

DROP CONSTRAINT recipient_email_unique IF EXISTS;
