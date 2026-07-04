// V004 — Remove Campaign node schema.
// Campaign ingestion is deferred; the node type, constraints, and indexes are removed
// until a proper feed integration is added.
// Safe to re-run — all statements use IF EXISTS.

DROP CONSTRAINT campaign_id_unique IF EXISTS;
DROP INDEX campaign_first_seen IF EXISTS;
DROP INDEX campaign_confidence IF EXISTS;
