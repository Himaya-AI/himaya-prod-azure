// V002 — Full schema: constraints and indexes for all node types
// Properties are set at write time via MERGE — this file defines the schema only.
// All statements use IF NOT EXISTS so this is safe to re-run.

// ── Sender ────────────────────────────────────────────────────────────────────
// Properties: email, domain, first_seen, last_seen, email_count, threat_count, reputation_score
CREATE CONSTRAINT sender_email_unique IF NOT EXISTS
  FOR (s:Sender) REQUIRE s.email IS UNIQUE;

CREATE INDEX sender_domain IF NOT EXISTS
  FOR (s:Sender) ON (s.domain);

CREATE INDEX sender_reputation IF NOT EXISTS
  FOR (s:Sender) ON (s.reputation_score);

// ── Recipient ─────────────────────────────────────────────────────────────────
// Properties: email, org_id
// NODE KEY requires Enterprise — composite index used on Community Edition
CREATE INDEX recipient_email_org IF NOT EXISTS
  FOR (r:Recipient) ON (r.email, r.org_id);

// ── Domain ────────────────────────────────────────────────────────────────────
// Properties: name, threat_score, first_seen, last_seen
CREATE CONSTRAINT domain_name_unique IF NOT EXISTS
  FOR (d:Domain) REQUIRE d.name IS UNIQUE;

CREATE INDEX domain_threat_score IF NOT EXISTS
  FOR (d:Domain) ON (d.threat_score);

// ── ThreatType ────────────────────────────────────────────────────────────────
// Properties: type
CREATE CONSTRAINT threat_type_unique IF NOT EXISTS
  FOR (t:ThreatType) REQUIRE t.type IS UNIQUE;

// ── Reporter ──────────────────────────────────────────────────────────────────
// Properties: email, org_id
// NODE KEY requires Enterprise — composite index used on Community Edition
CREATE INDEX reporter_email_org IF NOT EXISTS
  FOR (rep:Reporter) ON (rep.email, rep.org_id);

// ── Email ─────────────────────────────────────────────────────────────────────
// Properties: message_id, subject, subject_hash, received_at, llm_verdict, risk_score
CREATE CONSTRAINT email_message_id_unique IF NOT EXISTS
  FOR (e:Email) REQUIRE e.message_id IS UNIQUE;

CREATE INDEX email_risk_score IF NOT EXISTS
  FOR (e:Email) ON (e.risk_score);

CREATE INDEX email_received_at IF NOT EXISTS
  FOR (e:Email) ON (e.received_at);

// ── URL ───────────────────────────────────────────────────────────────────────
// Properties: url, domain, reputation_score, first_seen, last_seen
// Unique on full URL string — same URL across different emails is the same node.
// domain is denormalised here for fast lookup without traversing HOSTED_ON edge.
CREATE CONSTRAINT url_unique IF NOT EXISTS
  FOR (u:URL) REQUIRE u.url IS UNIQUE;

CREATE INDEX url_domain IF NOT EXISTS
  FOR (u:URL) ON (u.domain);

CREATE INDEX url_reputation IF NOT EXISTS
  FOR (u:URL) ON (u.reputation_score);

// ── Attachment ────────────────────────────────────────────────────────────────
// Properties: sha256, filename, extension, reputation_score
// Unique on sha256 — same file with different filenames is still the same node.
// filename is stored but NOT the unique key — sha256 is canonical.
CREATE CONSTRAINT attachment_sha256_unique IF NOT EXISTS
  FOR (a:Attachment) REQUIRE a.sha256 IS UNIQUE;

CREATE INDEX attachment_extension IF NOT EXISTS
  FOR (a:Attachment) ON (a.extension);

CREATE INDEX attachment_reputation IF NOT EXISTS
  FOR (a:Attachment) ON (a.reputation_score);

// ── Organization ──────────────────────────────────────────────────────────────
// Properties: org_id, name
CREATE CONSTRAINT org_id_unique IF NOT EXISTS
  FOR (o:Organization) REQUIRE o.org_id IS UNIQUE;
