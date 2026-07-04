// V001 — Initial schema
// Replaces the inline CREATE INDEX calls from the legacy graph_service.py.
// Upgrades to uniqueness constraints which also create indexes automatically.

// ── Sender ────────────────────────────────────────────────────────────────────
CREATE CONSTRAINT sender_email_unique IF NOT EXISTS
  FOR (s:Sender) REQUIRE s.email IS UNIQUE;

// ── Recipient — unique email index (Community Edition; org scoping is app-level)
CREATE CONSTRAINT recipient_email_unique IF NOT EXISTS
  FOR (r:Recipient) REQUIRE r.email IS UNIQUE;

// ── Domain ────────────────────────────────────────────────────────────────────
CREATE CONSTRAINT domain_name_unique IF NOT EXISTS
  FOR (d:Domain) REQUIRE d.name IS UNIQUE;

// ── ThreatType ────────────────────────────────────────────────────────────────
CREATE CONSTRAINT threat_type_unique IF NOT EXISTS
  FOR (t:ThreatType) REQUIRE t.type IS UNIQUE;

// ── Reporter — unique email index (Community Edition; org scoping is app-level)
CREATE CONSTRAINT reporter_email_unique IF NOT EXISTS
  FOR (rep:Reporter) REQUIRE rep.email IS UNIQUE;
