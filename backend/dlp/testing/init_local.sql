CREATE TABLE IF NOT EXISTS organizations (
    id UUID PRIMARY KEY,
    domain VARCHAR(255) NOT NULL UNIQUE,
    org_metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);

INSERT INTO organizations (id, domain, org_metadata)
VALUES (
    '00000000-0000-4000-8000-000000000001',
    'example.test',
    '{
      "dlp_v2": {
        "enabled": true,
        "mode": "enforce",
        "domains": ["example.test", "himaya.test"],
        "lexicon_version": "v1"
      }
    }'::jsonb
)
ON CONFLICT (id) DO UPDATE SET
    domain = EXCLUDED.domain,
    org_metadata = EXCLUDED.org_metadata;
