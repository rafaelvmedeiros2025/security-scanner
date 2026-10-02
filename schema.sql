CREATE TABLE IF NOT EXISTS scans (
 id uuid PRIMARY KEY, tenant text NOT NULL, target text NOT NULL, idem text NOT NULL,
 status text NOT NULL DEFAULT 'queued' CHECK(status IN ('queued','running','completed','failed')),
 attempts integer NOT NULL DEFAULT 0, token uuid, lease_until timestamptz,
 available_at timestamptz NOT NULL DEFAULT now(), created_at timestamptz NOT NULL DEFAULT now(),
 result jsonb, error text, UNIQUE(tenant, idem)
);
CREATE INDEX IF NOT EXISTS scans_queue ON scans(available_at) WHERE status IN ('queued','running');
