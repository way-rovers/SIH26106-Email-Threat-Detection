-- correlation_graph/schema.sql
-- SQLite schema for the campaign correlation database.
-- Initialise with: sqlite3 data/campaigns.db < correlation_graph/schema.sql

-- Stores one row per processed email.
CREATE TABLE IF NOT EXISTS emails (
    email_id TEXT PRIMARY KEY, sender_domain TEXT, origin_ip TEXT,
    impersonated_domain TEXT, campaign_id TEXT, raw_record TEXT
);

-- Stores directed edges between emails that share infrastructure.
CREATE TABLE IF NOT EXISTS edges (
    email_id_a TEXT, email_id_b TEXT, reason TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_edges_unique_pair_reason
ON edges (email_id_a, email_id_b, reason);
