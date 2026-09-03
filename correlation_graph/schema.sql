-- correlation_graph/schema.sql
-- SQLite schema for the campaign correlation database.
-- Initialise with: sqlite3 data/campaigns.db < correlation_graph/schema.sql

-- Stores one row per processed email.
CREATE TABLE IF NOT EXISTS emails (
    email_id            TEXT PRIMARY KEY,
    sender_domain       TEXT,
    origin_ip           TEXT,
    impersonated_domain TEXT,   -- closest_match from typosquat result (or NULL)
    campaign_id         TEXT,   -- assigned by correlate(); NULL until clustered
    raw_record          TEXT    -- full JSON of the combined pipeline record
);

-- Stores directed edges between emails that share infrastructure.
CREATE TABLE IF NOT EXISTS edges (
    email_id_a  TEXT NOT NULL,
    email_id_b  TEXT NOT NULL,
    reason      TEXT NOT NULL,  -- e.g. "same_origin_ip"
    PRIMARY KEY (email_id_a, email_id_b, reason),
    FOREIGN KEY (email_id_a) REFERENCES emails(email_id),
    FOREIGN KEY (email_id_b) REFERENCES emails(email_id)
);
