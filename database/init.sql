-- init_simple.sql - Juste remplacer SQLite par PostgreSQL

-- Table des flows signalés (identique à SQLite mais en PostgreSQL)
CREATE TABLE IF NOT EXISTS reported_flows (
    id SERIAL PRIMARY KEY,
    flow_key TEXT NOT NULL,
    src_ip TEXT,
    dst_ip TEXT,
    sport INTEGER,
    dport INTEGER,
    protocol TEXT,
    total_bytes BIGINT,
    pkt_count INTEGER,
    prediction TEXT,
    label_humain TEXT,
    user_id TEXT,
    reported_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    flow_data TEXT
);

-- Index pour la performance
CREATE INDEX IF NOT EXISTS idx_reported_flows_user_id ON reported_flows(user_id);
CREATE INDEX IF NOT EXISTS idx_reported_flows_prediction ON reported_flows(prediction);