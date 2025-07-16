-- init.sql - PostgreSQL database schema

-- Table des flows signalés
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

-- Index pour la performance des flows
CREATE INDEX IF NOT EXISTS idx_reported_flows_user_id ON reported_flows(user_id);
CREATE INDEX IF NOT EXISTS idx_reported_flows_prediction ON reported_flows(prediction);

-- Table des utilisateurs
CREATE TABLE IF NOT EXISTS users (
    user_id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    email TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL,
    last_login TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE,
    role TEXT DEFAULT 'user'
);

-- Table des sessions utilisateurs
CREATE TABLE IF NOT EXISTS user_sessions (
    session_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    username TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL,
    last_activity TIMESTAMP NOT NULL,
    ip_address TEXT NOT NULL,
    expires_at TIMESTAMP NOT NULL
);

-- Index pour la performance des sessions
CREATE INDEX IF NOT EXISTS idx_user_sessions_user_id ON user_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_user_sessions_expires_at ON user_sessions(expires_at);