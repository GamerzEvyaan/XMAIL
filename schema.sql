PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    account_id TEXT NOT NULL UNIQUE,
    password_salt TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    password_change_required INTEGER NOT NULL DEFAULT 0,
    role TEXT NOT NULL DEFAULT 'user',
    created_at TEXT NOT NULL,
    last_ip_hash TEXT,
    session_version INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS bans (
    id TEXT PRIMARY KEY,
    user_id TEXT,
    ip_hash TEXT,
    reason TEXT,
    expires_at TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS whitelist (
    username TEXT PRIMARY KEY,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id TEXT PRIMARY KEY,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT,
    details TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_users_username
ON users(username);

CREATE INDEX IF NOT EXISTS idx_bans_user
ON bans(user_id);

CREATE INDEX IF NOT EXISTS idx_bans_ip
ON bans(ip_hash);

CREATE INDEX IF NOT EXISTS idx_logs_created
ON audit_logs(created_at);

INSERT OR IGNORE INTO settings (key, value)
VALUES ('whitelist_mode', 'false');