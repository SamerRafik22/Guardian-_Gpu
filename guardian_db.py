"""
guardian_db.py — SQLite database layer for Guardian Web Portal
================================================================
Handles schema creation, migrations, and CRUD for all portal tables.
Uses aiosqlite for async compatibility with FastAPI.
"""

import aiosqlite
import os
import uuid
import json

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "guardian.db")
CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "guardian_config.json")

# ── Machine ID ────────────────────────────────────────────────────────────────
def get_machine_id():
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, 'r') as f:
            cfg = json.load(f)
            return cfg.get("machine_id", str(uuid.uuid4()))
    machine_id = str(uuid.uuid4())
    with open(CONFIG_PATH, 'w') as f:
        json.dump({"machine_id": machine_id}, f, indent=2)
    return machine_id

MACHINE_ID = get_machine_id()


# ── Schema ────────────────────────────────────────────────────────────────────
SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    username    TEXT    NOT NULL UNIQUE,
    email       TEXT    NOT NULL UNIQUE,
    password_hash TEXT  NOT NULL,
    role        TEXT    NOT NULL DEFAULT 'user',
    machine_id  TEXT,
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_active   BOOLEAN DEFAULT 1,
    is_verified BOOLEAN DEFAULT 0
);

CREATE TABLE IF NOT EXISTS web_sessions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL REFERENCES users(id),
    token       TEXT    NOT NULL UNIQUE,
    expires_at  TIMESTAMP NOT NULL,
    created_from_ip TEXT,
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS otp_requests (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    requested_by    TEXT    NOT NULL,
    machine_id      TEXT    NOT NULL,
    pid             TEXT    NOT NULL,
    process_name    TEXT    NOT NULL,
    exe_path        TEXT,
    otp_code        TEXT    NOT NULL,
    approved_by     INTEGER REFERENCES users(id),
    expires_at      TIMESTAMP NOT NULL,
    status          TEXT    DEFAULT 'pending',
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS auth_otps (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    email       TEXT    NOT NULL,
    otp_code    TEXT    NOT NULL,
    purpose     TEXT    NOT NULL,
    expires_at  TIMESTAMP NOT NULL,
    status      TEXT    DEFAULT 'pending',
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
