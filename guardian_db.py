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

CREATE TABLE IF NOT EXISTS session_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    machine_id      TEXT    NOT NULL,
    user_id         INTEGER REFERENCES users(id),
    start_time      TIMESTAMP,
    end_time        TIMESTAMP,
    total_rows      INTEGER DEFAULT 0,
    total_alerts    INTEGER DEFAULT 0,
    kb_matches      INTEGER DEFAULT 0,
    top_processes   TEXT,
    conclusion_text TEXT,
    health_score    REAL DEFAULT 100.0
);

CREATE TABLE IF NOT EXISTS whitelist_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    pid             TEXT    NOT NULL,
    process_name    TEXT    NOT NULL,
    exe_path        TEXT,
    approved_by     INTEGER REFERENCES users(id),
    otp_request_id  INTEGER REFERENCES otp_requests(id),
    approved_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS ignored_processes (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    pid             TEXT    NOT NULL,
    process_name    TEXT    NOT NULL,
    machine_id      TEXT    NOT NULL,
    ignored_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS system_whitelist (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    process_name    TEXT    NOT NULL UNIQUE,
    added_by        INTEGER REFERENCES users(id),
    added_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
"""


# ── Init ──────────────────────────────────────────────────────────────────────
async def init_db():
    async with aiosqlite.connect(DB_PATH) as db:
        await db.executescript(SCHEMA)
        # Migrations for existing DBs
        try:
            await db.execute("ALTER TABLE otp_requests ADD COLUMN exe_path TEXT")
        except: pass
        try:
            await db.execute("ALTER TABLE whitelist_log ADD COLUMN exe_path TEXT")
        except: pass
        try:
            await db.execute("ALTER TABLE users ADD COLUMN is_verified BOOLEAN DEFAULT 0")
            await db.execute("UPDATE users SET is_verified = 1") # Auto-verify existing users
        except: pass
        await db.commit()
        
    # Security: Enforce strict NTFS permissions using Windows icacls
    try:
        import subprocess
        subprocess.run(
            f'icacls "{DB_PATH}" /inheritance:r /grant:r "NT AUTHORITY\\SYSTEM":(R,W) /grant:r "BUILTIN\\Administrators":(R,W)', 
            shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
    except Exception:
        pass
        
    print(f"[DB] Initialized at {DB_PATH}")


# ── User CRUD ─────────────────────────────────────────────────────────────────
async def create_user(username, email, password_hash, role="user", machine_id=None, is_verified=0):
    async with aiosqlite.connect(DB_PATH) as db:
        try:
            await db.execute(
                "INSERT INTO users (username, email, password_hash, role, machine_id, is_verified) VALUES (?,?,?,?,?,?)",
                (username, email, password_hash, role, machine_id or MACHINE_ID, is_verified)
            )
            await db.commit()
            return True
        except aiosqlite.IntegrityError:
            return False
async def get_user_by_username(username):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM users WHERE username=? AND is_active=1", (username,)) as c:
            row = await c.fetchone()
            return dict(row) if row else None

async def get_user_by_id(user_id):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM users WHERE id=? AND is_active=1", (user_id,)) as c:
            row = await c.fetchone()
            return dict(row) if row else None

async def has_any_admin():
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute("SELECT COUNT(*) FROM users WHERE role='admin'") as c:
            count = await c.fetchone()
            return count[0] > 0

async def mark_user_verified(email):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("UPDATE users SET is_verified=1 WHERE email=?", (email,))
        await db.commit()

async def delete_user(user_id):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("DELETE FROM users WHERE id=?", (user_id,))
        await db.commit()

# ── Auth OTP CRUD ─────────────────────────────────────────────────────────────
async def create_auth_otp(email, otp_code, purpose, expires_at):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT INTO auth_otps (email, otp_code, purpose, expires_at) VALUES (?,?,?,?)",
            (email, otp_code, purpose, expires_at)
        )
        await db.commit()

async def validate_auth_otp(email, otp_code, purpose):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM auth_otps WHERE email=? AND otp_code=? AND purpose=? AND status='pending' AND expires_at > datetime('now')",
            (email, otp_code, purpose)
        ) as c:
            row = await c.fetchone()
            if not row:
                return False
        
        await db.execute("UPDATE auth_otps SET status='used' WHERE id=?", (row['id'],))
        await db.commit()
        return True


# ── Session CRUD ───────────────────────────────────────────────────────────────
async def create_web_session(user_id, token, expires_at, ip=None):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT INTO web_sessions (user_id, token, expires_at, created_from_ip) VALUES (?,?,?,?)",
            (user_id, token, expires_at, ip)
        )
        await db.commit()

async def get_session_by_token(token):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT s.*, u.username, u.role, u.email FROM web_sessions s "
            "JOIN users u ON s.user_id = u.id "
            "WHERE s.token=? AND s.expires_at > datetime('now')", (token,)
        ) as c:
            row = await c.fetchone()
            return dict(row) if row else None
async def delete_session(token):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("DELETE FROM web_sessions WHERE token=?", (token,))
        await db.commit()


# ── OTP CRUD ──────────────────────────────────────────────────────────────────
async def create_otp_request(pid, process_name, otp_code, expires_at, machine_id=None, requester="user", exe_path=None):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT INTO otp_requests (pid, process_name, exe_path, otp_code, expires_at, machine_id, requested_by) VALUES (?,?,?,?,?,?,?)",
            (pid, process_name, exe_path, otp_code, expires_at, machine_id or MACHINE_ID, requester)
        )
        await db.commit()

async def get_pending_otps():
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM otp_requests WHERE status='pending' AND expires_at > datetime('now') ORDER BY created_at DESC"
        ) as c:
            rows = await c.fetchall()
            return [dict(r) for r in rows]

async def validate_and_approve_otp(otp_code, pid, approved_by_user_id):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM otp_requests WHERE otp_code=? AND pid=? AND status='pending' AND expires_at > datetime('now')",
            (otp_code, pid)
        ) as c:
            row = await c.fetchone()
            if not row:
                return None
            row = dict(row)
        await db.execute(
            "UPDATE otp_requests SET status='approved', approved_by=? WHERE id=?",
            (approved_by_user_id, row['id'])
        )
        await db.execute(
            "INSERT INTO whitelist_log (pid, process_name, exe_path, approved_by, otp_request_id) VALUES (?,?,?,?,?)",
            (row['pid'], row['process_name'], row.get('exe_path'), approved_by_user_id, row['id'])
        )
        await db.commit()
        return row

async def create_whitelist_log(process_name: str, approved_by_user_id: int, exe_path: str = None):
    """Fallback for direct web dashboard whitelists without OTP."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT INTO whitelist_log (pid, process_name, exe_path, approved_by) VALUES (?,?,?,?)",
            ("0", process_name, exe_path, approved_by_user_id)
        )
        await db.commit()


# ── Session Events ─────────────────────────────────────────────────────────────
async def save_session_event(start_time, end_time, total_rows, total_alerts,
                              kb_matches, top_processes, conclusion_text,
                              health_score, user_id=None):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """INSERT INTO session_events
               (machine_id, user_id, start_time, end_time, total_rows,
                total_alerts, kb_matches, top_processes, conclusion_text, health_score)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (MACHINE_ID, user_id, start_time, end_time, total_rows,
             total_alerts, kb_matches, json.dumps(top_processes),
             conclusion_text, health_score)
        )
        await db.commit()
