"""
Database layer
==============
All SQLite interactions live here. The middleware, auth, and route modules
never write raw SQL — they call named helpers from this module.
"""

import sqlite3
from contextlib import contextmanager
from pathlib import Path

import bcrypt

from app.config import settings

DB_PATH = Path(settings.DB_PATH)

# ---------------------------------------------------------------------------
# Seeded password hashes (bcrypt, cost factor 12)
# Generated once: bcrypt.hashpw(b"demo1234",  bcrypt.gensalt())
#                 bcrypt.hashpw(b"alice1234", bcrypt.gensalt())
# Credentials:  demo / demo1234   |   alice / alice1234
# ---------------------------------------------------------------------------
_DEMO_HASH  = "$2b$12$52jj/dTM25rk7tP2al83s.CkzTbEzckawljFRK00Eq7Zk4OQ/QIGW"
_ALICE_HASH = "$2b$12$xa7PFZuAjXBKIpLzrKqqVOGCbUrdsOJ0gigyynYqQXzNL7SSxYu.e"


# ---------------------------------------------------------------------------
# Schema + seed
# ---------------------------------------------------------------------------

def init_db():
    """Create all tables and seed demo data. Safe to call on every startup."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    cur.execute("PRAGMA journal_mode=WAL;")

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            username        TEXT    NOT NULL UNIQUE,
            password_hash   TEXT    NOT NULL,
            last_user_agent TEXT,
            last_seen_ip    TEXT,
            last_seen_at    TEXT,
            is_active       INTEGER NOT NULL DEFAULT 1,
            created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
        );
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS access_policies (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            policy_name TEXT    NOT NULL UNIQUE,
            description TEXT,
            priority    INTEGER NOT NULL DEFAULT 10,
            rule_type   TEXT    NOT NULL CHECK(rule_type IN ('TIME','VELOCITY','DEVICE')),
            parameters  TEXT    NOT NULL DEFAULT '{}',
            action      TEXT    NOT NULL CHECK(action IN ('ALLOW','BLOCK','MFA_CHALLENGE')),
            is_enabled  INTEGER NOT NULL DEFAULT 1,
            created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
        );
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS access_logs (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT    NOT NULL DEFAULT (datetime('now')),
            user_id     INTEGER,
            username    TEXT,
            ip_address  TEXT    NOT NULL,
            country     TEXT    NOT NULL,
            city        TEXT,
            action      TEXT    NOT NULL CHECK(action IN ('ALLOW','BLOCK','CHALLENGE')),
            policy_name TEXT,
            reason      TEXT
        );
    """)

    # Migration: add city column to existing databases that were created
    # before this column existed. SQLite does not support IF NOT EXISTS on
    # ALTER TABLE so we check the column list first.
    existing_cols = [row[1] for row in cur.execute("PRAGMA table_info(access_logs)").fetchall()]
    if "city" not in existing_cols:
        cur.execute("ALTER TABLE access_logs ADD COLUMN city TEXT;")

    # Seed policies (idempotent)
    cur.executemany("""
        INSERT OR IGNORE INTO access_policies
            (policy_name, description, priority, rule_type, parameters, action)
        VALUES (?, ?, ?, ?, ?, ?);
    """, [
        (
            "business_hours_only",
            "Block all API access outside 09:00-17:00 local server time.",
            1, "TIME",
            '{"start_hour": 9, "end_hour": 17}',
            "BLOCK",
        ),
        (
            "impossible_travel",
            "Block requests where the IP country changes faster than physically possible.",
            2, "VELOCITY",
            '{"max_minutes": 10}',
            "BLOCK",
        ),
        (
            "device_fingerprint_change",
            "Require MFA when the User-Agent string changes between requests.",
            3, "DEVICE",
            '{"action": "MFA_CHALLENGE"}',
            "MFA_CHALLENGE",
        ),
    ])

    # Seed users — INSERT OR IGNORE keeps existing rows on re-runs
    cur.executemany("""
        INSERT OR IGNORE INTO users (username, password_hash, last_user_agent)
        VALUES (?, ?, ?);
    """, [
        ("demo",  _DEMO_HASH,  None),
        ("alice", _ALICE_HASH, "Mozilla/5.0 (Windows NT 10.0) TrustedBrowser/1.0"),
    ])

    # Migration: upgrade any leftover PLACEHOLDER_HASH rows from old runs
    cur.execute(
        "UPDATE users SET password_hash=? WHERE username='demo'  AND password_hash='PLACEHOLDER_HASH'",
        (_DEMO_HASH,),
    )
    cur.execute(
        "UPDATE users SET password_hash=? WHERE username='alice' AND password_hash='PLACEHOLDER_HASH'",
        (_ALICE_HASH,),
    )

    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Connection context manager
# ---------------------------------------------------------------------------

@contextmanager
def get_db():
    """Yield a per-request sqlite3 connection, close on exit."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# User queries
# ---------------------------------------------------------------------------

def fetch_user(conn: sqlite3.Connection, user_id: str | int) -> sqlite3.Row | None:
    """Return an active user by integer ID, or None."""
    return conn.execute(
        "SELECT * FROM users WHERE id = ? AND is_active = 1",
        (user_id,),
    ).fetchone()


def fetch_user_by_username(conn: sqlite3.Connection, username: str) -> sqlite3.Row | None:
    """Return an active user by username (used by the login endpoint)."""
    return conn.execute(
        "SELECT * FROM users WHERE username = ? AND is_active = 1",
        (username,),
    ).fetchone()


def record_trusted_device(conn: sqlite3.Connection, user_id: str | int, user_agent: str):
    """Enroll the current User-Agent as the user's trusted device baseline."""
    conn.execute(
        "UPDATE users SET last_user_agent = ? WHERE id = ?",
        (user_agent, user_id),
    )
    conn.commit()


# ---------------------------------------------------------------------------
# Policy queries
# ---------------------------------------------------------------------------

def fetch_active_policies(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    """Return enabled policies ordered by ascending priority."""
    return conn.execute(
        "SELECT * FROM access_policies WHERE is_enabled = 1 ORDER BY priority ASC",
    ).fetchall()


def fetch_all_policies(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    """Return ALL policies (enabled + disabled) for the admin policy panel."""
    return conn.execute(
        "SELECT * FROM access_policies ORDER BY priority ASC",
    ).fetchall()


def set_policy_enabled(conn: sqlite3.Connection, policy_id: int, is_enabled: bool):
    """Enable or disable a policy without deleting it."""
    conn.execute(
        "UPDATE access_policies SET is_enabled = ? WHERE id = ?",
        (1 if is_enabled else 0, policy_id),
    )
    conn.commit()


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------

def write_access_log(
    conn: sqlite3.Connection,
    *,
    user_id: int | None,
    username: str | None,
    ip_address: str,
    country: str,
    city: str | None = None,
    action: str,
    policy_name: str | None,
    reason: str,
):
    """
    Append one row to the append-only access_logs table.

    Normalises MFA_CHALLENGE -> CHALLENGE to match the DB CHECK constraint
    and the dashboard badge labels.
    """
    normalised = "CHALLENGE" if action == "MFA_CHALLENGE" else action
    conn.execute(
        """
        INSERT INTO access_logs
            (user_id, username, ip_address, country, city, action, policy_name, reason)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (user_id, username, ip_address, country, city, normalised, policy_name, reason),
    )
    conn.commit()


# ---------------------------------------------------------------------------
# Password helpers
# ---------------------------------------------------------------------------

def verify_password(plain: str, hashed: str) -> bool:
    """Return True if plain text matches the stored bcrypt hash."""
    return bcrypt.checkpw(plain.encode(), hashed.encode())
