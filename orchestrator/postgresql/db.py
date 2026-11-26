"""PostgreSQL state tracking for the pipeline."""
import logging
import os
import time
from contextlib import contextmanager

import psycopg2
from psycopg2 import extras, pool

log = logging.getLogger("db")
DSN = os.environ.get("DATABASE_URL", "postgresql://phishguard:phishguard@localhost:5432/phishguard")
_pool = None

SCHEMA = """
CREATE TABLE IF NOT EXISTS emails (
    id BIGSERIAL PRIMARY KEY,
    message_id TEXT UNIQUE NOT NULL,
    state TEXT NOT NULL,              -- RECEIVED / ANALYZING / SCORED / RESPONDED / FAILED
    severity TEXT,
    score INT,
    findings JSONB,
    action_taken TEXT,
    quarantined BOOLEAN NOT NULL DEFAULT false,
    error TEXT,
    email JSONB NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS email_events (
    id BIGSERIAL PRIMARY KEY,
    message_id TEXT NOT NULL,
    state TEXT NOT NULL,
    detail TEXT,
    at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS accounts (
    address TEXT PRIMARY KEY,
    suspended BOOLEAN NOT NULL DEFAULT false,
    suspended_at TIMESTAMPTZ,
    reason TEXT
);
"""

_FIELDS = {"severity", "score", "findings", "action_taken", "error", "quarantined"}


@contextmanager
def conn():
    c = _pool.getconn()
    try:
        yield c
        c.commit()
    except Exception:
        c.rollback()
        raise
    finally:
        _pool.putconn(c)


def init_db(retries=30):
    global _pool
    for _ in range(retries):
        try:
            _pool = pool.ThreadedConnectionPool(1, 10, DSN)
            break
        except psycopg2.OperationalError as e:
            log.warning("DB not ready (%s); retrying", str(e).strip())
            time.sleep(1)
    else:
        raise RuntimeError("could not connect to database")
    with conn() as c, c.cursor() as cur:
        cur.execute(SCHEMA)


def insert_email(message_id, email_dict):
    with conn() as c, c.cursor() as cur:
        cur.execute("INSERT INTO emails (message_id, state, email) VALUES (%s, 'RECEIVED', %s)",
                    (message_id, extras.Json(email_dict)))
        cur.execute("INSERT INTO email_events (message_id, state) VALUES (%s, 'RECEIVED')", (message_id,))


def set_state(message_id, state=None, detail=None, **fields):
    """Update state (and event history) and/or other columns."""
    bad = set(fields) - _FIELDS
    if bad:
        raise ValueError(f"unknown fields: {bad}")
    sets, vals = ["updated_at = now()"], []
    if state:
        sets.append("state = %s")
        vals.append(state)
    for k, v in fields.items():
        sets.append(f"{k} = %s")
        vals.append(extras.Json(v) if k == "findings" else v)
    vals.append(message_id)
    with conn() as c, c.cursor() as cur:
        cur.execute(f"UPDATE emails SET {', '.join(sets)} WHERE message_id = %s", vals)
        if state:
            cur.execute("INSERT INTO email_events (message_id, state, detail) VALUES (%s, %s, %s)",
                        (message_id, state, detail))


def get_email(message_id):
    with conn() as c, c.cursor(cursor_factory=extras.RealDictCursor) as cur:
        cur.execute("SELECT * FROM emails WHERE message_id = %s", (message_id,))
        return cur.fetchone()


def list_emails(after_id, limit):
    with conn() as c, c.cursor(cursor_factory=extras.RealDictCursor) as cur:
        cur.execute("SELECT * FROM emails WHERE id > %s ORDER BY id LIMIT %s", (after_id, limit))
        return cur.fetchall()


def suspend_accounts(addresses, reason):
    """Simulated suspension: just flips a flag in the accounts table."""
    with conn() as c, c.cursor() as cur:
        for a in addresses:
            cur.execute("""INSERT INTO accounts (address, suspended, suspended_at, reason)
                           VALUES (%s, true, now(), %s)
                           ON CONFLICT (address) DO UPDATE
                           SET suspended = true, suspended_at = now(), reason = EXCLUDED.reason""",
                        (a, reason))
