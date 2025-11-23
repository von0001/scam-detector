from __future__ import annotations

import os
from contextlib import contextmanager

import psycopg2
import psycopg2.extras
from psycopg2.pool import SimpleConnectionPool

# DATABASE_URL (or SUPABASE_DB_URL) must point to a persistent Postgres instance.
DATABASE_URL = os.getenv("DATABASE_URL") or os.getenv("SUPABASE_DB_URL")

if not DATABASE_URL:
    raise RuntimeError(
        "DATABASE_URL (or SUPABASE_DB_URL) must be set for persistent user storage."
    )

# Small pooled connection manager so requests survive redeploys and restarts.
pool = SimpleConnectionPool(minconn=1, maxconn=10, dsn=DATABASE_URL)


@contextmanager
def get_cursor():
    """
    Yield a real-dict cursor inside a transaction.
    Rolls back on error and always returns the connection to the pool.
    """
    conn = pool.getconn()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        yield conn, cur
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        cur.close()
        pool.putconn(conn)


def init_db() -> None:
    """Create tables if they do not already exist."""
    with get_cursor() as (_, cur):
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id UUID PRIMARY KEY,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT,
                plan TEXT NOT NULL DEFAULT 'free',
                is_admin BOOLEAN NOT NULL DEFAULT FALSE,
                subscription_status TEXT NOT NULL DEFAULT 'inactive',
                billing_cycle TEXT NOT NULL DEFAULT 'none',
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                last_login TIMESTAMPTZ NULL,
                daily_scan_date DATE NULL,
                daily_scan_count INTEGER NOT NULL DEFAULT 0,
                daily_limit INTEGER NOT NULL DEFAULT 8,
                auth_method TEXT NOT NULL DEFAULT 'password',
                google_sub TEXT UNIQUE,
                stripe_customer_id TEXT,
                stripe_subscription_id TEXT,
                subscription_renewal TIMESTAMPTZ NULL,
                last_plan_change TIMESTAMPTZ NULL
            );
            """
        )
        cur.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_lower
            ON users ((lower(email)));
            """
        )
        cur.execute(
            """
            ALTER TABLE users
            ADD COLUMN IF NOT EXISTS is_admin BOOLEAN NOT NULL DEFAULT FALSE;
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_logs (
                id BIGSERIAL PRIMARY KEY,
                user_id UUID NULL REFERENCES users(id) ON DELETE SET NULL,
                timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                category TEXT,
                mode TEXT,
                verdict TEXT,
                score INTEGER,
                snippet TEXT,
                details JSONB DEFAULT '{}'::jsonb
            );
            """
        )
        cur.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_scan_logs_user_ts
            ON scan_logs (user_id, timestamp DESC);
            """
        )
