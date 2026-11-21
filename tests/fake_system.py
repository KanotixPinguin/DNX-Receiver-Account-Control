# -*- coding: utf-8 -*-
"""Test-Hilfsmodul: baut eine realistische accounts.sqlite3 nach.

Enthalten sind Bestandsdaten (users/sessions/audit_log/audit_settings), damit in
den Tests bewiesen werden kann, dass die Systemsteuerung NICHTS davon anfasst.
"""

from __future__ import annotations

import os
import sqlite3
import time
from typing import Dict, List, Optional

USERS = [
    # (username, password_hash, role, active, created_at)
    ("dl1abc", "pbkdf2$altbestand$1", "admin", 1, 1700000000),
    ("dl2xyz", "pbkdf2$altbestand$2", "extended", 1, 1700000100),
    ("do3test", "pbkdf2$altbestand$3", "user", 1, 1700000200),
    ("swl99", "pbkdf2$altbestand$4", "user", 1, 1700000300),
    ("wartend", "pbkdf2$altbestand$5", "user", 0, 1700000400),
]

SESSIONS = [
    ("dl2xyz", "tok-alt-1", "7d", 1800000000),
    ("do3test", "tok-alt-2", "browser", 1800000000),
    ("swl99", "tok-alt-3", "forever", 0),
]

AUDIT_ROWS = [
    (1700000500, "registration", "swl99", "user", "192.0.2.50", "Mozilla/5.0", "{}"),
    (1700000600, "login_success", "dl2xyz", "extended", "192.0.2.51", "Mozilla/5.0", "{}"),
    (1700000700, "profile_change", "dl2xyz", "extended", "192.0.2.51", "Mozilla/5.0",
     '{"profile":"80m"}'),
]

AUDIT_SETTINGS = [("max_entries", "250000"), ("max_database_bytes", "1073741824"),
                  ("timezone", "Europe/Berlin")]

CANONICAL_AUDIT_DDL = """
CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    event TEXT NOT NULL,
    username TEXT,
    role TEXT,
    ip TEXT,
    user_agent TEXT,
    details TEXT
)
"""

# Alternative Spaltennamen – proves die schematolerante Audit-Schreibweise
ALIEN_AUDIT_DDL = """
CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at INTEGER NOT NULL,
    action TEXT NOT NULL,
    account_name TEXT,
    client_ip TEXT,
    agent TEXT,
    extra TEXT
)
"""


def make_db(path: str, *, audit_variant: str = "canonical",
            with_users: bool = True, with_audit_settings: bool = True) -> str:
    if os.path.exists(path):
        os.remove(path)
    conn = sqlite3.connect(path, isolation_level=None)
    try:
        if with_users:
            conn.execute("""CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user',
                active INTEGER NOT NULL DEFAULT 1,
                created_at INTEGER NOT NULL DEFAULT 0)""")
            conn.executemany(
                "INSERT INTO users (username, password_hash, role, active, created_at) "
                "VALUES (?,?,?,?,?)", USERS)
            conn.execute("""CREATE TABLE sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                token TEXT NOT NULL,
                duration TEXT NOT NULL DEFAULT 'browser',
                expires_at INTEGER NOT NULL DEFAULT 0)""")
            conn.executemany(
                "INSERT INTO sessions (username, token, duration, expires_at) VALUES (?,?,?,?)",
                SESSIONS)
        if audit_variant == "alien":
            conn.execute(ALIEN_AUDIT_DDL)
            conn.executemany(
                "INSERT INTO audit_log (created_at, action, account_name, client_ip, agent, extra) "
                "VALUES (?,?,?,?,?,?)",
                [(r[0], r[1], r[2], r[4], r[5], r[6]) for r in AUDIT_ROWS])
        else:
            conn.execute(CANONICAL_AUDIT_DDL)
            conn.executemany(
                "INSERT INTO audit_log (ts, event, username, role, ip, user_agent, details) "
                "VALUES (?,?,?,?,?,?,?)", AUDIT_ROWS)
        if with_audit_settings:
            conn.execute("CREATE TABLE audit_settings (key TEXT PRIMARY KEY, value TEXT)")
            conn.executemany("INSERT INTO audit_settings (key, value) VALUES (?,?)", AUDIT_SETTINGS)
    finally:
        conn.close()
    return path


def counts(path: str, tables: Optional[List[str]] = None) -> Dict[str, int]:
    conn = sqlite3.connect(path)
    try:
        names = tables or [r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]
        out = {}
        for name in names:
            try:
                out[name] = conn.execute('SELECT COUNT(*) FROM "%s"' % name).fetchone()[0]
            except sqlite3.Error:
                out[name] = -1
        return out
    finally:
        conn.close()


def rows(path: str, sql: str) -> List[tuple]:
    conn = sqlite3.connect(path)
    try:
        return conn.execute(sql).fetchall()
    finally:
        conn.close()


def write_policy(path: str, protected=("KW-Schutz", "Admin-only")) -> str:
    import json
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"protected": list(protected),
                   "profiles": {"80m": {"roles": ["user", "extended", "admin"]},
                                "KW-Schutz": {"roles": ["extended", "admin"]},
                                "Admin-only": {"roles": ["admin"]}}}, fh)
    return path


def now() -> int:
    return int(time.time())
