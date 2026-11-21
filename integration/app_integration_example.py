#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Referenz-Implementierung: So bindet app.py die globale Systemsteuerung ein.

Diese Datei ist KEIN Ersatz fuer /opt/owrx-docker/var/dnx-access-control/app.py,
sondern eine lauffaehige Vorlage zum Abkupfern. Sie zeigt alle acht
Integrationspunkte aus der Uebergabe (Kapitel 13) in einem Dienst:

    1. access_settings-Tabelle + Defaults         -> init_db()
    2. Admin-UI zum Lesen/Schreiben               -> create_blueprint(...)
    3. Registrierung an Einstellungen gebunden    -> /register
    4. Sitzungsoptionen gebunden                  -> /login (sanitize_session_request)
    5. Rollenaktivierung gebunden                 -> /login + effective_role
    6. Frontendstatus gebunden                    -> /receiver-simulator + /api/system/state
    7. Backend-Profilpruefung                     -> /api/profile/select
    8. Wartungsmodus inkl. Admin-Bypass           -> before_request + profile_decision
    9. Audit aller Ereignisse                     -> audit()

Start (Demo, z. B. in einer Sandbox oder auf einem Testsystem):
    python3 integration/app_integration_example.py
    -> http://127.0.0.1:8096/            Uebersicht
    -> http://127.0.0.1:8096/admin/system Systemsteuerung (Login: dl1abc / admin123)
    -> http://127.0.0.1:8096/receiver-simulator  Frontend-Reaktion auf die Schalter

Demo-Konten (simulieren BESTANDSUSER, die uebernommen werden muessen):
    dl1abc  / admin123   Rolle admin
    dl2xyz  / user1234   Rolle extended
    do3test / user1234   Rolle user
"""

from __future__ import annotations

import hashlib
import os
import random
import sqlite3
import sys
import time
from typing import Any, Dict, Optional

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SVC = os.path.join(ROOT, "account-service")
for path in (SVC, HERE):
    if path not in sys.path:
        sys.path.insert(0, path)

from flask import (Flask, Response, jsonify, redirect, request, session,  # noqa: E402
                   url_for)

from dnx_system_control import access_rules as R  # noqa: E402
from dnx_system_control.admin_api import create_blueprint  # noqa: E402
from dnx_system_control.settings_store import SettingsStore  # noqa: E402

DATA_DIR = os.environ.get("DNX_DEMO_DATA", os.path.join(ROOT, "demo-data"))
DB = os.environ.get("DNX_DEMO_DB", os.path.join(DATA_DIR, "accounts.sqlite3"))
POLICY = os.path.join(DATA_DIR, "profile-policy.json")
RECEIVER_JS = os.path.join(ROOT, "frontend", "dnx_access_control", "dnx_system_state.js")
HOST = os.environ.get("DNX_DEMO_HOST", "0.0.0.0")
PORT = int(os.environ.get("DNX_DEMO_PORT", "8096"))

DEMO_USERS = [
    ("dl1abc", "admin123", "admin"),
    ("dl2xyz", "user1234", "extended"),
    ("do3test", "user1234", "user"),
]

PAGE_CSS = """
body{margin:0;background:#0b0f14;color:#e6edf3;font:15px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,sans-serif}
header{padding:16px 22px;background:#131a22;border-bottom:1px solid #24303c;display:flex;gap:12px;align-items:center;flex-wrap:wrap}
header h1{font-size:18px;margin:0}
main{padding:20px 22px;max-width:1000px;margin:0 auto}
a{color:#4aa3ff}
.card{background:#131a22;border:1px solid #24303c;border-radius:10px;padding:16px;margin-bottom:16px}
table{width:100%;border-collapse:collapse;font-size:13.5px}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid #24303c}
th{color:#93a1af;font-size:12px;text-transform:uppercase;letter-spacing:.04em}
input,select,button{font:inherit;padding:8px 10px;border-radius:8px;border:1px solid #24303c;background:#101821;color:#e6edf3}
button{cursor:pointer;background:#1d7a4c;border-color:#2fa36a;font-weight:600}
button.ghost{background:#1b2531;border-color:#24303c;font-weight:400}
label{display:block;margin:10px 0 4px;color:#93a1af;font-size:12.5px}
.msg{padding:10px 12px;border-radius:8px;margin-bottom:12px;border:1px solid #2b6b48;background:#10241a}
.msg.err{border-color:#6d2b2b;background:#261212;color:#ffd9d9}
.msg.warn{border-color:#6b5a22;background:#241f0e;color:#f6e6b4}
code{font-family:ui-monospace,Menlo,Consolas,monospace;color:#93a1af}
.pill{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:11px;padding:2px 8px;border-radius:999px;background:#1f2b38;border:1px solid #24303c;color:#4aa3ff}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
small.dim{color:#93a1af}
"""


# --------------------------------------------------------------------------
# Datenbank (Demo-Bestand)
# --------------------------------------------------------------------------

def pw_hash(pw: str) -> str:
    return "demo$" + hashlib.sha256(pw.encode("utf-8")).hexdigest()[:32]


def init_db() -> None:
    os.makedirs(DATA_DIR, exist_ok=True)
    fresh = not os.path.exists(DB)
    conn = sqlite3.connect(DB, isolation_level=None)
    try:
        conn.execute("""CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            active INTEGER NOT NULL DEFAULT 1,
            created_at INTEGER NOT NULL DEFAULT 0)""")
        conn.execute("""CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            token TEXT NOT NULL UNIQUE,
            duration TEXT NOT NULL DEFAULT 'browser',
            expires_at INTEGER NOT NULL DEFAULT 0)""")
        conn.execute("""CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts INTEGER NOT NULL,
            event TEXT NOT NULL,
            username TEXT,
            role TEXT,
            ip TEXT,
            user_agent TEXT,
            details TEXT)""")
        conn.execute("""CREATE TABLE IF NOT EXISTS audit_settings (
            key TEXT PRIMARY KEY, value TEXT)""")
        conn.execute("INSERT OR IGNORE INTO audit_settings (key, value) VALUES "
                     "('max_entries','250000'),('max_database_bytes','1073741824')")
        if fresh:
            # BESTANDSUSER: werden angelegt und spaeter niemals von der
            # Systemsteuerung veraendert.
            for name, pw, role in DEMO_USERS:
                conn.execute(
                    "INSERT OR IGNORE INTO users (username, password_hash, role, active, created_at) "
                    "VALUES (?,?,?,?,?)",
                    (name, pw_hash(pw), role, 1, int(time.time()) - 86400 * 30))
            conn.execute("INSERT INTO audit_log (ts, event, username, role, ip, user_agent, details) "
                         "VALUES (?,?,?,?,?,?,?)",
                         (int(time.time()) - 3600, "registration", "do3test", "user",
                          "192.0.2.50", "Demo-Agent", '{"bestand":true}'))
    finally:
        conn.close()

    if not os.path.exists(POLICY):
        import json
        with open(POLICY, "w", encoding="utf-8") as fh:
            json.dump({
                "protected": ["KW-Schutz", "Admin-only"],
                "profiles": {
                    "80m": {"roles": ["user", "extended", "admin"], "frequency": 3615000},
                    "40m": {"roles": ["user", "extended", "admin"], "frequency": 7100000},
                    "KW-Schutz": {"roles": ["extended", "admin"], "frequency": 14200000},
                    "Admin-only": {"roles": ["admin"], "frequency": 28500000},
                },
            }, fh, indent=2, ensure_ascii=False)

    store = SettingsStore(DB)
    store.seed_defaults(actor="demo-init")


STORE = SettingsStore(DB)
init_db()

app = Flask(__name__)
app.secret_key = os.environ.get("DNX_DEMO_SECRET", "demo-secret-nicht-produktiv")
# Cookie-Politik: fuer die Anzeige in einem iframe-Preview (https-Proxy) muss
# SameSite=None + Secure gesetzt sein, sonst geht die Sitzung beim Login verloren.
# Im Produktivbetrieb entscheidet app.py selbst – dort nicht blind uebernehmen.
_SAMESITE = os.environ.get("DNX_DEMO_SAMESITE", "None")
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE=_SAMESITE,
    SESSION_COOKIE_SECURE=(_SAMESITE == "None"),
)


# --------------------------------------------------------------------------
# Hilfsfunktionen
# --------------------------------------------------------------------------

def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB, timeout=15)
    conn.row_factory = sqlite3.Row
    return conn


def settings() -> Dict[str, Any]:
    return STORE.values(use_cache=True, cache_seconds=2)


def client_ip() -> str:
    fwd = request.headers.get("X-Forwarded-For", "")
    return (fwd.split(",")[0].strip() if fwd else (request.remote_addr or "-"))


def audit(event: str, *, username: Optional[str] = None, role: Optional[str] = None,
          details: Any = None, force: bool = False) -> None:
    """Schreibt nur, wenn audit_enabled AN ist (Ausnahme: force)."""
    s = settings()
    if not force and not s.get("audit_enabled", True):
        return
    import json
    conn = db()
    try:
        conn.execute(
            "INSERT INTO audit_log (ts, event, username, role, ip, user_agent, details) "
            "VALUES (?,?,?,?,?,?,?)",
            (int(time.time()), event, username, role, client_ip(),
             request.headers.get("User-Agent", ""),
             details if isinstance(details, str)
             else json.dumps(details or {}, ensure_ascii=False)))
        conn.commit()
    finally:
        conn.close()


def current_session_user() -> Optional[Dict[str, Any]]:
    """Sitzung auslesen + Ablauf pruefen + wirksame Rolle bestimmen."""
    name = session.get("dnx_user")
    if not name:
        return None
    expires = int(session.get("dnx_expires") or 0)
    if expires and expires < int(time.time()):
        session.clear()
        return None
    conn = db()
    try:
        row = conn.execute("SELECT username, role, active FROM users WHERE username=?",
                           (name,)).fetchone()
    finally:
        conn.close()
    if not row:
        session.clear()
        return None
    s = settings()
    stored_role = R.normalize_role(row["role"])
    eff = R.effective_role(s, stored_role)
    return {
        "username": row["username"],
        "role": eff,                 # wirksame Rolle (Schalter beachten)
        "stored_role": stored_role,  # Rolle in der DB (unveraendert)
        "active": bool(row["active"]),
        "ip": client_ip(),
        "user_agent": request.headers.get("User-Agent", ""),
    }


def current_user_for_blueprint() -> Optional[Dict[str, Any]]:
    """Provider fuer create_blueprint(current_user=...)."""
    user = current_session_user()
    if not user:
        return {"username": None, "role": "guest", "ip": client_ip(),
                "user_agent": request.headers.get("User-Agent", "")}
    return {"username": user["username"], "role": user["stored_role"],
            "ip": user["ip"], "user_agent": user["user_agent"]}


def page(title: str, body: str, msg: str = "", kind: str = "") -> str:
    user = current_session_user()
    who = ("<span class='pill'>%s &middot; %s</span>" % (user["username"], user["role"])
           if user else "<span class='pill'>Gast</span>")
    nav = (" &middot; <a href='/'>Start</a> &middot; <a href='/activity'>Aktivitaet</a>"
           " &middot; <a href='/receiver-simulator'>Receiver-Simulator</a>")
    if user and user["role"] == "admin":
        nav += (" &middot; <a href='/admin/system'>Systemsteuerung</a>"
                " &middot; <a href='/admin/logbook'>Logbuch</a>"
                " &middot; <a href='/admin/users'>Benutzer</a>")
    if user:
        nav += " &middot; <a href='/logout'>Abmelden</a>"
    else:
        nav += " &middot; <a href='/login'>Anmelden</a> &middot; <a href='/register'>Registrieren</a>"
    return ("<!DOCTYPE html><html lang='de'><head><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width,initial-scale=1'>"
            "<title>%s</title><style>%s</style></head><body>"
            "<header><h1>DNX Account Control – Demo</h1>%s<div>%s</div></header>"
            "<main>%s%s</main></body></html>"
            % (title, PAGE_CSS, who, nav,
               ("<div class='msg %s'>%s</div>" % (kind, msg)) if msg else "", body))


# --------------------------------------------------------------------------
# Systemsteuerung (Blueprint) – EINBAU PUNKT 2
# --------------------------------------------------------------------------

app.register_blueprint(create_blueprint(STORE, current_user=current_user_for_blueprint,
                                       url_prefix="/admin"))


# --------------------------------------------------------------------------
# Wartungsmodus / Account-Zwang – EINBAU PUNKT 8
# --------------------------------------------------------------------------

# Exakte Pfade (wichtig: "/" darf NICHT als Praefix wirken, sonst waere alles offen)
OPEN_EXACT = {"/", "/login", "/register", "/logout", "/activity",
              "/receiver-simulator", "/favicon.ico"}
# Praefixe
OPEN_PREFIX = ("/api/system/", "/admin/system", "/admin/api/system/", "/static/")


@app.before_request
def guard():
    s = settings()
    if not s.get("maintenance_mode", False):
        return None
    user = current_session_user()
    state = R.maintenance_state(s, user["stored_role"] if user else "guest")
    if state["allowed"]:
        return None
    path = request.path
    if path in OPEN_EXACT or any(path.startswith(p) for p in OPEN_PREFIX):
        return None
    body = ("<div class='card'><h2>Wartungsmodus</h2><p>" + state["message"] + "</p>"
            "<p><small class='dim'>Grund: <code>" + str(state["reason"]) + "</code> &middot; "
            "Admin-Bypass: <code>" + ("AN" if s.get("maintenance_admin_bypass") else "AUS") +
            "</code></small></p></div>")
    return Response(page("Wartungsmodus", body), status=503)


# --------------------------------------------------------------------------
# Registrierung – EINBAU PUNKT 3
# --------------------------------------------------------------------------

@app.route("/register", methods=["GET", "POST"])
def register():
    s = settings()
    reg = R.registration_state(s)
    if not reg["enabled"]:
        return Response(page("Registrierung deaktiviert",
                             "<div class='card'><h2>Registrierung deaktiviert</h2>"
                             "<p>%s</p><p><code>registration_enabled = false</code></p></div>"
                             % reg["message"]), status=403)

    if "captcha_a" not in session:
        session["captcha_a"] = random.randint(3, 12)
        session["captcha_b"] = random.randint(2, 9)

    if request.method == "GET":
        captcha_html = ""
        if reg["captcha"]:
            captcha_html = ("<label>Rechenaufgabe: {a} + {b} = ?</label>"
                            "<input name='captcha' type='number' required>").format(
                                a=session["captcha_a"], b=session["captcha_b"])
        body = ("<div class='card'><h2>Registrieren</h2>"
                "<form method='post'>"
                "<label>Benutzername</label>"
                "<input name='username' required maxlength='32'>"
                "<label>Passwort (mindestens {minlen} Zeichen)</label>"
                "<input name='password' type='password' required minlength='{minlen}'>"
                "<label>Sitzungsdauer</label>{sessions}"
                "{captcha}"
                "<div class='row' style='margin-top:14px'><button>Registrieren</button>"
                "<small class='dim'>Standardrolle: <code>{role}</code> &middot; sofort aktiv: "
                "<code>{active}</code></small></div></form></div>").format(
                    minlen=reg["password_min_length"],
                    sessions=session_options_html(s),
                    captcha=captcha_html,
                    role=reg["role"],
                    active="ja" if reg["immediately_active"] else "nein (wartend)")
        return page("Registrieren", body)

    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    errors = []

    # Rate-Limit aus dem Audit-Log (Registrationen pro Fenster und IP)
    if reg["limit"] > 0:
        conn = db()
        try:
            since = int(time.time()) - reg["window_seconds"]
            rows = conn.execute(
                "SELECT ip, COUNT(*) AS n FROM audit_log WHERE event='registration' AND ts>=? "
                "GROUP BY ip", (since,)).fetchall()
        finally:
            conn.close()
        total = sum(r["n"] for r in rows)
        own = next((r["n"] for r in rows if r["ip"] == client_ip()), 0)
        ok, reason = R.registration_rate_allowed(s, max(own, total))
        if not ok:
            errors.append("Rate-Limit erreicht (%d/%d in %d s)"
                          % (max(own, total), reg["limit"], reg["window_seconds"]))

    if reg["captcha"]:
        try:
            if int(request.form.get("captcha", "")) != session["captcha_a"] + session["captcha_b"]:
                errors.append("Rechenaufgabe falsch")
        except ValueError:
            errors.append("Rechenaufgabe fehlt")
    if len(password) < reg["password_min_length"]:
        errors.append("Passwort zu kurz (min. %d Zeichen)" % reg["password_min_length"])
    if not username or len(username) > 32:
        errors.append("Benutzername ungueltig")

    if not errors:
        role = R.default_registration_role(s)
        active = 1 if R.new_account_state(s) == "active" else 0
        conn = db()
        try:
            exists = conn.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone()
            if exists:
                errors.append("Benutzername ist vergeben")
            else:
                conn.execute(
                    "INSERT INTO users (username, password_hash, role, active, created_at) "
                    "VALUES (?,?,?,?,?)",
                    (username, pw_hash(password), role, active, int(time.time())))
                conn.commit()
        finally:
            conn.close()
        if not errors:
            audit("registration", username=username, role=role,
                  details={"default_role": role, "active": bool(active),
                           "session": R.sanitize_session_request(s, request.form.get("duration"))})
            session.pop("captcha_a", None)
            session.pop("captcha_b", None)
            note = "" if active else ("<p class='msg warn'>Konto ist angelegt, aber noch "
                                      "nicht freigeschaltet (<code>new_accounts_active = false</code>).</p>")
            return page("Registriert",
                        "<div class='card'><h2>Willkommen, %s</h2>%s"
                        "<p>Rolle: <code>%s</code></p><p><a href='/login'>Zur Anmeldung</a></p></div>"
                        % (username, note, role), "Konto angelegt", "ok")

    body = ("<div class='card'><h2>Registrieren</h2>"
            + "".join("<div class='msg err'>%s</div>" % e for e in errors)
            + "<p><a href='/register'>Erneut versuchen</a></p></div>")
    return page("Registrieren", body)


def session_options_html(s: Dict[str, Any], selected: str = "") -> str:
    opts = "".join(
        "<option value='%s'%s>%s</option>"
        % (c["value"], " selected" if c["value"] == selected else "", c["label"])
        for c in R.session_choices(s))
    return "<select name='duration'>%s</select>" % opts


# --------------------------------------------------------------------------
# Login / Logout – EINBAU PUNKT 4 + 5
# --------------------------------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    s = settings()
    if request.method == "GET":
        body = ("<div class='card'><h2>Anmelden</h2><form method='post'>"
                "<label>Benutzername</label><input name='username' required>"
                "<label>Passwort</label><input name='password' type='password' required>"
                "<label>Sitzungsdauer (aus access_settings)</label>%s"
                "<div class='row' style='margin-top:14px'><button>Anmelden</button>"
                "<small class='dim'>Demo: dl1abc/admin123 (admin), dl2xyz/user1234 (extended), "
                "do3test/user1234 (user)</small></div></form></div>" % session_options_html(s))
        return page("Anmelden", body)

    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    policy = R.login_policy(s)

    conn = db()
    try:
        row = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        fails = conn.execute(
            "SELECT COUNT(*) AS n, MAX(ts) AS last FROM audit_log "
            "WHERE event='login_failed' AND username=?", (username,)).fetchone()
    finally:
        conn.close()

    blocked, remaining, reason = R.login_blocked(s, fails["n"] if fails else 0,
                                                 fails["last"] if fails else None)
    if blocked:
        audit("login_blocked", username=username,
              details={"remaining": remaining, "policy": policy})
        return page("Anmelden", "<div class='card'><h2>Gesperrt</h2>"
                                "<div class='msg err'>Zu viele Fehlversuche. "
                                "Bitte in %d s erneut versuchen.</div></div>" % remaining)

    ok = bool(row) and row["password_hash"] == pw_hash(password)
    if not ok:
        audit("login_failed", username=username or None,
              role=R.normalize_role(row["role"]) if row else None,
              details={"failures": (fails["n"] if fails else 0) + 1,
                       "max": policy["max_failures"]})
        left = policy["max_failures"] - ((fails["n"] if fails else 0) + 1)
        hint = (" Noch %d Versuch(e)." % left) if policy["lock_enabled"] and left > 0 else ""
        return page("Anmelden", "<div class='card'><h2>Anmeldung fehlgeschlagen</h2>"
                                "<div class='msg err'>Benutzername oder Passwort falsch.%s</div>"
                                "</div>" % hint)

    if not row["active"]:
        audit("login_denied", username=username, role=row["role"],
              details={"reason": "account_pending"})
        return page("Anmelden", "<div class='card'><h2>Konto wartet</h2>"
                                "<div class='msg warn'>Dieses Konto ist noch nicht "
                                "freigeschaltet.</div></div>")

    maint = R.maintenance_state(s, row["role"])
    if maint["active"] and not maint["allowed"]:
        audit("login_denied", username=username, role=row["role"],
              details={"reason": "maintenance_mode"})
        return page("Anmelden", "<div class='card'><h2>Wartungsmodus</h2>"
                                "<div class='msg err'>%s</div></div>" % maint["message"])

    duration = R.sanitize_session_request(s, request.form.get("duration"))
    seconds = {"browser": 0, "day": 86400, "week": 604800, "month": 2592000, "forever": 0}
    expires = int(time.time()) + seconds.get(duration, 0) if duration != "forever" else 0
    session.clear()
    session["dnx_user"] = row["username"]
    session["dnx_duration"] = duration
    session["dnx_expires"] = expires
    session.permanent = duration != "browser"

    stored_role = R.normalize_role(row["role"])
    eff = R.effective_role(s, stored_role)
    audit("login_success", username=row["username"], role=stored_role,
          details={"duration": duration, "effective_role": eff,
                   "stored_role": stored_role})
    note = ""
    if eff != stored_role:
        note = ("<div class='msg warn'>Die Rolle <code>%s</code> ist derzeit abgeschaltet – "
                "wirksam bist du als <code>%s</code> unterwegs. Dein Konto bleibt "
                "unveraendert gespeichert.</div>" % (stored_role, eff))
    return page("Angemeldet", "<div class='card'><h2>Hallo %s</h2>%s"
                "<p>Rolle: <code>%s</code> (gespeichert: <code>%s</code>)</p>"
                "<p>Sitzungsdauer: <code>%s</code></p>"
                "<p><a href='/receiver-simulator'>Zum Receiver-Simulator</a></p></div>"
                % (row["username"], note, eff, stored_role, duration),
                "Angemeldet", "ok")


@app.route("/logout")
def logout():
    user = current_session_user()
    if user:
        audit("logout", username=user["username"], role=user["stored_role"])
    session.clear()
    return redirect("/")


# --------------------------------------------------------------------------
# Profilwahl – EINBAU PUNKT 7 (dieselbe Logik wie im Container)
# --------------------------------------------------------------------------

@app.route("/api/profile/select", methods=["GET", "POST"])
def select_profile():
    profile = request.values.get("profile") or request.values.get("p") or ""
    s = settings()
    user = current_session_user()
    role = user["stored_role"] if user else "guest"
    policy = R.load_profile_policy(POLICY)
    decision = R.profile_decision(
        s, role=role, authenticated=bool(user), target_profile=profile,
        protected=policy.get("protected"), allowed_map=policy.get("allowed"))
    if decision["event"]:
        audit(decision["event"], username=user["username"] if user else None, role=role,
              details={"profile": profile, "reason": decision["reason"],
                       "effective_role": decision["effective_role"],
                       "maintenance": decision["maintenance"]["active"]})
    resp = jsonify({"ok": decision["allow"], "decision": decision})
    resp.status_code = 200 if decision["allow"] else 403
    return resp


@app.route("/profiles")
def profiles():
    s = settings()
    policy = R.load_profile_policy(POLICY)
    user = current_session_user()
    role = user["stored_role"] if user else "guest"
    rows = []
    for name in sorted(policy.get("protected") | set((policy.get("allowed") or {}).get("user", set()))
                       | {"80m", "40m", "KW-Schutz", "Admin-only"}):
        d = R.profile_decision(s, role=role, authenticated=bool(user), target_profile=name,
                               protected=policy.get("protected"),
                               allowed_map=policy.get("allowed"))
        rows.append((name, "ja" if d["allow"] else "nein", d["reason"]))
    trs = "".join("<tr><td>{}</td><td>{}</td><td><code>{}</code></td></tr>".format(*r)
                  for r in rows)
    body = ("<div class='card'><h2>Profilpruefung fuer Rolle <code>" + role + "</code></h2>"
            "<p><small class='dim'>Entscheidung aus <code>access_settings</code> + "
            "<code>profile-policy.json</code>. Dieselbe Funktion laeuft serverseitig im "
            "Container (<code>owrx/dnx_system_verify.py</code>).</small></p>"
            "<table><thead><tr><th>Profil</th><th>erlaubt</th><th>Grund</th></tr></thead>"
            "<tbody>" + trs + "</tbody></table></div>")
    return page("Profile", body)


# --------------------------------------------------------------------------
# Aktivitaetslog – oeffentlich (24 h, ohne IP) und Admin-Logbuch (voll)
# --------------------------------------------------------------------------

def audit_rows(since: Optional[int], limit: int = 200):
    conn = db()
    try:
        if since:
            rows = conn.execute(
                "SELECT ts, event, username, role, ip, user_agent, details FROM audit_log "
                "WHERE ts>=? ORDER BY ts DESC LIMIT ?", (since, limit)).fetchall()
        else:
            rows = conn.execute(
                "SELECT ts, event, username, role, ip, user_agent, details FROM audit_log "
                "ORDER BY ts DESC LIMIT ?", (limit,)).fetchall()
    finally:
        conn.close()
    return rows


@app.route("/activity")
def activity():
    s = settings()
    if not s.get("public_activity_enabled", True):
        return Response(page("Aktivitaet", "<div class='card'><h2>Oeffentliches "
                                           "Aktivitaetslog deaktiviert</h2>"
                                           "<p><code>public_activity_enabled = false</code></p>"
                                           "</div>"), status=404)
    hours = int(s.get("public_activity_hours", 24))
    since = int(time.time()) - hours * 3600
    rows = audit_rows(since)
    trs = []
    for r in rows:
        when = time.strftime("%d.%m.%Y %H:%M:%S", time.localtime(r["ts"]))
        trs.append("<tr><td>{}</td><td><code>{}</code></td><td>{}</td></tr>".format(
            when, r["event"], r["username"] or "Gast"))
    body = ("<div class='card'><h2>Oeffentliche Aktivitaet (letzte " + str(hours) +
            " Stunden)</h2>"
            "<p><small class='dim'>Keine IP, kein User-Agent, keine Sicherheitsdetails – "
            "gemaess Uebergabe Kapitel 6.</small></p>"
            "<table><thead><tr><th>Zeit</th><th>Ereignis</th><th>Konto</th></tr></thead>"
            "<tbody>" + "".join(trs) + "</tbody></table></div>")
    return page("Aktivitaet", body)


@app.route("/admin/logbook")
def logbook():
    user = current_session_user()
    if not user or user["role"] != "admin":
        return Response(page("Logbuch", "<div class='card'>Nur fuer Admins.</div>"), status=403)
    rows = audit_rows(None, 300)
    trs = []
    for r in rows:
        when = time.strftime("%d.%m.%Y %H:%M:%S", time.localtime(r["ts"]))
        trs.append(
            "<tr><td>{}</td><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td>"
            "<td><small>{}</small></td><td><code>{}</code></td></tr>".format(
                when, r["event"], r["username"] or "-", r["role"] or "-", r["ip"] or "-",
                (r["user_agent"] or "-")[:40], (r["details"] or "")[:120]))
    body = ("<div class='card'><h2>Admin-Logbuch (vollstaendig)</h2>"
            "<table><thead><tr><th>Zeit</th><th>Ereignis</th><th>Konto</th><th>Rolle</th>"
            "<th>IP</th><th>User-Agent</th><th>Details</th></tr></thead><tbody>" +
            "".join(trs) + "</tbody></table></div>")
    return page("Logbuch", body)


@app.route("/admin/users")
def users():
    user = current_session_user()
    if not user or user["role"] != "admin":
        return Response(page("Benutzer", "<div class='card'>Nur fuer Admins.</div>"), status=403)
    s = settings()
    conn = db()
    try:
        rows = conn.execute("SELECT username, role, active, created_at FROM users ORDER BY id").fetchall()
    finally:
        conn.close()
    trs = []
    for r in rows:
        trs.append(
            "<tr><td>{}</td><td><code>{}</code></td><td><code>{}</code></td><td>{}</td>"
            "<td>{}</td></tr>".format(
                r["username"], r["role"], R.effective_role(s, r["role"]),
                "ja" if r["active"] else "nein",
                time.strftime("%d.%m.%Y", time.localtime(r["created_at"]))))
    body = ("<div class='card'><h2>Bestandskonten</h2>"
            "<p><small class='dim'>Die Systemsteuerung aendert keine Konten. Abgeschaltete "
            "Rollen werden nur <em>wirksam</em> herabgestuft "
            "(<code>downgrade_disabled_roles</code>).</small></p>"
            "<table><thead><tr><th>Benutzer</th><th>Rolle (DB)</th><th>wirksam</th>"
            "<th>aktiv</th><th>seit</th></tr></thead><tbody>" + "".join(trs) +
            "</tbody></table></div>")
    return page("Benutzer", body)


# --------------------------------------------------------------------------
# Receiver-Simulator – EINBAU PUNKT 6 (Frontend zeigt Backendstatus)
# --------------------------------------------------------------------------

@app.route("/receiver-simulator")
def simulator():
    s = settings()
    user = current_session_user()
    sim_role = user["stored_role"] if user else "guest"
    html = """<!DOCTYPE html>
<html lang="de"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>DNX Receiver-Simulator</title>
<style>%s</style></head>
<body>
<header><h1>Receiver-Simulator</h1>
<div><span class="pill" id="sim-role">Rolle: lade ...</span></div></header>
<main>
  <div class="card">
    <h2>Frontend-Status aus <code>/api/system/state</code></h2>
    <p><small class="dim">Geladen wird einmal beim Oeffnen und auf Knopfdruck – kein Polling.
    Die Datei <code>dnx_system_state.js</code> ist dieselbe, die im OpenWebRX-Plugin liegt.</small></p>
    <pre id="sim-json" style="background:#101821;border:1px solid #24303c;border-radius:8px;padding:10px;overflow:auto;max-height:280px"></pre>
    <div class="row"><button class="ghost" id="sim-refresh">Status neu laden</button></div>
  </div>
  <div class="card">
    <h2>Anmelde-Dialog (reagiert auf die Schalter)</h2>
    <div class="row">
      <button class="ghost" id="dnx-register-btn" data-dnx-register>Registrieren</button>
      <button class="ghost" id="sim-login">Anmelden</button>
    </div>
    <label>Sitzungsdauer</label>
    <select id="sim-session" class="dnx-session-option">
      <option value="browser" data-dnx-session="browser">Browser (Sitzungsende)</option>
      <option value="1d" data-dnx-session="day">1 Tag</option>
      <option value="7d" data-dnx-session="week">7 Tage</option>
      <option value="30d" data-dnx-session="month">30 Tage</option>
      <option value="forever" data-dnx-session="forever">Unbegrenzt</option>
    </select>
    <label>Profilwahl</label>
    <select id="dnx-profile-select" data-dnx-profile-select>
      <option>80m</option><option>40m</option><option>KW-Schutz</option><option>Admin-only</option>
    </select>
    <div class="row" style="margin-top:12px">
      <button id="sim-switch">Profil wechseln</button>
      <span id="sim-result" class="pill">-</span>
    </div>
    <p><small class="dim">Der Button fragt <code>/api/profile/select</code> – also dieselbe
    Entscheidungslogik wie <code>owrx/dnx_system_verify.py</code> im Container.</small></p>
  </div>
  <div class="card">
    <h2>Aktivitaetslog-Link</h2>
    <a id="dnx-activity-link" data-dnx-activity href="/activity">Oeffentliche Aktivitaet</a>
  </div>
</main>
<script>window.DNX_ACCOUNT_BASE = location.origin; window.DNX_ROLE = "%s";</script>
<script src="/static/receiver/dnx_system_state.js"></script>
<script>
document.addEventListener("dnx:system-state", function (ev) {
  var d = ev.detail || {};
  document.getElementById("sim-role").textContent = "Rolle: " + (d.role || "guest") +
    " | Quelle: " + (d.source || "?") + (d.ok ? "" : " (fail-open)");
  var pre = document.getElementById("sim-json");
  pre.textContent = JSON.stringify({state: d.state, rules: d.rules, error: d.error}, null, 2);
});
document.getElementById("sim-refresh").addEventListener("click", function () {
  if (window.DNXSystemState) window.DNXSystemState.refresh();
});
document.getElementById("sim-switch").addEventListener("click", function () {
  var p = document.getElementById("dnx-profile-select").value;
  var res = document.getElementById("sim-result");
  var local = window.DNXSystemState ? window.DNXSystemState.decide(p) : {allow: true};
  res.textContent = "Vorab: " + (local.allow ? "ok" : local.reason);
  fetch("/api/profile/select?profile=" + encodeURIComponent(p))
    .then(function (r) { return r.json(); })
    .then(function (j) {
      res.textContent = (j.ok ? "ERLAUBT" : "ABGELEHNT") + " – " + j.decision.reason +
        " (Rolle wirksam: " + j.decision.effective_role + ")";
      res.style.color = j.ok ? "#35d07f" : "#ff5d5d";
    })
    .catch(function (e) { res.textContent = "Fehler: " + e; });
});
document.getElementById("sim-login").addEventListener("click", function () {
  location.href = "/login";
});
</script>
</body></html>""" % (PAGE_CSS, sim_role)
    return Response(html, mimetype="text/html; charset=utf-8")


@app.route("/static/receiver/dnx_system_state.js")
def receiver_js():
    try:
        with open(RECEIVER_JS, "r", encoding="utf-8") as fh:
            data = fh.read()
    except OSError as exc:
        return Response("// %s" % exc, mimetype="application/javascript")
    return Response(data, mimetype="application/javascript; charset=utf-8",
                    headers={"Access-Control-Allow-Origin": "*", "Cache-Control": "no-store"})


# --------------------------------------------------------------------------
# Start
# --------------------------------------------------------------------------

@app.route("/demo-login")
def demo_login():
    """NUR DEMO: direkter Sprung ins Panel ohne Passwort.

    In app.py gibt es so etwas selbstverstaendlich nicht – dort gilt ausschliesslich
    der normale Login inkl. max_login_failures / login_lock_seconds.
    """
    name = request.args.get("u", "dl1abc")
    allowed = {n: r for n, _p, r in DEMO_USERS}
    if name not in allowed:
        return page("Demo-Login", "<div class='card'>Unbekanntes Demo-Konto.</div>")
    s = settings()
    session.clear()
    session["dnx_user"] = name
    session["dnx_duration"] = "browser"
    session["dnx_expires"] = 0
    audit("login_success", username=name, role=allowed[name],
          details={"duration": "browser", "weg": "demo-login"})
    return redirect("/admin/system" if allowed[name] == "admin" else "/receiver-simulator")


@app.route("/")
def index():
    s = settings()
    summary = R.admin_summary(s, STORE.warnings())
    lines = [
        ("Registrierung", summary["registration"]),
        ("Neue Konten", summary["new_accounts"]),
        ("Profilsteuerung", summary["profile_control"]),
        ("Account-Zwang", summary["account_required"]),
        ("Gast-Profilwechsel", summary["guest_switch"]),
        ("Rolle user", "AN" if summary["roles"]["user"] else "AUS"),
        ("Rolle extended", "AN" if summary["roles"]["extended"] else "AUS"),
        ("Standardrolle", summary["roles"]["default"]),
        ("Wartungsmodus", "AN" if summary["maintenance"]["active"] else "AUS"),
        ("Oeffentliches Log", "{} ({} h)".format(
            "AN" if summary["audit"]["public"] else "AUS", summary["audit"]["hours"])),
        ("Audit-Logging", "AN" if summary["audit"]["enabled"] else "AUS"),
        ("Sitzungsdauern", ", ".join(summary["sessions"])),
    ]
    body = ("<div class='card'><h2>Globale Systemsteuerung</h2><table><tbody>" +
            "".join("<tr><th>{}</th><td>{}</td></tr>".format(k, v) for k, v in lines) +
            "</tbody></table>"
            "<div class='msg warn' style='margin-top:12px'>Demo-Sprungmarke: "
            "<a href='/demo-login?u=dl1abc'><b>als Admin anmelden und Systemsteuerung "
            "oeffnen</b></a> &middot; <a href='/demo-login?u=dl2xyz'>als Extended</a> "
            "&middot; <a href='/demo-login?u=do3test'>als User</a> &middot; "
            "<a href='/logout'>abmelden</a></div>"
            "<p style='margin-top:14px'><a href='/admin/system'><b>Systemsteuerung oeffnen</b></a>"
            " &middot; <a href='/profiles'>Profilpruefung</a> &middot; "
            "<a href='/receiver-simulator'>Receiver-Simulator</a> &middot; "
            "<a href='/activity'>Aktivitaet</a> &middot; <a href='/api/system/state'>API-Status</a>"
            "</p></div>")
    return page("DNX Account Control Demo", body)


if __name__ == "__main__":
    print("DNX Systemsteuerung – Referenz/Demo")
    print("  DB       : %s" % DB)
    print("  Policy   : %s" % POLICY)
    print("  Panel    : http://%s:%d/admin/system" % (HOST, PORT))
    print("  Login    : dl1abc / admin123 (admin)")
    app.run(host=HOST, port=PORT, debug=False, threaded=True)
