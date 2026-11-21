# -*- coding: utf-8 -*-
"""dnx_system_control_integration – Einbau-Helfer fuer app.py.

Ziel: app.py muss nur um ZWEI Zeilen erweitert werden, damit der neue
Admin-Bereich "Systemsteuerung" lebt:

    import dnx_system_control_integration as dnx_sc   # nach den bestehenden Imports
    dnx_sc.install(app)                               # direkt nach app = Flask(__name__)

Alles Weitere (Store, Blueprint, CSRF, Wartungsmodus-Waechter, Helfer fuer
Registrierung/Login/Sitzungen/Profilpruefung) kommt aus dieser Datei.

Sicherheitsprinzip: Wenn hier etwas schiefgeht, darf der Account-Dienst NICHT
sterben. install() faengt Fehler ab, protokolliert sie und laeuft im
fail-open-Modus weiter (Systemsteuerung nicht erreichbar, Rest wie bisher).

Anpassung an die bestehende Sitzung:
    install(app, session_user_keys=(...), session_role_keys=(...))
    oder komplett eigener Provider:
    install(app, current_user=lambda: {"username": ..., "role": ..., ...})
"""

from __future__ import annotations

import logging
import os
import sys
import time
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

from dnx_system_control import access_rules as R            # noqa: E402
from dnx_system_control.settings_store import (PACKAGE_VERSION, SettingsStore,  # noqa: E402
                                              defaults as _defaults, write_audit)

log = logging.getLogger("dnx.system_control")

DEFAULT_DB = os.environ.get(
    "DNX_ACCOUNTS_DB", "/opt/owrx-docker/var/dnx-access-control/accounts.sqlite3")
DEFAULT_POLICY = os.environ.get(
    "DNX_PROFILE_POLICY",
    "/opt/owrx-docker/var/dnx-access-control/profile-policy.json")

# Sitzungsschluessel, die in app.py ueblich sein koennten (tolerant)
SESSION_USER_KEYS = ("dnx_user", "dnx_username", "dnx_account", "username",
                     "account", "user", "chat_name")
SESSION_ROLE_KEYS = ("dnx_role", "dnx_account_role", "role", "user_role", "account_role")
SESSION_EXPIRY_KEYS = ("dnx_expires", "expires_at", "exp", "dnx_session_expires")

# Pfade, die im Wartungsmodus erreichbar bleiben muessen.
# Bewusst NICHT offen: "/" (Startseite zeigt "Ausser Betrieb"), "/register",
# "/activity", "/api/policy" – ausser Betrieb heisst ausser Betrieb.
GUARD_OPEN_EXACT = {"/favicon.ico"}
GUARD_OPEN_PREFIX = ("/api/system/", "/admin", "/static/", "/login",
                     "/logout", "/healthz")

WARTUNG_TITEL = "Ausser Betrieb"
WARTUNG_UNTERTITEL = "Wartungsarbeiten"
WARTUNG_DEFAULT = ("Wartungsarbeiten: Der Empfaenger ist voruebergehend ausser "
                   "Betrieb. Bitte spaeter erneut versuchen.")

_state: Dict[str, Any] = {"installed": False, "store": None, "error": None,
                          "installed_at": None, "version": PACKAGE_VERSION}


# --------------------------------------------------------------------------
# Zugriff fuer den Rest von app.py
# --------------------------------------------------------------------------

def store() -> SettingsStore:
    """Der zentrale Einstellungs-Store (access_settings)."""
    if _state["store"] is None:
        _state["store"] = SettingsStore(DEFAULT_DB)
    return _state["store"]


def settings(**kw) -> Dict[str, Any]:
    """Aktuelle globale Einstellungen (mit Cache, fail-open)."""
    try:
        return store().values(use_cache=True, **kw)
    except Exception as exc:  # pragma: no cover
        log.warning("settings() fehlgeschlagen, Defaults aktiv: %s", exc)
        return _defaults()


def rules():
    """access_rules-Modul (Rollen, Sitzungen, Profilentscheidungen)."""
    return R


def invalidate() -> None:
    """Cache verwerfen, z. B. nachdem Einstellungen ausserhalb des Dienstes
    geaendert wurden (sqlite3 direkt, Migration, Rollback)."""
    try:
        store()._cache = None
    except Exception as exc:  # pragma: no cover
        log.debug("invalidate() fehlgeschlagen: %s", exc)


def status() -> Dict[str, Any]:
    return dict(_state)


# --------------------------------------------------------------------------
# Sitzungs-/Benutzererkennung (an app.py anpassbar)
# --------------------------------------------------------------------------

def _flask():
    from flask import request, session
    return request, session


def _flask_safe() -> Tuple[Any, Any]:
    """(request, session) oder (None, None) ausserhalb eines Request-Kontexts.

    Damit detect_user() auch aus CLI-Skripten, Timern oder Tests aufgerufen
    werden kann, ohne dass die ganze Anwendung abbricht.
    """
    try:
        from flask import has_request_context, request, session
        if has_request_context():
            return request, session
    except Exception:
        pass
    return None, None


def detect_user(session_user_keys: Iterable[str] = SESSION_USER_KEYS,
                session_role_keys: Iterable[str] = SESSION_ROLE_KEYS,
                session_expiry_keys: Iterable[str] = SESSION_EXPIRY_KEYS,
                db_role_lookup: bool = True) -> Dict[str, Any]:
    """Liest die angemeldete Person aus der bestehenden Flask-Sitzung.

    Reihenfolge: Sitzungs-Schluessel (tolerant) -> optional Abgleich mit der
    users-Tabelle (Rolle aus der DB ist massgeblich, nicht die Sitzung).
    """
    request, session = _flask_safe()
    session = session if session is not None else {}
    if request is not None:
        ip = (request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
              or request.remote_addr)
        agent = request.headers.get("User-Agent", "")
    else:
        ip, agent = None, ""
    info: Dict[str, Any] = {
        "username": None,
        "role": "guest",
        "stored_role": "guest",
        "active": None,
        "ip": ip,
        "user_agent": agent,
        "source": "none" if request is not None else "no-request-context",
    }
    for key in session_user_keys:
        if session.get(key):
            info["username"] = str(session[key])
            info["source"] = "session:%s" % key
            break
    for key in session_role_keys:
        if session.get(key):
            info["stored_role"] = R.normalize_role(session[key])
            break
    for key in session_expiry_keys:
        val = session.get(key)
        if val:
            try:
                if int(val) and int(val) < int(time.time()):
                    info["expired"] = True
            except (TypeError, ValueError):
                pass
            break
    if info.get("expired"):
        info["username"] = None
        info["stored_role"] = "guest"
        info["source"] = "expired"

    if db_role_lookup and info["username"]:
        row = _lookup_user(info["username"])
        if row:
            info["stored_role"] = R.normalize_role(row.get("role") or info["stored_role"])
            info["active"] = bool(row.get("active", True))
            info["source"] = "db"

    info["role"] = R.effective_role(settings(), info["stored_role"])
    return info


def _lookup_user(username: str) -> Optional[Dict[str, Any]]:
    """Liest Benutzername/Rolle/aktiv aus der users-Tabelle – rein lesend."""
    try:
        import sqlite3
        conn = sqlite3.connect(store().db_path, timeout=10)
        try:
            tables = [r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
            for cand in ("users", "accounts", "dnx_users"):
                if cand not in tables:
                    continue
                cols = [r[1].lower() for r in
                        conn.execute('PRAGMA table_info("%s")' % cand).fetchall()]
                name_col = next((c for c in ("username", "name", "account", "user")
                                 if c in cols), None)
                if not name_col:
                    continue
                row = conn.execute('SELECT * FROM "%s" WHERE "%s"=? LIMIT 1'
                                   % (cand, name_col), (username,)).fetchone()
                if row:
                    data = {c: v for c, v in zip(cols, row)}
                    return {"role": data.get("role") or data.get("user_role"),
                            "active": data.get("active", data.get("is_active", 1))}
        finally:
            conn.close()
    except Exception as exc:
        log.debug("Benutzerabgleich fehlgeschlagen: %s", exc)
    return None


# --------------------------------------------------------------------------
# Audit-Helfer (nutzt die vorhandene audit_log-Tabelle)
# --------------------------------------------------------------------------

def audit_event(event: str, *, username: Optional[str] = None,
                role: Optional[str] = None, ip: Optional[str] = None,
                user_agent: Optional[str] = None, details: Any = None,
                force: bool = False) -> bool:
    """Schreibt ein Audit-Ereignis, wenn audit_enabled AN ist (oder force)."""
    try:
        s = settings()
        if not force and not s.get("audit_enabled", True):
            return False
        if ip is None or user_agent is None:
            try:
                request, _session = _flask()
                ip = ip or request.headers.get("X-Forwarded-For", "").split(",")[0].strip() \
                    or request.remote_addr
                user_agent = user_agent or request.headers.get("User-Agent", "")
            except Exception:
                pass
        import sqlite3
        conn = sqlite3.connect(store().db_path, timeout=10, isolation_level=None)
        try:
            return write_audit(conn, event, username=username, role=role, ip=ip,
                               user_agent=user_agent, details=details)
        finally:
            conn.close()
    except Exception as exc:
        log.warning("audit_event(%s) fehlgeschlagen: %s", event, exc)
        return False


# --------------------------------------------------------------------------
# Fachliche Helfer fuer Registrierung / Login / Sitzungen / Profile
# --------------------------------------------------------------------------

def registration_gate(recent_registrations: int = 0) -> Tuple[bool, str, Dict[str, Any]]:
    """(erlaubt, grund, details) fuer die Registrierungsroute."""
    s = settings()
    reg = R.registration_state(s)
    if not reg["enabled"]:
        return False, "registration_disabled", reg
    ok, reason = R.registration_rate_allowed(s, recent_registrations)
    if not ok:
        return False, reason or "registration_rate_limit", reg
    return True, "ok", reg


def login_gate(username: str, failure_count: int,
               last_failure_ts: Optional[int]) -> Tuple[bool, int, str]:
    """(gesperrt, verbleibende_sekunden, grund) – VOR der Passwortpruefung aufrufen.

    Zaehlt die Fehlversuche aus dem Audit-Log (login_failed), damit die Werte aus
    der Systemsteuerung (max_login_failures / login_lock_seconds) sofort wirken.
    """
    s = settings()
    blocked, remaining, reason = R.login_blocked(s, failure_count, last_failure_ts)
    if blocked:
        audit_event("login_blocked", username=username,
                    details={"remaining": remaining, "failures": failure_count})
        return True, remaining, reason or "login_locked"
    return False, 0, "ok"


def failure_stats(username: str) -> Tuple[int, Optional[int]]:
    """(Anzahl Fehlversuche, Zeitstempel des letzten) aus dem Audit-Log."""
    try:
        import sqlite3
        conn = sqlite3.connect(store().db_path, timeout=10)
        try:
            row = conn.execute(
                "SELECT COUNT(*), MAX(ts) FROM audit_log WHERE event='login_failed' "
                "AND username=?", (username,)).fetchone()
            return (int(row[0] or 0), int(row[1]) if row and row[1] else None)
        finally:
            conn.close()
    except Exception as exc:
        log.debug("failure_stats fehlgeschlagen: %s", exc)
        return 0, None


def session_choices() -> List[Dict[str, Any]]:
    return R.session_choices(settings())


def sanitize_session(value: Any) -> str:
    return R.sanitize_session_request(settings(), value)


def initial_role() -> str:
    return R.default_registration_role(settings())


def initial_active() -> bool:
    return R.new_account_state(settings()) == "active"


def password_min_length() -> int:
    return int(settings().get("password_min_length", 8))


def captcha_required() -> bool:
    return bool(settings().get("captcha_enabled", True))


def login_max_failures() -> int:
    """max_login_failures aus der Systemsteuerung (0 = Sperre aus)."""
    return int(settings().get("max_login_failures", 5) or 0)


def login_lock_seconds() -> int:
    """login_lock_seconds aus der Systemsteuerung (0 = keine Sperre)."""
    return int(settings().get("login_lock_seconds", 900) or 0)


def login_lock_active() -> bool:
    return login_max_failures() > 0 and login_lock_seconds() > 0


def registration_limit() -> int:
    return int(settings().get("registration_limit", 5) or 0)


def registration_window() -> int:
    return int(settings().get("registration_window_seconds", 3600) or 3600)


def initial_status() -> str:
    """Status fuer ein frisch registriertes Konto.

    app.py kennt 'active' und 'blocked'; die Anmeldung prueft status=='active'.
    Bei new_accounts_active=AUS wird also 'blocked' geschrieben und ein Admin
    schaltet das Konto in seiner Benutzerliste frei.
    """
    if initial_active():
        return "active"
    return os.environ.get("DNX_INACTIVE_STATUS", "blocked")


def audit_wanted() -> bool:
    """True, wenn neue Audit-Zeilen geschrieben werden sollen."""
    return bool(settings().get("audit_enabled", True))


def session_options_html(selected: Optional[str] = None) -> str:
    """<select name=duration> mit genau den erlaubten Sitzungsdauern.

    Werte sind die Schluessel aus DURS in app.py:
    browser / day / week / month / forever.
    """
    try:
        import html as _html
    except Exception:
        _html = None
    sel = sanitize_session(selected) if selected else None
    teile = []
    for c in session_choices():
        marke = ' selected' if sel and c["id"] == sel else ''
        label = c.get("label") or c["id"]
        if _html is not None:
            label = _html.escape(str(label))
        teile.append('<option value=%s%s>%s</option>' % (c["id"], marke, label))
    if not teile:
        teile.append('<option value=browser selected>Bis Browser geschlossen</option>')
    return '<select name=duration>' + ''.join(teile) + '</select>'


def profile_check(profile_name: Any, user: Optional[Dict[str, Any]] = None,
                  policy_path: Optional[str] = None) -> Dict[str, Any]:
    """Verbindliche Profilentscheidung – identisch zur Containerpruefung.

    Nutzt access_settings + profile-policy.json und schreibt das passende
    Audit-Ereignis (profile_change / profile_denied).
    """
    s = settings()
    user = user or detect_user()
    policy = R.load_profile_policy(policy_path or DEFAULT_POLICY)
    decision = R.profile_decision(
        s, role=user.get("stored_role") or user.get("role") or "guest",
        authenticated=bool(user.get("username")),
        target_profile=profile_name,
        protected=policy.get("protected"),
        allowed_map=policy.get("allowed"))
    event = decision.get("event")
    if event:
        audit_event(event, username=user.get("username"),
                    role=user.get("stored_role") or user.get("role"),
                    details={"profile": profile_name, "reason": decision["reason"],
                             "effective_role": decision["effective_role"],
                             "maintenance": decision["maintenance"]["active"]})
    return decision


def public_state() -> Dict[str, Any]:
    """Was das Receiver-Frontend sehen darf."""
    s = settings()
    return {"state": store().public_state(s), "rules": R.public_view(s)}


# --------------------------------------------------------------------------
# Installation
# --------------------------------------------------------------------------

def maintenance_response(maint: Dict[str, Any], path: str = "/",
                         accept: str = "") -> Any:
    """503-Antwort im Wartungsmodus: HTML-Seite fuer Menschen, JSON fuer APIs.

    Die Seite ist bewusst selbstenthalten (kein Template, kein CSS-File), damit
    sie auch dann funktioniert, wenn /static/ nicht ausgeliefert wird.
    """
    from flask import Response
    msg = str(maint.get("message") or "").strip() or WARTUNG_DEFAULT
    msg = msg.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    pfad = path or "/"
    will_json = pfad.startswith("/api/") or "application/json" in (accept or "")
    if will_json:
        import json as _json
        body = _json.dumps({
            "ok": False, "error": "maintenance", "status": 503,
            "maintenance": {"active": True, "allowed": False,
                            "reason": maint.get("reason") or "maintenance",
                            "message": msg},
        }, ensure_ascii=False)
        resp = Response(body, status=503, mimetype="application/json; charset=utf-8")
    else:
        html = (
            "<!doctype html><html lang=de><head><meta charset=utf-8>"
            '<meta name=viewport content="width=device-width,initial-scale=1">'
            '<meta name=robots content="noindex,nofollow">'
            "<title>" + WARTUNG_TITEL + " &middot; " + WARTUNG_UNTERTITEL + "</title>"
            '<style>body{margin:0;background:#12161c;color:#e8edf4;'
            "font:16px/1.55 system-ui,-apple-system,Segoe UI,sans-serif;"
            "display:flex;min-height:100vh;align-items:center;justify-content:center}"
            ".b{max-width:34rem;padding:2.2rem 1.5rem;text-align:center}"
            ".z{font-size:3rem}.t{margin:.4rem 0;font-size:1.7rem;font-weight:650}"
            ".u{margin:0 0 1.1rem;color:#9fb0c2;letter-spacing:.08em;"
            "text-transform:uppercase;font-size:.82rem}"
            ".m{margin:0 0 1.4rem;padding:.95rem 1.05rem;background:#1b222b;"
            "border:1px solid #2b3644;border-radius:10px;text-align:left}"
            ".f{margin:0;color:#8b98a8;font-size:.9rem}"
            "a{color:#6fb3f0}</style></head><body><div class=b>"
            '<div class=z>&#9888;&#65039;</div>'
            '<h1 class=t>' + WARTUNG_TITEL + "</h1>"
            '<p class=u>' + WARTUNG_UNTERTITEL + "</p>"
            '<p class=m>' + msg + "</p>"
            '<p class=f>Anmeldung und Adminbereich bleiben erreichbar.'
            "<br><a href=/login>Zur Anmeldung</a></p>"
            "</div></body></html>")
        resp = Response(html, status=503, mimetype="text/html; charset=utf-8")
    resp.headers["Retry-After"] = "600"
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["X-DNX-Maintenance"] = "1"
    return resp

def install(app, *,
            url_prefix: str = "/admin",
            db_path: Optional[str] = None,
            web_dir: Optional[str] = None,
            current_user: Optional[Callable[[], Optional[Dict[str, Any]]]] = None,
            session_user_keys: Iterable[str] = SESSION_USER_KEYS,
            session_role_keys: Iterable[str] = SESSION_ROLE_KEYS,
            enable_maintenance_guard: bool = True,
            guard_open_exact: Iterable[str] = GUARD_OPEN_EXACT,
            guard_open_prefix: Iterable[str] = GUARD_OPEN_PREFIX,
            strict_origin: bool = True,
            auto_schema: bool = True) -> Dict[str, Any]:
    """Registriert Blueprint + Wartungsmodus-Waechter an der Flask-App.

    Gibt eine Statusauskunft zurueck und wirft keine Exception.
    """
    result: Dict[str, Any] = {"installed": False, "error": None,
                              "version": PACKAGE_VERSION}
    try:
        if db_path:
            global DEFAULT_DB
            DEFAULT_DB = db_path
        _state["store"] = SettingsStore(db_path or DEFAULT_DB)
        if auto_schema:
            try:
                _state["store"].ensure_schema()
            except Exception as exc:
                # Tabelle fehlt und konnte nicht angelegt werden -> Migration noetig
                log.warning("access_settings nicht initialisierbar (%s). "
                            "Bitte migrate_add_access_settings.py ausfuehren.", exc)
                result["schema_warning"] = str(exc)

        provider = current_user or (lambda: detect_user(session_user_keys, session_role_keys))

        from dnx_system_control.admin_api import create_blueprint
        existing = None
        try:
            existing = app.blueprints.get("dnx_system_control")
        except Exception:
            existing = None
        if existing is not None:
            # install() ist idempotent: mehrfach aufrufen schadet nicht
            result["already_registered"] = True
            log.info("Systemsteuerung war bereits registriert – uebersprungen")
        else:
            app.register_blueprint(create_blueprint(
                _state["store"], current_user=provider, url_prefix=url_prefix,
                web_dir=web_dir, strict_origin=strict_origin))

        if enable_maintenance_guard:
            open_exact = set(guard_open_exact)
            open_prefix = tuple(guard_open_prefix)

            @app.before_request
            def _dnx_maintenance_guard():  # pragma: no cover - laeuft im Dienst
                from flask import request
                s = settings()
                if not s.get("maintenance_mode", False):
                    return None
                path = request.path or "/"
                if path in open_exact or path.startswith(open_prefix):
                    return None
                user = provider() or {}
                maint = R.maintenance_state(s, user.get("role") or "guest")
                if maint["allowed"]:
                    return None
                return maintenance_response(
                    maint, path, request.headers.get("Accept", ""))

        _state.update({"installed": True, "installed_at": int(time.time()),
                       "error": None})
        result.update({"installed": True, "url_prefix": url_prefix,
                       "db": _state["store"].db_path,
                       "panel": url_prefix.rstrip("/") + "/system",
                       "maintenance_guard": bool(enable_maintenance_guard)})
        log.info("DNX Systemsteuerung %s installiert (%s)", PACKAGE_VERSION, result["panel"])
    except Exception as exc:
        # Der Account-Dienst darf wegen der Systemsteuerung nicht ausfallen.
        _state["error"] = str(exc)
        result["error"] = str(exc)
        log.error("DNX Systemsteuerung konnte nicht installiert werden: %s", exc)
    return result


__all__ = [
    "install", "store", "settings", "rules", "status", "detect_user", "audit_event",
    "failure_stats", "invalidate",
    "registration_gate", "login_gate", "session_choices", "sanitize_session",
    "session_options_html", "initial_role", "initial_active", "initial_status",
    "password_min_length", "captcha_required", "audit_wanted",
    "login_max_failures", "login_lock_seconds", "login_lock_active",
    "registration_limit", "registration_window",
    "profile_check", "public_state", "maintenance_response",
    "WARTUNG_TITEL", "WARTUNG_DEFAULT", "PACKAGE_VERSION",
]
