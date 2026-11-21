# -*- coding: utf-8 -*-
"""admin_api – Flask-Blueprint fuer den neuen Admin-Bereich "Systemsteuerung".

Einbau in /opt/owrx-docker/var/dnx-access-control/app.py (siehe INTEGRATION.md):

    from dnx_system_control.settings_store import SettingsStore
    from dnx_system_control.admin_api import create_blueprint

    dnx_store = SettingsStore()                      # accounts.sqlite3
    dnx_store.ensure_schema()                        # idempotent

    def _dnx_current_user():
        # HIER an die bestehende Sitzung anbinden (Rolle/Name aus app.py)
        return {"username": ..., "role": ..., "ip": ..., "user_agent": ...}

    app.register_blueprint(create_blueprint(
        dnx_store, current_user=_dnx_current_user, url_prefix="/admin"))

Endpunkte:
    GET  /admin/system                        HTML-Panel (nur admin)
    GET  /admin/system/static/<datei>         CSS/JS des Panels (nur admin)
    GET  /admin/api/system/settings           Ist-Zustand + Metadaten + Auswirkung
    POST /admin/api/system/settings           atomares Speichern + Audit
    POST /admin/api/system/restore-defaults   Defaults zurueckholen (confirm=true)
    GET  /admin/api/system/impact             Auswirkung auf Bestandsuser
    GET  /api/system/state                    oeffentlicher Status + Regeln (Frontend)
    GET  /api/system/healthz                  Smoke-Test

Der Praefix ist konfigurierbar (url_prefix, Default "/admin").

Sicherheit:
    * Admin-only: ohne gueltige admin-Rolle gibt es 403 (deny by default).
      Wird kein current_user-Provider uebergeben, bleibt der Bereich gesperrt.
    * CSRF: Sitzungs-Token + Origin/Referer-Pruefung, constant-time Vergleich.
    * Schreibschutz: read-only-Schluessel und unbekannte Schluessel -> 400.
    * Kleine Rate-Limit fuer Schreibvorgaenge.
"""

from __future__ import annotations

import collections
import hmac
import json
import os
import secrets
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

try:
    from flask import (Blueprint, Response, abort, jsonify, request, session,
                       send_from_directory)
except ImportError as exc:  # pragma: no cover - nur relevant ohne Flask
    raise ImportError(
        "admin_api benoetigt Flask (wird von app.py bereitgestellt): %s" % exc)

from . import access_rules
from .settings_store import (PACKAGE_VERSION, SettingsStore,
                             SettingsUnavailable, SettingsValidationError)

CSRF_SESSION_KEY = "dnx_sys_csrf"
CSRF_HEADER = "X-CSRF-Token"
CSRF_FIELD = "csrf_token"
ADMIN_ROLE = "admin"

_WRITE_LIMIT = 30          # Schreibaktionen
_WRITE_WINDOW = 60         # Sekunden


# --------------------------------------------------------------------------
# Helfer
# --------------------------------------------------------------------------

def _json_error(message: str, status: int, **extra) -> Tuple[Response, int]:
    """Fehlerantwort. `extra` darf zusaetzliche Felder wie code=... enthalten."""
    payload: Dict[str, Any] = {"ok": False, "error": message, "status": status}
    payload.update(extra)
    return jsonify(payload), status


def _no_store(resp: Response) -> Response:
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    return resp


def _safe_json_blob(obj: Any) -> str:
    return (json.dumps(obj, ensure_ascii=False, default=str)
            .replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026"))


def _client_ip(req) -> Optional[str]:
    fwd = req.headers.get("X-Forwarded-For", "")
    if fwd:
        return fwd.split(",")[0].strip()
    return req.remote_addr


class _RateLimiter:
    """Sehr kleine Sliding-Window-Limit fuer Schreibaktionen."""

    def __init__(self, limit: int = _WRITE_LIMIT, window: int = _WRITE_WINDOW):
        self.limit = limit
        self.window = window
        self._hits: Dict[str, collections.deque] = collections.defaultdict(collections.deque)

    def allow(self, key: str) -> Tuple[bool, int]:
        now = time.time()
        dq = self._hits[key]
        while dq and now - dq[0] > self.window:
            dq.popleft()
        if len(dq) >= self.limit:
            return False, int(self.window - (now - dq[0]))
        dq.append(now)
        if len(self._hits) > 512:  # Speicherschutz
            for k in list(self._hits)[:128]:
                if not self._hits[k]:
                    self._hits.pop(k, None)
        return True, 0


# --------------------------------------------------------------------------
# Blueprint-Fabrik
# --------------------------------------------------------------------------

def create_blueprint(store: SettingsStore,
                     current_user: Optional[Callable[[], Optional[Dict[str, Any]]]] = None,
                     *,
                     url_prefix: str = "/admin",
                     web_dir: Optional[str] = None,
                     csrf_token_name: str = CSRF_SESSION_KEY,
                     strict_origin: bool = True,
                     rate_limit: Optional[_RateLimiter] = None,
                     audit_hook: Optional[Callable[[Dict[str, Any]], None]] = None,
                     ) -> Blueprint:
    """Erzeugt das Blueprint. `current_user()` muss liefern:
    {'username': str|None, 'role': str|None, 'ip': str|None, 'user_agent': str|None}
    oder None (dann gilt: nicht angemeldet).
    """
    # Kein Blueprint-Prefix: die Pfade werden explizit aus url_prefix gebaut,
    # damit exakt die dokumentierten URLs entstehen
    #   /admin/system  /admin/api/system/settings  /api/system/state
    bp = Blueprint("dnx_system_control", __name__)
    A = (url_prefix or "").rstrip("/")
    web_dir = web_dir or os.environ.get("DNX_SYSTEM_WEB_DIR") or \
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")
    limiter = rate_limit or _RateLimiter()

    # ---------------- Zugriffskontrolle ----------------

    def _actor() -> Dict[str, Any]:
        info: Dict[str, Any] = {"username": None, "role": None,
                                "ip": _client_ip(request),
                                "user_agent": request.headers.get("User-Agent")}
        if current_user is None:
            return info
        try:
            got = current_user() or {}
        except Exception:
            got = {}
        if isinstance(got, dict):
            info.update({k: v for k, v in got.items() if v is not None})
        info["role"] = access_rules.normalize_role(info.get("role"))
        return info

    def _require_admin() -> Tuple[Optional[Dict[str, Any]], Optional[Tuple[Response, int]]]:
        actor = _actor()
        if actor["role"] != ADMIN_ROLE:
            detail = ("Systemsteuerung ist nur fuer die Rolle 'admin' erreichbar."
                      if current_user is not None else
                      "Kein current_user-Provider registriert: Bereich bleibt "
                      "aus Sicherheitsgruenden gesperrt (siehe INTEGRATION.md).")
            return actor, _json_error(detail, 403, role=actor["role"])
        return actor, None

    def _csrf_token(actor_username: Optional[str]) -> str:
        token = session.get(csrf_token_name)
        if not token:
            token = secrets.token_urlsafe(32)
            session[csrf_token_name] = token
            session.permanent = False
        return token

    def _csrf_ok() -> Tuple[bool, str]:
        expected = session.get(csrf_token_name)
        if not expected:
            return False, "CSRF-Token fehlt (Seite neu laden)"
        got = request.headers.get(CSRF_HEADER) or \
            (request.form.get(CSRF_FIELD) if request.form else None)
        if not got and request.is_json:
            body = request.get_json(silent=True) or {}
            if isinstance(body, dict):
                got = body.get(CSRF_FIELD)
        if not got:
            return False, "CSRF-Token nicht uebermittelt"
        if not hmac.compare_digest(str(got), str(expected)):
            return False, "CSRF-Token ungueltig"
        if strict_origin:
            origin = request.headers.get("Origin") or request.headers.get("Referer") or ""
            if origin:
                host = request.headers.get("Host", "")
                if host and host not in origin:
                    return False, "Origin passt nicht zum Host"
        return True, ""

    def _check_write_limit(actor: Dict[str, Any]) -> Optional[Tuple[Response, int]]:
        key = "%s|%s" % (actor.get("username") or actor.get("ip") or "anon", request.path)
        ok, retry = limiter.allow(key)
        if not ok:
            resp, code = _json_error("Zu viele Schreibvorgaenge, bitte kurz warten.", 429,
                                     retry_after=retry)
            resp.headers["Retry-After"] = str(max(1, retry))
            return resp, code
        return None

    # ---------------- Daten ----------------

    def _payload(actor: Dict[str, Any], *, with_impact: bool = True) -> Dict[str, Any]:
        settings, warnings = store.load()
        data: Dict[str, Any] = {
            "ok": True,
            "version": PACKAGE_VERSION,
            "settings": settings,
            "meta": store.meta(),
            "warnings": warnings,
            "summary": access_rules.admin_summary(settings, warnings),
            "csrf_token": _csrf_token(actor.get("username")),
            "actor": {"username": actor.get("username"), "role": actor.get("role")},
            "server_time": int(time.time()),
        }
        if with_impact:
            try:
                data["impact"] = store.impact_preview()
            except Exception as exc:
                data["impact"] = {"error": str(exc)}
        return data

    # ---------------- Seiten ----------------

    @bp.route(A + "/system", methods=["GET"], strict_slashes=False)
    @bp.route(A + "/system/", methods=["GET"])
    def system_page():
        actor, err = _require_admin()
        if err:
            return err
        settings, warnings = store.load()
        bootstrap = {
            "version": PACKAGE_VERSION,
            "settings": settings,
            "meta": store.meta(),
            "warnings": warnings,
            "summary": access_rules.admin_summary(settings, warnings),
            "actor": {"username": actor.get("username"), "role": actor.get("role")},
            "prefix": url_prefix.rstrip("/"),
            "csrf_token": _csrf_token(actor.get("username")),
            "server_time": int(time.time()),
        }
        template = os.path.join(web_dir, "dnx_system_control.html")
        try:
            with open(template, "r", encoding="utf-8") as fh:
                html = fh.read()
        except OSError:
            return _no_store(Response(
                "<h1>DNX Systemsteuerung</h1><p>Panel-Datei fehlt: %s</p>"
                "<p>API funktioniert: <code>%s/api/admin/system/settings</code></p>"
                % (template, url_prefix), mimetype="text/html; charset=utf-8")), 200
        html = (html
                .replace("__DNX_PREFIX__", url_prefix.rstrip("/"))
                .replace("__DNX_CSRF__", bootstrap["csrf_token"])
                .replace("__DNX_USER__", str(actor.get("username") or "admin"))
                .replace("__DNX_ROLE__", str(actor.get("role") or "admin"))
                .replace("__DNX_BOOTSTRAP__", _safe_json_blob(bootstrap)))
        return _no_store(Response(html, mimetype="text/html; charset=utf-8"))

    @bp.route(A + "/system/static/<path:filename>", methods=["GET"])
    def system_static(filename: str):
        actor, err = _require_admin()
        if err:
            return err
        if not os.path.isdir(web_dir):
            abort(404)
        return send_from_directory(web_dir, filename, max_age=0)

    # ---------------- Admin-API ----------------

    @bp.route(A + "/api/system/settings", methods=["GET"])
    def api_get_settings():
        actor, err = _require_admin()
        if err:
            return err
        return _no_store(jsonify(_payload(actor)))

    @bp.route(A + "/api/system/settings", methods=["POST"])
    def api_post_settings():
        actor, err = _require_admin()
        if err:
            return err
        limited = _check_write_limit(actor)
        if limited:
            return limited
        ok, why = _csrf_ok()
        if not ok:
            return _json_error(why, 403, code="csrf")

        body = request.get_json(silent=True)
        if body is None:
            body = request.form.to_dict() or {}
        changes = body.get("settings", body)
        if not isinstance(changes, dict):
            return _json_error("Erwartet {'settings': {...}}", 400)
        changes = {k: v for k, v in changes.items() if k != CSRF_FIELD}
        if not changes:
            return _json_error("Keine Aenderung uebermittelt", 400)

        try:
            result = store.update(changes, actor=actor.get("username") or "admin",
                                  role=actor.get("role"), ip=actor.get("ip"),
                                  user_agent=actor.get("user_agent"))
        except SettingsValidationError as exc:
            return _json_error("Ungueltige Werte", 400, field_errors=exc.errors)
        except SettingsUnavailable as exc:
            return _json_error(str(exc), 503)
        except Exception as exc:  # atomar fehlgeschlagen -> nichts geschrieben
            return _json_error("Speichern fehlgeschlagen: %s" % exc, 500)

        if audit_hook:
            try:
                audit_hook({"event": "admin_access_settings",
                            "actor": actor, "changed": result.get("changed")})
            except Exception:
                pass

        payload = _payload(actor)
        payload["changed"] = result.get("changed")
        payload["audit_written"] = result.get("audit_written")
        return _no_store(jsonify(payload))

    @bp.route(A + "/api/system/restore-defaults", methods=["POST"])
    def api_restore_defaults():
        actor, err = _require_admin()
        if err:
            return err
        limited = _check_write_limit(actor)
        if limited:
            return limited
        ok, why = _csrf_ok()
        if not ok:
            return _json_error(why, 403, code="csrf")
        body = request.get_json(silent=True) or {}
        keys = body.get("keys")
        if keys is not None and not isinstance(keys, list):
            return _json_error("'keys' muss eine Liste sein", 400)
        confirm = bool(body.get("confirm"))
        if not confirm:
            return _json_error("Ruecksetzen erfordert confirm=true", 400)
        try:
            result = store.reset_defaults(keys, actor=actor.get("username") or "admin",
                                          role=actor.get("role"), ip=actor.get("ip"),
                                          user_agent=actor.get("user_agent"))
        except SettingsValidationError as exc:
            return _json_error("Ungueltige Schluessel", 400, field_errors=exc.errors)
        except Exception as exc:
            return _json_error("Ruecksetzen fehlgeschlagen: %s" % exc, 500)
        payload = _payload(actor)
        payload["changed"] = result.get("changed")
        return _no_store(jsonify(payload))

    @bp.route(A + "/api/system/impact", methods=["GET"])
    def api_impact():
        actor, err = _require_admin()
        if err:
            return err
        try:
            return _no_store(jsonify({"ok": True, "impact": store.impact_preview()}))
        except Exception as exc:
            return _json_error(str(exc), 500)

    # ---------------- Oeffentliche Status-API (Receiver-Frontend) ----------------

    @bp.route("/api/system/state", methods=["GET"])
    def api_public_state():
        settings, _warnings = store.load(use_cache=True, cache_seconds=3)
        resp = jsonify({"ok": True, "state": store.public_state(settings),
                        "rules": access_rules.public_view(settings)})
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["Access-Control-Allow-Origin"] = "*"
        return resp

    @bp.route("/api/system/healthz", methods=["GET"])
    def api_health():
        settings, warnings = store.load(use_cache=True, cache_seconds=1)
        return jsonify({
            "ok": True,
            "service": "dnx-system-control",
            "version": PACKAGE_VERSION,
            "db": store.db_path,
            "keys": len(settings),
            "warnings": len(warnings),
            "maintenance_mode": bool(settings.get("maintenance_mode")),
            "registration_enabled": bool(settings.get("registration_enabled")),
            "server_time": int(time.time()),
        })

    return bp


__all__ = ["create_blueprint", "CSRF_SESSION_KEY", "CSRF_HEADER", "CSRF_FIELD"]
