#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Erzeugt preview/systemsteuerung-vorschau.html – eine OFFLINE-Vorschau des
Admin-Panels mit echten Daten und funktionierendem Speichern (im Speicher).

Grund: Die Datei soll ohne Server, ohne Netzwerk und ohne externe Ressourcen in
einem Datei-Viewer laufen. CSS/JS werden inline eingebettet, die API wird durch
einen Fetch-Stub ersetzt, der sich exakt wie das Backend verhaelt
(Validierung, atomare Antwort, Diff, CSRF).

Aufruf:  python3 tools/make_preview.py
"""

from __future__ import annotations

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SVC = os.path.join(ROOT, "account-service")
WEB = os.path.join(SVC, "dnx_system_control", "web")
OUT = os.path.join(ROOT, "preview", "systemsteuerung-vorschau.html")
sys.path.insert(0, SVC)

from dnx_system_control import access_rules as R          # noqa: E402
from dnx_system_control.settings_store import (PACKAGE_VERSION, SPEC,  # noqa: E402
                                              defaults, spec_meta)

# Ein paar Beispielwerte, damit die Vorschau nicht nur Defaults zeigt
DEMO_WERTE = {
    "registration_enabled": True,
    "new_accounts_active": True,
    "profile_control_enabled": True,
    "account_required": False,
    "guest_profile_switch": False,
    "role_user_enabled": True,
    "role_extended_enabled": True,
    "default_registration_role": "user",
    "maintenance_mode": False,
    "max_login_failures": 5,
    "registration_limit": 5,
    "public_activity_hours": 24,
    "maintenance_message": ("Wartungsmodus: Der Empfaenger ist voruebergehend nur "
                            "fuer Administratoren verfuegbar."),
}

IMPACT = {
    "tables": ["access_settings", "audit_log", "audit_settings", "sessions", "users"],
    "user_tables": ["users"],
    "total_users": 17,
    "by_role": {"admin": 1, "extended": 3, "user": 12, "guest": 1},
    "downgraded": [],
    "locked_by_maintenance": False,
    "session_options": ["browser", "day", "week", "month", "forever"],
    "note": "Bestandskonten werden von der Systemsteuerung nicht veraendert.",
    "active_column": "active",
}


def build_payload(settings: dict) -> dict:
    return {
        "ok": True,
        "version": PACKAGE_VERSION,
        "settings": settings,
        "meta": spec_meta(),
        "warnings": [],
        "summary": R.admin_summary(settings, []),
        "csrf_token": "vorschau-token-offline",
        "actor": {"username": "dl1abc", "role": "admin"},
        "server_time": 1760371200,
        "impact": IMPACT,
    }


STUB = r"""
<script>
/* OFFLINE-STUB: ersetzt die Backend-API der Vorschau.
   Verhaelt sich wie /admin/api/system/settings: validiert, speichert atomar
   (alles oder nichts) und liefert den Diff zurueck. */
(function () {
  "use strict";
  var BOOT = window.DNX_SYSTEM_BOOTSTRAP;
  var current = JSON.parse(JSON.stringify(BOOT.settings));
  var SPEC = {};
  (BOOT.meta.fields || []).forEach(function (f) { SPEC[f.key] = f; });

  function coerce(key, raw) {
    var f = SPEC[key];
    if (!f) throw new Error("Unbekannter Schluessel");
    if (!f.editable) throw new Error("schreibgeschuetzt");
    if (f.type === "bool") {
      if (typeof raw === "boolean") return raw;
      var s = String(raw).toLowerCase();
      if (["1","true","on","yes","ja","an"].indexOf(s) >= 0) return true;
      if (["0","false","off","no","nein","aus"].indexOf(s) >= 0) return false;
      throw new Error("erwartet AN/AUS (bool)");
    }
    if (f.type === "int") {
      var n = parseInt(raw, 10);
      if (isNaN(n)) throw new Error("erwartet ganze Zahl");
      if (f.min !== null && n < f.min) throw new Error("zu klein (Minimum " + f.min + ")");
      if (f.max !== null && n > f.max) throw new Error("zu gross (Maximum " + f.max + ")");
      return n;
    }
    if (f.type === "enum") {
      var v = String(raw).toLowerCase();
      if ((f.choices || []).indexOf(v) < 0) throw new Error("erlaubt: " + (f.choices||[]).join(", "));
      return v;
    }
    var t = String(raw).trim();
    if (t.length > (f.max_length || 500)) throw new Error("zu lang");
    return t;
  }

  function validate(incoming) {
    var clean = {}, errors = {};
    Object.keys(incoming).forEach(function (k) {
      try { clean[k] = coerce(k, incoming[k]); }
      catch (e) { errors[k] = e.message; }
    });
    var m = JSON.parse(JSON.stringify(current));
    Object.keys(clean).forEach(function (k) { m[k] = clean[k]; });
    if (!["browser","day","week","month","forever"].some(function (k) {
          return m["allowed_session_" + k]; })) {
      errors["allowed_session_browser"] = "Mindestens eine Sitzungsdauer muss erlaubt bleiben";
    }
    if (m.default_registration_role === "extended" && !m.role_extended_enabled) {
      errors["default_registration_role"] =
        "Standardrolle 'extended' ist nicht moeglich, solange die Extended-Rolle AUS ist";
    }
    if (m.registration_limit > 0 && m.registration_window_seconds <= 0) {
      errors["registration_window_seconds"] = "Zeitfenster muss > 0 sein";
    }
    if (m.max_login_failures > 0 && m.login_lock_seconds <= 0) {
      errors["login_lock_seconds"] = "Sperrzeit muss > 0 sein";
    }
    return {clean: clean, errors: errors};
  }

  function response(status, body) {
    return {
      ok: status >= 200 && status < 300,
      status: status,
      json: function () { return Promise.resolve(body); }
    };
  }

  function payload(changed, audit) {
    var p = JSON.parse(JSON.stringify(BOOT));
    p.settings = JSON.parse(JSON.stringify(current));
    p.warnings = ["Offline-Vorschau: Änderungen bleiben nur in diesem Fenster."];
    p.changed = changed || {};
    p.audit_written = audit !== false;
    return p;
  }

  window.fetch = function (url, opts) {
    opts = opts || {};
    var method = (opts.method || "GET").toUpperCase();
    var body = {};
    try { body = opts.body ? JSON.parse(opts.body) : {}; } catch (e) { body = {}; }

    if (url.indexOf("/api/system/settings") >= 0 && method === "GET") {
      return Promise.resolve(response(200, payload()));
    }
    if (url.indexOf("/api/system/settings") >= 0 && method === "POST") {
      var token = (opts.headers && (opts.headers["X-CSRF-Token"] ||
                   opts.headers["X-Csrf-Token"])) || body.csrf_token;
      if (!token) {
        return Promise.resolve(response(403,
          {ok: false, error: "CSRF-Token fehlt (Seite neu laden)", code: "csrf"}));
      }
      var incoming = body.settings || body;
      var v = validate(incoming);
      if (Object.keys(v.errors).length) {
        return Promise.resolve(response(400,
          {ok: false, error: "Ungueltige Werte", field_errors: v.errors}));
      }
      var changed = {};
      Object.keys(v.clean).forEach(function (k) {
        if (current[k] !== v.clean[k]) {
          changed[k] = {label: (SPEC[k] || {}).label || k, old: current[k], "new": v.clean[k]};
        }
      });
      Object.keys(v.clean).forEach(function (k) { current[k] = v.clean[k]; });
      return Promise.resolve(response(200, payload(changed)));
    }
    if (url.indexOf("/restore-defaults") >= 0 && method === "POST") {
      if (!body.confirm) {
        return Promise.resolve(response(400,
          {ok: false, error: "Ruecksetzen erfordert confirm=true"}));
      }
      var defaults = JSON.parse(JSON.stringify(BOOT.settings));
      var changed2 = {};
      Object.keys(SPEC).forEach(function (k) {
        if (SPEC[k].editable && current[k] !== defaults[k]) {
          changed2[k] = {label: SPEC[k].label, old: current[k], "new": defaults[k]};
          current[k] = defaults[k];
        }
      });
      return Promise.resolve(response(200, payload(changed2)));
    }
    if (url.indexOf("/api/system/impact") >= 0) {
      return Promise.resolve(response(200, {ok: true, impact: BOOT.impact}));
    }
    return Promise.resolve(response(404, {ok: false, error: "Stub: " + url}));
  };
})();
</script>
"""


def main() -> int:
    settings = defaults()
    settings.update(DEMO_WERTE)
    bootstrap = build_payload(settings)

    with open(os.path.join(WEB, "dnx_system_control.html"), "r", encoding="utf-8") as fh:
        html = fh.read()
    with open(os.path.join(WEB, "dnx_system_control.css"), "r", encoding="utf-8") as fh:
        css = fh.read()
    with open(os.path.join(WEB, "dnx_system_control.js"), "r", encoding="utf-8") as fh:
        js = fh.read()

    blob = json.dumps(bootstrap, ensure_ascii=False, default=str)
    blob = blob.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")

    html = html.replace(
        '<link rel="stylesheet" href="__DNX_PREFIX__/system/static/dnx_system_control.css">',
        "<style>\n" + css + "\n</style>")
    html = html.replace(
        '<script src="__DNX_PREFIX__/system/static/dnx_system_control.js"></script>',
        "<script>\n" + js + "\n</script>")
    html = html.replace("<script>window.DNX_SYSTEM_BOOTSTRAP = __DNX_BOOTSTRAP__;</script>",
                        "<script>window.DNX_SYSTEM_BOOTSTRAP = " + blob + ";</script>")
    html = html.replace("__DNX_PREFIX__", "/admin")
    html = html.replace("__DNX_USER__", "dl1abc")
    html = html.replace("__DNX_ROLE__", "admin")
    # Stub VOR dem Panel-Skript einhaengen
    html = html.replace("<script>window.DNX_SYSTEM_BOOTSTRAP", STUB +
                        "<script>window.DNX_SYSTEM_BOOTSTRAP", 1)
    html = html.replace("<title>DNX Systemsteuerung &middot; Admin</title>",
                        "<title>DNX Systemsteuerung &middot; Admin (Offline-Vorschau)</title>")
    hinweis = ("""<div class="dnxsc-alert info" id="dnxsc-preview-hint" style="margin:14px 22px 0">
      <div><b>Offline-Vorschau</b>
      <ul>
        <li>Diese Datei ist eine statische Vorschau des Panels – CSS/JS sind eingebettet,
            die Backend-API wird durch einen Stub ersetzt.</li>
        <li>Schalter umlegen, <b>Speichern</b>, <b>Defaults</b>, Validierung, CSRF-Abweisung
            und der Bestätigungs-Diff funktionieren wie im Echtbetrieb – nur eben ohne Datenbank.</li>
        <li>Im Echtbetrieb kommt dieselbe Oberfläche von
            <code>http://<SERVER-IP>:8096/admin/system</code>.</li>
      </ul></div></div>""")
    # Hinweis AUSSERHALB von #dnxsc-alerts, weil das Panel diesen Bereich leert
    html = html.replace('<section id="dnxsc-summary"', hinweis + '\n<section id="dnxsc-summary"', 1)

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as fh:
        fh.write(html)
    size = os.path.getsize(OUT) / 1024.0
    print("Vorschau erzeugt: %s (%.1f KiB, %d Einstellungen)" % (OUT, size, len(settings)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
