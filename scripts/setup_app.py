#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""setup_app.py – Provider + Button + Verdrahtung fuer app.py in einem Schritt.

Teil 1  Provider:  Rolle/Status aus Cookie dnxac_session -> sessions -> users
        Button  :  sichtbarer Link zur Systemsteuerung, nur fuer Admins
Teil 2  Verdrahtung der Schalter in register(), login() und api_policy()

Alles idempotent, mit Backup, py_compile und automatischem Rueckbau.
Nicht gefundene Anker werden als FEHLT gemeldet (kein Abbruch).

    python3 scripts/setup_app.py --dry-run
    python3 scripts/setup_app.py
"""

from __future__ import annotations

import argparse
import os
import py_compile
import re
import shutil
import sys
import time

DEFAULT_APP = "/opt/owrx-docker/var/dnx-access-control/app.py"

IMPORTS = ("import os as _dnx_os, sys as _dnx_sys\n"
           "_dnx_sys.path.insert(0, _dnx_os.path.dirname(_dnx_os.path.abspath(__file__)))\n"
           "import dnx_system_control_integration as dnx_sc\n")

PROVIDER = '''# --- DNX Systemsteuerung v1.2.0: Cookie dnxac_session -> sessions -> users ---
def dnx_current_user():
    """Rolle/Status aus der Datenbank. Unklare Spalten sperren niemanden aus.

    Die Gueltigkeit der Sitzung bestimmt weiterhin user() in app.py – genau wie
    fuer die bestehende /admin-Seite. Damit bleibt kein Bestandsuser draussen.
    """
    try:
        u = user()
    except Exception:
        u = None
    if not u:
        return {"username": None, "role": "guest"}
    try:
        row = dict(zip(u.keys(), tuple(u))) if hasattr(u, "keys") else dict(u)
    except Exception:
        row = {}
    name = row.get("username")
    role = str(row.get("role") or "").strip().lower() or "guest"
    if str(row.get("status") or "").strip().lower() in ("blocked", "banned", "disabled", "deleted", "gesperrt"):
        return {"username": name, "role": "guest"}
    return {"username": name, "role": role,
            "ip": request.remote_addr,
            "user_agent": request.headers.get("User-Agent")}


dnx_sc.install(app, current_user=dnx_current_user)  # DNX Systemsteuerung v1.2.0
'''

BUTTON = '''

@app.after_request
def dnx_admin_button(resp):
    """Sichtbarer Button zur Systemsteuerung fuer angemeldete Admins."""
    try:
        if resp.status_code != 200 or getattr(resp, "direct_passthrough", False):
            return resp
        if "text/html" not in (resp.headers.get("Content-Type") or ""):
            return resp
        u = dnx_current_user()
        if not u or str(u.get("role") or "").lower() != "admin":
            return resp
        html = resp.get_data(as_text=True)
        if "/admin/system" in html:
            return resp
        bar = ('<div style="position:fixed;right:14px;bottom:14px;z-index:9999">'
               '<a href="/admin/system" style="display:inline-block;padding:10px 16px;'
               'background:#1d6fb8;color:#fff;border-radius:8px;text-decoration:none;'
               'font:600 14px system-ui,sans-serif;box-shadow:0 2px 10px rgba(0,0,0,.35)">'
               'Systemsteuerung</a></div>')
        resp.set_data(html.replace("</body>", bar + "</body>", 1) if "</body>" in html else html + bar)
    except Exception:
        pass
    return resp
'''

REGELN = [
    ("reg-gate", "Registrierung AN/AUS (+ Meldung)", "einfuegen",
     r"^[ \t]*def register\(\):[ \t]*$", "dnx_sc.registration_gate()", [
         "ok, grund, reg = dnx_sc.registration_gate()",
         "if not ok:",
         "    msg = reg.get('message') or 'Die Registrierung ist derzeit deaktiviert.'",
         "    if request.method == 'GET':",
         "        return layout('<div class=box><h2>Registrieren</h2><p>' + msg + "
         "'</p><p><a href=/login>Zur Anmeldung</a></p></div>')",
         "    flash(msg); return redirect('/login')"]),
    ("reg-ratelimit", "Rate-Limit aus den Einstellungen", "text",
     "rate_ok('register',5,3600)", "rate_ok('register',dnx_sc.registration_limit()",
     "rate_ok('register',dnx_sc.registration_limit(),dnx_sc.registration_window())"),
    ("reg-captcha", "Rechenaufgabe nur wenn captcha_enabled", "text",
     "if str(request.form.get('answer'))!=str(session.get('captcha')):",
     "dnx_sc.captcha_required() and str(request.form.get('answer'))",
     "if dnx_sc.captcha_required() and str(request.form.get('answer'))"
     "!=str(session.get('captcha')):"),
    ("reg-pwlaenge", "Passwort-Mindestlaenge", "text",
     "or len(p)<8:", "len(p)<dnx_sc.password_min_length()",
     "or len(p)<dnx_sc.password_min_length():"),
    ("reg-pw-hinweis", "Formularhinweis + minlength dynamisch", "text",
     "Passwort (mindestens 8 Zeichen)<input name=password type=password required minlength=8>",
     "minlength={dnx_sc.password_min_length()}",
     "Passwort (mindestens {dnx_sc.password_min_length()} Zeichen)"
     "<input name=password type=password required minlength={dnx_sc.password_min_length()}>"),
    ("reg-insert", "Rolle + Status beim Anlegen", "text",
     "INSERT INTO users(username,password,created) VALUES(?,?,?)',"
     "(n,generate_password_hash(p,method='scrypt'),int(time.time())))",
     "dnx_sc.initial_role()",
     "INSERT INTO users(username,password,role,status,created) VALUES(?,?,?,?,?)',"
     "(n,generate_password_hash(p,method='scrypt'),dnx_sc.initial_role(),"
     "dnx_sc.initial_status(),int(time.time())))"),
    ("reg-flash", "Erfolgsmeldung + Audit register", "text",
     "flash('Registrierung erfolgreich. Du kannst dich sofort anmelden.');return redirect('/login')",
     "dnx_sc.audit_event('register'",
     "dnx_sc.audit_event('register',username=n,details={'role':dnx_sc.initial_role(),"
     "'status':dnx_sc.initial_status()});"
     "flash('Registrierung erfolgreich. Du kannst dich sofort anmelden.' "
     "if dnx_sc.initial_active() else "
     "'Registrierung erfolgreich. Dein Konto muss noch von einem Admin "
     "freigeschaltet werden.');return redirect('/login')"),
    ("login-dauer", "Sitzungsdauer nur aus erlaubten Werten", "text",
     "dur=request.form.get('duration','day')", "dur=dnx_sc.sanitize_session(",
     "dur=dnx_sc.sanitize_session(request.form.get('duration'))"),
    ("login-select", "Sitzungs-Auswahl = erlaubte Dauern", "regex",
     r"<select name=duration>.*?</select>", "dnx_sc.session_options_html()",
     "'''+dnx_sc.session_options_html()+'''"),
    ("login-sperre", "Fehlversuche/Sperrzeit statt 5/900", "text",
     "lock=now+900 if f>=5 else 0", "dnx_sc.login_lock_seconds()",
     "lock=now+dnx_sc.login_lock_seconds() if (dnx_sc.login_lock_active() "
     "and f>=dnx_sc.login_max_failures()) else 0"),
    ("policy-state", "/api/policy liefert Systemzustand", "text",
     "return {'policy':json.loads(POL.read_text() or '{}'),'profiles':profiles()}",
     "'system':dnx_sc.public_state()",
     "return {'policy':json.loads(POL.read_text() or '{}'),'profiles':profiles(),"
     "'system':dnx_sc.public_state()}"),
]


def _einheit(zeilen, i):
    for z in zeilen[i + 1:i + 6]:
        if z.strip():
            return len(z) - len(z.lstrip(" ")) or 4
    return 4


def _block(block, einheit):
    out = []
    for z in block:
        level = (len(z) - len(z.lstrip(" "))) // 4
        out.append(" " * (einheit + level * einheit) + z.strip())
    return "\n".join(out) + "\n"


def aufbauen(src):
    log = []
    # ---- Teil 1: Provider -------------------------------------------------
    alt = (re.search(r"^[ \t]*# --- DNX Systemsteuerung v1\.2\.0: Cookie.*?"
                     r"^[ \t]*dnx_sc\.install\(app[^\n]*\n", src, re.M | re.S)
           or re.search(r"^def dnx_current_user\(\):.*?^[ \t]*dnx_sc\.install\(app[^\n]*\n",
                        src, re.M | re.S))
    if alt:
        if alt.group(0) == PROVIDER:
            log.append(("provider", "SCHON", "Anmeldung ueber dnxac_session/sessions/users"))
        else:
            src = src[:alt.start()] + PROVIDER + src[alt.end():]
            log.append(("provider", "ERSETZT", "Anmeldung ueber dnxac_session/sessions/users"))
    elif "dnx_sc.install(" in src:
        m = re.search(r"^[ \t]*dnx_sc\.install\(app[^\n]*\n", src, re.M)
        src = src[:m.start()] + PROVIDER + src[m.end():]
        log.append(("provider", "ERSETZT", "install()-Zeile durch Provider ersetzt"))
    else:
        f = re.search(r"^[ \t]*app[ \t]*=[ \t]*(?:flask\.)?Flask\([^\n]*\n", src, re.M)
        if not f:
            log.append(("provider", "FEHLT", "keine app=Flask(...)-Zeile gefunden"))
            return src, log, False
        imp = "" if "dnx_system_control_integration" in src else IMPORTS
        src = src[:f.end()] + imp + PROVIDER + src[f.end():]
        log.append(("provider", "EINGEFUEGT", "Block nach app=Flask(...)"))

    # ---- Teil 1b: Button --------------------------------------------------
    if "dnx_admin_button" in src:
        log.append(("button", "SCHON", "Button vorhanden"))
    else:
        g = re.search(r"^if __name__[^\n]*\n|^[ \t]*app\.run\(", src, re.M)
        if g:
            src = src[:g.start()] + BUTTON + "\n" + src[g.start():]
            log.append(("button", "EINGEFUEGT", "vor dem Startblock (wichtig!)"))
        else:
            src = src.rstrip("\n") + "\n" + BUTTON
            log.append(("button", "EINGEFUEGT", "am Dateiende"))

    # ---- Teil 2: Verdrahtung ---------------------------------------------
    for rid, titel, art, suche, schon, ersetze in REGELN:
        if schon in src:
            log.append((rid, "SCHON", titel))
            continue
        if art == "einfuegen":
            m = re.search(suche, src, re.M)
            if not m:
                log.append((rid, "FEHLT", titel))
                continue
            ende = src.index("\n", m.end() - 1) + 1
            einheit = _einheit(src.splitlines(), len(src[:m.end()].splitlines()) - 1)
            src = src[:ende] + _block(ersetze, einheit or 4) + src[ende:]
            log.append((rid, "EINGEFUEGT", titel))
        elif art == "regex":
            m = re.search(suche, src, re.S)
            if not m:
                log.append((rid, "FEHLT", titel))
                continue
            src = src[:m.start()] + ersetze + src[m.end():]
            log.append((rid, "ERSETZT", titel))
        else:
            if suche not in src:
                log.append((rid, "FEHLT", titel))
                continue
            src = src.replace(suche, ersetze, 1)
            log.append((rid, "ERSETZT", titel))
    return src, log, True


def main(argv=None):
    ap = argparse.ArgumentParser(description="app.py an die Systemsteuerung anbinden")
    ap.add_argument("--app", default=DEFAULT_APP)
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args(argv)

    if not os.path.exists(a.app):
        print("FEHLER: %s nicht gefunden" % a.app)
        return 2
    alt = open(a.app, "r", encoding="utf-8", errors="replace").read()
    neu, log, ok = aufbauen(alt)
    if not ok:
        print("app=Flask(...) nicht gefunden – nichts geaendert.")
        return 3

    print("%-15s %-11s %s" % ("TEIL", "STATUS", "WIRKUNG"))
    print("-" * 78)
    for rid, status, titel in log:
        print("%-15s %-11s %s" % (rid, status, titel))
    print("-" * 78)
    geaendert = sum(1 for _, s, _ in log if s in ("ERSETZT", "EINGEFUEGT"))
    fehlt = [r for r, s, _ in log if s == "FEHLT"]
    print("Geaendert: %d | Schon erledigt: %d | Nicht gefunden: %d%s"
          % (geaendert, sum(1 for _, s, _ in log if s == "SCHON"), len(fehlt),
             (" -> " + ", ".join(fehlt)) if fehlt else ""))

    if a.dry_run:
        print("DRY-RUN: nichts geschrieben.")
        return 0
    if neu == alt:
        print("Nichts zu tun.")
        return 0

    bak = "%s.bak-%s" % (a.app, time.strftime("%Y%m%d-%H%M%S"))
    shutil.copy2(a.app, bak)
    print("Backup: %s" % bak)
    open(a.app, "w", encoding="utf-8").write(neu)
    try:
        py_compile.compile(a.app, doraise=True)
    except Exception as exc:
        shutil.copy2(bak, a.app)
        print("SYNTAXFEHLER – Backup zurueckgespielt: %s" % exc)
        return 4
    print("OK: py_compile bestaetigt.")
    print("Weiter: systemctl restart dnx-access-control.service")
    return 0


if __name__ == "__main__":
    sys.exit(main())
