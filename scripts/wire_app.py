#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""wire_app.py – verdrahtet die Schalter der Systemsteuerung mit app.py.

Anker sind die echten Zeilen aus app.py (Stand 13.10.2026, Server 113):

    register(): rate_ok('register',5,3600)
                if str(request.form.get('answer'))!=str(session.get('captcha')):
                ... or len(p)<8:
                INSERT INTO users(username,password,created) VALUES(?,?,?)
                flash('Registrierung erfolgreich. Du kannst dich sofort anmelden.')
    login():    dur=request.form.get('duration','day')
                lock=now+900 if f>=5 else 0
                <select name=duration>...</select>
    api_policy(): return {'policy':...,'profiles':profiles()}

Jede Regel ist idempotent (Marker dnx_sc.), wird einzeln berichtet und ein
Syntaxfehler spielt das Backup zurueck. Nicht gefundene Anker sind WARNUNGEN,
kein Abbruch: dann ist die Stelle im eigenen app.py leicht anders formuliert.

Aufruf:
    python3 scripts/wire_app.py --dry-run
    python3 scripts/wire_app.py
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
MARKER = "dnx_sc."

# ---------------------------------------------------------------------------
# Regeln
#   art      : "text"   = exakter Teilstring (erste Fundstelle)
#              "regex"  = regulaerer Ausdruck (erste Fundstelle)
#              "einfuegen" = Block nach der Ankerzeile einfuegen
#   schon    : Text, der vorhanden sein muss, damit die Regel als erledigt gilt
# ---------------------------------------------------------------------------
REGELN = [
    {
        "id": "reg-gate",
        "titel": "Registrierung AN/AUS (+ Meldung)",
        "art": "einfuegen",
        "anker": r"^[ \t]*def register\(\):[ \t]*$",
        "schon": "dnx_sc.registration_gate()",
        "block": [
            "ok, grund, reg = dnx_sc.registration_gate()",
            "if not ok:",
            "    msg = reg.get('message') or 'Die Registrierung ist derzeit deaktiviert.'",
            "    if request.method == 'GET':",
            "        return layout('<div class=box><h2>Registrieren</h2><p>' + msg + "
            "'</p><p><a href=/login>Zur Anmeldung</a></p></div>')",
            "    flash(msg); return redirect('/login')",
        ],
    },
    {
        "id": "reg-ratelimit",
        "titel": "Registrierungs-Rate-Limit aus den Einstellungen",
        "art": "text",
        "suche": "rate_ok('register',5,3600)",
        "ersetze": "rate_ok('register',dnx_sc.registration_limit(),dnx_sc.registration_window())",
        "schon": "rate_ok('register',dnx_sc.registration_limit()",
    },
    {
        "id": "reg-captcha",
        "titel": "Rechenaufgabe nur wenn captcha_enabled",
        "art": "text",
        "suche": "if str(request.form.get('answer'))!=str(session.get('captcha')):",
        "ersetze": "if dnx_sc.captcha_required() and str(request.form.get('answer'))"
                   "!=str(session.get('captcha')):",
        "schon": "dnx_sc.captcha_required() and str(request.form.get('answer'))",
    },
    {
        "id": "reg-pwlaenge",
        "titel": "Passwort-Mindestlaenge aus den Einstellungen",
        "art": "text",
        "suche": "or len(p)<8:",
        "ersetze": "or len(p)<dnx_sc.password_min_length():",
        "schon": "or len(p)<dnx_sc.password_min_length():",
    },
    {
        "id": "reg-pw-hinweis",
        "titel": "Formularhinweis + minlength dynamisch",
        "art": "text",
        "suche": "Passwort (mindestens 8 Zeichen)<input name=password type=password required minlength=8>",
        "ersetze": "Passwort (mindestens {dnx_sc.password_min_length()} Zeichen)"
                   "<input name=password type=password required minlength={dnx_sc.password_min_length()}>",
        "schon": "minlength={dnx_sc.password_min_length()}",
    },
    {
        "id": "reg-insert",
        "titel": "Rolle + Status beim Anlegen (Standardrolle / sofort aktiv)",
        "art": "text",
        "suche": "INSERT INTO users(username,password,created) VALUES(?,?,?)',"
                 "(n,generate_password_hash(p,method='scrypt'),int(time.time())))",
        "ersetze": "INSERT INTO users(username,password,role,status,created) VALUES(?,?,?,?,?)',"
                   "(n,generate_password_hash(p,method='scrypt'),dnx_sc.initial_role(),"
                   "dnx_sc.initial_status(),int(time.time())))",
        "schon": "dnx_sc.initial_role()",
    },
    {
        "id": "reg-flash",
        "titel": "Erfolgsmeldung + Audit-Eintrag register",
        "art": "text",
        "suche": "flash('Registrierung erfolgreich. Du kannst dich sofort anmelden.');return redirect('/login')",
        "ersetze": "dnx_sc.audit_event('register',username=n,details={'role':dnx_sc.initial_role(),"
                   "'status':dnx_sc.initial_status()});"
                   "flash('Registrierung erfolgreich. Du kannst dich sofort anmelden.' "
                   "if dnx_sc.initial_active() else "
                   "'Registrierung erfolgreich. Dein Konto muss noch von einem Admin "
                   "freigeschaltet werden.');return redirect('/login')",
        "schon": "dnx_sc.audit_event('register'",
    },
    {
        "id": "login-dauer",
        "titel": "Sitzungsdauer nur aus erlaubten Werten",
        "art": "text",
        "suche": "dur=request.form.get('duration','day')",
        "ersetze": "dur=dnx_sc.sanitize_session(request.form.get('duration'))",
        "schon": "dur=dnx_sc.sanitize_session(",
    },
    {
        "id": "login-select",
        "titel": "Sitzungs-Auswahl im Formular = erlaubte Dauern",
        "art": "regex",
        "suche": r"<select name=duration>.*?</select>",
        "ersetze": "'''+dnx_sc.session_options_html()+'''",
        "schon": "dnx_sc.session_options_html()",
    },
    {
        "id": "login-sperre",
        "titel": "Fehlversuche/Sperrzeit aus den Einstellungen (statt 5/900)",
        "art": "text",
        "suche": "lock=now+900 if f>=5 else 0",
        "ersetze": "lock=now+dnx_sc.login_lock_seconds() if (dnx_sc.login_lock_active() "
                   "and f>=dnx_sc.login_max_failures()) else 0",
        "schon": "dnx_sc.login_lock_seconds()",
    },
    {
        "id": "policy-state",
        "titel": "/api/policy liefert den Systemzustand ans Receiver-Frontend",
        "art": "text",
        "suche": "return {'policy':json.loads(POL.read_text() or '{}'),'profiles':profiles()}",
        "ersetze": "return {'policy':json.loads(POL.read_text() or '{}'),'profiles':profiles(),"
                   "'system':dnx_sc.public_state()}",
        "schon": "'system':dnx_sc.public_state()",
    },
]


def _einheit(zeilen: list, i: int) -> int:
    """Einrueckung der naechsten Nicht-Leerzeile nach Zeile i (in Leerzeichen)."""
    for z in zeilen[i + 1:i + 6]:
        if z.strip():
            return len(z) - len(z.lstrip(" ")) or 4
    return 4


def _block_einruecken(block: list, einheit: int) -> str:
    out = []
    for z in block:
        level = (len(z) - len(z.lstrip(" "))) // 4
        out.append(" " * (einheit + level * einheit) + z.strip())
    return "\n".join(out) + "\n"


def anwenden(src: str, trocken: bool = False):
    zeilen = src.splitlines(keepends=True)
    bericht = []
    for r in REGELN:
        if r.get("schon") and r["schon"] in src:
            bericht.append((r["id"], r["titel"], "schon"))
            continue
        if r["art"] == "einfuegen":
            m = re.search(r["anker"], src, re.M)
            if not m:
                bericht.append((r["id"], r["titel"], "fehlt"))
                continue
            ende = src.index("\n", m.end() - 1) + 1
            einheit = _einheit(src.splitlines(), len(src[:m.end()].splitlines()) - 1)
            src = src[:ende] + _block_einruecken(r["block"], einheit or 4) + src[ende:]
            bericht.append((r["id"], r["titel"], "eingefuegt"))
            continue
        if r["art"] == "regex":
            m = re.search(r["suche"], src, re.S)
            if not m:
                bericht.append((r["id"], r["titel"], "fehlt"))
                continue
            src = src[:m.start()] + r["ersetze"] + src[m.end():]
            bericht.append((r["id"], r["titel"], "ersetzt"))
            continue
        if r["suche"] not in src:
            bericht.append((r["id"], r["titel"], "fehlt"))
            continue
        src = src.replace(r["suche"], r["ersetze"], 1)
        bericht.append((r["id"], r["titel"], "ersetzt"))
    return src, bericht


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Systemsteuerung mit app.py verdrahten")
    ap.add_argument("--app", default=DEFAULT_APP)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)

    if not os.path.exists(args.app):
        print("FEHLER: %s nicht gefunden" % args.app)
        return 2
    alt = open(args.app, "r", encoding="utf-8", errors="replace").read()
    if MARKER not in alt:
        print("FEHLER: app.py ist noch nicht angebunden (kein dnx_sc.). "
              "Erst patch_app_provider.py ausfuehren.")
        return 3

    neu, bericht = anwenden(alt)
    print("%-16s %-8s %s" % ("REGEL", "STATUS", "WIRKUNG"))
    print("-" * 78)
    for rid, titel, status in bericht:
        print("%-16s %-8s %s" % (rid, status.upper(), titel))
    print("-" * 78)
    getan = sum(1 for _, _, s in bericht if s in ("ersetzt", "eingefuegt"))
    fehlt = [rid for rid, _, s in bericht if s == "fehlt"]
    print("Geaendert: %d | Bereits erledigt: %d | Nicht gefunden: %d %s"
          % (getan,
             sum(1 for _, _, s in bericht if s == "schon"),
             len(fehlt), ("(%s)" % ", ".join(fehlt)) if fehlt else ""))

    if args.dry_run:
        print("DRY-RUN: nichts geschrieben.")
        return 0
    if getan == 0:
        print("Nichts zu tun.")
        return 0

    bak = "%s.bak-wire-%s" % (args.app, time.strftime("%Y%m%d-%H%M%S"))
    shutil.copy2(args.app, bak)
    print("Backup: %s" % bak)
    open(args.app, "w", encoding="utf-8").write(neu)
    try:
        py_compile.compile(args.app, doraise=True)
    except Exception as exc:
        shutil.copy2(bak, args.app)
        print("SYNTAXFEHLER – Backup zurueckgespielt: %s" % exc)
        return 4
    print("OK: py_compile bestaetigt.")
    print("Weiter: systemctl restart dnx-access-control.service")
    return 0


if __name__ == "__main__":
    sys.exit(main())
