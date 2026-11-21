#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""session_probe.py – findet heraus, wie app.py die Anmeldung speichert.

Hintergrund: /admin/system liefert 403 mit role=guest, wenn detect_user() die
angemeldete Person nicht findet. Ursache ist fast immer eine von zwei Sachen:

  A) Man ist auf :8013 (OpenWebRX) eingeloggt, aber nicht auf :8096 (Account-Dienst).
     Beides sind getrennte Sitzungen – das war schon bei den Bookmarks so.
  B) app.py nutzt andere Sitzungsschluessel als die vermuteten
     (dnx_user / username / account / user / chat_name bzw. dnx_role / role).

Dieses Skript liest NUR (app.py, accounts.sqlite3) und schreibt nichts. Es gibt
am Ende die passende install()-Zeile aus.

Aufruf:
    python3 scripts/session_probe.py
    python3 scripts/session_probe.py --app /opt/owrx-docker/var/dnx-access-control/app.py
"""

from __future__ import annotations

import argparse
import os
import re
import sqlite3
import sys
from typing import Dict, List, Set

ACC = "/opt/owrx-docker/var/dnx-access-control"

VERDACHT_USER = ("user", "account", "name", "login", "who", "mitglied", "caller")
VERDACHT_ROLE = ("role", "rolle", "rechte", "level", "rang")


def probe(app_path: str, db_path: str) -> int:
    print("=" * 74)
    print("DNX Systemsteuerung – Sitzungs-Diagnose (nur lesend)")
    print("=" * 74)
    print("app.py : %s" % app_path)
    print("DB     : %s" % db_path)
    if not os.path.exists(app_path):
        print("FEHLER: app.py nicht gefunden")
        return 2
    with open(app_path, "r", encoding="utf-8", errors="replace") as fh:
        src = fh.read()

    # 1) Sitzungsschluessel
    keys: Dict[str, Set[str]] = {}
    for m in re.finditer(r"session\s*\[\s*['\"]([\w\.\-]+)['\"]\s*\]\s*=\s*([^\n]+)", src):
        keys.setdefault(m.group(1), set()).add("schreibt=%s" % m.group(2).strip()[:44])
    for m in re.finditer(r"session\.get\s*\(\s*['\"]([\w\.\-]+)['\"]", src):
        keys.setdefault(m.group(1), set()).add("liest")
    for m in re.finditer(r"session\s*\[\s*['\"]([\w\.\-]+)['\"]\s*\]", src):
        keys.setdefault(m.group(1), set()).add("liest")
    for m in re.finditer(r"session\.setdefault\s*\(\s*['\"]([\w\.\-]+)['\"]", src):
        keys.setdefault(m.group(1), set()).add("setdefault")

    print("\n1) Flask-Sitzungsschluessel in app.py")
    if keys:
        for k in sorted(keys):
            print("   %-24s %s" % (k, ", ".join(sorted(keys[k]))[:70]))
    else:
        print("   KEINE – app.py nutzt offenbar nicht flask.session")
        for m in re.finditer(r"(cookies\.get|set_cookie|jwt|itsdangerous|URLSafeTimedSerializer|"
                             r"Authorization|X-DNX-[\w\-]+)", src):
            print("   Hinweis: %s" % m.group(0))

    # 2) Routen (wo kann man sich auf :8096 anmelden?)
    print("\n2) Routen des Account-Dienstes (Port 8096)")
    routes = [m.group(0) for m in
              re.finditer(r"@app\.route\(\s*['\"][^'\"]+['\"][^\n]*", src)]
    for r in routes[:40]:
        print("   %s" % r.strip())
    if len(routes) > 40:
        print("   ... und %d weitere" % (len(routes) - 40))
    if not routes:
        print("   keine @app.route gefunden (Blueprint-Struktur?)")

    # 3) Rollen/Spalten in der DB
    print("\n3) Benutzer-Tabelle in accounts.sqlite3")
    user_keys_found: List[str] = []
    role_keys_found: List[str] = []
    try:
        conn = sqlite3.connect("file:%s?mode=ro" % db_path, uri=True, timeout=10)
        tables = [r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")]
        for t in ("users", "accounts", "dnx_users"):
            if t not in tables:
                continue
            cols = [r[1] for r in conn.execute('PRAGMA table_info("%s")' % t)]
            print("   Tabelle %-10s Spalten: %s" % (t, ", ".join(cols)))
            rc = [c for c in cols if c.lower() in ("role", "user_role", "account_role")]
            nc = [c for c in cols if c.lower() in ("username", "name", "account", "user")]
            if rc:
                rows = conn.execute('SELECT "%s", COUNT(*) FROM "%s" GROUP BY "%s"'
                                    % (rc[0], t, rc[0])).fetchall()
                print("   Rollen: %s" % ["%s=%d" % (r[0], r[1]) for r in rows])
            if nc:
                sample = [r[0] for r in conn.execute(
                    'SELECT "%s" FROM "%s" ORDER BY id LIMIT 5' % (nc[0], t))]
                print("   Erste Konten: %s" % sample)
        conn.close()
    except Exception as exc:
        print("   DB nicht lesbar: %s" % exc)

    # 4) Vorschlag
    for k in sorted(keys):
        low = k.lower()
        if any(w in low for w in VERDACHT_ROLE):
            role_keys_found.append(k)
        elif any(w in low for w in VERDACHT_USER):
            user_keys_found.append(k)
    print("\n4) Einbau-Vorschlag")
    if user_keys_found or role_keys_found:
        uk = tuple(user_keys_found) or ("username",)
        rk = tuple(role_keys_found) or ("role",)
        print("   In app.py die install()-Zeile ersetzen durch:")
        print("")
        print("       dnx_sc.install(app, session_user_keys=%s," % (uk,))
        print("                            session_role_keys=%s)" % (rk,))
        print("")
        print("   Die Rolle wird zusaetzlich aus der DB gelesen, nicht aus der Sitzung.")
    else:
        print("   Keine passenden Schluessel erkannt. Dann entweder:")
        print("     a) auf :8096 anmelden (nicht nur auf :8013), oder")
        print("     b) eigenen Provider uebergeben:")
        print("")
        print("        def mein_user():")
        print("            return {'username': <aktueller Benutzer>,")
        print("                    'role': <aktuelle Rolle>,")
        print("                    'ip': request.remote_addr,")
        print("                    'user_agent': request.headers.get('User-Agent')}")
        print("        dnx_sc.install(app, current_user=mein_user)")
    print("")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Sitzungs-Diagnose fuer app.py")
    ap.add_argument("--app", default=os.path.join(ACC, "app.py"))
    ap.add_argument("--db", default=os.path.join(ACC, "accounts.sqlite3"))
    args = ap.parse_args(argv)
    return probe(args.app, args.db)


if __name__ == "__main__":
    sys.exit(main())
