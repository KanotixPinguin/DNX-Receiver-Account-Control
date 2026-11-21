#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""patch_app_provider.py – verbindet die Systemsteuerung mit der DNX-Anmeldung.

Ausgangslage auf dem Produktivsystem (aus app.py ausgelesen):
    app=Flask(__name__)                       # Zeile 12
    Cookie  : dnxac_session  (secrets.token_urlsafe(40))
    Tabelle : sessions(id, user_id, expires, created)   expires=0 => unbegrenzt
    Tabelle : users(id, username, password, role, status, created, failed, locked_until)
    Helper  : user() -> sqlite3.Row mit u.* und s.expires AS session_expires

Der Standard-Provider (flask.session) greift dort nicht, weil app.py die Sitzung
nur fuer das captcha benutzt. Dieses Skript traegt deshalb einen Provider ein,
der exakt diesen Weg geht: Cookie -> sessions -> users.

Vorgehen:
    * Backup von app.py
    * ersetzt ein vorhandenes  dnx_sc.install(app)  durch die Provider-Variante,
      sonst wird der komplette Block nach der app=Flask(...)-Zeile eingefuegt
    * py_compile; bei Fehler wird das Backup zurueckgespielt
    * idempotent: laeuft der Patch zweimal, passiert nichts

Aufruf:
    python3 scripts/patch_app_provider.py --dry-run
    python3 scripts/patch_app_provider.py
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
MARKER = "DNX Systemsteuerung v1.2.0"

IMPORT_BLOCK = (
    "# --- {m} ---\n"
    "import os as _dnx_os, sys as _dnx_sys\n"
    "_dnx_sys.path.insert(0, _dnx_os.path.dirname(_dnx_os.path.abspath(__file__)))\n"
    "import dnx_system_control_integration as dnx_sc\n"
)

PROVIDER_BLOCK = """# --- {m}: Cookie dnxac_session -> sessions -> users ---
def dnx_current_user():
    \"\"\"Rolle/Status kommen aus der Datenbank, nicht aus einem Cookie-Wert.

    Fehlende oder unklare Spalten sperren niemanden aus; nur klar gesperrte
    Konten (blocked/banned/disabled/gesperrt) werden zu guest. Die Gueltigkeit
    der Sitzung bestimmt weiterhin user() in app.py.
    \"\"\"
    try:
        u = user()
    except Exception:
        u = None
    if not u:
        return {{"username": None, "role": "guest"}}
    try:
        row = dict(zip(u.keys(), tuple(u))) if hasattr(u, "keys") else dict(u)
    except Exception:
        row = {{}}
    name = row.get("username")
    role = str(row.get("role") or "").strip().lower() or "guest"
    status = str(row.get("status") or "").strip().lower()
    if status in ("blocked", "banned", "disabled", "deleted", "gesperrt"):
        return {{"username": name, "role": "guest"}}
    # Ablauf der Sitzung wird NICHT hier geprueft: massgeblich ist user() in
    # app.py, also genau dieselbe Gueltigkeit wie fuer die bestehende
    # /admin-Seite. DURS['browser']=0 wuerde sonst Browser-Sitzungen sofort
    # als abgelaufen werten und Bestandsuser aussperren.
    return {{"username": name, "role": role,
            "ip": request.remote_addr,
            "user_agent": request.headers.get("User-Agent")}}


dnx_sc.install(app, current_user=dnx_current_user)  # {m}
"""


BUTTON_BLOCK = """

@app.after_request
def dnx_admin_button(resp):
    \"\"\"Sichtbarer Button zur Systemsteuerung fuer angemeldete Admins.\"\"\"
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
        resp.set_data(html.replace("</body>", bar + "</body>", 1)
                      if "</body>" in html else html + bar)
    except Exception:
        pass
    return resp
"""


def patch(app_path: str, dry_run: bool = False) -> int:
    if not os.path.exists(app_path):
        print("FEHLER: %s nicht gefunden" % app_path)
        return 2
    src = open(app_path, "r", encoding="utf-8", errors="replace").read()

    if "dnx_current_user" in src:
        print("OK: Provider ist bereits eingetragen – nichts zu tun.")
        return 0

    provider = PROVIDER_BLOCK.format(m=MARKER)
    # 1) alten (zu strengen) Provider-Block ersetzen, sonst install()-Zeile,
    #    sonst ganz neu nach app=Flask(...) einfuegen
    alt = re.search(r"^[ \t]*# --- DNX Systemsteuerung v1\.2\.0: Cookie.*?"
                    r"^[ \t]*dnx_sc\.install\(app[^\n]*\n", src, re.M | re.S)
    alt2 = re.search(r"^def dnx_current_user\(\):.*?^[ \t]*dnx_sc\.install\(app[^\n]*\n",
                     src, re.M | re.S)
    install_line = alt or alt2 or re.search(
        r"^[ \t]*dnx_sc\.install\(app\)[^\n]*\n", src, re.MULTILINE)

    if install_line:
        neu = src[:install_line.start()] + provider + src[install_line.end():]
        wo = ("alter Provider-Block ersetzt (toleranter)" if (alt or alt2)
              else "vorhandene install()-Zeile ersetzt")
    else:
        flask_line = re.search(r"^[ \t]*app[ \t]*=[ \t]*(?:flask\.)?Flask\([^\n]*\n",
                               src, re.MULTILINE)
        if not flask_line:
            print("WEDER dnx_sc.install(app) NOCH app = Flask(...) gefunden.")
            print("Nichts geaendert. Bitte INTEGRATION.md Schritt 3 manuell ausfuehren.")
            return 3
        imports = IMPORT_BLOCK.format(m=MARKER)
        neu = (src[:flask_line.end()] + imports + provider + src[flask_line.end():])
        wo = "Block nach der app=Flask(...)-Zeile eingefuegt"

    # 2) sichtbaren Button einfuegen – VOR if __name__/app.run(), sonst laeuft
    #    der after_request-Decorator bei "python3 app.py" nie
    if "dnx_admin_button" not in neu:
        grenze = re.search(r"^if __name__[^\n]*\n|^[ \t]*app\.run\(", neu, re.M)
        if grenze:
            neu = neu[:grenze.start()] + BUTTON_BLOCK + "\n" + neu[grenze.start():]
            wo += "; Button vor dem Startblock eingefuegt"
        else:
            neu = neu.rstrip("\n") + "\n" + BUTTON_BLOCK
            wo += "; Button am Dateiende angehaengt"
    else:
        wo += "; Button schon vorhanden"

    print("Aenderung: %s" % wo)
    print("-" * 68)
    print(provider.rstrip())
    print("-" * 68)

    if dry_run:
        print("DRY-RUN: nichts geschrieben.")
        return 0

    backup = "%s.bak-%s" % (app_path, time.strftime("%Y%m%d-%H%M%S"))
    shutil.copy2(app_path, backup)
    print("Backup: %s" % backup)
    open(app_path, "w", encoding="utf-8").write(neu)
    try:
        py_compile.compile(app_path, doraise=True)
    except Exception as exc:
        shutil.copy2(backup, app_path)
        print("SYNTAXFEHLER – Backup zurueckgespielt: %s" % exc)
        return 4
    print("OK: py_compile bestaetigt.")
    print("Weiter: systemctl restart dnx-access-control.service")
    print("Danach auf :8096 anmelden (dnxac_session) und /admin/system oeffnen.")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Systemsteuerung an Cookie dnxac_session / sessions / users anbinden")
    ap.add_argument("--app", default=DEFAULT_APP)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)
    return patch(args.app, dry_run=args.dry_run)


if __name__ == "__main__":
    sys.exit(main())
