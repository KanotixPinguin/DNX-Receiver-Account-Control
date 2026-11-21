#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""patch_app.py – bindet die Systemsteuerung an app.py an (2 Zeilen, reversibel).

Das Skript ist bewusst konservativ:
  * es legt zuerst ein datiertes Backup an
  * es sucht die Zeile  app = Flask(...)  (auch eingerueckt, z. B. in einer Factory)
  * findet es sie nicht, wird NICHTS geaendert (Exit 3)
  * nach dem Einfuegen laeuft py_compile; bei Fehler wird das Backup zurueckgespielt
  * ist app.py schon angebunden, passiert nichts (idempotent)

Aufruf:
    sudo python3 scripts/patch_app.py
    sudo python3 scripts/patch_app.py --app /pfad/zu/app.py
    sudo python3 scripts/patch_app.py --dry-run
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

BLOCK_IMPORT = (
    "{i}# --- {m} ---------------------------------------------\n"
    "{i}import os as _dnx_os, sys as _dnx_sys\n"
    "{i}_dnx_sys.path.insert(0, _dnx_os.path.dirname(_dnx_os.path.abspath(__file__)))\n"
    "{i}import dnx_system_control_integration as dnx_sc\n"
)
BLOCK_INSTALL = "{i}dnx_sc.install(app)  # {m}\n"


def patch(app_path: str, dry_run: bool = False) -> int:
    if not os.path.exists(app_path):
        print("FEHLER: %s nicht gefunden" % app_path)
        return 2
    with open(app_path, "r", encoding="utf-8") as fh:
        src = fh.read()

    if MARKER in src or "dnx_system_control_integration" in src:
        print("OK: %s ist bereits angebunden – nichts zu tun." % app_path)
        return 0

    match = re.search(r"^[ \t]*app[ \t]*=[ \t]*(?:flask\.)?Flask\([^\n]*\n", src, re.MULTILINE)
    if not match:
        print("KEINE Stelle 'app = Flask(...)' gefunden. Nichts geaendert.")
        print("Bitte manuell einbauen (siehe INTEGRATION.md, Schritt 3):")
        print("    import dnx_system_control_integration as dnx_sc")
        print("    dnx_sc.install(app)")
        return 3

    indent = re.match(r"[ \t]*", match.group(0)).group(0)
    imp = BLOCK_IMPORT.format(i=indent, m=MARKER)
    ins = BLOCK_INSTALL.format(i=indent, m=MARKER)
    neu = src[:match.start()] + imp + match.group(0) + ins + src[match.end():]

    zeile = src[:match.start()].count("\n") + 1
    print("Gefunden in Zeile %d: %s" % (zeile, match.group(0).rstrip()))
    print("---- wird eingefuegt ----")
    for line in (imp + match.group(0) + ins).rstrip().splitlines():
        print("   " + line)
    print("-------------------------")

    if dry_run:
        print("DRY-RUN: keine Aenderung geschrieben.")
        return 0

    backup = "%s.bak-%s" % (app_path, time.strftime("%Y%m%d-%H%M%S"))
    shutil.copy2(app_path, backup)
    print("Backup: %s" % backup)

    with open(app_path, "w", encoding="utf-8") as fh:
        fh.write(neu)
    try:
        py_compile.compile(app_path, doraise=True)
    except Exception as exc:
        shutil.copy2(backup, app_path)
        print("SYNTAXFEHLER – Backup zurueckgespielt: %s" % exc)
        return 4
    print("OK: py_compile bestaetigt. app.py ist angebunden.")
    print("Weiter mit: sudo systemctl restart dnx-access-control.service")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="app.py an die DNX Systemsteuerung anbinden")
    ap.add_argument("--app", default=DEFAULT_APP, help="Pfad zu app.py")
    ap.add_argument("--dry-run", action="store_true", help="nur anzeigen")
    args = ap.parse_args(argv)
    return patch(args.app, dry_run=args.dry_run)


if __name__ == "__main__":
    sys.exit(main())
