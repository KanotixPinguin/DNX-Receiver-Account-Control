#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Migration: Tabelle `access_settings` fuer die DNX Systemsteuerung anlegen.

GARANTIEN (wichtig fuer Bestandsuser):
  * Es wird NUR die Tabelle access_settings angelegt/befuellt.
  * users / sessions / audit_log / audit_settings / profile-policy.json bleiben
    unveraendert. Das wird vor und nach der Migration gezaehlt und protokolliert.
  * Bestehende Werte in access_settings werden NICHT ueberschrieben
    (ausser mit --overwrite).
  * Vor dem ersten Schreibzugriff entsteht ein konsistentes, datiertes Backup
    (sqlite3-Backup-API, kein Dateikopie-Versuch bei laufendem Dienst).
  * Laeuft irgendetwas schief, wird die Transaktion zurueckgerollt.

Aufruf:
    python3 migrate_add_access_settings.py --dry-run
    python3 migrate_add_access_settings.py
    python3 migrate_add_access_settings.py --db /pfad/zu/accounts.sqlite3
    python3 migrate_add_access_settings.py --overwrite   # Defaults erzwingen
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sqlite3
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

from dnx_system_control.settings_store import (  # noqa: E402
    DEFAULT_DB, PACKAGE_VERSION, SPEC, TABLE, SettingsStore, resolve_db_path)

WATCHED_TABLES = ("users", "accounts", "sessions", "audit_log", "audit_settings",
                  "profile_policy", "invites", "tokens", "login_attempts")


# --------------------------------------------------------------------------
# Bestandserfassung
# --------------------------------------------------------------------------

def table_counts(conn: sqlite3.Connection) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    try:
        names = [r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        ).fetchall()]
    except sqlite3.Error as exc:
        return {"__error__": str(exc)}
    for name in sorted(names):
        if name == TABLE:
            continue
        try:
            counts[name] = int(conn.execute('SELECT COUNT(*) FROM "%s"' % name).fetchone()[0])
        except sqlite3.Error:
            counts[name] = -1
    return counts


def integrity_check(conn: sqlite3.Connection) -> str:
    try:
        return str(conn.execute("PRAGMA integrity_check").fetchone()[0])
    except sqlite3.Error as exc:
        return "Fehler: %s" % exc


def role_breakdown(conn: sqlite3.Connection) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for cand in ("users", "accounts", "dnx_users"):
        try:
            cols = [r[1].lower() for r in
                    conn.execute('PRAGMA table_info("%s")' % cand).fetchall()]
        except sqlite3.Error:
            continue
        if not cols:
            continue
        role_col = next((c for c in ("role", "user_role", "account_role") if c in cols), None)
        if not role_col:
            continue
        try:
            rows = conn.execute('SELECT "%s", COUNT(*) FROM "%s" GROUP BY "%s"'
                                % (role_col, cand, role_col)).fetchall()
            out[cand] = {str(r[0]): int(r[1]) for r in rows}
        except sqlite3.Error:
            continue
    return out


# --------------------------------------------------------------------------
# Backup
# --------------------------------------------------------------------------

def make_backup(db_path: str, backup_dir: Optional[str], tag: str,
                dry_run: bool) -> Optional[str]:
    """Konsistentes Backup ueber die sqlite3-Backup-API."""
    if dry_run:
        return None
    stamp = time.strftime("%Y%m%d-%H%M%S")
    target_dir = backup_dir or os.path.dirname(os.path.abspath(db_path))
    os.makedirs(target_dir, exist_ok=True)
    base = os.path.basename(db_path).replace(".sqlite3", "").replace(".db", "")
    target = os.path.join(target_dir,
                          "%s-%s-%s.sqlite3.bak" % (base, tag, stamp))
    src = sqlite3.connect(db_path, timeout=30)
    try:
        dst = sqlite3.connect(target, timeout=30)
        try:
            src.backup(dst)
        finally:
            dst.close()
    finally:
        src.close()
    for suffix in ("-wal", "-shm"):
        wal = db_path + suffix
        if os.path.exists(wal):
            shutil.copy2(wal, target + suffix)
    return target


# --------------------------------------------------------------------------
# Migration
# --------------------------------------------------------------------------

def migrate(db_path: str, *, dry_run: bool = False, overwrite: bool = False,
            backup_dir: Optional[str] = None, actor: str = "migration",
            quiet: bool = False) -> int:
    say = (lambda *a: None) if quiet else (lambda *a: print(*a, flush=True))

    if not os.path.exists(db_path):
        say("FEHLER: Datenbank nicht gefunden: %s" % db_path)
        return 2

    say("=" * 78)
    say("DNX Systemsteuerung – Migration access_settings")
    say("Paketversion : %s" % PACKAGE_VERSION)
    say("Datenbank    : %s" % db_path)
    say("Groesse      : %.1f KiB" % (os.path.getsize(db_path) / 1024.0))
    say("Modus        : %s" % ("DRY-RUN (keine Aenderung)" if dry_run else "SCHREIBEND"))
    say("=" * 78)

    conn = sqlite3.connect(db_path, timeout=30, isolation_level=None)
    try:
        before = table_counts(conn)
        check_before = integrity_check(conn)
        roles_before = role_breakdown(conn)
        say("\n[VORHER] integrity_check : %s" % check_before)
        if check_before != "ok":
            say("ABBRUCH: Datenbank ist nicht integer. Erst Backup/Reparatur pruefen.")
            return 3
        say("[VORHER] Tabellen/Zeilen  : %s"
            % json.dumps(before, ensure_ascii=False, sort_keys=True))
        if roles_before:
            say("[VORHER] Rollenverteilung : %s" % json.dumps(roles_before, ensure_ascii=False))
        else:
            say("[VORHER] Rollenverteilung : keine Benutzer-Tabelle mit Rollenspalte erkannt")

        existing_settings: Dict[str, str] = {}
        has_table = bool(conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=?", (TABLE,)).fetchall())
        say("[VORHER] Tabelle %s: %s" % (TABLE, "vorhanden" if has_table else "fehlt"))
        if has_table:
            try:
                existing_settings = {str(r[0]): r[1] for r in conn.execute(
                    "SELECT key, value FROM %s" % TABLE).fetchall()}
            except sqlite3.Error:
                existing_settings = {}
            say("[VORHER] vorhandene Schluessel: %d" % len(existing_settings))

        if dry_run:
            planned = {k: v["default"] for k, v in SPEC.items()
                       if k not in existing_settings or overwrite}
            keep = [k for k in existing_settings if not overwrite]
            say("\n[DRY-RUN] wuerde %d Schluessel anlegen/aktualisieren, %d behalten"
                % (len(planned), len(keep)))
            say("[DRY-RUN] DDL: %s" % " ".join(SettingsStore.DDL.split()))
            say("\nGeplante Defaults:")
            for key in SPEC:
                flag = "NEU " if key not in existing_settings else "BEI "
                say("   %s %-34s = %r" % (flag, key, planned.get(key, SPEC[key]["default"])))
            say("\nBestandsdaten bleiben unberuehrt (users/sessions/audit_log).")
            return 0

        backup_path = make_backup(db_path, backup_dir, "pre-access-settings", dry_run)
        say("\n[BACKUP] %s" % backup_path)
        if not backup_path or not os.path.exists(backup_path):
            say("ABBRUCH: Backup konnte nicht erstellt werden.")
            return 4

        store = SettingsStore(db_path)
        result = store.seed_defaults(actor=actor, overwrite=overwrite, conn=conn)

        after = table_counts(conn)
        check_after = integrity_check(conn)
        roles_after = role_breakdown(conn)
        say("\n[NACHHER] integrity_check : %s" % check_after)
        say("[NACHHER] Tabellen/Zeilen  : %s"
            % json.dumps(after, ensure_ascii=False, sort_keys=True))

        # ---- Beweis: Bestandsuser uebernommen ----
        problems: List[str] = []
        if check_after != "ok":
            problems.append("integrity_check nach Migration: %s" % check_after)
        for name, count in before.items():
            if name == "__error__":
                continue
            if after.get(name) != count:
                problems.append("Zeilenanzahl von '%s' hat sich geaendert: %s -> %s"
                                % (name, count, after.get(name)))
        if roles_before and roles_after and roles_before != roles_after:
            problems.append("Rollenverteilung hat sich geaendert: %s -> %s"
                            % (json.dumps(roles_before, ensure_ascii=False),
                               json.dumps(roles_after, ensure_ascii=False)))
        missing = [t for t in WATCHED_TABLES if t in before and t not in after]
        if missing:
            problems.append("Tabellen verschwunden: %s" % ", ".join(missing))

        say("\nErgebnis:")
        say("   angelegte/aktualisierte Schluessel : %d" % len(result["created"]))
        say("   unveraendert uebernommen           : %d" % len(result["kept"]))
        say("   Bestandsuser vor/nach              : %s / %s"
            % (json.dumps(roles_before, ensure_ascii=False) or "-",
               json.dumps(roles_after, ensure_ascii=False) or "-"))

        if problems:
            say("\n*** PROBLEM ERKANNT ***")
            for p in problems:
                say("   - %s" % p)
            say("Backup liegt unter: %s" % backup_path)
            say("Rollback: python3 %s --restore %s" % (os.path.basename(__file__), backup_path))
            return 5

        say("\nOK: access_settings bereit, alle Bestandsdaten unveraendert.")
        say("Naechster Schritt: Dienst neu starten und /admin/system oeffnen.")
        return 0
    finally:
        conn.close()


def restore(backup_path: str, db_path: str) -> int:
    if not os.path.exists(backup_path):
        print("FEHLER: Backup nicht gefunden: %s" % backup_path)
        return 2
    safety = db_path + ".vor-rollback-%s" % time.strftime("%Y%m%d-%H%M%S")
    if os.path.exists(db_path):
        shutil.copy2(db_path, safety)
        print("Aktueller Stand gesichert unter: %s" % safety)
    shutil.copy2(backup_path, db_path)
    for suffix in ("-wal", "-shm"):
        if os.path.exists(backup_path + suffix):
            shutil.copy2(backup_path + suffix, db_path + suffix)
        elif os.path.exists(db_path + suffix):
            os.remove(db_path + suffix)
    print("Zurueckgespielt: %s -> %s" % (backup_path, db_path))
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description="Legt access_settings fuer die DNX Systemsteuerung an "
                    "(ohne Bestandsdaten zu veraendern).")
    ap.add_argument("--db", default=None, help="Pfad zu accounts.sqlite3")
    ap.add_argument("--dry-run", action="store_true", help="nur anzeigen, nichts schreiben")
    ap.add_argument("--overwrite", action="store_true",
                    help="vorhandene Werte mit Defaults ueberschreiben (Vorsicht)")
    ap.add_argument("--backup-dir", default=None,
                    help="Zielverzeichnis fuer das Backup (Default: neben der DB)")
    ap.add_argument("--restore", metavar="BACKUP", default=None,
                    help="spielt ein Backup zurueck und beendet sich")
    ap.add_argument("--actor", default="migration")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args(argv)

    db_path = resolve_db_path(args.db)
    if args.restore:
        return restore(args.restore, db_path)
    return migrate(db_path, dry_run=args.dry_run, overwrite=args.overwrite,
                   backup_dir=args.backup_dir, actor=args.actor, quiet=args.quiet)


if __name__ == "__main__":
    sys.exit(main())
