# -*- coding: utf-8 -*-
"""Tests fuer settings_store + Migration.

Ausfuehren:
    python3 -m unittest discover -s tests -v
    (oder: python3 tests/test_settings_store.py)
"""

from __future__ import annotations

import importlib
import os
import sqlite3
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SVC = os.path.join(ROOT, "account-service")
for path in (SVC, HERE):
    if path not in sys.path:
        sys.path.insert(0, path)

import fake_system  # noqa: E402
from dnx_system_control.settings_store import (  # noqa: E402
    AUDIT_EVENT, SPEC, SettingsStore, SettingsValidationError, defaults)

migrate_mod = importlib.import_module("migrate_add_access_settings")


class StoreTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name
        self.db = os.path.join(self.dir, "accounts.sqlite3")
        fake_system.make_db(self.db)

    def tearDown(self):
        self.tmp.cleanup()

    # ---------------------------------------------------------------- Defaults

    def test_defaults_bilden_heutiges_verhalten_ab(self):
        d = defaults()
        self.assertTrue(d["registration_enabled"])
        self.assertTrue(d["new_accounts_active"])
        self.assertTrue(d["profile_control_enabled"])
        self.assertFalse(d["account_required"])
        self.assertFalse(d["guest_profile_switch"])
        self.assertTrue(d["role_user_enabled"])
        self.assertTrue(d["role_extended_enabled"])
        self.assertEqual(d["default_registration_role"], "user")
        self.assertFalse(d["maintenance_mode"])
        self.assertTrue(d["maintenance_admin_bypass"])
        self.assertTrue(d["public_activity_enabled"])
        self.assertTrue(d["audit_enabled"])
        self.assertEqual(d["max_audit_entries"], 250000)
        self.assertEqual(d["max_audit_bytes"], 1073741824)
        self.assertFalse(d["audit_auto_purge"], "automatische Loeschung ist derzeit AUS")
        # Alle Sitzungsdauern bleiben erlaubt -> Bestandsuser werden nicht ausgesperrt
        for key in ("browser", "day", "week", "month", "forever"):
            self.assertTrue(d["allowed_session_" + key])

    def test_alle_anforderungs_schluessel_vorhanden(self):
        required = [
            "registration_enabled", "new_accounts_active", "profile_control_enabled",
            "account_required", "guest_profile_switch", "role_user_enabled",
            "role_extended_enabled", "default_registration_role", "maintenance_mode",
            "public_activity_enabled", "audit_enabled", "allowed_session_browser",
            "allowed_session_day", "allowed_session_week", "allowed_session_month",
            "allowed_session_forever", "max_login_failures", "login_lock_seconds",
            "registration_limit", "registration_window_seconds", "max_audit_entries",
            "max_audit_bytes",
        ]
        missing = [k for k in required if k not in SPEC]
        self.assertEqual(missing, [], "Schluessel aus Kapitel 12 fehlen: %s" % missing)

    def test_admin_zusatzeinstellungen_existieren(self):
        extra = [k for k, v in SPEC.items() if v["admin_only"]]
        self.assertTrue(extra)
        for key in ("downgrade_disabled_roles", "revoke_sessions_on_change",
                    "settings_cache_seconds", "settings_fail_open", "audit_auto_purge"):
            self.assertIn(key, extra)

    # ---------------------------------------------------------------- Migration

    def test_migration_legt_tabelle_an_und_erhaelt_bestandsdaten(self):
        before = fake_system.counts(self.db)
        rc = migrate_mod.migrate(self.db, quiet=True)
        self.assertEqual(rc, 0)
        after = fake_system.counts(self.db)

        # Bestandsdaten unveraendert
        for table, count in before.items():
            self.assertEqual(after.get(table), count,
                             "Tabelle %s hat sich veraendert" % table)
        # Benutzer im Einzelnen
        users = fake_system.rows(self.db, "SELECT username, role, active FROM users ORDER BY id")
        self.assertEqual([u[0] for u in users],
                         ["dl1abc", "dl2xyz", "do3test", "swl99", "wartend"])
        self.assertEqual([u[1] for u in users],
                         ["admin", "extended", "user", "user", "user"])
        sessions = fake_system.rows(self.db, "SELECT username, duration FROM sessions ORDER BY id")
        self.assertEqual(len(sessions), 3)
        # access_settings angelegt
        self.assertIn("access_settings", after)
        self.assertEqual(after["access_settings"], len(SPEC))

    def test_migration_dry_run_schreibt_nichts(self):
        before = fake_system.counts(self.db)
        rc = migrate_mod.migrate(self.db, dry_run=True, quiet=True)
        self.assertEqual(rc, 0)
        self.assertEqual(fake_system.counts(self.db), before)
        self.assertNotIn("access_settings", fake_system.counts(self.db))

    def test_migration_erzeugt_datiertes_backup(self):
        rc = migrate_mod.migrate(self.db, quiet=True)
        self.assertEqual(rc, 0)
        backups = [f for f in os.listdir(self.dir) if "pre-access-settings" in f]
        self.assertTrue(backups, "kein Backup erzeugt")
        bak = os.path.join(self.dir, backups[0])
        # Backup enthaelt die Bestandsuser, aber keine access_settings
        self.assertEqual(fake_system.counts(bak, ["users"])["users"], len(fake_system.USERS))
        self.assertEqual(fake_system.counts(bak, ["access_settings"])["access_settings"], -1)

    def test_migration_ist_idempotent_und_ueberschreibt_nicht(self):
        self.assertEqual(migrate_mod.migrate(self.db, quiet=True), 0)
        store = SettingsStore(self.db)
        store.update({"registration_enabled": False}, actor="admin")
        self.assertEqual(migrate_mod.migrate(self.db, quiet=True), 0)
        self.assertFalse(store.values()["registration_enabled"],
                         "zweite Migration hat Admin-Wert ueberschrieben")

    def test_migration_seed_uebernimmt_audit_grenzen(self):
        self.assertEqual(migrate_mod.migrate(self.db, quiet=True), 0)
        store = SettingsStore(self.db)
        values = store.values()
        self.assertEqual(values["max_audit_entries"], 250000)
        self.assertEqual(values["max_audit_bytes"], 1073741824)

    def test_migration_bricht_bei_defekter_db_ab(self):
        with open(self.db, "wb") as fh:
            fh.write(b"das ist keine sqlite-datei" * 10)
        rc = migrate_mod.migrate(self.db, quiet=True)
        self.assertNotEqual(rc, 0)

    # ---------------------------------------------------------------- Speichern

    def test_update_schreibt_atomar_und_liefert_diff(self):
        store = SettingsStore(self.db)
        store.ensure_schema()
        res = store.update({"registration_enabled": False, "max_login_failures": 3},
                           actor="dl1abc", role="admin", ip="192.0.2.10",
                           user_agent="pytest")
        self.assertEqual(set(res["changed"]), {"registration_enabled", "max_login_failures"})
        self.assertEqual(res["changed"]["max_login_failures"]["old"], 5)
        self.assertEqual(res["changed"]["max_login_failures"]["new"], 3)
        values = SettingsStore(self.db).values()
        self.assertFalse(values["registration_enabled"])
        self.assertEqual(values["max_login_failures"], 3)

    def test_update_ohne_aenderung_schreibt_nichts(self):
        store = SettingsStore(self.db)
        store.ensure_schema()
        res = store.update({"registration_enabled": True}, actor="admin")
        self.assertEqual(res["changed"], {})
        self.assertFalse(res["audit_written"])

    def test_ungueltige_werte_werden_abgelehnt(self):
        store = SettingsStore(self.db)
        store.ensure_schema()
        cases = [
            ({"max_login_failures": 1000}, "max_login_failures"),
            ({"max_login_failures": -1}, "max_login_failures"),
            ({"default_registration_role": "admin"}, "default_registration_role"),
            ({"registration_enabled": "vielleicht"}, "registration_enabled"),
            ({"audit_timezone": "x" * 600}, "audit_timezone"),
            ({"allowed_session_browser": False, "allowed_session_day": False,
              "allowed_session_week": False, "allowed_session_month": False,
              "allowed_session_forever": False}, "allowed_session_browser"),
            ({"registration_limit": 3, "registration_window_seconds": 0},
             "registration_window_seconds"),
            ({"max_login_failures": 3, "login_lock_seconds": 0}, "login_lock_seconds"),
            ({"default_registration_role": "extended", "role_extended_enabled": False},
             "default_registration_role"),
        ]
        for payload, expected_field in cases:
            with self.subTest(payload=payload):
                with self.assertRaises(SettingsValidationError) as ctx:
                    store.update(payload, actor="admin")
                self.assertIn(expected_field, ctx.exception.errors)
        # nichts geschrieben
        self.assertEqual(fake_system.counts(self.db, ["access_settings"])["access_settings"], 0)

    def test_unbekannter_schluessel_strict_abgelehnt(self):
        store = SettingsStore(self.db)
        store.ensure_schema()
        with self.assertRaises(SettingsValidationError):
            store.update({"registration_enabled": False, "böse_falle": 1}, actor="admin")
        # wegen Atomaritaet darf auch der gueltige Wert nicht drin sein
        self.assertEqual(store.values()["registration_enabled"], True)
        res = store.update({"böse_falle": 1}, actor="admin", strict=False)
        self.assertEqual(res["changed"], {})

    def test_schreibgeschuetzte_schluessel(self):
        store = SettingsStore(self.db)
        store.ensure_schema()
        with self.assertRaises(SettingsValidationError) as ctx:
            store.update({"schema_version": 99}, actor="admin")
        self.assertIn("schreibgeschuetzt", ctx.exception.errors["schema_version"])

    def test_beschaedigter_wert_faellt_auf_default_zurueck(self):
        store = SettingsStore(self.db)
        store.ensure_schema()
        conn = sqlite3.connect(self.db)
        conn.execute("INSERT OR REPLACE INTO access_settings (key, value, type, updated_at, updated_by) "
                     "VALUES ('max_login_failures','nicht-eine-zahl','int',0,'test')")
        conn.commit()
        conn.close()
        values, warnings = SettingsStore(self.db).load()
        self.assertEqual(values["max_login_failures"], SPEC["max_login_failures"]["default"])
        self.assertTrue(any("max_login_failures" in w for w in warnings))

    def test_bool_speicherung_als_0_1(self):
        store = SettingsStore(self.db)
        store.ensure_schema()
        store.update({"account_required": True}, actor="admin")
        raw = fake_system.rows(self.db, "SELECT value FROM access_settings WHERE key='account_required'")
        self.assertEqual(raw[0][0], "1")
        store.update({"account_required": "off"}, actor="admin")
        raw = fake_system.rows(self.db, "SELECT value FROM access_settings WHERE key='account_required'")
        self.assertEqual(raw[0][0], "0")

    # -------------------------------------------------------------------- Audit

    def test_audit_wird_in_bestehende_tabelle_geschrieben(self):
        store = SettingsStore(self.db)
        store.ensure_schema()
        before = fake_system.counts(self.db, ["audit_log"])["audit_log"]
        res = store.update({"maintenance_mode": True}, actor="dl1abc", role="admin",
                           ip="192.0.2.10", user_agent="pytest")
        self.assertTrue(res["audit_written"])
        after = fake_system.rows(
            self.db, "SELECT event, username, role, ip, details FROM audit_log ORDER BY id DESC LIMIT 1")
        self.assertEqual(after[0][0], AUDIT_EVENT)
        self.assertEqual(after[0][1], "dl1abc")
        self.assertEqual(after[0][2], "admin")
        self.assertEqual(after[0][3], "192.0.2.10")
        self.assertIn("maintenance_mode", after[0][4])
        self.assertEqual(fake_system.counts(self.db, ["audit_log"])["audit_log"], before + 1)

    def test_audit_toleriert_fremde_spaltennamen(self):
        db = os.path.join(self.dir, "alien.sqlite3")
        fake_system.make_db(db, audit_variant="alien")
        store = SettingsStore(db)
        store.ensure_schema()
        res = store.update({"registration_enabled": False}, actor="dl1abc", role="admin",
                           ip="10.0.0.1", user_agent="alien-agent")
        self.assertTrue(res["audit_written"])
        row = fake_system.rows(
            db, "SELECT action, account_name, client_ip, agent, extra FROM audit_log "
                "ORDER BY id DESC LIMIT 1")[0]
        self.assertEqual(row[0], AUDIT_EVENT)
        self.assertEqual(row[1], "dl1abc")
        self.assertEqual(row[2], "10.0.0.1")
        self.assertEqual(row[3], "alien-agent")
        self.assertIn("registration_enabled", row[4])

    def test_allgemeines_audit_aus_aber_einstellungen_bleiben_protokolliert(self):
        """audit_enabled steuert Login-/Profilereignisse. Einstellungs-aenderungen
        laufen ueber audit_settings_changes und bleiben sichtbar (Admin-Nachvollziehbarkeit)."""
        store = SettingsStore(self.db)
        store.ensure_schema()
        store.update({"audit_enabled": False}, actor="admin")
        before = fake_system.counts(self.db, ["audit_log"])["audit_log"]
        res = store.update({"registration_limit": 9}, actor="admin")
        self.assertEqual(res["changed"]["registration_limit"]["new"], 9)
        self.assertEqual(fake_system.counts(self.db, ["audit_log"])["audit_log"], before + 1)
        self.assertTrue(res["audit_written"])

    def test_einstellungs_audit_abschaltbar(self):
        store = SettingsStore(self.db)
        store.ensure_schema()
        store.update({"audit_enabled": False, "audit_settings_changes": False}, actor="admin")
        before = fake_system.counts(self.db, ["audit_log"])["audit_log"]
        res = store.update({"registration_limit": 9}, actor="admin")
        self.assertEqual(res["changed"]["registration_limit"]["new"], 9)
        self.assertFalse(res["audit_written"])
        self.assertEqual(fake_system.counts(self.db, ["audit_log"])["audit_log"], before)

    def test_auto_purge_nur_wenn_aktiv(self):
        store = SettingsStore(self.db)
        store.ensure_schema()
        conn = sqlite3.connect(self.db)
        conn.executemany("INSERT INTO audit_log (ts, event, username) VALUES (?,?,?)",
                         [(1700000000 + i, "test_event", "u%d" % i) for i in range(1200)])
        conn.commit()
        conn.close()
        vor_purge = fake_system.counts(self.db, ["audit_log"])["audit_log"]
        self.assertGreater(vor_purge, 1000)
        store.update({"max_audit_entries": 1000, "audit_auto_purge": False}, actor="admin")
        self.assertGreaterEqual(fake_system.counts(self.db, ["audit_log"])["audit_log"],
                                vor_purge, "ohne auto_purge darf nichts geloescht werden")
        store.update({"audit_auto_purge": True}, actor="admin")
        store.update({"max_audit_entries": 1000}, actor="admin")
        remaining = fake_system.counts(self.db, ["audit_log"])["audit_log"]
        self.assertLessEqual(remaining, 1002, "Purge hat nicht eingegriffen")
        self.assertGreater(remaining, 900, "Purge darf nicht zu viel loeschen")

    # ------------------------------------------------------------------- Sichten

    def test_public_state_verraet_keine_interna(self):
        store = SettingsStore(self.db)
        store.ensure_schema()
        state = store.public_state()
        for key in ("max_audit_entries", "max_audit_bytes", "settings_fail_open",
                    "downgrade_disabled_roles", "strict_unknown_keys", "login_lock_seconds",
                    "password_min_length", "audit_timezone"):
            self.assertNotIn(key, state, "interner Schluessel %s ist oeffentlich" % key)
        for key in ("registration_enabled", "maintenance_mode", "account_required",
                    "guest_profile_switch", "profile_control_enabled"):
            self.assertIn(key, state)

    def test_expose_state_to_receiver_aus_liefert_defaults(self):
        store = SettingsStore(self.db)
        store.ensure_schema()
        store.update({"expose_state_to_receiver": False, "registration_enabled": False},
                     actor="admin")
        state = store.public_state()
        self.assertEqual(state["_meta"]["source"], "defaults")
        self.assertTrue(state["registration_enabled"])

    def test_readonly_store_fail_open_bei_fehlender_db(self):
        store = SettingsStore(os.path.join(self.dir, "gibt-es-nicht.sqlite3"), readonly=True)
        values, warnings = store.load()
        self.assertEqual(values, defaults())
        self.assertTrue(warnings)
        self.assertTrue(values["profile_control_enabled"],
                        "fail-open: Profilsteuerung darf nicht sperren")

    def test_readonly_store_kann_nicht_schreiben(self):
        store = SettingsStore(self.db, readonly=True)
        with self.assertRaises(Exception):
            store.update({"registration_enabled": False}, actor="admin")

    def test_impact_preview_zeigt_bestandsuser_und_herabstufung(self):
        store = SettingsStore(self.db)
        store.ensure_schema()
        info = store.impact_preview()
        self.assertEqual(info["by_role"].get("extended"), 1)
        self.assertEqual(info["by_role"].get("user"), 3)
        self.assertEqual(info["by_role"].get("admin"), 1)
        self.assertEqual(info["total_users"], len(fake_system.USERS))
        self.assertEqual(info["downgraded"], [])
        store.update({"role_extended_enabled": False}, actor="admin")
        info = store.impact_preview()
        self.assertEqual(len(info["downgraded"]), 1)
        self.assertEqual(info["downgraded"][0]["role"], "extended")
        self.assertEqual(info["downgraded"][0]["effective"], "user")
        # Rollen in der DB bleiben unveraendert
        self.assertEqual(fake_system.rows(
            self.db, "SELECT role FROM users WHERE username='dl2xyz'")[0][0], "extended")

    def test_reset_defaults(self):
        store = SettingsStore(self.db)
        store.ensure_schema()
        store.update({"registration_enabled": False, "max_login_failures": 1}, actor="admin")
        res = store.reset_defaults(["registration_enabled"], actor="admin")
        self.assertTrue(store.values()["registration_enabled"])
        self.assertEqual(store.values()["max_login_failures"], 1,
                         "nicht angeforderte Schluessel durften sich nicht aendern")
        self.assertIn("registration_enabled", res["changed"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
