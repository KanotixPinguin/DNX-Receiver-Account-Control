# -*- coding: utf-8 -*-
"""Tests fuer den Einbau-Helfer dnx_system_control_integration (app.py-Anbindung)."""

from __future__ import annotations

import importlib
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SVC = os.path.join(ROOT, "account-service")
INTEG = os.path.join(ROOT, "integration")
for path in (SVC, HERE, INTEG):
    if path not in sys.path:
        sys.path.insert(0, path)

import fake_system  # noqa: E402
from dnx_system_control.settings_store import SettingsStore  # noqa: E402

migrate_mod = importlib.import_module("migrate_add_access_settings")
integ = importlib.import_module("dnx_system_control_integration")


class IntegrationTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name
        self.db = os.path.join(self.dir, "accounts.sqlite3")
        fake_system.make_db(self.db)
        migrate_mod.migrate(self.db, quiet=True)
        self.policy = fake_system.write_policy(os.path.join(self.dir, "profile-policy.json"))
        integ.DEFAULT_DB = self.db
        integ.DEFAULT_POLICY = self.policy
        integ._state.update({"installed": False, "store": None, "error": None})

        from flask import Flask, session as flask_session, jsonify

        self.app = Flask(__name__)
        self.app.secret_key = "integration-test"

        @self.app.route("/als/<username>")
        def _als(username):
            flask_session["username"] = username   # wie in einem bestehenden app.py
            return "ok"

        @self.app.route("/geschuetzt")
        def _geschuetzt():
            return "inhalt"

        @self.app.route("/profil/<name>")
        def _profil(name):
            return jsonify(integ.profile_check(name))

        @self.app.route("/wer-bin-ich")
        def _wer():
            return jsonify(integ.detect_user())

        self.result = integ.install(self.app, db_path=self.db)
        self.client = self.app.test_client()
        # Bewusst DERSELBE Store, den die App benutzt: schreibt durch denselben
        # Cache-Pfad wie der produktive Dienst.
        self.store = integ.store()

    def tearDown(self):
        self.tmp.cleanup()

    # ------------------------------------------------------------- Installation

    def test_installation_gelingt(self):
        self.assertTrue(self.result["installed"], self.result)
        self.assertIsNone(self.result["error"])
        self.assertEqual(self.result["panel"], "/admin/system")
        self.assertTrue(integ.status()["installed"])

    def test_installation_ueberlebt_fehler(self):
        integ._state.update({"installed": False, "store": None})
        res = integ.install(self.app, db_path="/pfad/gibt/es/nicht/accounts.sqlite3",
                            auto_schema=True)
        # kein Abbruch, Dienst bleibt ansprechbar
        self.assertIn("installed", res)
        self.assertEqual(self.client.get("/geschuetzt").status_code, 200)

    # ------------------------------------------------------------- Rollen-/Sitzung

    def test_panel_ist_fuer_gaeste_gesperrt(self):
        self.assertEqual(self.client.get("/admin/system").status_code, 403)
        self.assertEqual(self.client.get("/admin/api/system/settings").status_code, 403)

    def test_benutzername_aus_der_sitzung_wird_erkannt(self):
        self.client.get("/als/dl1abc")
        self.assertEqual(self.client.get("/admin/system").status_code, 200)
        data = self.client.get("/admin/api/system/settings").get_json()
        self.assertEqual(data["actor"]["username"], "dl1abc")
        self.assertEqual(data["actor"]["role"], "admin")

    def test_rolle_kommt_aus_der_datenbank_nicht_aus_der_sitzung(self):
        """Ein Benutzer kann sich die Rolle nicht selbst in die Sitzung schreiben."""
        from flask import session as flask_session

        @self.app.route("/faelschen")
        def _faelschen():
            flask_session["username"] = "do3test"
            flask_session["role"] = "admin"      # Versuch der Rechteausweitung
            return "ok"

        client = self.app.test_client()
        client.get("/faelschen")
        with client.session_transaction() as sess:
            self.assertEqual(sess.get("role"), "admin")
        # DB-Rolle (user) gewinnt ueber den Sitzungs-Abgleich
        resp = client.get("/admin/api/system/settings")
        self.assertEqual(resp.status_code, 403)

    def test_abgeschaltete_rolle_wirkt_sofort_ohne_db_aenderung(self):
        client = self.app.test_client()
        client.get("/als/dl2xyz")                    # extended-Bestandsuser
        user = client.get("/wer-bin-ich").get_json()
        self.assertEqual(user["stored_role"], "extended")
        self.assertEqual(user["role"], "extended")
        self.assertEqual(user["source"], "db", "Rolle muss aus der DB kommen")

        self.store.update({"role_extended_enabled": False}, actor="admin")
        user = client.get("/wer-bin-ich").get_json()
        self.assertEqual(user["stored_role"], "extended", "DB-Rolle bleibt gespeichert")
        self.assertEqual(user["role"], "user", "wirksam herabgestuft")
        self.assertEqual(fake_system.rows(
            self.db, "SELECT role FROM users WHERE username='dl2xyz'")[0][0], "extended",
            "die Datenbankrolle darf nicht veraendert werden")

        self.store.update({"downgrade_disabled_roles": False}, actor="admin")
        user = client.get("/wer-bin-ich").get_json()
        self.assertEqual(user["role"], "extended",
                         "ohne Herabstufung bleibt die Rolle wirksam")

    def test_detect_user_ausserhalb_eines_requests_bricht_nicht_ab(self):
        user = integ.detect_user()
        self.assertEqual(user["role"], "guest")
        self.assertEqual(user["source"], "no-request-context")

    # ------------------------------------------------------------- Wartungsmodus

    def test_wartungsmodus_blockiert_gaeste_und_admin_hat_bypass(self):
        # Sitzung VOR dem Wartungsmodus setzen: /als/... ist kein offener Pfad
        admin_client = self.app.test_client()
        admin_client.get("/als/dl1abc")
        self.store.update({"maintenance_mode": True}, actor="admin")
        self.assertEqual(self.client.get("/geschuetzt").status_code, 503)
        self.assertEqual(admin_client.get("/geschuetzt").status_code, 200)
        # Offene Pfade bleiben erreichbar (Login, Status-API, Panel)
        self.assertNotEqual(self.client.get("/api/system/state").status_code, 503)
        self.assertNotEqual(self.client.get("/login").status_code, 503)

    def test_wartungsmodus_ohne_bypass_sperrt_auch_admin(self):
        admin_client = self.app.test_client()
        admin_client.get("/als/dl1abc")
        self.store.update({"maintenance_mode": True, "maintenance_admin_bypass": False},
                          actor="admin")
        self.assertEqual(admin_client.get("/geschuetzt").status_code, 503)
        # Die Systemsteuerung selbst bleibt erreichbar, sonst kaeme niemand mehr raus
        self.assertEqual(admin_client.get("/admin/system").status_code, 200)

    def test_wartungsmodus_aus_laestet_alles_durch(self):
        self.assertEqual(self.client.get("/geschuetzt").status_code, 200)

    # ------------------------------------------------------------- Profilpruefung

    def test_profilpruefung_und_audit(self):
        before = fake_system.counts(self.db, ["audit_log"])["audit_log"]
        resp = self.client.get("/profil/KW-Schutz").get_json()
        self.assertFalse(resp["allow"])
        self.assertEqual(resp["reason"], "guest_profile_switch_disabled")
        after = fake_system.counts(self.db, ["audit_log"])["audit_log"]
        self.assertEqual(after, before + 1, "profile_denied muss protokolliert werden")
        self.assertEqual(fake_system.rows(
            self.db, "SELECT event FROM audit_log ORDER BY id DESC LIMIT 1")[0][0],
            "profile_denied")

    def test_profilpruefung_fuer_angemeldete_rollen(self):
        client = self.app.test_client()
        client.get("/als/dl2xyz")
        self.assertTrue(client.get("/profil/KW-Schutz").get_json()["allow"])
        client2 = self.app.test_client()
        client2.get("/als/do3test")
        self.assertFalse(client2.get("/profil/KW-Schutz").get_json()["allow"])
        self.assertTrue(client2.get("/profil/80m").get_json()["allow"])

    def test_profilsteuerung_aus_ist_fail_open(self):
        self.store.update({"profile_control_enabled": False}, actor="admin")
        resp = self.client.get("/profil/Admin-only").get_json()
        self.assertTrue(resp["allow"], "fail-open verletzt")
        self.assertEqual(resp["reason"], "profile_control_disabled")

    # ------------------------------------------------- Registrierung/Login/Sitzung

    def test_registrierungs_gate(self):
        ok, reason, reg = integ.registration_gate(0)
        self.assertTrue(ok)
        self.assertEqual(reg["role"], "user")
        self.store.update({"registration_enabled": False}, actor="admin")
        ok, reason, _ = integ.registration_gate(0)
        self.assertFalse(ok)
        self.assertEqual(reason, "registration_disabled")
        self.store.update({"registration_enabled": True, "registration_limit": 2}, actor="admin")
        self.assertFalse(integ.registration_gate(2)[0])
        self.assertTrue(integ.registration_gate(1)[0])

    def test_login_gate_sperrt_nach_fehlversuchen(self):
        now = fake_system.now()
        self.store.update({"max_login_failures": 3, "login_lock_seconds": 600}, actor="admin")
        gesperrt, remaining, reason = integ.login_gate("do3test", 2, now)
        self.assertFalse(gesperrt)
        gesperrt, remaining, reason = integ.login_gate("do3test", 3, now)
        self.assertTrue(gesperrt)
        self.assertGreater(remaining, 0)
        self.assertEqual(reason, "login_locked")
        row = fake_system.rows(
            self.db, "SELECT event FROM audit_log ORDER BY id DESC LIMIT 1")[0]
        self.assertEqual(row[0], "login_blocked")

    def test_failure_stats_zaehlt_aus_dem_audit_log(self):
        for i in range(3):
            integ.audit_event("login_failed", username="do3test", details={"i": i})
        count, last = integ.failure_stats("do3test")
        self.assertEqual(count, 3)
        self.assertIsNotNone(last)
        count, last = integ.failure_stats("gibt-es-nicht")
        self.assertEqual(count, 0)

    def test_sitzungs_optionen_und_sanitize(self):
        self.assertEqual(len(integ.session_choices()), 5)
        self.assertEqual(integ.sanitize_session("month"), "month")
        self.assertEqual(integ.sanitize_session("30d"), "month")
        self.store.update({"allowed_session_forever": False}, actor="admin")
        self.assertEqual(len(integ.session_choices()), 4)
        self.assertEqual(integ.sanitize_session("forever"), "browser",
                         "nicht erlaubte Dauer faellt auf 'browser' zurueck")
        self.assertEqual(integ.initial_role(), "user")
        self.assertTrue(integ.initial_active())
        self.store.update({"new_accounts_active": False, "default_registration_role": "extended"},
                          actor="admin")
        self.assertFalse(integ.initial_active())
        self.assertEqual(integ.initial_role(), "extended")

    def test_audit_event_respektiert_audit_enabled(self):
        before = fake_system.counts(self.db, ["audit_log"])["audit_log"]
        self.assertTrue(integ.audit_event("receiver_join", username="gast",
                                          details={"profile": "80m"}))
        self.assertEqual(fake_system.counts(self.db, ["audit_log"])["audit_log"], before + 1)
        self.store.update({"audit_enabled": False}, actor="admin")
        before = fake_system.counts(self.db, ["audit_log"])["audit_log"]
        self.assertFalse(integ.audit_event("receiver_join", username="gast"))
        self.assertEqual(fake_system.counts(self.db, ["audit_log"])["audit_log"], before)
        self.assertTrue(integ.audit_event("admin_access_settings", username="admin", force=True))

    def test_public_state_ist_oeffentlich_erreichbar(self):
        resp = self.client.get("/api/system/state")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("state", data)
        self.assertIn("rules", data)
        self.assertNotIn("max_audit_bytes", data["state"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
