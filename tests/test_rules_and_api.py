# -*- coding: utf-8 -*-
"""Tests fuer access_rules, die Admin-API (Flask) und den OpenWebRX-Hook."""

from __future__ import annotations

import importlib
import importlib.util
import json
import os
import sys
import tempfile
import types
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SVC = os.path.join(ROOT, "account-service")
OWRX = os.path.join(ROOT, "owrx")
for path in (SVC, HERE):
    if path not in sys.path:
        sys.path.insert(0, path)

import fake_system  # noqa: E402
from dnx_system_control import access_rules as R  # noqa: E402
from dnx_system_control.settings_store import SPEC, SettingsStore, defaults  # noqa: E402

migrate_mod = importlib.import_module("migrate_add_access_settings")


def load_module(name: str, path: str):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------- Regeln

class RulesTestCase(unittest.TestCase):
    def setUp(self):
        self.s = defaults()

    # Rollen
    def test_rollen_abschalten_und_herabstufen(self):
        self.assertTrue(R.role_enabled(self.s, "admin"))
        self.assertTrue(R.role_enabled(self.s, "guest"))
        self.s["role_extended_enabled"] = False
        self.assertFalse(R.role_enabled(self.s, "extended"))
        self.assertEqual(R.effective_role(self.s, "extended"), "user")
        self.s["role_user_enabled"] = False
        self.assertEqual(R.effective_role(self.s, "extended"), "guest")
        self.s["downgrade_disabled_roles"] = False
        self.assertEqual(R.effective_role(self.s, "extended"), "extended",
                         "ohne Herabstufung bleibt die Rolle wirksam")
        self.assertEqual(R.effective_role(self.s, "admin"), "admin")

    def test_standardrolle_faellt_zurueck(self):
        self.assertEqual(R.default_registration_role(self.s), "user")
        self.s["default_registration_role"] = "extended"
        self.assertEqual(R.default_registration_role(self.s), "extended")
        self.s["role_extended_enabled"] = False
        self.assertEqual(R.default_registration_role(self.s), "user")
        self.s["role_user_enabled"] = False
        self.assertEqual(R.default_registration_role(self.s), "guest")
        self.s["default_registration_role"] = "admin"
        self.assertEqual(R.default_registration_role(self.s), "guest",
                         "admin darf nie Standardrolle sein")

    def test_selectable_roles(self):
        self.assertEqual(R.selectable_roles(self.s), ["guest", "user", "extended", "admin"])
        self.s["role_extended_enabled"] = False
        self.assertEqual(R.selectable_roles(self.s), ["guest", "user", "admin"])

    # Registrierung
    def test_registrierung_an_aus(self):
        st = R.registration_state(self.s)
        self.assertTrue(st["enabled"])
        self.assertEqual(st["role"], "user")
        self.assertTrue(st["immediately_active"])
        self.s["registration_enabled"] = False
        st = R.registration_state(self.s)
        self.assertFalse(st["enabled"])
        self.assertEqual(st["reason"], "registration_disabled")
        self.assertTrue(st["message"])

    def test_registrierung_rate_limit(self):
        self.s["registration_limit"] = 3
        self.assertEqual(R.registration_rate_allowed(self.s, 2), (True, None))
        self.assertEqual(R.registration_rate_allowed(self.s, 3), (False, "registration_rate_limit"))
        self.s["registration_limit"] = 0
        self.assertEqual(R.registration_rate_allowed(self.s, 999), (True, None))

    def test_neue_konten_aktiv_oder_wartend(self):
        self.assertEqual(R.new_account_state(self.s), "active")
        self.s["new_accounts_active"] = False
        self.assertEqual(R.new_account_state(self.s), "pending")

    # Login-Sperre
    def test_login_sperre(self):
        self.s["max_login_failures"] = 3
        self.s["login_lock_seconds"] = 600
        blocked, remaining, reason = R.login_blocked(self.s, 2, last_failure_ts=1_000_000, now=1_000_100)
        self.assertFalse(blocked)
        blocked, remaining, reason = R.login_blocked(self.s, 3, last_failure_ts=1_000_000, now=1_000_100)
        self.assertTrue(blocked)
        self.assertEqual(remaining, 500)
        self.assertEqual(reason, "login_locked")
        blocked, remaining, reason = R.login_blocked(self.s, 3, last_failure_ts=1_000_000, now=1_000_700)
        self.assertFalse(blocked)
        self.s["max_login_failures"] = 0
        self.assertFalse(R.login_blocked(self.s, 99, last_failure_ts=1, now=2)[0])

    # Sitzungen
    def test_sitzungsdauern(self):
        choices = R.session_choices(self.s)
        self.assertEqual(len(choices), 5)
        self.s["allowed_session_forever"] = False
        choices = R.session_choices(self.s)
        self.assertEqual(len(choices), 4)
        self.assertNotIn("forever", [c["id"] for c in choices])
        for key in ("browser", "day", "week", "month", "forever"):
            self.s["allowed_session_" + key] = False
        choices = R.session_choices(self.s)
        self.assertEqual([c["id"] for c in choices], ["browser"],
                         "es muss immer mindestens eine Option geben")
        self.assertEqual(R.sanitize_session_request(self.s, "30d"), "browser")
        self.s["allowed_session_month"] = True
        # kanonische Werte = Schluessel aus DURS in app.py
        self.assertEqual(R.sanitize_session_request(self.s, "30d"), "month")
        self.assertEqual(R.sanitize_session_request(self.s, "month"), "month")
        self.assertTrue(R.session_value_allowed(self.s, "month"))
        self.assertTrue(R.session_value_allowed(self.s, "30d"))

    def test_sitzungs_aliasse_aus_bestehenden_formularen(self):
        for alt, kanon in (("1d", "day"), ("7d", "week"), ("30d", "month"),
                           ("unbegrenzt", "forever"), ("session", "browser"),
                           ("DAY", "day"), ("forever", "forever")):
            with self.subTest(alt=alt):
                self.assertEqual(R.sanitize_session_request(self.s, alt), kanon)
        self.assertEqual([c["value"] for c in R.session_choices(self.s)],
                         ["browser", "day", "week", "month", "forever"],
                         "Werte muessen zu DURS in app.py passen")

    def test_profile_policy_als_flache_rollenzuordnung(self):
        """So liegt profile-policy.json produktiv: {"profil": "mindestrolle"}."""
        with tempfile.TemporaryDirectory() as tmp:
            p = os.path.join(tmp, "profile-policy.json")
            with open(p, "w", encoding="utf-8") as fh:
                json.dump({"80m": "user", "40m": "user",
                           "KW-Schutz": "extended", "Admin-only": "admin"}, fh)
            pol = R.load_profile_policy(p)
            self.assertEqual(pol["form"], "flat_min_role")
            self.assertEqual(pol["protected"], {"KW-Schutz", "Admin-only"})
            self.assertEqual(pol["allowed"]["user"], {"80m", "40m"})
            self.assertEqual(pol["allowed"]["extended"], {"80m", "40m", "KW-Schutz"})
            self.assertEqual(pol["allowed"]["admin"],
                             {"80m", "40m", "KW-Schutz", "Admin-only"})
            d = R.profile_decision(self.s, role="user", authenticated=True,
                                   target_profile="KW-Schutz",
                                   protected=pol["protected"], allowed_map=pol["allowed"])
            self.assertFalse(d["allow"])
            d = R.profile_decision(self.s, role="extended", authenticated=True,
                                   target_profile="KW-Schutz",
                                   protected=pol["protected"], allowed_map=pol["allowed"])
            self.assertTrue(d["allow"])
            d = R.profile_decision(self.s, role="admin", authenticated=True,
                                   target_profile="Admin-only",
                                   protected=pol["protected"], allowed_map=pol["allowed"])
            self.assertTrue(d["allow"])
            d = R.profile_decision(self.s, role="user", authenticated=True,
                                   target_profile="unbekannt",
                                   protected=pol["protected"], allowed_map=pol["allowed"])
            self.assertFalse(d["allow"])
            self.assertEqual(d["reason"], "profile_not_in_role_policy")

    # Wartung
    def test_wartungsmodus_mit_admin_bypass(self):
        st = R.maintenance_state(self.s, "user")
        self.assertFalse(st["active"])
        self.assertTrue(st["allowed"])
        self.s["maintenance_mode"] = True
        self.assertFalse(R.maintenance_state(self.s, "user")["allowed"])
        self.assertFalse(R.maintenance_state(self.s, "guest")["allowed"])
        self.assertTrue(R.maintenance_state(self.s, "admin")["allowed"])
        self.assertEqual(R.maintenance_state(self.s, "admin")["reason"], "maintenance_admin_bypass")
        self.s["maintenance_admin_bypass"] = False
        self.assertFalse(R.maintenance_state(self.s, "admin")["allowed"],
                         "ohne Bypass kommt auch der Admin nicht durch (Warnfall)")
        self.assertTrue(R.maintenance_state(self.s, "admin")["message"])

    # Profilentscheidungen
    def test_profilsteuerung_aus_ist_fail_open(self):
        self.s["profile_control_enabled"] = False
        for role in ("guest", "user", "extended", "admin"):
            d = R.profile_decision(self.s, role=role, authenticated=(role != "guest"),
                                   target_profile="Admin-only")
            self.assertTrue(d["allow"], "fail-open verletzt fuer Rolle %s" % role)
            self.assertEqual(d["reason"], "profile_control_disabled")
            self.assertEqual(d["event"], "profile_change")
        # auch mit Account-Zwang und Wartungsmodus: nichts wird gesperrt
        self.s["account_required"] = True
        self.s["maintenance_mode"] = True
        d = R.profile_decision(self.s, role="guest", authenticated=False, target_profile="80m")
        self.assertTrue(d["allow"])

    def test_profilentscheidungen_matrix(self):
        protected = ["KW-Schutz", "Admin-only"]
        cases = [
            # (settings-aenderung, role, authenticated, profil, allow, reason)
            ({}, "guest", False, "80m", False, "guest_profile_switch_disabled"),
            ({"guest_profile_switch": True}, "guest", False, "80m", True, "guest_allowed"),
            ({"guest_profile_switch": True}, "guest", False, "KW-Schutz", False,
             "guest_protected_profile"),
            ({"account_required": True}, "guest", False, "80m", False, "account_required"),
            ({"account_required": True}, "user", True, "80m", True, "role_user"),
            ({}, "user", True, "80m", True, "role_user"),
            ({}, "user", True, "KW-Schutz", False, "protected_profile_role_insufficient"),
            ({}, "extended", True, "KW-Schutz", True, "role_extended"),
            ({}, "extended", True, "Admin-only", True, "role_extended"),
            ({}, "admin", True, "Admin-only", True, "admin"),
            ({"role_extended_enabled": False}, "extended", True, "KW-Schutz", False,
             "protected_profile_role_insufficient"),
            ({"role_extended_enabled": False, "downgrade_disabled_roles": False},
             "extended", True, "KW-Schutz", True, "role_extended"),
            ({"maintenance_mode": True}, "user", True, "80m", False, "maintenance_mode"),
            ({"maintenance_mode": True}, "admin", True, "80m", True, "admin"),
            ({"maintenance_mode": True, "maintenance_admin_bypass": False}, "admin", True,
             "80m", False, "maintenance_mode"),
            ({"role_user_enabled": False}, "user", True, "80m", False,
             "guest_profile_switch_disabled"),
        ]
        for patch, role, auth, profile, allow, reason in cases:
            with self.subTest(patch=patch, role=role, profile=profile):
                s = dict(self.s)
                s.update(patch)
                d = R.profile_decision(s, role=role, authenticated=auth,
                                       target_profile=profile, protected=protected)
                self.assertEqual(d["allow"], allow)
                self.assertEqual(d["reason"], reason)
                self.assertEqual(d["event"], "profile_change" if allow else "profile_denied")

    def test_allowed_map_hat_vorrang(self):
        allowed_map = {"user": ["80m", "40m"], "extended": ["80m", "40m", "KW-Schutz"]}
        d = R.profile_decision(self.s, role="user", authenticated=True,
                               target_profile="2m", allowed_map=allowed_map)
        self.assertFalse(d["allow"])
        self.assertEqual(d["reason"], "profile_not_in_role_policy")
        d = R.profile_decision(self.s, role="extended", authenticated=True,
                               target_profile="KW-Schutz", allowed_map=allowed_map)
        self.assertTrue(d["allow"])
        d = R.profile_decision(self.s, role="admin", authenticated=True,
                               target_profile="irgendwas", allowed_map=allowed_map)
        self.assertTrue(d["allow"], "admin bleibt immer erlaubt")

    def test_profile_policy_varianten(self):
        with tempfile.TemporaryDirectory() as tmp:
            p1 = os.path.join(tmp, "p1.json")
            with open(p1, "w", encoding="utf-8") as fh:
                json.dump({"protected": ["A", "B"]}, fh)
            pol = R.load_profile_policy(p1)
            self.assertTrue(pol["raw_ok"])
            self.assertEqual(pol["protected"], {"A", "B"})

            p2 = os.path.join(tmp, "p2.json")
            with open(p2, "w", encoding="utf-8") as fh:
                json.dump({"profiles": {"80m": {"roles": ["user", "admin"]},
                                        "KW": {"roles": ["extended", "admin"]}}}, fh)
            pol = R.load_profile_policy(p2)
            self.assertIn("KW", pol["protected"])
            self.assertIn("user", pol["allowed"])
            self.assertIn("80m", pol["allowed"]["user"])

            p3 = os.path.join(tmp, "p3.json")
            with open(p3, "w", encoding="utf-8") as fh:
                json.dump({"roles": {"extended": ["X"], "user": ["Y"]}}, fh)
            pol = R.load_profile_policy(p3)
            self.assertEqual(pol["allowed"]["extended"], {"X"})

            p4 = os.path.join(tmp, "p4.json")
            with open(p4, "w", encoding="utf-8") as fh:
                json.dump(["80m", "40m"], fh)
            pol = R.load_profile_policy(p4)
            self.assertEqual(pol["allowed"]["user"], {"80m", "40m"})

            p5 = os.path.join(tmp, "kaputt.json")
            with open(p5, "w", encoding="utf-8") as fh:
                fh.write("{kein json")
            pol = R.load_profile_policy(p5)
            self.assertFalse(pol["raw_ok"])
            self.assertTrue(pol["error"])

            pol = R.load_profile_policy(os.path.join(tmp, "gibt-es-nicht.json"))
            self.assertFalse(pol["raw_ok"])

    def test_public_view_und_admin_summary(self):
        view = R.public_view(self.s)
        self.assertIn("registration", view)
        self.assertEqual(len(view["sessions"]), 5)
        summary = R.admin_summary(self.s, ["warnung"])
        self.assertEqual(summary["registration"], "AN")
        self.assertEqual(summary["new_accounts"], "sofort aktiv")
        self.assertEqual(summary["warnings"], ["warnung"])
        self.s["profile_control_enabled"] = False
        self.assertEqual(R.admin_summary(self.s)["profile_control"], "AUS (fail-open)")

    def test_normalisiere_rollennamen_aus_der_anzeige(self):
        self.assertEqual(R.normalize_role("Erweitert"), "extended")
        self.assertEqual(R.normalize_role("Administrator"), "admin")
        self.assertEqual(R.normalize_role("Chat"), "guest")
        self.assertEqual(R.normalize_role(""), "guest")
        self.assertEqual(R.normalize_role(None), "guest")
        self.assertEqual(R.normalize_role("unbekannt"), "guest")


# ---------------------------------------------------------------- Admin-API

class AdminApiTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from flask import Flask
        from dnx_system_control import admin_api
        cls.Flask = Flask
        cls.admin_api = admin_api

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name
        self.db = os.path.join(self.dir, "accounts.sqlite3")
        fake_system.make_db(self.db)
        self.assertEqual(migrate_mod.migrate(self.db, quiet=True), 0)
        self.store = SettingsStore(self.db)
        self.actor = {"username": "dl1abc", "role": "admin",
                      "ip": "192.0.2.10", "user_agent": "pytest"}
        self.app = self.Flask(__name__)
        self.app.secret_key = "test-secret"
        self.app.register_blueprint(self.admin_api.create_blueprint(
            self.store, current_user=lambda: dict(self.actor), url_prefix="/admin"))
        self.app.config.update(TESTING=True)
        self.client = self.app.test_client()

    def tearDown(self):
        self.tmp.cleanup()

    def csrf(self):
        data = self.client.get("/admin/api/system/settings").get_json()
        return data["csrf_token"], data

    # Zugriff
    def test_ohne_current_user_provider_gesperrt(self):
        app = self.Flask(__name__)
        app.secret_key = "x"
        app.register_blueprint(self.admin_api.create_blueprint(self.store))
        client = app.test_client()
        self.assertEqual(client.get("/admin/system").status_code, 403)
        self.assertEqual(client.get("/admin/api/system/settings").status_code, 403)

    def test_nicht_admin_wird_abgewiesen(self):
        for role in ("guest", "user", "extended"):
            with self.subTest(role=role):
                self.actor["role"] = role
                self.assertEqual(self.client.get("/admin/system").status_code, 403)
                self.assertEqual(self.client.get("/admin/api/system/settings").status_code, 403)

    def test_admin_bekommt_seite_und_daten(self):
        page = self.client.get("/admin/system")
        self.assertEqual(page.status_code, 200)
        html = page.get_data(as_text=True)
        self.assertIn("Systemsteuerung", html)
        self.assertIn("dnx_system_control.css", html)
        self.assertNotIn("__DNX_", html, "Platzhalter wurden nicht ersetzt")
        data = self.client.get("/admin/api/system/settings").get_json()
        self.assertTrue(data["ok"])
        self.assertEqual(len(data["settings"]), len(SPEC))
        self.assertTrue(data["csrf_token"])
        self.assertEqual(data["actor"]["role"], "admin")
        self.assertIn("impact", data)
        self.assertEqual(data["impact"]["by_role"].get("extended"), 1)

    def test_static_nur_fuer_admin(self):
        self.assertEqual(
            self.client.get("/admin/system/static/dnx_system_control.css").status_code, 200)
        self.actor["role"] = "user"
        self.assertEqual(
            self.client.get("/admin/system/static/dnx_system_control.css").status_code, 403)

    # CSRF
    def test_post_ohne_csrf_wird_abgelehnt(self):
        resp = self.client.post("/admin/api/system/settings",
                                json={"settings": {"registration_enabled": False}})
        self.assertEqual(resp.status_code, 403)
        self.assertEqual(resp.get_json()["code"], "csrf")
        self.assertTrue(self.store.values()["registration_enabled"],
                        "ohne CSRF durfte nichts gespeichert werden")

    def test_post_mit_fremdem_csrf_token_wird_abgelehnt(self):
        token, _ = self.csrf()
        resp = self.client.post("/admin/api/system/settings",
                                json={"settings": {"registration_enabled": False}},
                                headers={"X-CSRF-Token": token + "x"})
        self.assertEqual(resp.status_code, 403)

    def test_post_mit_falscher_origin_wird_abgelehnt(self):
        token, _ = self.csrf()
        resp = self.client.post("/admin/api/system/settings",
                                json={"settings": {"maintenance_mode": True}},
                                headers={"X-CSRF-Token": token,
                                         "Origin": "http://evil.example"})
        self.assertEqual(resp.status_code, 403)

    def test_post_speichert_atomar_und_auditiert(self):
        token, _ = self.csrf()
        payload = {"registration_enabled": False, "max_login_failures": 3,
                   "default_registration_role": "extended"}
        resp = self.client.post("/admin/api/system/settings",
                                json={"settings": payload, "csrf_token": token})
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(set(data["changed"]), set(payload))
        self.assertTrue(data["audit_written"])
        values = SettingsStore(self.db).values()
        self.assertFalse(values["registration_enabled"])
        self.assertEqual(values["max_login_failures"], 3)
        self.assertEqual(values["default_registration_role"], "extended")
        row = fake_system.rows(
            self.db, "SELECT event, username, details FROM audit_log ORDER BY id DESC LIMIT 1")[0]
        self.assertEqual(row[0], "admin_access_settings")
        self.assertEqual(row[1], "dl1abc")
        self.assertIn("registration_enabled", row[2])
        # Antwort liefert den echten Backendzustand
        self.assertFalse(data["settings"]["registration_enabled"])

    def test_post_mit_fehlerhaften_werten_aendert_nichts(self):
        token, _ = self.csrf()
        before = SettingsStore(self.db).values()
        resp = self.client.post("/admin/api/system/settings",
                                json={"settings": {"registration_enabled": False,
                                                   "max_login_failures": 99999}},
                                headers={"X-CSRF-Token": token})
        self.assertEqual(resp.status_code, 400)
        self.assertIn("max_login_failures", resp.get_json()["field_errors"])
        self.assertEqual(SettingsStore(self.db).values(), before,
                         "bei einem Fehler darf kein Teil gespeichert werden")

    def test_post_mit_valider_csrf_und_gueltigem_token_header(self):
        token, _ = self.csrf()
        resp = self.client.post("/admin/api/system/settings",
                                json={"settings": {"guest_profile_switch": True}},
                                headers={"X-CSRF-Token": token})
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(SettingsStore(self.db).values()["guest_profile_switch"])

    def test_unbekannte_und_geschuetzte_schluessel(self):
        token, _ = self.csrf()
        resp = self.client.post("/admin/api/system/settings",
                                json={"settings": {"gibts_nicht": 1}},
                                headers={"X-CSRF-Token": token})
        self.assertEqual(resp.status_code, 400)
        resp = self.client.post("/admin/api/system/settings",
                                json={"settings": {"package_version": "9.9.9"}},
                                headers={"X-CSRF-Token": token})
        self.assertEqual(resp.status_code, 400)

    def test_leere_aenderung(self):
        token, _ = self.csrf()
        resp = self.client.post("/admin/api/system/settings", json={"settings": {}},
                                headers={"X-CSRF-Token": token})
        self.assertEqual(resp.status_code, 400)

    def test_restore_defaults(self):
        token, _ = self.csrf()
        self.client.post("/admin/api/system/settings",
                         json={"settings": {"registration_enabled": False}},
                         headers={"X-CSRF-Token": token})
        resp = self.client.post("/admin/api/system/restore-defaults", json={},
                                headers={"X-CSRF-Token": token})
        self.assertEqual(resp.status_code, 400, "ohne confirm=true darf nichts passieren")
        resp = self.client.post("/admin/api/system/restore-defaults",
                                json={"confirm": True},
                                headers={"X-CSRF-Token": token})
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(SettingsStore(self.db).values()["registration_enabled"])

    def test_schreib_rate_limit(self):
        token, _ = self.csrf()
        codes = []
        for i in range(34):
            resp = self.client.post(
                "/admin/api/system/settings",
                json={"settings": {"registration_limit": 1 + (i % 50)}},
                headers={"X-CSRF-Token": token})
            codes.append(resp.status_code)
        self.assertIn(429, codes)
        self.assertEqual(codes.count(200), 30)

    # Oeffentliche Endpunkte
    def test_oeffentlicher_status_ohne_login(self):
        self.actor["role"] = "guest"
        resp = self.client.get("/api/system/state")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        state = data["state"]
        rules = data["rules"]
        for key in ("registration_enabled", "maintenance_mode", "account_required",
                    "guest_profile_switch", "profile_control_enabled"):
            self.assertIn(key, state)
        for key in ("max_audit_entries", "max_audit_bytes", "settings_fail_open",
                    "login_lock_seconds", "password_min_length"):
            self.assertNotIn(key, state)
        self.assertEqual(len(rules["sessions"]), 5)
        self.assertIn("registration", rules)

    def test_healthz(self):
        resp = self.client.get("/api/system/healthz")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["ok"])
        self.assertEqual(data["version"], "1.2.0")
        self.assertGreater(data["keys"], 20)


# --------------------------------------------------- OpenWebRX-Container-Hook

class OwrxHookTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # owrx-Paket simulieren und die gemeinsame Logik einspielen
        pkg = types.ModuleType("owrx")
        pkg.__path__ = [OWRX]
        sys.modules["owrx"] = pkg
        load_module("owrx.dnx_sys_store",
                    os.path.join(SVC, "dnx_system_control", "settings_store.py"))
        load_module("owrx.dnx_sys_rules",
                    os.path.join(SVC, "dnx_system_control", "access_rules.py"))
        cls.hook = load_module("owrx.dnx_system_verify",
                               os.path.join(OWRX, "dnx_system_verify.py"))

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name
        self.db = os.path.join(self.dir, "accounts.sqlite3")
        fake_system.make_db(self.db)
        migrate_mod.migrate(self.db, quiet=True)
        self.policy = fake_system.write_policy(os.path.join(self.dir, "profile-policy.json"))
        self.hook.DB_CANDIDATES = (self.db,)
        self.hook.POLICY_CANDIDATES = (self.policy,)
        self.hook.get_settings(force=True)
        self.hook.get_policy(force=True)
        self.store = SettingsStore(self.db)

    def tearDown(self):
        self.tmp.cleanup()

    def test_gemeinsame_logik_wird_verwendet(self):
        self.assertTrue(self.hook.HAVE_SHARED_LOGIC,
                        "Container-Hook muss settings_store/access_rules nutzen")

    def test_container_liest_dieselben_einstellungen(self):
        self.store.update({"guest_profile_switch": True}, actor="admin")
        settings = self.hook.get_settings(force=True)
        self.assertTrue(settings["guest_profile_switch"])
        self.assertEqual(self.hook._cache["source"], "access_settings")

    def test_profilpruefung_matrix(self):
        cases = [
            ({"guest_profile_switch": False}, "guest", False, "80m", False),
            ({"guest_profile_switch": True}, "guest", False, "80m", True),
            ({"guest_profile_switch": True}, "guest", False, "KW-Schutz", False),
            ({"account_required": True}, "guest", False, "80m", False),
            ({}, "user", True, "80m", True),
            ({}, "user", True, "KW-Schutz", False),
            ({}, "extended", True, "KW-Schutz", True),
            ({}, "admin", True, "Admin-only", True),
            ({"maintenance_mode": True}, "user", True, "80m", False),
            ({"maintenance_mode": True}, "admin", True, "80m", True),
            ({"profile_control_enabled": False}, "guest", False, "Admin-only", True),
        ]
        for patch, role, auth, profile, allow in cases:
            with self.subTest(patch=patch, role=role, profile=profile):
                if patch:
                    self.store.update(patch, actor="admin")
                d = self.hook.verify_profile(profile, role=role, authenticated=auth,
                                             username=None if not auth else role,
                                             force=True)
                self.assertEqual(d["allow"], allow, d)
                if patch:
                    self.store.update({k: defaults()[k] for k in patch}, actor="admin")
                self.hook.get_settings(force=True)

    def test_fail_open_bei_fehlender_db(self):
        self.hook.DB_CANDIDATES = (os.path.join(self.dir, "weg.sqlite3"),)
        settings = self.hook.get_settings(force=True)
        self.assertEqual(settings, self.hook._FALLBACK_DEFAULTS)
        self.assertEqual(self.hook._cache["source"], "fallback")
        d = self.hook.verify_profile("80m", role="user", authenticated=True, username="do3test")
        self.assertTrue(d["allow"], "bei unlesbarer DB darf niemand gesperrt werden")
        self.assertTrue(d["fail_open"])

    def test_cache_vermeidet_db_zugriffe(self):
        self.hook.get_settings(force=True)
        first = self.hook._cache["ts"]
        self.store.update({"maintenance_mode": True}, actor="admin")
        cached = self.hook.get_settings()          # ohne force -> Cache
        self.assertFalse(cached["maintenance_mode"])
        fresh = self.hook.get_settings(force=True)
        self.assertTrue(fresh["maintenance_mode"])
        self.assertGreater(self.hook._cache["ts"], first)

    def test_audit_entscheidung(self):
        d = self.hook.verify_profile("KW-Schutz", role="user", authenticated=True, force=True)
        self.assertEqual(self.hook.audit_decision(d), "profile_denied")
        d = self.hook.verify_profile("80m", role="user", authenticated=True, force=True)
        self.assertEqual(self.hook.audit_decision(d), "profile_change")
        self.assertIsNone(self.hook.audit_decision(None))

    def test_status_auskunft(self):
        st = self.hook.status()
        self.assertEqual(st["db_path"], self.db)
        self.assertEqual(st["source"], "access_settings")
        self.assertTrue(st["shared_logic"])
        self.assertEqual(st["keys"], len(SPEC))

    # DSP-Schutz
    def test_dnx_properties_werden_gefiltert(self):
        props = {
            "frequency": 3615000,
            "mod": "LSB",
            "dnx_account_token": "signed.token.value",
            "dnx_role": "extended",
            "DNX_STATUS": 1,
            "key": "DNXAUTH:abc.def.ghi",
            "waterfall": True,
        }
        out = self.hook.filter_dnx_properties(props)
        self.assertEqual(sorted(out), ["frequency", "mod", "waterfall"])
        self.assertTrue(self.hook.is_dnx_property("dnx_account_token"))
        self.assertTrue(self.hook.is_dnx_property("key", "DNXAUTH:x"))
        self.assertFalse(self.hook.is_dnx_property("key", "normaler-wert"))
        self.assertFalse(self.hook.is_dnx_property("frequency"))
        self.assertEqual(self.hook.filter_dnx_properties(None), {})
        self.assertEqual(self.hook.filter_dnx_properties({}), {})

    def test_token_aus_key_extrahieren(self):
        self.assertEqual(self.hook.split_auth_key("DNXAUTH:aaa.bbb"), "aaa.bbb")
        self.assertIsNone(self.hook.split_auth_key("irgendwas"))
        self.assertIsNone(self.hook.split_auth_key(None))
        self.assertIsNone(self.hook.split_auth_key("DNXAUTH:"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
