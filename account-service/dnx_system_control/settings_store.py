# -*- coding: utf-8 -*-
"""access_settings – globaler Einstellungsstore fuer die DNX Systemsteuerung.

Umsetzt die Regeln aus der Uebergabe (Kapitel 12):
  * Einstellungen atomar speichern            -> BEGIN IMMEDIATE / COMMIT / ROLLBACK
  * sichere Defaults bei fehlendem Schluessel -> SPEC-Defaults, niemals KeyError
  * Aenderungen auditieren                    -> audit_log (schematolerant)
  * profile_control_enabled = false darf NICHT versehentlich alle sperren
                                              -> fail-open in access_rules
  * Adminseite nur Rolle admin                -> admin_api.py
  * Wartungsmodus mit Admin-Bypass            -> maintenance_admin_bypass

Bestandsdaten:
  Diese Datei legt ausschliesslich die Tabelle `access_settings` an und schreibt
  dort. `users`, `sessions`, `audit_log`, `audit_settings` und `profile-policy.json`
  werden NIE veraendert (Audit-Log ausgenommen: dort werden nur Zeilen
  HINZUGEFUEGT, niemals geloescht, ausser audit_auto_purge ist aktiv).

Read-only-Betrieb (OpenWebRX-Container):
  SettingsStore(db, readonly=True) oeffnet die DB als URI mit mode=ro. Bei jedem
  Fehler werden Defaults geliefert ("fail-open"), damit eine unlesbare DB niemanden
  aussperrt.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from typing import Any, Dict, Iterable, List, Optional, Tuple

# --------------------------------------------------------------------------
# Konstanten
# --------------------------------------------------------------------------

PACKAGE_VERSION = "1.2.0"
SCHEMA_VERSION = 1
TABLE = "access_settings"

# Host (Account-Dienst, Port 8096)
DEFAULT_DB = "/opt/owrx-docker/var/dnx-access-control/accounts.sqlite3"
# Container owrx-8013: /opt/owrx-docker/var -> /var/lib/openwebrx
CONTAINER_DB = "/var/lib/openwebrx/dnx-access-control/accounts.sqlite3"
ENV_DB = "DNX_ACCOUNTS_DB"

BOOL, INT, STR, ENUM = "bool", "int", "str", "enum"

GROUPS: List[Tuple[str, str]] = [
    ("core", "Kernschalter"),
    ("roles", "Rollen & Registrierung"),
    ("sessions", "Sitzungsdauern"),
    ("limits", "Sicherheitslimits"),
    ("activity", "Aktivitaetslog & Audit"),
    ("maintenance", "Wartungsmodus"),
    ("advanced", "Erweitert / Technisch (nur Admin)"),
]
GROUP_LABELS: Dict[str, str] = dict(GROUPS)

# Audit-Ereignisname fuer Einstellungs-aenderungen
AUDIT_EVENT = "admin_access_settings"

_TRUE = {"1", "true", "yes", "y", "on", "ja", "an"}
_FALSE = {"0", "false", "no", "n", "off", "nein", "aus"}


def _spec(
    kind: str,
    default: Any,
    group: str,
    label: str,
    hint: str = "",
    public: bool = False,
    admin_only: bool = False,
    choices: Optional[List[str]] = None,
    minimum: Optional[int] = None,
    maximum: Optional[int] = None,
    editable: bool = True,
    unit: str = "",
    max_length: int = 500,
) -> Dict[str, Any]:
    return {
        "key": None,  # wird unten gesetzt
        "type": kind,
        "default": default,
        "group": group,
        "label": label,
        "hint": hint,
        "public": public,       # darf an /api/system/state (Frontend) raus
        "admin_only": admin_only,  # Zusatzbereich, nur fuer Rolle admin sichtbar
        "choices": choices or [],
        "min": minimum,
        "max": maximum,
        "editable": editable,
        "unit": unit,
        "max_length": max_length,
    }


def _b(default, group, label, hint="", public=False, admin_only=False):
    return _spec(BOOL, default, group, label, hint, public, admin_only)


def _i(default, group, label, minimum, maximum, hint="", unit="", public=False,
       admin_only=False, editable=True):
    return _spec(INT, default, group, label, hint, public, admin_only,
                 minimum=minimum, maximum=maximum, unit=unit, editable=editable)


# --------------------------------------------------------------------------
# Spezifikation aller Schluessel (Default = HEUTIGES Verhalten, damit die
# Migration nichts an der laufenden Anlage aendert)
# --------------------------------------------------------------------------

SPEC: Dict[str, Dict[str, Any]] = {
    # ---------------- Kernschalter (aus der Anforderung) ----------------
    "registration_enabled": _b(
        True, "core", "Registrierung",
        "Neue Konten koennen sich selbst registrieren.", public=True),
    "new_accounts_active": _b(
        True, "core", "Neue Konten sofort aktiv",
        "AUS = neues Konto wird mit status 'blocked' angelegt und muss von einem Admin auf 'active' gesetzt werden.",
        public=True),
    "profile_control_enabled": _b(
        True, "core", "Profilsteuerung",
        "AUS = Profilpruefung deaktiviert. WICHTIG: faellt offen aus (fail-open), "
        "es wird dadurch niemand gesperrt.", public=True),
    "account_required": _b(
        False, "core", "Account-Zwang",
        "AN = Hoeren nur mit DNX-Konto, reine Gaeste werden abgewiesen.", public=True),
    "guest_profile_switch": _b(
        False, "core", "Gast darf Profile wechseln",
        "Nur wirksam, wenn Account-Zwang AUS ist.", public=True),
    "maintenance_mode": _b(
        False, "core", "Wartungsmodus",
        "AN = ausser Betrieb: Startseite und alle Seiten liefern 503 mit der Wartungsseite. Nur Admins kommen durch (Bypass siehe unten). Anmeldung bleibt offen.", public=True),

    # ---------------- Rollen ----------------
    "role_user_enabled": _b(
        True, "roles", "User-Rolle erlaubt",
        "AUS = die Rolle 'user' wird nicht mehr vergeben/akzeptiert.", public=True),
    "role_extended_enabled": _b(
        True, "roles", "Extended-Rolle erlaubt",
        "AUS = 'extended' verliert serverseitig die geschuetzten Profile.", public=True),
    "default_registration_role": _spec(
        ENUM, "user", "roles", "Standardrolle neuer Konten",
        "Rolle, die ein frisch registriertes Konto bekommt.",
        public=True, choices=["user", "extended"]),

    # ---------------- Sitzungsdauern ----------------
    "allowed_session_browser": _b(True, "sessions", "Browser (Sitzungsende)", public=True),
    "allowed_session_day": _b(True, "sessions", "1 Tag", public=True),
    "allowed_session_week": _b(True, "sessions", "7 Tage", public=True),
    "allowed_session_month": _b(True, "sessions", "30 Tage", public=True),
    "allowed_session_forever": _b(
        True, "sessions", "Unbegrenzt",
        "Sicherheitshinweis: unbegrenzte Sitzungen bleiben bis zum Widerruf gueltig.",
        public=True),

    # ---------------- Sicherheitslimits ----------------
    "max_login_failures": _i(
        5, "limits", "Maximale Login-Fehlversuche", 0, 100,
        "0 = Sperre deaktiviert.", unit="Versuche"),
    "login_lock_seconds": _i(
        900, "limits", "Sperrzeit nach Fehlversuchen", 0, 86400,
        "0 = keine Sperre.", unit="Sekunden"),
    "registration_limit": _i(
        5, "limits", "Registrierungs-Rate-Limit", 0, 1000,
        "Maximale Registrierungen pro Zeitfenster (IP + global). 0 = aus.", unit="Stueck"),
    "registration_window_seconds": _i(
        3600, "limits", "Rate-Limit-Zeitfenster", 60, 86400,
        unit="Sekunden"),
    "password_min_length": _i(
        8, "limits", "Passwort-Mindestlaenge", 6, 128,
        "Aktuell 8 Zeichen.", unit="Zeichen"),
    "captcha_enabled": _b(
        True, "limits", "Rechenaufgabe gegen Bots",
        "Auch bei aktiver Registrierung empfohlen."),

    # ---------------- Aktivitaetslog / Audit ----------------
    "public_activity_enabled": _b(
        True, "activity", "Oeffentliches 24-Stunden-Aktivitaetslog",
        "AUS = /activity zeigt keine Daten mehr. Admin-Logbuch bleibt erhalten.",
        public=True),
    "public_activity_hours": _i(
        24, "activity", "Zeitraum des oeffentlichen Logs", 1, 168,
        "Nie mit IP oder User-Agent.", unit="Stunden"),
    "audit_enabled": _b(
        True, "activity", "Vollstaendiges Audit-Logging",
        "AUS = keine neuen Ereignis-Zeilen (Login, Profilwechsel, Receiver-Join usw.)."),
    "audit_settings_changes": _b(
        True, "activity", "Aenderungen der Systemsteuerung auditieren",
        "Unabhaengig vom allgemeinen Audit-Logging: wer welchen Schalter wann "
        "umgelegt hat, bleibt nachvollziehbar.", admin_only=True),
    "max_audit_entries": _i(
        250000, "activity", "Technische Grenze: Audit-Zeilen", 1000, 10000000,
        unit="Zeilen"),
    "max_audit_bytes": _i(
        1073741824, "activity", "Technische Grenze: Datenbankgroesse", 1048576, 107374182400,
        unit="Bytes"),
    "audit_auto_purge": _b(
        False, "activity", "Automatische Loeschung",
        "Derzeit deaktiviert. AN = alte Zeilen werden bei Ueberschreiten der "
        "Grenzen entfernt.", admin_only=True),
    "audit_retention_days": _i(
        0, "activity", "Aufbewahrungsdauer Audit", 0, 3650,
        "0 = unbegrenzt. Nur wirksam bei aktiver automatischer Loeschung.",
        unit="Tage", admin_only=True),
    "audit_timezone": _spec(
        STR, "Europe/Berlin", "activity", "Zeitzone der Anzeige",
        "DB speichert weiterhin Unix-Zeitstempel.", admin_only=True),

    # ---------------- Wartungsmodus ----------------
    "maintenance_admin_bypass": _b(
        True, "maintenance", "Admin-Bypass im Wartungsmodus",
        "Pflicht gemaess Uebergabe: Admin kommt immer rein."),
    "maintenance_message": _spec(
        STR,
        "Wartungsarbeiten: Der Empfaenger ist voruebergehend ausser Betrieb. Bitte spaeter erneut versuchen.",
        "maintenance", "Meldung im Wartungsmodus",
        "Text auf der Wartungsseite (503) fuer Gast/User/Extended.", public=True),
    "maintenance_lock_existing_sessions": _b(
        False, "maintenance", "Bestehende Sitzungen im Wartungsmodus sperren",
        "AUS (empfohlen) = Konten und Sitzungen bleiben erhalten, nur der Zugriff "
        "auf Profile wird blockiert.", admin_only=True),

    # ---------------- Erweitert / Technisch (nur Admin) ----------------
    "downgrade_disabled_roles": _b(
        True, "advanced", "Abgeschaltete Rollen wirksam herabstufen",
        "AN = ein 'extended'-User zaehlt bei abgeschalteter Extended-Rolle als 'user'. "
        "Die Rolle in der Datenbank wird dabei NICHT geaendert.", admin_only=True),
    "revoke_sessions_on_change": _b(
        False, "advanced", "Sitzungen bei Regel-aenderung widerrufen",
        "AUS (empfohlen) = Bestandsuser bleiben angemeldet.", admin_only=True),
    "settings_cache_seconds": _i(
        3, "advanced", "Cache der Container-Profilpruefung", 0, 300,
        "0 = jede Pruefung liest die DB (hoehere Last).", unit="Sekunden", admin_only=True),
    "settings_fail_open": _b(
        True, "advanced", "Fail-open bei unlesbarer Einstellungs-DB",
        "AN = bei Stoerung gelten die Defaults (niemand wird ausgesperrt). "
        "AUS = Profilwechsel werden verweigert.", admin_only=True),
    "expose_state_to_receiver": _b(
        True, "advanced", "Status an Receiver-Frontend liefern",
        "AUS = das Frontend zeigt nur lokale Defaults (Status-Anzeige wird grau).",
        admin_only=True),
    "strict_unknown_keys": _b(
        True, "advanced", "Unbekannte Schluessel beim Speichern ablehnen",
        "AN = API-Fehler 400 statt stiller Ignoranz.", admin_only=True),
    "schema_version": _i(
        SCHEMA_VERSION, "advanced", "Schema-Version access_settings", 1, 99,
        "Nur Anzeige, nicht editierbar.", editable=False, admin_only=True),
    "package_version": _spec(
        STR, PACKAGE_VERSION, "advanced", "Paketversion",
        "DNX Receiver Account Control", editable=False, admin_only=True),
}

for _k, _v in SPEC.items():
    _v["key"] = _k

PUBLIC_KEYS = [k for k, v in SPEC.items() if v["public"]]
EDITABLE_KEYS = [k for k, v in SPEC.items() if v["editable"]]


class SettingsValidationError(ValueError):
    """Wird geworfen, wenn eine Aenderung nicht gespeichert werden darf."""

    def __init__(self, errors: Dict[str, str]):
        self.errors = errors
        super().__init__("Ungueltige Einstellungen: " + json.dumps(errors, ensure_ascii=False))


class SettingsUnavailable(RuntimeError):
    """DB nicht lesbar/schreibbar."""


# --------------------------------------------------------------------------
# Hilfsfunktionen
# --------------------------------------------------------------------------

def resolve_db_path(explicit: Optional[str] = None) -> str:
    """Liefert den plausibelsten Pfad zu accounts.sqlite3."""
    for cand in (explicit, os.environ.get(ENV_DB), DEFAULT_DB, CONTAINER_DB):
        if cand and os.path.exists(cand):
            return cand
    return explicit or os.environ.get(ENV_DB) or DEFAULT_DB


def coerce(key: str, raw: Any) -> Any:
    """Wandelt einen Eingabewert in den kanonischen Typ. Wirft ValueError."""
    if key not in SPEC:
        raise ValueError("Unbekannter Schluessel: %s" % key)
    spec = SPEC[key]
    kind = spec["type"]

    if kind == BOOL:
        if isinstance(raw, bool):
            return raw
        if isinstance(raw, (int, float)):
            return bool(raw)
        if isinstance(raw, str):
            low = raw.strip().lower()
            if low in _TRUE:
                return True
            if low in _FALSE:
                return False
        raise ValueError("erwartet AN/AUS (bool)")

    if kind == INT:
        try:
            if isinstance(raw, bool):
                val = int(raw)
            elif isinstance(raw, int):
                val = raw
            elif isinstance(raw, float):
                if raw != int(raw):
                    raise ValueError()
                val = int(raw)
            else:
                val = int(str(raw).strip())
        except Exception:
            raise ValueError("erwartet ganze Zahl")
        lo, hi = spec["min"], spec["max"]
        if lo is not None and val < lo:
            raise ValueError("zu klein (Minimum %s)" % lo)
        if hi is not None and val > hi:
            raise ValueError("zu gross (Maximum %s)" % hi)
        return val

    if kind == ENUM:
        val = str(raw).strip().lower()
        if val not in spec["choices"]:
            raise ValueError("erlaubt: %s" % ", ".join(spec["choices"]))
        return val

    # STR
    val = str(raw).strip()
    if len(val) > spec["max_length"]:
        raise ValueError("zu lang (max. %d Zeichen)" % spec["max_length"])
    return val


def to_storage(key: str, value: Any) -> str:
    spec = SPEC[key]
    if spec["type"] == BOOL:
        return "1" if value else "0"
    return str(value)


def from_storage(key: str, stored: Optional[str]) -> Tuple[Any, Optional[str]]:
    """(wert, warnung). Bei beschaedigtem Wert: Default + Warnung."""
    spec = SPEC[key]
    if stored is None:
        return spec["default"], None
    try:
        return coerce(key, stored), None
    except ValueError:
        return spec["default"], "Wert von '%s' war ungueltig (%r) -> Default %r" % (
            key, stored, spec["default"])


def defaults() -> Dict[str, Any]:
    return {k: v["default"] for k, v in SPEC.items()}


def public_defaults() -> Dict[str, Any]:
    return {k: SPEC[k]["default"] for k in PUBLIC_KEYS}


def spec_meta() -> Dict[str, Any]:
    """Metadaten fuer die Admin-UI (Reihenfolge, Gruppen, Grenzen)."""
    return {
        "version": PACKAGE_VERSION,
        "schema_version": SCHEMA_VERSION,
        "table": TABLE,
        "groups": [{"id": gid, "label": label} for gid, label in GROUPS],
        "fields": [
            {k: v for k, v in spec.items() if k != "key"} | {"key": key}
            for key, spec in SPEC.items()
        ],
    }


# --------------------------------------------------------------------------
# Audit (schematolerant gegenueber der vorhandenen audit_log-Tabelle)
# --------------------------------------------------------------------------

_AUDIT_ALIASES = {
    "ts": ["ts", "timestamp", "created_at", "time", "event_time", "date"],
    "event": ["event", "event_type", "type", "action", "kind", "category"],
    "user": ["username", "account", "account_name", "user", "user_name", "chat_name", "name"],
    "role": ["role", "user_role", "account_role"],
    "ip": ["ip", "ip_address", "remote_addr", "client_ip", "addr"],
    "ua": ["user_agent", "ua", "agent", "http_user_agent"],
    "details": ["details", "detail", "data", "json", "extra", "message", "info", "payload", "meta"],
}


def _audit_columns(conn: sqlite3.Connection) -> Optional[Dict[str, str]]:
    try:
        rows = conn.execute("PRAGMA table_info(audit_log)").fetchall()
    except sqlite3.Error:
        return None
    if not rows:
        return None
    cols = [r[1] for r in rows]
    low = {c.lower(): c for c in cols}
    mapping: Dict[str, str] = {}
    for slot, aliases in _AUDIT_ALIASES.items():
        for alias in aliases:
            if alias in low:
                mapping[slot] = low[alias]
                break
    if "event" not in mapping or "ts" not in mapping:
        return None
    return mapping


def write_audit(
    conn: sqlite3.Connection,
    event: str,
    *,
    username: Optional[str] = None,
    role: Optional[str] = None,
    ip: Optional[str] = None,
    user_agent: Optional[str] = None,
    details: Any = None,
    ts: Optional[int] = None,
) -> bool:
    """Schreibt eine Audit-Zeile in die vorhandene audit_log-Tabelle.

    Gibt True zurueck, wenn geschrieben wurde. Wirft keine Exception: ein
    Audit-Fehler darf niemals eine Admin-Aktion oder einen Login blockieren.
    """
    mapping = _audit_columns(conn)
    if not mapping:
        return False
    try:
        cols: List[str] = []
        vals: List[Any] = []

        def add(slot: str, value: Any) -> None:
            col = mapping.get(slot)
            if col is not None and value is not None:
                cols.append(col)
                vals.append(value)

        add("ts", int(ts if ts is not None else time.time()))
        add("event", event)
        add("user", username)
        add("role", role)
        add("ip", ip)
        add("ua", user_agent)
        if details is not None:
            add("details", details if isinstance(details, str)
                else json.dumps(details, ensure_ascii=False, separators=(",", ":"), default=str))
        conn.execute(
            "INSERT INTO audit_log (%s) VALUES (%s)" % (", ".join(cols), ", ".join("?" * len(cols))),
            vals,
        )
        return True
    except sqlite3.Error:
        return False


def purge_audit_if_needed(conn: sqlite3.Connection, settings: Dict[str, Any]) -> Dict[str, Any]:
    """Nur aktiv, wenn audit_auto_purge = AN. Loescht aelteste Zeilen."""
    result = {"purged": 0, "reason": None}
    if not settings.get("audit_auto_purge"):
        return result
    mapping = _audit_columns(conn)
    if not mapping:
        return result
    ts_col = mapping["ts"]
    try:
        max_entries = int(settings.get("max_audit_entries") or 250000)
        count = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
        if count > max_entries:
            cur = conn.execute(
                "DELETE FROM audit_log WHERE rowid NOT IN "
                "(SELECT rowid FROM audit_log ORDER BY %s DESC, rowid DESC LIMIT ?)" % ts_col,
                (max_entries,),
            )
            result["purged"] += cur.rowcount or 0
            result["reason"] = "max_audit_entries"
        retention = int(settings.get("audit_retention_days") or 0)
        if retention > 0:
            cutoff = int(time.time()) - retention * 86400
            cur = conn.execute("DELETE FROM audit_log WHERE %s < ?" % ts_col, (cutoff,))
            result["purged"] += cur.rowcount or 0
            result["reason"] = (result["reason"] or "") + "+retention"
        return result
    except sqlite3.Error:
        return result


# --------------------------------------------------------------------------
# Store
# --------------------------------------------------------------------------

class SettingsStore:
    """Thread-sicherer Zugriff auf access_settings."""

    def __init__(self, db_path: Optional[str] = None, *, readonly: bool = False,
                 actor_default: str = "system", timeout: float = 15.0):
        self.db_path = resolve_db_path(db_path)
        self.readonly = readonly
        self.actor_default = actor_default
        self.timeout = timeout
        self._lock = threading.RLock()
        self._cache: Optional[Dict[str, Any]] = None
        self._cache_ts = 0.0
        self._cache_warnings: List[str] = []

    # ---------------- Verbindung ----------------

    def _connect(self) -> sqlite3.Connection:
        if self.readonly:
            uri = "file:%s?mode=ro" % self.db_path
            conn = sqlite3.connect(uri, uri=True, timeout=self.timeout,
                                   isolation_level=None, check_same_thread=False)
        else:
            conn = sqlite3.connect(self.db_path, timeout=self.timeout,
                                   isolation_level=None, check_same_thread=False)
        conn.execute("PRAGMA busy_timeout = %d" % int(self.timeout * 1000))
        if not self.readonly:
            try:
                conn.execute("PRAGMA journal_mode = WAL")
                conn.execute("PRAGMA synchronous = NORMAL")
                conn.execute("PRAGMA foreign_keys = ON")
            except sqlite3.Error:
                pass
        return conn

    # ---------------- Schema ----------------

    DDL = """
    CREATE TABLE IF NOT EXISTS access_settings (
        key        TEXT PRIMARY KEY,
        value      TEXT NOT NULL,
        type       TEXT NOT NULL DEFAULT 'str',
        updated_at INTEGER NOT NULL DEFAULT 0,
        updated_by TEXT NOT NULL DEFAULT ''
    )
    """

    def ensure_schema(self, conn: Optional[sqlite3.Connection] = None) -> None:
        own = conn is None
        conn = conn or self._connect()
        try:
            conn.execute(self.DDL)
            conn.execute(
                "CREATE INDEX IF NOT EXISTS ix_access_settings_updated ON access_settings(updated_at)")
        finally:
            if own:
                conn.close()

    # ---------------- Lesen ----------------

    def _read_raw(self, conn: sqlite3.Connection) -> Dict[str, str]:
        try:
            rows = conn.execute("SELECT key, value FROM %s" % TABLE).fetchall()
        except sqlite3.Error:
            return {}
        return {str(r[0]): r[1] for r in rows}

    def load(self, *, use_cache: bool = False, cache_seconds: Optional[int] = None
             ) -> Tuple[Dict[str, Any], List[str]]:
        """Liefert (einstellungen, warnungen). Faellt bei Fehlern auf Defaults."""
        ttl = self._cache_seconds_hint() if cache_seconds is None else cache_seconds
        if use_cache and self._cache is not None and (time.time() - self._cache_ts) < ttl:
            return dict(self._cache), list(self._cache_warnings)

        warnings: List[str] = []
        values = defaults()
        try:
            conn = self._connect()
            try:
                raw = self._read_raw(conn)
            finally:
                conn.close()
            if raw:
                for key, stored in raw.items():
                    if key not in SPEC:
                        warnings.append("Unbekannter Schluessel in DB ignoriert: %s" % key)
                        continue
                    val, warn = from_storage(key, stored)
                    values[key] = val
                    if warn:
                        warnings.append(warn)
            else:
                warnings.append("access_settings leer oder nicht vorhanden -> Defaults aktiv")
        except Exception as exc:  # fail-open
            warnings.append("Einstellungen nicht lesbar (%s) -> Defaults aktiv" % exc)

        self._cache = values
        self._cache_ts = time.time()
        self._cache_warnings = warnings
        return dict(values), warnings

    def _cache_seconds_hint(self) -> int:
        try:
            return int((self._cache or {}).get("settings_cache_seconds", 3))
        except Exception:
            return 3

    def values(self, **kw) -> Dict[str, Any]:
        return self.load(**kw)[0]

    def get(self, key: str, **kw) -> Any:
        if key not in SPEC:
            raise KeyError(key)
        return self.load(**kw)[0].get(key, SPEC[key]["default"])

    def warnings(self) -> List[str]:
        self.load()
        return list(self._cache_warnings)

    def meta(self) -> Dict[str, Any]:
        return spec_meta()

    def public_state(self, settings: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Alles, was das Receiver-Frontend sehen darf. Keine IPs, keine Secrets,
        keine internen Grenzen."""
        s = settings if settings is not None else self.values(use_cache=True)
        state = {k: s.get(k, SPEC[k]["default"]) for k in PUBLIC_KEYS}
        state["_meta"] = {
            "version": PACKAGE_VERSION,
            "expose_state_to_receiver": bool(s.get("expose_state_to_receiver", True)),
            "server_time": int(time.time()),
            "source": "access_settings",
        }
        if not s.get("expose_state_to_receiver", True):
            # Frontend soll sehen, dass der Status absichtlich nicht geliefert wird
            state = {k: SPEC[k]["default"] for k in PUBLIC_KEYS}
            state["_meta"] = {"version": PACKAGE_VERSION,
                              "expose_state_to_receiver": False,
                              "server_time": int(time.time()),
                              "source": "defaults"}
        return state

    # ---------------- Validieren ----------------

    def validate(self, incoming: Dict[str, Any], *, strict: Optional[bool] = None
                 ) -> Tuple[Dict[str, Any], Dict[str, str]]:
        current, _ = self.load()
        strict = current.get("strict_unknown_keys", True) if strict is None else bool(strict)
        clean: Dict[str, Any] = {}
        errors: Dict[str, str] = {}
        if not isinstance(incoming, dict):
            return {}, {"_": "Erwartet ein JSON-Objekt"}

        for key, raw in incoming.items():
            if key not in SPEC:
                if strict:
                    errors[key] = "Unbekannter Schluessel"
                continue
            if not SPEC[key]["editable"]:
                errors[key] = "Schluessel ist schreibgeschuetzt"
                continue
            try:
                clean[key] = coerce(key, raw)
            except ValueError as exc:
                errors[key] = str(exc)

        # Inhaltliche Plausibilitaet (Kombinationsregeln)
        merged = dict(current)
        merged.update(clean)
        if merged.get("registration_limit", 0) and \
                merged.get("registration_window_seconds", 0) <= 0:
            errors["registration_window_seconds"] = "Zeitfenster muss > 0 sein, wenn ein Limit gilt"
        if merged.get("max_login_failures", 0) and merged.get("login_lock_seconds", 0) <= 0:
            errors["login_lock_seconds"] = "Sperrzeit muss > 0 sein, wenn Fehlversuche begrenzt werden"
        if not any(merged.get("allowed_session_%s" % k) for k in
                   ("browser", "day", "week", "month", "forever")):
            errors["allowed_session_browser"] = "Mindestens eine Sitzungsdauer muss erlaubt bleiben"
        if merged.get("default_registration_role") == "extended" and \
                not merged.get("role_extended_enabled", True):
            errors["default_registration_role"] = (
                "Standardrolle 'extended' ist nicht moeglich, solange die Extended-Rolle AUS ist")
        return clean, errors

    # ---------------- Schreiben (atomar) ----------------

    def update(self, changes: Dict[str, Any], *, actor: Optional[str] = None,
               role: Optional[str] = None, ip: Optional[str] = None,
               user_agent: Optional[str] = None, audit: bool = True,
               strict: Optional[bool] = None) -> Dict[str, Any]:
        """Speichert atomar. Wirft SettingsValidationError bei ungueltigen Werten.

        Gibt {'changed': {...}, 'settings': {...}, 'audit_written': bool} zurueck.
        """
        if self.readonly:
            raise SettingsUnavailable("Store ist read-only geoeffnet")
        actor = actor or self.actor_default
        clean, errors = self.validate(changes, strict=strict)
        if errors:
            raise SettingsValidationError(errors)
        if not clean:
            return {"changed": {}, "settings": self.values(), "audit_written": False}

        now = int(time.time())
        audit_written = False
        with self._lock:
            conn = self._connect()
            try:
                self.ensure_schema(conn)
                before, _ = self.load()
                diff: Dict[str, Dict[str, Any]] = {}
                for key, val in clean.items():
                    old = before.get(key, SPEC[key]["default"])
                    if old != val:
                        diff[key] = {
                            "label": SPEC[key]["label"],
                            "old": old,
                            "new": val,
                        }

                merged = dict(before)
                merged.update(clean)
                # Einstellungs-aenderungen werden ueber 'audit_settings_changes'
                # gesteuert und sind UNABHAENGIG von 'audit_enabled': ein Admin
                # soll immer nachvollziehen koennen, wer welchen Schalter bewegt hat.
                should_audit = bool(audit) and bool(diff) and \
                    bool(merged.get("audit_settings_changes", True))

                conn.execute("BEGIN IMMEDIATE")
                try:
                    for key, val in clean.items():
                        conn.execute(
                            "INSERT INTO %s (key, value, type, updated_at, updated_by) "
                            "VALUES (?, ?, ?, ?, ?) "
                            "ON CONFLICT(key) DO UPDATE SET value=excluded.value, "
                            "type=excluded.type, updated_at=excluded.updated_at, "
                            "updated_by=excluded.updated_by" % TABLE,
                            (key, to_storage(key, val), SPEC[key]["type"], now, str(actor)),
                        )
                    if should_audit:
                        audit_written = write_audit(
                            conn, AUDIT_EVENT, username=actor, role=role, ip=ip,
                            user_agent=user_agent,
                            details={"changed": diff, "count": len(diff),
                                     "version": PACKAGE_VERSION},
                            ts=now,
                        )
                    if merged.get("audit_auto_purge"):
                        purge_audit_if_needed(conn, merged)
                    conn.execute("COMMIT")
                except Exception:
                    try:
                        conn.execute("ROLLBACK")
                    except sqlite3.Error:
                        pass
                    raise
            finally:
                conn.close()
            self._cache = None  # Cache invalidieren

        after, warns = self.load()
        return {"changed": diff, "settings": after, "warnings": warns,
                "audit_written": audit_written, "updated_at": now}

    def reset_defaults(self, keys: Optional[Iterable[str]] = None, **kw) -> Dict[str, Any]:
        """Setzt die genannten (oder alle editierbaren) Schluessel auf Defaults."""
        keys = list(keys) if keys else EDITABLE_KEYS
        payload = {k: SPEC[k]["default"] for k in keys if k in SPEC and SPEC[k]["editable"]}
        return self.update(payload, **kw)

    def seed_defaults(self, *, actor: str = "migration", overwrite: bool = False,
                      conn: Optional[sqlite3.Connection] = None) -> Dict[str, Any]:
        """Legt fehlende Schluessel mit Defaults an (idempotent).

        Wird von migrate_add_access_settings.py genutzt. Bestehende Werte bleiben
        unberuehrt, solange overwrite=False.
        """
        own = conn is None
        conn = conn or self._connect()
        created, kept = [], []
        try:
            self.ensure_schema(conn)
            existing = self._read_raw(conn)
            seeded = dict(self._seed_from_audit_settings(conn))
            now = int(time.time())
            own_tx = own
            if own_tx:
                conn.execute("BEGIN IMMEDIATE")
            try:
                for key, spec in SPEC.items():
                    if not spec["editable"] and key != "schema_version":
                        value = spec["default"]
                    else:
                        value = spec["default"]
                    if key in existing and not overwrite:
                        kept.append(key)
                        continue
                    if key in seeded:
                        value = seeded[key]
                    conn.execute(
                        "INSERT INTO %s (key, value, type, updated_at, updated_by) "
                        "VALUES (?, ?, ?, ?, ?) "
                        "ON CONFLICT(key) DO UPDATE SET value=excluded.value, "
                        "type=excluded.type, updated_at=excluded.updated_at, "
                        "updated_by=excluded.updated_by" % TABLE,
                        (key, to_storage(key, value), spec["type"], now, actor),
                    )
                    created.append(key)
                if own_tx:
                    conn.execute("COMMIT")
            except Exception:
                if own_tx:
                    try:
                        conn.execute("ROLLBACK")
                    except sqlite3.Error:
                        pass
                raise
        finally:
            if own:
                conn.close()
        self._cache = None
        return {"created": created, "kept": kept, "table": TABLE}

    @staticmethod
    def _seed_from_audit_settings(conn: sqlite3.Connection) -> Dict[str, Any]:
        """Uebernimmt max_entries / max_database_bytes aus der vorhandenen
        audit_settings-Tabelle, damit beide Stellen dieselben Grenzen zeigen."""
        out: Dict[str, Any] = {}
        try:
            rows = conn.execute("PRAGMA table_info(audit_settings)").fetchall()
            if not rows:
                return out
            cols = [r[1] for r in rows]
            if {"key", "value"}.issubset({c.lower() for c in cols}):
                data = {str(r[0]): r[1] for r in
                        conn.execute("SELECT key, value FROM audit_settings").fetchall()}
            else:
                data = {}
                single = conn.execute("SELECT * FROM audit_settings LIMIT 1").fetchone()
                if single:
                    data = {c.lower(): v for c, v in zip(cols, single)}
            mapping = {
                "max_entries": "max_audit_entries",
                "max_database_bytes": "max_audit_bytes",
                "max_audit_entries": "max_audit_entries",
                "max_audit_bytes": "max_audit_bytes",
            }
            for src, dst in mapping.items():
                if src in data and data[src] is not None:
                    try:
                        out[dst] = coerce(dst, data[src])
                    except ValueError:
                        pass
        except sqlite3.Error:
            return out
        return out

    # ---------------- Bestandsdaten-Analyse (nur lesend) ----------------

    def impact_preview(self) -> Dict[str, Any]:
        """Zeigt dem Admin, was die aktuellen Schalter fuer BESTANDSUSER bedeuten.

        Liest ausschliesslich. Aendert niemals Rollen oder Konten.
        """
        settings, _ = self.load()
        info: Dict[str, Any] = {
            "settings": settings,
            "user_tables": [],
            "total_users": None,
            "by_role": {},
            "downgraded": [],
            "locked_by_maintenance": bool(settings.get("maintenance_mode"))
            and not bool(settings.get("maintenance_admin_bypass", True)),
            "session_options": [k for k in ("browser", "day", "week", "month", "forever")
                                if settings.get("allowed_session_%s" % k)],
            "note": "Bestandskonten werden von der Systemsteuerung nicht veraendert.",
        }
        try:
            conn = self._connect()
        except Exception as exc:
            info["error"] = str(exc)
            return info
        try:
            tables = [r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
            info["tables"] = sorted(tables)
            for cand in ("users", "accounts", "dnx_users", "user"):
                if cand in tables:
                    try:
                        cols = [r[1].lower() for r in
                                conn.execute("PRAGMA table_info(%s)" % cand).fetchall()]
                        total = conn.execute("SELECT COUNT(*) FROM %s" % cand).fetchone()[0]
                        info["user_tables"].append(cand)
                        info["total_users"] = total if info["total_users"] is None \
                            else info["total_users"] + total
                        role_col = next((c for c in ("role", "user_role", "account_role")
                                         if c in cols), None)
                        if role_col:
                            for role, count in conn.execute(
                                    "SELECT %s, COUNT(*) FROM %s GROUP BY %s"
                                    % (role_col, cand, role_col)).fetchall():
                                info["by_role"][str(role)] = count
                        active_col = next((c for c in ("active", "is_active", "enabled", "status")
                                           if c in cols), None)
                        if active_col:
                            info["active_column"] = active_col
                    except sqlite3.Error:
                        continue
            # Wer waere von einer abgeschalteten Rolle betroffen?
            for role, toggle in (("extended", "role_extended_enabled"),
                                 ("user", "role_user_enabled")):
                if not settings.get(toggle, True) and settings.get("downgrade_disabled_roles", True):
                    n = info["by_role"].get(role, 0)
                    if n:
                        info["downgraded"].append({
                            "role": role,
                            "count": n,
                            "effective": "user" if role == "extended" else "guest",
                            "note": "Rolle bleibt in der DB gespeichert, Zugriff wird "
                                    "nur fuer die Dauer des Schalters herabgestuft.",
                        })
        finally:
            conn.close()
        return info


__all__ = [
    "PACKAGE_VERSION", "SCHEMA_VERSION", "TABLE", "DEFAULT_DB", "CONTAINER_DB",
    "SPEC", "GROUPS", "GROUP_LABELS", "PUBLIC_KEYS", "EDITABLE_KEYS",
    "BOOL", "INT", "STR", "ENUM", "AUDIT_EVENT",
    "SettingsStore", "SettingsValidationError", "SettingsUnavailable",
    "resolve_db_path", "coerce", "to_storage", "from_storage", "defaults",
    "public_defaults", "spec_meta", "write_audit", "purge_audit_if_needed",
]
