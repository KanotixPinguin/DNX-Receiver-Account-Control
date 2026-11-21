# -*- coding: utf-8 -*-
"""access_rules – DIE gemeinsame Entscheidungslogik der Systemsteuerung.

Wird an vier Stellen benutzt, damit die Schalter ueberall gleich wirken
(Uebergabe Kapitel 1):
    1. Account-Webdienst (app.py, Port 8096)
    2. Receiver-Frontend (dnx_access.js / dnx_system_state.js) via /api/system/state
    3. serverseitige OpenWebRX-Profilpruefung (owrx/dnx_access_verify.py)
    4. Audit-/Aktivitaetslog (welches Ereignis geschrieben wird)

Reine Funktionen: kein Flask, keine DB, nur ein Einstellungs-Dict. Dadurch ist
das Verhalten in Dienst und Container garantiert identisch und testbar.

Fail-open-Grundsaetze (aus Kapitel 12/14):
    * profile_control_enabled = false  -> ALLES erlaubt, nichts wird gesperrt
    * unlesbare Einstellungen           -> Defaults, niemand wird ausgesperrt
    * Wartungsmodus                     -> Admin kommt immer durch (Bypass)
    * abgeschaltete Rollen              -> Bestandsuser werden nur wirksam
                                           herabgestuft, niemals geloescht
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

ROLES = ("guest", "user", "extended", "admin")
ROLE_DOWNGRADE = {"extended": "user", "user": "guest", "guest": "guest", "admin": "admin"}

SESSION_KEYS = ("browser", "day", "week", "month", "forever")
SESSION_LABELS = {
    "browser": "Browser (Sitzungsende)",
    "day": "1 Tag",
    "week": "7 Tage",
    "month": "30 Tage",
    "forever": "Unbegrenzt",
}
# Kanonische Werte = exakt die Schluessel, die app.py in DURS und im
# Login-Formular benutzt (browser/day/week/month/forever). Keine Umcodierung.
SESSION_VALUES = {
    "browser": "browser",
    "day": "day",
    "week": "week",
    "month": "month",
    "forever": "forever",
}
# Aliase, die trotzdem akzeptiert werden (aeltere Frontends/Formulare)
SESSION_ALIASES = {
    "1d": "day", "1tag": "day", "86400": "day", "24h": "day",
    "7d": "week", "7tage": "week", "604800": "week",
    "30d": "month", "30tage": "month", "2592000": "month",
    "unlimited": "forever", "unbegrenzt": "forever", "never": "forever",
    "session": "browser", "0": "browser",
}

POLICY_PATH = "/opt/owrx-docker/var/dnx-access-control/profile-policy.json"
CONTAINER_POLICY_PATH = "/var/lib/openwebrx/dnx-access-control/profile-policy.json"


# --------------------------------------------------------------------------
# Rollen
# --------------------------------------------------------------------------

def normalize_role(role: Any) -> str:
    r = str(role or "").strip().lower()
    if r in ("erweitert", "ext"):
        return "extended"
    if r in ("administrator", "root"):
        return "admin"
    if r in ("gaeste", "anonymous", "chat", ""):
        return "guest"
    return r if r in ROLES else "guest"


def role_enabled(settings: Dict[str, Any], role: str) -> bool:
    """Ist die Rolle grundsaetzlich erlaubt? admin und guest sind nie abschaltbar."""
    role = normalize_role(role)
    if role == "admin":
        return True
    if role == "guest":
        return True
    if role == "user":
        return bool(settings.get("role_user_enabled", True))
    if role == "extended":
        return bool(settings.get("role_extended_enabled", True))
    return False


def effective_role(settings: Dict[str, Any], role: str) -> str:
    """Wirksame Rolle fuer Zugriffsentscheidungen.

    Bestandsuser behalten ihre Rolle in der Datenbank. Ist eine Rolle per
    Schalter abgeschaltet UND downgrade_disabled_roles = AN, wird sie nur fuer
    die Entscheidung herabgestuft (extended -> user -> guest).
    """
    role = normalize_role(role)
    if not settings.get("downgrade_disabled_roles", True):
        return role
    seen = 0
    while not role_enabled(settings, role) and role in ROLE_DOWNGRADE and seen < 5:
        nxt = ROLE_DOWNGRADE[role]
        if nxt == role:
            break
        role = nxt
        seen += 1
    return role


def default_registration_role(settings: Dict[str, Any]) -> str:
    """Standardrolle fuer NEUE Konten – faellt zurueck, wenn nicht erlaubt."""
    wanted = normalize_role(settings.get("default_registration_role", "user"))
    if wanted in ("guest", "admin"):
        wanted = "user"
    if role_enabled(settings, wanted):
        return wanted
    for fallback in ("user", "guest"):
        if role_enabled(settings, fallback):
            return fallback
    return "guest"


def selectable_roles(settings: Dict[str, Any]) -> List[str]:
    """Rollen, die ein Admin im Benutzerdialog anbieten darf."""
    return [r for r in ROLES if role_enabled(settings, r)]


# --------------------------------------------------------------------------
# Registrierung
# --------------------------------------------------------------------------

def registration_state(settings: Dict[str, Any]) -> Dict[str, Any]:
    offen = bool(settings.get("registration_enabled", True))
    return {
        "enabled": offen,
        "captcha": bool(settings.get("captcha_enabled", True)),
        "password_min_length": int(settings.get("password_min_length", 8)),
        "limit": int(settings.get("registration_limit", 0) or 0),
        "window_seconds": int(settings.get("registration_window_seconds", 3600) or 3600),
        "role": default_registration_role(settings),
        "immediately_active": bool(settings.get("new_accounts_active", True)),
        "reason": None if offen else "registration_disabled",
        "message": None if offen else
        "Die Registrierung ist derzeit deaktiviert.",
    }


def registration_rate_allowed(settings: Dict[str, Any], recent_count: int) -> Tuple[bool, Optional[str]]:
    """recent_count = Registrierungen im aktuellen Fenster (IP oder global)."""
    limit = int(settings.get("registration_limit", 0) or 0)
    if limit <= 0:
        return True, None
    if int(recent_count) >= limit:
        return False, "registration_rate_limit"
    return True, None


def new_account_state(settings: Dict[str, Any]) -> str:
    """'active' oder 'pending' fuer ein frisch registriertes Konto."""
    return "active" if settings.get("new_accounts_active", True) else "pending"


# --------------------------------------------------------------------------
# Login / Sperren
# --------------------------------------------------------------------------

def login_policy(settings: Dict[str, Any]) -> Dict[str, Any]:
    max_fail = int(settings.get("max_login_failures", 0) or 0)
    lock = int(settings.get("login_lock_seconds", 0) or 0)
    return {
        "max_failures": max_fail,
        "lock_seconds": lock,
        "lock_enabled": max_fail > 0 and lock > 0,
        "audit_enabled": bool(settings.get("audit_enabled", True)),
    }


def login_blocked(settings: Dict[str, Any], failure_count: int,
                  last_failure_ts: Optional[int] = None, now: Optional[int] = None
                  ) -> Tuple[bool, int, Optional[str]]:
    """(gesperrt, verbleibende_sekunden, grund) – reine Auswertung, kein DB-Zugriff."""
    policy = login_policy(settings)
    if not policy["lock_enabled"]:
        return False, 0, None
    if int(failure_count) < policy["max_failures"]:
        return False, 0, None
    import time as _time
    now = int(now if now is not None else _time.time())
    if last_failure_ts is None:
        return False, 0, None
    remaining = int(last_failure_ts) + policy["lock_seconds"] - now
    if remaining > 0:
        return True, remaining, "login_locked"
    return False, 0, None


# --------------------------------------------------------------------------
# Sitzungen
# --------------------------------------------------------------------------

def session_choices(settings: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Erlaubte Sitzungsdauern fuer UI UND Login-API (dieselbe Quelle)."""
    out = []
    for key in SESSION_KEYS:
        if settings.get("allowed_session_%s" % key, True):
            out.append({"id": key, "value": SESSION_VALUES[key],
                        "label": SESSION_LABELS[key]})
    if not out:  # niemals ohne gueltige Option
        out = [{"id": "browser", "value": SESSION_VALUES["browser"],
                "label": SESSION_LABELS["browser"]}]
    return out


def normalize_session_value(value: Any) -> str:
    """'30d' -> 'month', 'unbegrenzt' -> 'forever', 'browser' -> 'browser'."""
    v = str(value or "").strip().lower()
    if v in SESSION_KEYS:
        return v
    return SESSION_ALIASES.get(v, v)


def session_value_allowed(settings: Dict[str, Any], value: Any) -> bool:
    v = normalize_session_value(value)
    allowed = {c["id"] for c in session_choices(settings)}
    return v in allowed


def sanitize_session_request(settings: Dict[str, Any], value: Any) -> str:
    """Erzwingt eine erlaubte Sitzungsdauer (faellt auf 'browser' zurueck).

    Liefert immer einen Schluessel, den DURS in app.py direkt versteht:
    browser / day / week / month / forever.
    """
    v = normalize_session_value(value)
    if v in {c["id"] for c in session_choices(settings)}:
        return v
    return "browser"


# --------------------------------------------------------------------------
# Wartungsmodus
# --------------------------------------------------------------------------

def maintenance_state(settings: Dict[str, Any], role: Any = "guest") -> Dict[str, Any]:
    aktiv = bool(settings.get("maintenance_mode", False))
    role = normalize_role(role)
    bypass = bool(settings.get("maintenance_admin_bypass", True))
    allowed = True
    reason = None
    if aktiv:
        if role == "admin" and bypass:
            allowed = True
            reason = "maintenance_admin_bypass"
        elif role == "admin":
            allowed = False
            reason = "maintenance"
        else:
            allowed = False
            reason = "maintenance"
    return {
        "active": aktiv,
        "allowed": allowed,
        "reason": reason,
        "message": settings.get(
            "maintenance_message",
            "Wartungsmodus: Der Empfaenger ist voruebergehend nur fuer "
            "Administratoren verfuegbar.") if aktiv else "",
        "lock_existing_sessions": bool(settings.get("maintenance_lock_existing_sessions", False)),
    }


# --------------------------------------------------------------------------
# Profilrichtlinie (profile-policy.json, tolerant gelesen)
# --------------------------------------------------------------------------

def load_profile_policy(path: Optional[str] = None) -> Dict[str, Any]:
    """Liest profile-policy.json so robust wie moeglich.

    Unterstuetzte Formen:
        {"protected": ["name1", ...]}
        {"profiles": {"name": {"roles": ["extended","admin"]}}}
        {"roles": {"extended": ["name1"], "user": ["name2"]}}
        ["name1", "name2"]

    Rueckgabe: {'protected': set(), 'allowed': {role: set()|None}, 'raw_ok': bool}
    allowed[role] = None bedeutet 'keine Einschraenkung bekannt'.
    """
    result: Dict[str, Any] = {"protected": set(), "allowed": {}, "raw_ok": False,
                              "path": None, "error": None}
    candidates = [path] if path else [POLICY_PATH, CONTAINER_POLICY_PATH]
    for cand in candidates:
        if cand and os.path.exists(cand):
            result["path"] = cand
            break
    if not result["path"]:
        result["error"] = "profile-policy.json nicht gefunden"
        return result
    try:
        with open(result["path"], "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception as exc:
        result["error"] = "profile-policy.json nicht lesbar: %s" % exc
        return result

    result["raw_ok"] = True
    protected: Set[str] = set()
    allowed: Dict[str, Set[str]] = {}

    # --- Sonderfall: flache Zuordnung {"profilkey": "mindestrolle"} ---
    # Genau so liegt profile-policy.json auf dem Produktivsystem:
    #   {"80m": "user", "KW-Schutz": "extended", "Admin-only": "admin"}
    if isinstance(data, dict) and data and all(
            isinstance(v, str) and normalize_role(v) in ROLES for v in data.values()):
        hierarchy = {"guest": 0, "user": 1, "extended": 2, "admin": 3}
        for name, minrole in data.items():
            need = hierarchy[normalize_role(minrole)]
            if need >= hierarchy["extended"]:
                protected.add(str(name))
            for role, level in hierarchy.items():
                if level >= need:
                    allowed.setdefault(role, set()).add(str(name))
        result["protected"] = protected
        result["allowed"] = allowed
        result["form"] = "flat_min_role"
        return result

    def add_allowed(role: str, name: str) -> None:
        allowed.setdefault(normalize_role(role), set()).add(str(name))

    if isinstance(data, list):
        for item in data:
            if isinstance(item, str):
                add_allowed("user", item)
    elif isinstance(data, dict):
        for key in ("protected", "protected_profiles", "admin_only"):
            val = data.get(key)
            if isinstance(val, (list, tuple, set)):
                protected.update(str(v) for v in val)
            elif isinstance(val, dict):
                protected.update(str(k) for k, v in val.items() if v)
        profiles = data.get("profiles")
        if isinstance(profiles, dict):
            for name, cfg in profiles.items():
                if isinstance(cfg, dict):
                    roles = cfg.get("roles") or cfg.get("allowed_roles")
                    if isinstance(roles, (list, tuple, set)):
                        for r in roles:
                            add_allowed(r, name)
                        if not any(normalize_role(r) in ("user", "guest") for r in roles):
                            protected.add(str(name))
                    elif cfg.get("protected"):
                        protected.add(str(name))
                elif cfg in (True, "protected"):
                    protected.add(str(name))
        elif isinstance(profiles, (list, tuple)):
            for name in profiles:
                add_allowed("user", str(name))
        roles_map = data.get("roles")
        if isinstance(roles_map, dict):
            for role, names in roles_map.items():
                if isinstance(names, (list, tuple, set)):
                    for name in names:
                        add_allowed(role, str(name))

    result["protected"] = protected
    result["allowed"] = allowed
    result["form"] = "structured"
    return result


# --------------------------------------------------------------------------
# Profilentscheidung (serverseitig UND fuer das Audit-Log)
# --------------------------------------------------------------------------

def profile_decision(settings: Dict[str, Any], *, role: Any = "guest",
                     authenticated: bool = False, target_profile: Optional[str] = None,
                     protected: Optional[Sequence[str]] = None,
                     allowed_map: Optional[Dict[str, Sequence[str]]] = None,
                     ) -> Dict[str, Any]:
    """Zentrale Entscheidung fuer einen Profilwechsel.

    Rueckgabe:
        {'allow': bool, 'reason': str, 'event': 'profile_change'|'profile_denied'|None,
         'effective_role': str, 'maintenance': dict}

    Reihenfolge der Pruefung:
        1. Profilsteuerung AUS        -> erlaubt (fail-open, kein Denied-Log)
        2. Wartungsmodus              -> nur Admin (mit Bypass)
        3. Account-Zwang ohne Konto   -> abgelehnt
        4. Gast ohne Gast-Freigabe    -> abgelehnt
        5. abgeschaltete Rolle        -> wirksam herabgestuft
        6. geschuetztes Profil        -> nur extended/admin
    """
    eff = effective_role(settings, role)
    maint = maintenance_state(settings, role)
    target = str(target_profile) if target_profile is not None else None
    protected_set: Set[str] = {str(p) for p in (protected or [])}

    def out(allow: bool, reason: str) -> Dict[str, Any]:
        event = None
        if target is not None:
            event = "profile_change" if allow else "profile_denied"
        return {"allow": allow, "reason": reason, "event": event,
                "effective_role": eff, "requested_role": normalize_role(role),
                "profile": target, "maintenance": maint}

    # 1. Profilsteuerung global aus -> fail-open
    if not settings.get("profile_control_enabled", True):
        return out(True, "profile_control_disabled")

    # 2. Wartungsmodus
    if maint["active"] and not maint["allowed"]:
        return out(False, "maintenance_mode")

    # 3. Account-Zwang
    if settings.get("account_required", False) and not authenticated:
        return out(False, "account_required")

    # 4. Gaeste (bzw. nicht angemeldet ohne Account-Zwang)
    if not authenticated or eff == "guest":
        if not settings.get("guest_profile_switch", False):
            return out(False, "guest_profile_switch_disabled")
        if target is not None and target in protected_set:
            return out(False, "guest_protected_profile")
        return out(True, "guest_allowed")

    # 5./6. angemeldete Rollen
    if eff == "admin":
        return out(True, "admin")

    if target is not None:
        if allowed_map:
            permitted = allowed_map.get(eff)
            if permitted is not None and target not in {str(p) for p in permitted}:
                return out(False, "profile_not_in_role_policy")
        if target in protected_set and eff != "extended":
            return out(False, "protected_profile_role_insufficient")

    return out(True, "role_%s" % eff)


def profile_access_for_role(settings: Dict[str, Any], role: Any,
                            policy: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Vereinfachte Sicht fuer UI/Status: was darf diese Rolle gerade?"""
    policy = policy or {"protected": set(), "allowed": {}}
    eff = effective_role(settings, role)
    decision = profile_decision(settings, role=role, authenticated=(eff != "guest"),
                                target_profile=None)
    return {
        "role": normalize_role(role),
        "effective_role": eff,
        "may_switch_profiles": decision["allow"],
        "reason": decision["reason"],
        "protected_profiles_allowed": eff in ("extended", "admin"),
        "protected_known": sorted(policy.get("protected") or []),
    }


# --------------------------------------------------------------------------
# Frontend-Sicht
# --------------------------------------------------------------------------

def public_view(settings: Dict[str, Any]) -> Dict[str, Any]:
    """Was das Receiver-Frontend aus den oeffentlichen Schluesseln ableitet."""
    return {
        "registration": registration_state(settings),
        "sessions": session_choices(settings),
        "roles": selectable_roles(settings),
        "account_required": bool(settings.get("account_required", False)),
        "guest_profile_switch": bool(settings.get("guest_profile_switch", False)),
        "profile_control_enabled": bool(settings.get("profile_control_enabled", True)),
        "maintenance": maintenance_state(settings, "guest"),
        "public_activity_enabled": bool(settings.get("public_activity_enabled", True)),
        "public_activity_hours": int(settings.get("public_activity_hours", 24)),
        "audit_enabled": bool(settings.get("audit_enabled", True)),
    }


def admin_summary(settings: Dict[str, Any], warnings: Optional[List[str]] = None) -> Dict[str, Any]:
    """Kompakte Lage fuer den Kopf der Adminseite."""
    reg = registration_state(settings)
    policy = login_policy(settings)
    return {
        "version": "1.2.0",
        "registration": "AN" if reg["enabled"] else "AUS",
        "new_accounts": "sofort aktiv" if settings.get("new_accounts_active") else "wartend",
        "profile_control": "AN" if settings.get("profile_control_enabled") else "AUS (fail-open)",
        "account_required": "AN" if settings.get("account_required") else "AUS",
        "guest_switch": "AN" if settings.get("guest_profile_switch") else "AUS",
        "roles": {"user": bool(settings.get("role_user_enabled")),
                  "extended": bool(settings.get("role_extended_enabled")),
                  "default": default_registration_role(settings)},
        "maintenance": maintenance_state(settings, "admin"),
        "sessions": [c["label"] for c in session_choices(settings)],
        "limits": {"login": policy, "registration": {"limit": reg["limit"],
                                                     "window": reg["window_seconds"]}},
        "audit": {"enabled": bool(settings.get("audit_enabled")),
                  "public": bool(settings.get("public_activity_enabled")),
                  "hours": int(settings.get("public_activity_hours", 24)),
                  "max_entries": int(settings.get("max_audit_entries", 250000)),
                  "max_bytes": int(settings.get("max_audit_bytes", 1073741824)),
                  "auto_purge": bool(settings.get("audit_auto_purge"))},
        "warnings": warnings or [],
    }


__all__ = [
    "ROLES", "ROLE_DOWNGRADE", "SESSION_KEYS", "SESSION_LABELS", "SESSION_VALUES",
    "SESSION_ALIASES", "normalize_session_value",
    "normalize_role", "role_enabled", "effective_role", "default_registration_role",
    "selectable_roles", "registration_state", "registration_rate_allowed",
    "new_account_state", "login_policy", "login_blocked", "session_choices",
    "session_value_allowed", "sanitize_session_request", "maintenance_state",
    "load_profile_policy", "profile_decision", "profile_access_for_role",
    "public_view", "admin_summary",
]
