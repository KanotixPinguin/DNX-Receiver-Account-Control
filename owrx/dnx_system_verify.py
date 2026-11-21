# -*- coding: utf-8 -*-
"""dnx_system_verify – serverseitige Profilpruefung mit der globalen Systemsteuerung.

Ablageort im Container owrx-8013:
    /usr/lib/python3/dist-packages/owrx/dnx_system_verify.py

Dazu gehoeren (werden von install.sh mitkopiert, damit die Logik EINMAL existiert):
    /usr/lib/python3/dist-packages/owrx/dnx_sys_store.py   (= settings_store.py)
    /usr/lib/python3/dist-packages/owrx/dnx_sys_rules.py   (= access_rules.py)

Die DB ist im Container ueber den Bind-Mount sichtbar:
    /opt/owrx-docker/var  ->  /var/lib/openwebrx
    also: /var/lib/openwebrx/dnx-access-control/accounts.sqlite3

Grundsaetze (Uebergabe Kapitel 12/14):
    * dieselben Einstellungen wie der Account-Dienst lesen (eine Quelle)
    * read-only, TTL-Cache, keine Schreibzugriffe aus dem Container
    * fail-open: bei Stoerung gelten Defaults -> niemand wird ausgesperrt
    * profile_control_enabled = false -> ALLES erlaubt (kein versehentliches Sperren)
    * keine DNX-Schluessel an DSP-Properties weitergeben
"""

from __future__ import annotations

import os
import threading
import time
from typing import Any, Dict, Optional

# --------------------------------------------------------------------------
# Logik: bevorzugt die mitinstallierten Module, sonst eingebaute Minimalkopie
# --------------------------------------------------------------------------

_FALLBACK_DEFAULTS: Dict[str, Any] = {
    "profile_control_enabled": True,
    "account_required": False,
    "guest_profile_switch": False,
    "role_user_enabled": True,
    "role_extended_enabled": True,
    "maintenance_mode": False,
    "maintenance_admin_bypass": True,
    "downgrade_disabled_roles": True,
    "settings_cache_seconds": 3,
    "settings_fail_open": True,
    "audit_enabled": True,
    "default_registration_role": "user",
}

try:  # pragma: no cover - abhaengig von der Installation
    from owrx.dnx_sys_store import SettingsStore as _Store  # type: ignore
    from owrx.dnx_sys_rules import (  # type: ignore
        profile_decision as _profile_decision,
        effective_role as _effective_role,
        maintenance_state as _maintenance_state,
        normalize_role as _normalize_role,
        load_profile_policy as _load_profile_policy,
    )
    HAVE_SHARED_LOGIC = True
except Exception:  # pragma: no cover
    HAVE_SHARED_LOGIC = False

    def _normalize_role(role: Any) -> str:
        r = str(role or "").strip().lower()
        if r in ("erweitert", "ext"):
            return "extended"
        if r in ("administrator",):
            return "admin"
        return r if r in ("guest", "user", "extended", "admin") else "guest"

    def _effective_role(settings: Dict[str, Any], role: Any) -> str:
        role = _normalize_role(role)
        if not settings.get("downgrade_disabled_roles", True):
            return role
        order = {"extended": "user", "user": "guest"}
        guard = 0
        while guard < 4:
            if role == "extended" and not settings.get("role_extended_enabled", True):
                role = "user"
            elif role == "user" and not settings.get("role_user_enabled", True):
                role = order.get(role, "guest")
            else:
                break
            guard += 1
        return role

    def _maintenance_state(settings: Dict[str, Any], role: Any = "guest") -> Dict[str, Any]:
        active = bool(settings.get("maintenance_mode", False))
        role = _normalize_role(role)
        allowed = True
        if active:
            allowed = (role == "admin") and bool(settings.get("maintenance_admin_bypass", True))
        return {"active": active, "allowed": allowed,
                "reason": "maintenance_admin_bypass" if (active and allowed) else
                          ("maintenance" if active else None),
                "message": settings.get("maintenance_message", "")}

    def _load_profile_policy(path: Optional[str] = None) -> Dict[str, Any]:
        return {"protected": set(), "allowed": {}, "raw_ok": False, "error": "no-shared-logic"}

    def _profile_decision(settings, *, role="guest", authenticated=False,
                          target_profile=None, protected=None, allowed_map=None):
        eff = _effective_role(settings, role)
        maint = _maintenance_state(settings, role)
        target = str(target_profile) if target_profile is not None else None
        prot = {str(p) for p in (protected or [])}

        def out(allow, reason):
            event = None
            if target is not None:
                event = "profile_change" if allow else "profile_denied"
            return {"allow": allow, "reason": reason, "event": event,
                    "effective_role": eff, "requested_role": _normalize_role(role),
                    "profile": target, "maintenance": maint}

        if not settings.get("profile_control_enabled", True):
            return out(True, "profile_control_disabled")
        if maint["active"] and not maint["allowed"]:
            return out(False, "maintenance_mode")
        if settings.get("account_required", False) and not authenticated:
            return out(False, "account_required")
        if not authenticated or eff == "guest":
            if not settings.get("guest_profile_switch", False):
                return out(False, "guest_profile_switch_disabled")
            if target is not None and target in prot:
                return out(False, "guest_protected_profile")
            return out(True, "guest_allowed")
        if eff == "admin":
            return out(True, "admin")
        if target is not None and target in prot and eff != "extended":
            return out(False, "protected_profile_role_insufficient")
        return out(True, "role_%s" % eff)


# --------------------------------------------------------------------------
# Pfade
# --------------------------------------------------------------------------

DB_CANDIDATES = (
    os.environ.get("DNX_ACCOUNTS_DB", ""),
    "/var/lib/openwebrx/dnx-access-control/accounts.sqlite3",   # Container
    "/opt/owrx-docker/var/dnx-access-control/accounts.sqlite3",  # Host (Fallback)
)
POLICY_CANDIDATES = (
    os.environ.get("DNX_PROFILE_POLICY", ""),
    "/var/lib/openwebrx/dnx-access-control/profile-policy.json",
    "/opt/owrx-docker/var/dnx-access-control/profile-policy.json",
)

DNX_PROP_PREFIXES = ("dnx_", "dnx-", "dnxauth")
DNX_AUTH_MARKER = "DNXAUTH:"

_lock = threading.RLock()
_cache: Dict[str, Any] = {"settings": dict(_FALLBACK_DEFAULTS), "ts": 0.0,
                          "source": "fallback", "error": None, "policy_ts": 0.0,
                          "policy": {"protected": set(), "allowed": {}}}


def _first_existing(candidates) -> Optional[str]:
    for cand in candidates:
        if cand and os.path.exists(cand):
            return cand
    return None


def db_path() -> Optional[str]:
    return _first_existing(DB_CANDIDATES)


def policy_path() -> Optional[str]:
    return _first_existing(POLICY_CANDIDATES)


# --------------------------------------------------------------------------
# Einstellungen lesen (read-only, gecacht)
# --------------------------------------------------------------------------

def get_settings(force: bool = False, cache_seconds: Optional[int] = None) -> Dict[str, Any]:
    """Liefert die globalen Einstellungen. Bei jedem Fehler: Defaults (fail-open)."""
    with _lock:
        ttl = cache_seconds if cache_seconds is not None else \
            int(_cache["settings"].get("settings_cache_seconds", 3) or 0)
        if not force and _cache["ts"] and (time.time() - _cache["ts"]) < max(0.0, ttl):
            return dict(_cache["settings"])

        settings = dict(_FALLBACK_DEFAULTS)
        source = "fallback"
        error = None
        path = db_path()
        if not path:
            error = "accounts.sqlite3 nicht gefunden"
        elif not HAVE_SHARED_LOGIC:
            error = "dnx_sys_store/dnx_sys_rules fehlen -> Minimallogik mit Defaults"
        else:
            try:
                store = _Store(path, readonly=True)
                settings, _warnings = store.load()
                source = "access_settings"
            except Exception as exc:
                error = "Lesen fehlgeschlagen: %s" % exc

        # Fail-open abschaltbar (Admin-Zusatzschalter), aber NIE ohne Defaults
        if not settings.get("settings_fail_open", True) and source == "fallback":
            settings["_strict"] = True

        _cache.update({"settings": settings, "ts": time.time(), "source": source,
                       "error": error})
        return dict(settings)


def get_policy(force: bool = False) -> Dict[str, Any]:
    """profile-policy.json (geschuetzte Profile), ebenfalls gecacht."""
    with _lock:
        if not force and _cache["policy_ts"] and (time.time() - _cache["policy_ts"]) < 30:
            return _cache["policy"]
        path = policy_path()
        policy = _load_profile_policy(path) if path else \
            {"protected": set(), "allowed": {}, "raw_ok": False, "error": "nicht gefunden"}
        _cache["policy"] = policy
        _cache["policy_ts"] = time.time()
        return policy


def status() -> Dict[str, Any]:
    """Diagnoseauskunft fuer Logs und Smoke-Tests."""
    settings = get_settings()
    return {
        "db_path": db_path(),
        "policy_path": policy_path(),
        "source": _cache["source"],
        "error": _cache["error"],
        "shared_logic": HAVE_SHARED_LOGIC,
        "profile_control_enabled": bool(settings.get("profile_control_enabled", True)),
        "maintenance_mode": bool(settings.get("maintenance_mode", False)),
        "account_required": bool(settings.get("account_required", False)),
        "guest_profile_switch": bool(settings.get("guest_profile_switch", False)),
        "keys": len(settings),
    }


# --------------------------------------------------------------------------
# Pruefung
# --------------------------------------------------------------------------

def verify_profile(profile_name: Any, *, role: Any = "guest",
                   authenticated: Optional[bool] = None,
                   username: Optional[str] = None,
                   protected: Optional[Any] = None,
                   force: bool = False) -> Dict[str, Any]:
    """Verbindliche Entscheidung fuer `selectprofile`.

    Aufruf aus dnx_access_verify.py / connection.py:

        from owrx.dnx_system_verify import verify_profile
        decision = verify_profile(profile, role=role, authenticated=True, username=name)
        if not decision["allow"]:
            # auditieren als profile_denied und ablehnen
            ...

    Rueckgabe: {'allow', 'reason', 'event', 'effective_role', 'profile', 'maintenance',
                'source', 'fail_open'}
    """
    settings = get_settings(force=force)
    if authenticated is None:
        authenticated = bool(username) or _normalize_role(role) not in ("guest", "")
    policy = get_policy(force=force)
    prot = protected if protected is not None else policy.get("protected") or set()
    allowed_map = policy.get("allowed") or None
    decision = _profile_decision(settings, role=role, authenticated=authenticated,
                                 target_profile=profile_name, protected=prot,
                                 allowed_map=allowed_map)
    decision["source"] = _cache["source"]
    decision["fail_open"] = (not settings.get("profile_control_enabled", True)) or \
                            (_cache["source"] == "fallback" and
                             bool(settings.get("settings_fail_open", True)))
    decision["audit_event"] = decision.get("event")
    decision["username"] = username
    return decision


def audit_decision(decision: Dict[str, Any]) -> Optional[str]:
    """Liefert den zu protokollierenden Ereignisnamen (oder None).

    Bewusst identisch zum Account-Dienst: ein erlaubter Wechsel wird als
    'profile_change' protokolliert, ein abgewiesener als 'profile_denied' –
    auch dann, wenn die Profilsteuerung ausgeschaltet ist (fail-open).
    So bleiben Frontend, Dienst und Container im Log widerspruchsfrei.
    """
    if not decision:
        return None
    return decision.get("event")


# --------------------------------------------------------------------------
# DSP-Schutz: keine DNX-Daten an connectionProperties/DSP
# --------------------------------------------------------------------------

def is_dnx_property(key: Any, value: Any = None) -> bool:
    k = str(key or "").strip().lower()
    if k.startswith(DNX_PROP_PREFIXES):
        return True
    if k == "key" and isinstance(value, str) and value.startswith(DNX_AUTH_MARKER):
        return True
    if k in ("dnxauth", "dnx_token", "dnx_account_token"):
        return True
    return False


def filter_dnx_properties(props: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Entfernt DNX-Schluessel, bevor Properties an SDR/DSP gehen.

    Einzusetzen an BEIDEN Stellen (Uebergabe Kapitel 4):
        * connectionproperties-Patch (bereits vorhanden)
        * handleSdrAvailable(): self.getDsp().setProperties(filter_dnx_properties(self.connectionProperties))
    """
    if not props:
        return {}
    return {k: v for k, v in dict(props).items() if not is_dnx_property(k, v)}


def split_auth_key(raw: Any) -> Optional[str]:
    """Extrahiert den signierten Token aus params.key = 'DNXAUTH:<token>'."""
    if not isinstance(raw, str):
        return None
    raw = raw.strip()
    if raw.startswith(DNX_AUTH_MARKER):
        return raw[len(DNX_AUTH_MARKER):].strip() or None
    return None


__all__ = [
    "DB_CANDIDATES", "POLICY_CANDIDATES", "HAVE_SHARED_LOGIC",
    "db_path", "policy_path", "get_settings", "get_policy", "status",
    "verify_profile", "audit_decision", "is_dnx_property",
    "filter_dnx_properties", "split_auth_key",
]
