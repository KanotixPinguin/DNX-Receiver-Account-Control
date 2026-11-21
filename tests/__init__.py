# -*- coding: utf-8 -*-
"""DNX Receiver Account Control – globale Systemsteuerung (v1.2.0).

Paketinhalt:
    settings_store.py   access_settings (SQLite), atomar, sichere Defaults, Audit
    access_rules.py     Entscheidungslogik – identisch fuer Dienst, Frontend, Container
    admin_api.py        Flask-Blueprint: /admin/system + APIs (Admin-only, CSRF)

Keine harte Flask-Abhaengigkeit im Kern: settings_store und access_rules laufen
auch read-only im OpenWebRX-Container (serverseitige Profilpruefung).
"""

from .settings_store import (  # noqa: F401
    PACKAGE_VERSION,
    SCHEMA_VERSION,
    SPEC,
    GROUP_LABELS,
    SettingsStore,
    SettingsValidationError,
    resolve_db_path,
)
from . import access_rules  # noqa: F401

__version__ = PACKAGE_VERSION
__all__ = [
    "PACKAGE_VERSION",
    "SCHEMA_VERSION",
    "SPEC",
    "GROUP_LABELS",
    "SettingsStore",
    "SettingsValidationError",
    "resolve_db_path",
    "access_rules",
    "__version__",
]
