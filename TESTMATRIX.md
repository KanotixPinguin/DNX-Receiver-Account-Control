# TESTMATRIX – Abnahme Systemsteuerung v1.2.0

Ziel: Kapitel 13, Punkt 11 („Tests Gast/User/Extended/Admin“) vollständig abhaken.
Jeder Block ist unabhängig; Reihenfolge egal. Vor jedem Block `smoke_tests.sh`
laufen lassen, danach ebenfalls.

Testkonten (Bezeichnung aus der Übergabe):

| Kürzel | Rolle | Zweck |
|---|---|---|
| **G** | Gast (kein Konto) | hören, keine Profilwechsel |
| **U** | `user` | Standardprofile |
| **E** | `extended` | Standard- + geschützte Profile |
| **A** | `admin` | alles + Verwaltung |

Kurzbefehle (auf `192.0.2.113`):

```bash
BASE=http://127.0.0.1:8096
sqlite3 /opt/owrx-docker/var/dnx-access-control/accounts.sqlite3 \
  "SELECT key, value FROM access_settings ORDER BY key;"
curl -s $BASE/api/system/state | python3 -m json.tool
curl -s $BASE/api/system/healthz | python3 -m json.tool
sudo ./scripts/smoke_tests.sh
```

---

## 0. Vorbereitung

- [ ] Vollbackup liegt (`<USER_HOME>/DNX-Account-Control-Backup-*.tar.gz`)
- [ ] `install.sh`-Backup liegt (`<USER_HOME>/dnx-system-control-backups/<Zeitstempel>/`)
- [ ] `systemctl is-active dnx-access-control.service` → `active`
- [ ] `docker ps --filter name=owrx-8013` → läuft
- [ ] `migrate_add_access_settings.py` meldete „Bestandsuser vor/nach identisch“
- [ ] `smoke_tests.sh` → 0 FAIL
- [ ] `sqlite3 … 'PRAGMA integrity_check;'` → `ok`
- [ ] Bestand gezählt und notiert: `SELECT role, COUNT(*) FROM users GROUP BY role;` → ______

## 1. Admin-Bereich erreicht nur Admins

| # | Test | Erwartung | ok |
|---|---|---|---|
| 1.1 | `/admin/system` ohne Anmeldung | **403** | [ ] |
| 1.2 | `/admin/system` als G | **403** | [ ] |
| 1.3 | `/admin/system` als U | **403** | [ ] |
| 1.4 | `/admin/system` als E | **403** | [ ] |
| 1.5 | `/admin/system` als A | **200**, Panel sichtbar | [ ] |
| 1.6 | `/admin/system/static/dnx_system_control.css` als U | **403** | [ ] |
| 1.7 | `/admin/api/system/settings` als A | **200**, 40 Schlüssel, `csrf_token` | [ ] |
| 1.8 | `/api/system/state` ohne Anmeldung | **200** (öffentlich, nur public-Schlüssel) | [ ] |
| 1.9 | `/api/system/state` enthält `max_audit_bytes`, `password_min_length`, `login_lock_seconds` | **nein** | [ ] |
| 1.10 | Bereich „Erweitert / Technisch (nur Admin)“ im Panel | sichtbar für A | [ ] |

## 2. Speichern, CSRF, Atomarität

| # | Test | Erwartung | ok |
|---|---|---|---|
| 2.1 | Schalter umlegen, ohne zu speichern, Seite verlassen | Browser warnt („ungepeichert“) | [ ] |
| 2.2 | Speichern mit Bestätigungsdialog | Diff Alt→Neu sichtbar, dann 200 | [ ] |
| 2.3 | `POST` ohne `X-CSRF-Token` | **403**, `code: csrf`, **nichts** gespeichert | [ ] |
| 2.4 | `POST` mit manipuliertem Token | **403** | [ ] |
| 2.5 | `POST` mit `Origin: http://evil.example` | **403** | [ ] |
| 2.6 | `POST` mit einem gültigen + einem ungültigen Wert (`max_login_failures: 99999`) | **400** mit `field_errors`, **keiner** der beiden Werte gespeichert | [ ] |
| 2.7 | `POST` mit unbekanntem Schlüssel | **400** („Unbekannter Schlüssel“) | [ ] |
| 2.8 | `POST` auf `package_version` / `schema_version` | **400** („schreibgeschützt“) | [ ] |
| 2.9 | Alle fünf Sitzungsdauern gleichzeitig AUS | **400** („Mindestens eine …“) | [ ] |
| 2.10 | `default_registration_role=extended` bei `role_extended_enabled=false` | **400** | [ ] |
| 2.11 | 35 Speicheraktionen in < 60 s | ab der 31. **429** | [ ] |
| 2.12 | Nach `Speichern` zeigt das Panel den Wert aus der DB (nicht den lokalen) | identisch | [ ] |
| 2.13 | „Defaults“ mit Bestätigung | alle editierbaren Schlüssel auf Default | [ ] |

## 3. Registrierung

| Schalter | G/Neuanlage | Erwartung | ok |
|---|---|---|---|
| `registration_enabled = AN` | Registrierungsseite | offen, Rechenaufgabe sichtbar | [ ] |
| `registration_enabled = AUS` | Registrierungsseite | **403** + Hinweis; Register-Button im Receiver ausgeblendet | [ ] |
| `new_accounts_active = AN` | neues Konto | sofort anmeldbar | [ ] |
| `new_accounts_active = AUS` | neues Konto | angelegt, aber „wartend“, Login abgelehnt | [ ] |
| `default_registration_role = user` | neues Konto | Rolle `user` in `users` | [ ] |
| `default_registration_role = extended` | neues Konto | Rolle `extended`, Zugriff auf geschützte Profile | [ ] |
| `password_min_length = 12` | Registrierung mit 8 Zeichen | abgelehnt | [ ] |
| `captcha_enabled = AUS` | Registrierung | ohne Rechenaufgabe | [ ] |
| `registration_limit = 2`, Fenster 3600 s | 3. Registrierung im Fenster | abgelehnt (`registration_rate_limit`) | [ ] |
| `registration_limit = 0` | 10 Registrierungen | alle erlaubt (Limit aus) | [ ] |

Bestandscheck nach jedem Registrierungsversuch:
`SELECT username, role, active FROM users ORDER BY id;` → Bestandsuser unverändert [ ]

## 4. Login, Sperren, Sitzungen

| # | Test | Erwartung | ok |
|---|---|---|---|
| 4.1 | `max_login_failures = 3`, 3× falsches Passwort | 4. Versuch gesperrt, Restzeit sichtbar | [ ] |
| 4.2 | `login_lock_seconds = 60` | nach 60 s wieder möglich | [ ] |
| 4.3 | `max_login_failures = 0` | Sperre deaktiviert, beliebig viele Versuche | [ ] |
| 4.4 | Sperre erzeugt Audit-Ereignis | `login_blocked` im Logbuch | [ ] |
| 4.5 | `allowed_session_forever = AUS` | „Unbegrenzt“ im Formular nicht wählbar | [ ] |
| 4.6 | „Unbegrenzt“ per manipuliertem Formular gesendet | Server erzwingt `browser` | [ ] |
| 4.7 | Nur `allowed_session_day = AN` | ausschließlich „1 Tag“ wählbar | [ ] |
| 4.8 | Bestehende Sitzung vor Schalteränderung | bleibt gültig (`revoke_sessions_on_change = AUS`) | [ ] |
| 4.9 | Nach Ablauf der Sitzungsdauer | Neuanmeldung nötig | [ ] |

## 5. Rollen und Profilprüfung (Kern der Übergabe)

Profilbeispiele: `80m` (Standard), `KW-Schutz` (geschützt), `Admin-only`.

| # | Profil | G | U | E | A | ok |
|---|---|---|---|---|---|---|
| 5.1 | `80m`, `guest_profile_switch = AUS` | abgelehnt | erlaubt | erlaubt | erlaubt | [ ] |
| 5.2 | `80m`, `guest_profile_switch = AN` | **erlaubt** | erlaubt | erlaubt | erlaubt | [ ] |
| 5.3 | `KW-Schutz`, `guest_profile_switch = AN` | abgelehnt | abgelehnt | **erlaubt** | erlaubt | [ ] |
| 5.4 | `Admin-only` | abgelehnt | abgelehnt | abgelehnt¹ | **erlaubt** | [ ] |
| 5.5 | `account_required = AN` | **abgelehnt** | erlaubt | erlaubt | erlaubt | [ ] |
| 5.6 | `role_extended_enabled = AUS` | – | – | wirksam als `user` → `KW-Schutz` abgelehnt, DB-Rolle bleibt `extended` | erlaubt | [ ] |
| 5.7 | `role_user_enabled = AUS` | – | wirksam `guest` | erlaubt | erlaubt | [ ] |
| 5.8 | `downgrade_disabled_roles = AUS` bei 5.6 | – | – | `KW-Schutz` wieder erlaubt | erlaubt | [ ] |
| 5.9 | `profile_control_enabled = AUS` | **alles erlaubt** | alles erlaubt | alles erlaubt | alles erlaubt | [ ] |
| 5.10 | Erlaubte Wechsel | `profile_change` im Log | gleich | gleich | gleich | [ ] |
| 5.11 | Abgewiesene Wechsel | `profile_denied` im Log | gleich | gleich | gleich | [ ] |
| 5.12 | Container-Prüfung identisch zur Dienst-Prüfung | `docker exec … d.status()` → `source: access_settings` | [ ] |

¹ außer `Admin-only` ist in `profile-policy.json` ausdrücklich für `extended` freigegeben.

**Fail-open-Pflichttest 5.9:** Nach `profile_control_enabled = AUS` darf **kein**
Benutzer ausgesperrt sein. Zeigt das Panel trotzdem „Profilsteuerung AUS
(fail-open)“ im Lage-Chip? [ ]

## 6. Wartungsmodus

| # | Test | Erwartung | ok |
|---|---|---|---|
| 6.1 | `maintenance_mode = AN`, G ruft geschützte Seite auf | **503** + Wartungstext | [ ] |
| 6.2 | dito U, E | **503** | [ ] |
| 6.3 | dito A mit `maintenance_admin_bypass = AN` | **200** (Bypass) | [ ] |
| 6.4 | A mit `maintenance_admin_bypass = AUS` | **503**, aber `/admin/system` bleibt **200** | [ ] |
| 6.5 | `maintenance_message` ändern | Text erscheint auf der 503-Seite und im Receiver-Banner | [ ] |
| 6.6 | Login-Seite im Wartungsmodus | erreichbar (sonst kommt niemand mehr rein) | [ ] |
| 6.7 | `maintenance_lock_existing_sessions = AUS` | bestehende Sitzungen bleiben in `sessions` | [ ] |
| 6.8 | Wartungsmodus AUS | alles wieder normal, keine Restsperren | [ ] |

## 7. Aktivitätslog und Audit

| # | Test | Erwartung | ok |
|---|---|---|---|
| 7.1 | `/activity` als G | nur letzte `public_activity_hours`, **keine IP, kein User-Agent** | [ ] |
| 7.2 | `/activity` zeigt nur Kontonamen/Gast | ja | [ ] |
| 7.3 | `public_activity_enabled = AUS` | `/activity` liefert keine Daten (404/Hinweis), Link im Receiver ausgeblendet | [ ] |
| 7.4 | `public_activity_hours = 1` | nur letzte Stunde | [ ] |
| 7.5 | `/admin/logbook` als A | volle Historie **mit** IP und User-Agent | [ ] |
| 7.6 | `/admin/logbook` als U | **403** | [ ] |
| 7.7 | `audit_enabled = AUS` | keine neuen `login_*`/`profile_*`-Zeilen | [ ] |
| 7.8 | `audit_enabled = AUS`, aber Schalter ändern | `admin_access_settings` wird **trotzdem** geschrieben | [ ] |
| 7.9 | `audit_settings_changes = AUS` | auch Einstellungsänderungen ohne Zeile | [ ] |
| 7.10 | `audit_auto_purge = AUS`, `max_audit_entries = 1000` | **keine** Löschung (Übergabestand) | [ ] |
| 7.11 | `audit_auto_purge = AN` | älteste Zeilen verschwinden, `integrity_check` bleibt `ok` | [ ] |
| 7.12 | Zeitanzeige | `Europe/Berlin`, DB weiter Unix-Zeitstempel | [ ] |
| 7.13 | `audit_timezone` ändern | Anzeige folgt, Speicherformat unverändert | [ ] |

## 8. Frontend zeigt den echten Backendstatus

| # | Test | Erwartung | ok |
|---|---|---|---|
| 8.1 | Receiver-Seite laden | genau **ein** Request auf `/api/system/state` (Netzwerk-Tab) | [ ] |
| 8.2 | Kein `setInterval`/Polling im Netzwerk-Tab | ja | [ ] |
| 8.3 | Schalter ändern, Seite neu laden | Änderung sofort sichtbar | [ ] |
| 8.4 | `registration_enabled = AUS` | Register-Button weg | [ ] |
| 8.5 | `allowed_session_month = AUS` | „30 Tage“ nicht wählbar | [ ] |
| 8.6 | `maintenance_mode = AN` als G | rotes Banner mit `maintenance_message` | [ ] |
| 8.7 | `account_required = AN` als G | Banner „Account erforderlich“ | [ ] |
| 8.8 | Account-Dienst stoppen (`systemctl stop`) | Receiver läuft weiter, Konsole: `fail-open`, **keine** Sperre | [ ] |
| 8.9 | Account-Dienst wieder starten | Status kommt zurück | [ ] |
| 8.10 | `dnx_system_state.js` doppelt einbinden | zweiter Load wird ignoriert (`DNX_SYSTEM_STATE_LOADED`) | [ ] |
| 8.11 | Bestehende Tool-Leiste/Scrollbar | unverändert, kein Zappeln beim Resize | [ ] |

## 9. Bestandsdaten (Kernanforderung)

| # | Test | Erwartung | ok |
|---|---|---|---|
| 9.1 | `SELECT role, COUNT(*) FROM users GROUP BY role` vor/nach Installation | identisch | [ ] |
| 9.2 | Alle Bestandsuser können sich weiter anmelden | ja | [ ] |
| 9.3 | Bestehende Sitzungen laufen weiter | ja | [ ] |
| 9.4 | `/admin/users`: DB-Rolle vs. wirksame Rolle | DB-Rolle unverändert, wirksam ggf. herabgestuft | [ ] |
| 9.5 | `audit_log`-Zeilenanzahl vor/nach Migration | nur **+0** (Migration auditiert nicht) | [ ] |
| 9.6 | `profile-policy.json` | unverändert (Checksumme) | [ ] |
| 9.7 | `secret` | unverändert (Checksumme) | [ ] |
| 9.8 | Zweite Migration ausführen | idempotent, Admin-Werte bleiben | [ ] |

## 10. Container und DSP-Schutz

| # | Test | Erwartung | ok |
|---|---|---|---|
| 10.1 | `docker exec owrx-8013 python3 -m py_compile …` für alle drei Module | ohne Fehler | [ ] |
| 10.2 | `d.status()` im Container | `source=access_settings`, `shared_logic=true`, `keys=40` | [ ] |
| 10.3 | `filter_dnx_properties({'frequency':1,'dnx_account_token':'x','key':'DNXAUTH:y'})` | `{'frequency': 1}` | [ ] |
| 10.4 | Receiver starten, Wasserfall läuft | kein `KeyError: dnx_account_token` im Log | [ ] |
| 10.5 | `handleSdrAvailable()` nutzt den Filter | keine `dnx_`-Werte in DSP-Properties | [ ] |
| 10.6 | Container neu erstellen, Overrides erneut installieren | Profilprüfung funktioniert wieder | [ ] |
| 10.7 | DB im Container umbenennen (Test!) | `source=fallback`, Defaults, **niemand gesperrt** | [ ] |

## 11. Gesamtabnahme v1.2.0

- [ ] Alle vier Wirkorte verhalten sich gleich: Dienst, Frontend, Container, Log
- [ ] `smoke_tests.sh` → 0 FAIL
- [ ] `python3 -m unittest discover -s tests -t .` → 86 Tests OK
- [ ] Kein neues Polling-Skript, Master-Tool-Row unverändert
- [ ] Keine IPs im öffentlichen 24-h-Log
- [ ] Keine Secrets/Backups im öffentlichen ZIP
- [ ] Paket im Projekt-Manager auf v1.2.0, SHA-256 veröffentlicht
- [ ] Rollback einmal geprobt (`rollback.sh --dry-run`)
- [ ] Neues datiertes Backup **nach** der Abnahme erstellt

---

## Automatisierter Teil (läuft ohne Server)

```bash
cd <USER_HOME>/dnx-system-control
python3 -m unittest discover -s tests -t . -v
```

Diese 86 Tests decken die Zeilen 2.3–2.13, 3.x, 4.1–4.7, 5.x, 6.x, 7.7–7.11,
9.1–9.8 und 10.3 bereits gegen eine nachgebaute Datenbank ab. Manuell bleiben
die Browser- und Container-Tests (1.x, 8.x, 10.1–10.2, 10.4–10.7).
