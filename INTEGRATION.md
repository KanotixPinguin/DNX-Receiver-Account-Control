# INTEGRATION – Systemsteuerung v1.2.0 in die bestehende Anlage einbauen

Zielsystem: `<SERVER-IP>` · Container `owrx-8013` · Account-Dienst Port 8096
Reihenfolge entspricht Kapitel 13 der Übergabe. Jeder Schritt ist einzeln
umkehrbar; vor Schritt 1 steht immer ein neues Backup.

> **Wichtig:** Kein Skript dieses Pakets verändert `app.py`, `init.js`,
> `connection.py` oder `dnx_access_verify.py` automatisch. Die Stellen sind
> unten exakt bezeichnet, die Änderungen bleiben in deiner Hand.

---

## Schritt 1 – Vollständiges neues Backup

```bash
cd $HOME/dnx-system-control
sudo ./scripts/install.sh --dry-run          # zeigt, was gesichert wird
sudo ./scripts/install.sh                    # legt Backups an + installiert
```

Backup-Ziel (konfigurierbar über `BACKUP_ROOT`):

```
$HOME/dnx-system-control-backups/<JJJJMMTT-HHMMSS>/
├── db/accounts-<Zeitstempel>.sqlite3   # konsistentes sqlite3-Backup
├── files/account-service/              # app.py, profile-policy.json, Helfer
├── files/plugin/                       # dnx_access.js/.css, dnx_system_state.js, init.js
├── container/                          # connection.py, client.py, dnx_access_verify.py, …
├── plugin-receiver-<Zeitstempel>.tar.gz
└── MANIFEST.sha256                     # Fingerabdrücke aller installierten Dateien
```

Zusätzlich das gewohnte Vollbackup der Übergabe ziehen:

```bash
sudo tar -czf $HOME/DNX-Account-Control-Backup-$(date +%Y%m%d-%H%M%S).tar.gz \
  /opt/owrx-docker/var/dnx-access-control /opt/owrx-docker/plugins/receiver
```

## Schritt 2 – `access_settings` und Defaults

Läuft automatisch in `install.sh`, kann aber einzeln ausgeführt werden:

```bash
cd /opt/owrx-docker/var/dnx-access-control
sudo python3 migrate_add_access_settings.py --dry-run   # zeigt alle 40 Schlüssel
sudo python3 migrate_add_access_settings.py             # Backup + Anlage + Beweis
```

Die Ausgabe enthält den Bestandsdaten-Beweis:

```
[VORHER]  integrity_check : ok
[VORHER]  Tabellen/Zeilen : {"audit_log": …, "sessions": …, "users": …}
[VORHER]  Rollenverteilung: {"users": {"admin": 1, "extended": 2, "user": 14}}
[BACKUP]  …/accounts-pre-access-settings-20261013-180000.sqlite3.bak
[NACHHER] integrity_check : ok
   Bestandsuser vor/nach  : identisch
OK: access_settings bereit, alle Bestandsdaten unverändert.
```

Bricht das Skript ab (Exit-Code ≠ 0), ist nichts verändert; Rückspiel mit
`--restore <backup>`.

## Schritt 3 – Admin-UI zum Lesen/Schreiben

**Zwei Zeilen in `/opt/owrx-docker/var/dnx-access-control/app.py`:**

```python
# --- DNX Systemsteuerung v1.2.0 -----------------------------------------
import dnx_system_control_integration as dnx_sc    # bei den anderen Imports
# ...
app = Flask(__name__)                              # bestehende Zeile
dnx_sc.install(app)                                # direkt danach
# ------------------------------------------------------------------------
```

`install()` registriert:

| Route | Zweck |
|---|---|
| `GET /admin/system` | das Panel (nur `admin`) |
| `GET /admin/system/static/<datei>` | CSS/JS des Panels (nur `admin`) |
| `GET /admin/api/system/settings` | Ist-Zustand, Metadaten, Auswirkung, CSRF-Token |
| `POST /admin/api/system/settings` | atomares Speichern + Audit |
| `POST /admin/api/system/restore-defaults` | Defaults zurückholen (`confirm=true`) |
| `GET /admin/api/system/impact` | Auswirkung auf Bestandskonten |
| `GET /api/system/state` | öffentlicher Status für das Receiver-Frontend |
| `GET /api/system/healthz` | Smoke-Test |

Falls deine Sitzungsvariablen anders heißen, explizit übergeben:

```python
dnx_sc.install(
    app,
    url_prefix="/admin",
    session_user_keys=("dnx_account", "username"),   # wie in app.py üblich
    session_role_keys=("dnx_role", "role"),
    enable_maintenance_guard=True,                   # 503 für Nicht-Admins
)
```

Oder eigener Provider (dann entscheidet ausschließlich dein Code):

```python
def mein_current_user():
    return {"username": aktueller_benutzer(), "role": aktuelle_rolle(),
            "ip": request.remote_addr, "user_agent": request.headers.get("User-Agent")}

dnx_sc.install(app, current_user=mein_current_user)
```

**Ohne gültige `admin`-Rolle bleibt der Bereich 403.** Wird kein Provider
gefunden und liefert die Sitzung nichts, ist das Panel gesperrt – gewollt.

Navigation von der bestehenden Adminseite aus (ein Link in deinem
`/admin`-Template):

```html
<a href="/admin/system">Systemsteuerung</a>
```

## Schritt 4 – Registrierung anbinden

In der bestehenden Registrierungsroute:

```python
# vor der Anlage des Kontos
zaehler = anzahl_registrierungen_seit(int(time.time()) - 3600)   # aus audit_log
ok, grund, reg = dnx_sc.registration_gate(zaehler)
if not ok:
    dnx_sc.audit_event("registration_denied", username=benutzername,
                       details={"reason": grund})
    return fehlerseite(reg["message"] or grund)

if reg["captcha"] and rechnung_falsch:
    return fehlerseite("Rechenaufgabe falsch")
if len(passwort) < dnx_sc.password_min_length():
    return fehlerseite("Passwort zu kurz")

rolle  = dnx_sc.initial_role()        # default_registration_role, mit Fallback
aktiv  = dnx_sc.initial_active()      # new_accounts_active
dauer  = dnx_sc.sanitize_session(form.get("duration"))
```

`registration_gate()` prüft `registration_enabled` **und** das Rate-Limit
(`registration_limit` / `registration_window_seconds`) in einem Aufruf.

## Schritt 5 – Sitzungsoptionen anbinden

```python
# Formular bauen (zeigt nur erlaubte Dauern)
optionen = dnx_sc.session_choices()
# [{"id": "browser", "value": "browser", "label": "Browser (Sitzungsende)"}, …]

# beim Login erzwingen (Server entscheidet, nicht das Formular)
dauer = dnx_sc.sanitize_session(request.form.get("duration"))
# nicht erlaubt -> fällt auf "browser" zurück
```

`revoke_sessions_on_change` steht bewusst auf **AUS**: bestehende Sitzungen
laufen weiter, sonst würden Bestandsuser beim ersten Umschalten rausfliegen.

## Schritt 6 – Rollenaktivierung anbinden

```python
user = dnx_sc.detect_user()
# user["stored_role"]  Rolle in der Datenbank (unverändert)
# user["role"]         wirksame Rolle nach den Schaltern
```

* `role_extended_enabled = AUS` → ein Extended-User zählt wirksam als `user`,
  sein Konto bleibt aber `extended` in der DB.
* `role_user_enabled = AUS` → wirksam `guest`.
* `downgrade_disabled_roles = AUS` → Rollen bleiben voll wirksam (Notausstieg,
  falls die Schalter versehentlich jemanden aussperren).
* `admin` und `guest` sind nie abschaltbar.

Für die Rollenverwaltung (Admin darf Rollen zuweisen):

```python
auswahl = dnx_sc.rules().selectable_roles(dnx_sc.settings())
```

## Schritt 7 – Frontendstatus anbinden

Datei liegt nach der Installation unter

```
/opt/owrx-docker/plugins/receiver/dnx_access_control/dnx_system_state.js
```

Einbindung in `init.js` **innerhalb eines markierten Blocks** (keine neuen
Polling-Skripte, Kapitel 14):

```javascript
// DNX_SYSTEM_CONTROL_START
(function () {
  if (window.DNX_SYSTEM_STATE_LOADED) { return; }
  var s = document.createElement("script");
  s.src = "/static/plugins/receiver/dnx_access_control/dnx_system_state.js";
  s.async = true;
  document.head.appendChild(s);
})();
// DNX_SYSTEM_CONTROL_END
```

Der Baustein holt **einmal** `http://<host>:8096/api/system/state` (CORS ist am
Endpunkt offen, Cookies werden nicht gebraucht) und

* blendet den Registrier-Button aus, wenn `registration_enabled = false`,
* deaktiviert Sitzungsdauern, die nicht erlaubt sind,
* zeigt ein Banner bei Wartungsmodus / Account-Zwang / Profilsteuerung AUS,
* versteckt den Link zum öffentlichen Aktivitätslog, wenn deaktiviert,
* stellt `window.DNXSystemState.decide(profilName)` als **Vorab**prüfung bereit
  (verbindlich bleibt der Server),
* macht bei nicht erreichbarem Dienst **nichts** (fail-open) und meldet
  `source: "unavailable"` in der Konsole.

Eigenes Ereignis zum Anhängen (z. B. aus `dnx_access.js`):

```javascript
document.addEventListener("dnx:system-state", function (ev) {
  var d = ev.detail;      // { ok, source, state, rules, role, refresh, decide }
});
window.DNXSystemState.setRole("extended");   // nach erfolgreichem Login
```

## Schritt 8 – Backend-`verify_profile()` anbinden

Im Container `owrx-8013` liegen nach der Installation:

```
/usr/lib/python3/dist-packages/owrx/dnx_system_verify.py
/usr/lib/python3/dist-packages/owrx/dnx_sys_store.py    (= settings_store.py)
/usr/lib/python3/dist-packages/owrx/dnx_sys_rules.py    (= access_rules.py)
```

Persistente Kopien (gegen Container-Neuerstellung, Kapitel 14):

```
/opt/owrx-docker/server-overrides/system-control/
```

Die DB ist über den Bind-Mount sichtbar:
`/opt/owrx-docker/var` → `/var/lib/openwebrx`, also
`/var/lib/openwebrx/dnx-access-control/accounts.sqlite3`.

In `dnx_access_verify.py`:

```python
from owrx.dnx_system_verify import verify_profile, audit_decision, split_auth_key

def dnx_pruefe_profil(profil_name, token):
    daten = token_pruefen(token)            # bestehende Signaturprüfung
    if not daten:
        return {"allow": False, "reason": "token_invalid", "event": "profile_denied"}
    return verify_profile(
        profil_name,
        role=daten.get("role", "guest"),
        authenticated=True,
        username=daten.get("username"),
    )
```

In `connection.py` bei `selectprofile`:

```python
from owrx.dnx_system_verify import split_auth_key, filter_dnx_properties

token = split_auth_key(params.get("key"))    # "DNXAUTH:<token>" -> Token
decision = dnx_pruefe_profil(profil, token)
if not decision["allow"]:
    audit_schreiben(decision["event"] or "profile_denied",
                    details={"profile": profil, "reason": decision["reason"]})
    return ablehnen(decision["reason"])
audit_schreiben("profile_change", details={"profile": profil,
                                           "reason": decision["reason"]})
```

**DSP-Schutz** (bekannter Fehler `KeyError: dnx_account_token`, Kapitel 4):

```python
from owrx.dnx_system_verify import filter_dnx_properties

# bestehender connectionproperties-Patch:
props = filter_dnx_properties(self.connectionProperties)

# und zusätzlich in handleSdrAvailable():
self.getDsp().setProperties(filter_dnx_properties(self.connectionProperties))
```

`filter_dnx_properties()` entfernt jeden Schlüssel mit Präfix `dnx_`/`dnx-`/
`dnxauth` **und** `key`, wenn der Wert mit `DNXAUTH:` beginnt. Damit kann kein
Account-Token mehr in DSP-Properties landen.

Diagnose im Container:

```bash
docker exec owrx-8013 python3 -c \
  "from owrx import dnx_system_verify as d; import json; print(json.dumps(d.status(), indent=2))"
```

Erwartet: `"source": "access_settings"`, `"shared_logic": true`, `"keys": 40`.
Steht dort `"fallback"`, stimmt der DB-Pfad nicht oder die beiden
`dnx_sys_*`-Module fehlen → dann gelten Defaults (fail-open, niemand gesperrt).

## Schritt 9 – Wartungs-/Bypass-Test

```bash
TOKEN=$(curl -s -b cookies.txt http://127.0.0.1:8096/admin/api/system/settings \
        | python3 -c 'import json,sys;print(json.load(sys.stdin)["csrf_token"])')

# Wartungsmodus einschalten
curl -s -b cookies.txt -c cookies.txt -H "X-CSRF-Token: $TOKEN" \
  -H 'Content-Type: application/json' -H "Origin: http://127.0.0.1:8096" \
  -d '{"settings":{"maintenance_mode":true}}' \
  http://127.0.0.1:8096/admin/api/system/settings | python3 -m json.tool | head -20

# Gast muss abgewiesen werden, Admin muss durchkommen
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8013/            # Receiver-Seite
curl -s "http://127.0.0.1:8096/api/profile/select?profile=80m" | python3 -m json.tool

# danach zurück
curl -s -b cookies.txt -H "X-CSRF-Token: $TOKEN" -H 'Content-Type: application/json' \
  -H "Origin: http://127.0.0.1:8096" -d '{"confirm":true}' \
  http://127.0.0.1:8096/admin/api/system/restore-defaults >/dev/null
```

Zusätzlich im Browser prüfen: `maintenance_admin_bypass = AUS` → auch der Admin
sieht die 503-Seite, **aber** `/admin/system` bleibt erreichbar (sonst käme
niemand mehr aus dem Wartungsmodus heraus).

## Schritt 10 – Audit der Einstellungsänderungen

Jede Änderung schreibt eine Zeile `admin_access_settings` in `audit_log`:

```bash
sqlite3 /opt/owrx-docker/var/dnx-access-control/accounts.sqlite3 \
  "SELECT datetime(ts,'unixepoch','+2 hours'), username, details FROM audit_log
   WHERE event='admin_access_settings' ORDER BY id DESC LIMIT 5;"
```

`details` enthält den Diff (`{"changed":{"maintenance_mode":{"label":"Wartungsmodus","old":false,"new":true}},"count":1,"version":"1.2.0"}`).
Sichtbar auch in `/admin/logbook`.

Der Audit-Writer erkennt die Spaltennamen deiner `audit_log`-Tabelle selbst
(`ts`/`timestamp`/`created_at`, `event`/`type`/`action`, `username`/`account`,
`ip`/`remote_addr`, `user_agent`/`agent`, `details`/`data`/`extra`). Bitte
einmal gegenprüfen:

```bash
sqlite3 /opt/owrx-docker/var/dnx-access-control/accounts.sqlite3 'PRAGMA table_info(audit_log);'
```

## Schritt 11 – Tests Gast/User/Extended/Admin

→ **TESTMATRIX.md** (fertig abhakbar)

## Schritt 12 – Paket aktualisieren

```bash
cd $HOME/dnx-system-control
sha256sum account-service/dnx_system_control/*.py \
          account-service/dnx_system_control/web/* \
          frontend/dnx_access_control/dnx_system_state.js \
          owrx/dnx_system_verify.py \
          integration/dnx_system_control_integration.py > PAKET-v1.2.0.sha256
```

Versionsstände an drei Orten konsistent halten: `settings_store.py`
(`PACKAGE_VERSION`), Panel-Headline, Download-Eintrag im Projekt-Manager
(Port 8094).

## Schritt 13 – Öffentlichen Download und SHA-256 aktualisieren

Im Projekt-Manager (`http://<SERVER-IP>:8094/`) das Paket
`DNX Receiver Account Control` auf **v1.2.0** setzen, ZIP nach
`/opt/dnx-project-manager/files` legen und in `projects.sqlite3` registrieren.

**Ausschlussliste für das ZIP** (Kapitel 14):

```
secret, *.sqlite3, *.bak, profile-policy.json, Backups/, __pycache__/,
dnx_system_control_integration.py? -> nein, gehört ins Paket
```

Prüfen vor dem Hochladen:

```bash
unzip -l DNX-Receiver-Account-Control-v1.2.0.zip | grep -Ei 'secret|sqlite|\.bak|backup' \
  && echo "STOP: geheime Daten im ZIP" || echo "ZIP sauber"
sha256sum DNX-Receiver-Account-Control-v1.2.0.zip
```

---

## Rückbau

```bash
sudo ./scripts/rollback.sh --list            # verfügbare Backups
sudo ./scripts/rollback.sh --dry-run         # was würde passieren
sudo ./scripts/rollback.sh                   # Dateien zurück (DB bleibt!)
sudo ./scripts/rollback.sh --with-db         # zusätzlich accounts.sqlite3
```

Die zwei Zeilen in `app.py` wieder entfernen und
`sudo systemctl restart dnx-access-control.service`. Die Tabelle
`access_settings` kann gefahrlos in der DB bleiben – sie wird von nichts anderem
gelesen.

## Häufige Stolperstellen

| Symptom | Ursache | Lösung |
|---|---|---|
| `/admin/system` → 403 | `install()` fehlt oder Rolle nicht `admin` | `grep dnx_sc.install app.py`, `detect_user()`-Ausgabe prüfen |
| `access_settings fehlt` | Migration nicht gelaufen | `migrate_add_access_settings.py` |
| Panel speichert nicht, 403 `csrf` | Seite zu lange offen / Cookie verloren | „Neu laden“ |
| Panel speichert nicht, 400 | Wert außerhalb `min`/`max` oder unbekannte Taste | Feldfehler im Panel lesen |
| Container: `"source": "fallback"` | DB-Pfad im Container falsch oder `dnx_sys_*` fehlen | `docker exec … d.status()`, Pfade in `DNX_ACCOUNTS_DB` |
| Nach Container-Neubau keine Profilprüfung | Overrides nicht neu installiert | `install.sh` erneut (nur Container-Teil) |
| `KeyError: dnx_account_token` | `filter_dnx_properties()` fehlt an einer Stelle | beide Stellen patchen (Kapitel 4/8) |
| Alles gesperrt nach `profile_control_enabled=AUS` | darf nicht passieren | fail-open greift; falls doch: `settings_fail_open` und `status()` prüfen |
