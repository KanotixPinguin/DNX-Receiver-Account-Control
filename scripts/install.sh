#!/usr/bin/env bash
# =============================================================================
# DNX Systemsteuerung – Installation (v1.2.0)
#
# Was dieses Skript tut:
#   1. datiertes Backup aller Dateien, die es anfasst (inkl. accounts.sqlite3)
#   2. Paket nach /opt/owrx-docker/var/dnx-access-control/dnx_system_control/
#   3. Einbau-Helfer dnx_system_control_integration.py neben app.py
#   4. Receiver-Frontend-Baustein dnx_system_state.js ins Plugin-Verzeichnis
#   5. Migration access_settings (erst --dry-run, dann echt)
#   6. Backend-Module in den Container owrx-8013 (docker cp) + Override-Kopien
#   7. Syntaxchecks, Dienstneustart, Smoke-Tests, SHA-256-Manifest
#
# Was dieses Skript NICHT tut:
#   * app.py wird niemals automatisch umgeschrieben. Es prueft nur, ob die zwei
#     Einbauzeilen vorhanden sind, und gibt sie sonst aus.
#   * es loescht keine Backups, keine Konten, keine Logs.
#
# Aufruf:
#   sudo ./scripts/install.sh --dry-run      # alles anzeigen, nichts schreiben
#   sudo ./scripts/install.sh                # installieren
#   sudo ./scripts/install.sh --check        # nur Ist-Zustand pruefen
#   sudo ./scripts/install.sh --skip-container
# =============================================================================
set -euo pipefail

# ------------------------------------------------------------ Konfiguration --
HOST_BASE="${HOST_BASE:-/opt/owrx-docker}"
ACC_DIR="${ACC_DIR:-$HOST_BASE/var/dnx-access-control}"
PLUGIN_DIR="${PLUGIN_DIR:-$HOST_BASE/plugins/receiver/dnx_access_control}"
OVERRIDE_DIR="${OVERRIDE_DIR:-$HOST_BASE/server-overrides}"
CONTAINER="${CONTAINER:-owrx-8013}"
OWRX_PKG="${OWRX_PKG:-/usr/lib/python3/dist-packages/owrx}"
SERVICE="${SERVICE:-dnx-access-control.service}"
BACKUP_ROOT="${BACKUP_ROOT:-$HOME/dnx-system-control-backups}"
ACCOUNT_PORT="${ACCOUNT_PORT:-8096}"
OWRX_PORT="${OWRX_PORT:-8013}"

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP_DIR="$BACKUP_ROOT/$STAMP"

DRY=0; ASSUME_YES=0; SKIP_CONTAINER=0; SKIP_MIGRATE=0; NO_RESTART=0; CHECK_ONLY=0

# ------------------------------------------------------------------- Helfer --
c_red=$'\033[31m'; c_grn=$'\033[32m'; c_ylw=$'\033[33m'; c_blu=$'\033[36m'; c_off=$'\033[0m'
log()  { printf '%s[%s]%s %s\n' "$c_blu" "INFO" "$c_off" "$*"; }
ok()   { printf '%s[%s]%s %s\n' "$c_grn" " OK " "$c_off" "$*"; }
warn() { printf '%s[%s]%s %s\n' "$c_ylw" "WARN" "$c_off" "$*"; }
die()  { printf '%s[%s]%s %s\n' "$c_red" "FEHL" "$c_off" "$*" >&2; exit 1; }
run()  {
  if [[ $DRY -eq 1 ]]; then printf '   %s(dry-run)%s %s\n' "$c_ylw" "$c_off" "$*"; return 0; fi
  "$@"
}

usage() {
  sed -n '2,30p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run)        DRY=1 ;;
    -y|--yes)         ASSUME_YES=1 ;;
    --skip-container) SKIP_CONTAINER=1 ;;
    --skip-migrate)   SKIP_MIGRATE=1 ;;
    --no-restart)     NO_RESTART=1 ;;
    --check)          CHECK_ONLY=1 ;;
    --backup-root)    BACKUP_ROOT="$2"; BACKUP_DIR="$BACKUP_ROOT/$STAMP"; shift ;;
    -h|--help)        usage ;;
    *) die "Unbekannte Option: $1 (siehe --help)" ;;
  esac
  shift
done

# --------------------------------------------------------------- Vorkontrolle
preflight() {
  log "Quelle            : $SRC"
  log "Account-Verzeichnis: $ACC_DIR"
  log "Plugin-Verzeichnis : $PLUGIN_DIR"
  log "Container          : $CONTAINER"
  log "Backup-Ziel        : $BACKUP_DIR"
  [[ $DRY -eq 1 ]] && warn "DRY-RUN: es wird nichts geschrieben"

  command -v python3 >/dev/null || die "python3 fehlt"
  [[ -f "$SRC/account-service/dnx_system_control/settings_store.py" ]] \
    || die "Paket unvollstaendig: $SRC/account-service/dnx_system_control fehlt"
  [[ -f "$SRC/owrx/dnx_system_verify.py" ]] || die "owrx/dnx_system_verify.py fehlt"
  [[ -f "$SRC/frontend/dnx_access_control/dnx_system_state.js" ]] \
    || die "frontend/dnx_access_control/dnx_system_state.js fehlt"

  [[ -d "$ACC_DIR" ]]    || warn "$ACC_DIR existiert nicht – Pfade pruefen"
  [[ -f "$ACC_DIR/app.py" ]] || warn "$ACC_DIR/app.py nicht gefunden"
  [[ -d "$PLUGIN_DIR" ]] || warn "$PLUGIN_DIR existiert nicht"

  if [[ $SKIP_CONTAINER -eq 0 ]]; then
    command -v docker >/dev/null || { warn "docker fehlt – Container-Teil wird uebersprungen"; SKIP_CONTAINER=1; }
    if [[ $SKIP_CONTAINER -eq 0 ]]; then
      docker ps --filter "name=$CONTAINER" --format '{{.Names}}' | grep -q "$CONTAINER" \
        || warn "Container $CONTAINER laeuft nicht – docker cp wird uebersprungen"
    fi
  fi
  ok "Vorkontrolle abgeschlossen"
  return 0
}

# ------------------------------------------------------------------- Backups --
backup_file() {
  local f="$1" tag="${2:-datei}"
  [[ -e "$f" ]] || { warn "Backup uebersprungen (nicht vorhanden): $f"; return 0; }
  local dest="$BACKUP_DIR/files/$tag"
  run mkdir -p "$dest"
  run cp -a "$f" "$dest/"
  log "Backup: $f -> $dest/"
}

backup_sqlite() {
  local db="$ACC_DIR/accounts.sqlite3"
  [[ -f "$db" ]] || { warn "keine accounts.sqlite3 gefunden"; return 0; }
  run mkdir -p "$BACKUP_DIR/db"
  if [[ $DRY -eq 0 ]]; then
    if command -v sqlite3 >/dev/null; then
      sqlite3 "$db" ".backup '$BACKUP_DIR/db/accounts-$STAMP.sqlite3'" \
        || cp -a "$db" "$BACKUP_DIR/db/accounts-$STAMP.sqlite3"
    else
      python3 - "$db" "$BACKUP_DIR/db/accounts-$STAMP.sqlite3" <<'PY'
import sqlite3, sys
src = sqlite3.connect(sys.argv[1], timeout=60)
dst = sqlite3.connect(sys.argv[2], timeout=60)
with dst:
    src.backup(dst)
src.close(); dst.close()
PY
    fi
    ok "DB-Backup: $BACKUP_DIR/db/accounts-$STAMP.sqlite3"
  else
    log "(dry-run) DB-Backup nach $BACKUP_DIR/db/accounts-$STAMP.sqlite3"
  fi
}

backup_container_files() {
  if [[ $SKIP_CONTAINER -eq 1 ]]; then return 0; fi
  docker ps --filter "name=$CONTAINER" --format '{{.Names}}' | grep -q "$CONTAINER" || return 0
  local f dest="$BACKUP_DIR/container"
  run mkdir -p "$dest"
  for f in connection.py client.py dnx_access_verify.py dnx_system_verify.py \
           dnx_sys_store.py dnx_sys_rules.py controllers/settings/bookmarks.py \
           controllers/visitorstatus.py; do
    if [[ $DRY -eq 0 ]]; then
      if docker exec "$CONTAINER" test -f "$OWRX_PKG/$f" 2>/dev/null; then
        docker cp "$CONTAINER:$OWRX_PKG/$f" "$dest/$(echo "$f" | tr '/' '_')" \
          && log "Container-Backup: $f"
      fi
    else
      log "(dry-run) Container-Backup: $OWRX_PKG/$f"
    fi
  done
}

make_backups() {
  log "=== Schritt 1: Backups ==="
  run mkdir -p "$BACKUP_DIR"
  backup_sqlite
  backup_file "$ACC_DIR/app.py" "account-service"
  backup_file "$ACC_DIR/profile-policy.json" "account-service"
  backup_file "$ACC_DIR/dnx_system_control_integration.py" "account-service"
  backup_file "$PLUGIN_DIR/dnx_system_state.js" "plugin"
  backup_file "$PLUGIN_DIR/dnx_access.js" "plugin"
  backup_file "$PLUGIN_DIR/dnx_access.css" "plugin"
  backup_file "$HOST_BASE/plugins/receiver/init.js" "plugin"
  if [[ $DRY -eq 0 && -d "$PLUGIN_DIR" ]]; then
    tar -czf "$BACKUP_DIR/plugin-receiver-$STAMP.tar.gz" -C "$HOST_BASE/plugins/receiver" . \
      && ok "Plugin-Gesamtbackup: plugin-receiver-$STAMP.tar.gz"
  fi
  backup_container_files
  if [[ $DRY -eq 0 ]]; then ok "Backups liegen in $BACKUP_DIR"; fi
  return 0
}

# -------------------------------------------------------------- Installation --
copy_pkg() {
  log "=== Schritt 2: Account-Dienst ==="
  run mkdir -p "$ACC_DIR/dnx_system_control/web"
  run cp -a "$SRC/account-service/dnx_system_control/__init__.py"      "$ACC_DIR/dnx_system_control/"
  run cp -a "$SRC/account-service/dnx_system_control/settings_store.py" "$ACC_DIR/dnx_system_control/"
  run cp -a "$SRC/account-service/dnx_system_control/access_rules.py"  "$ACC_DIR/dnx_system_control/"
  run cp -a "$SRC/account-service/dnx_system_control/admin_api.py"     "$ACC_DIR/dnx_system_control/"
  run cp -a "$SRC/account-service/dnx_system_control/web/." "$ACC_DIR/dnx_system_control/web/"
  run cp -a "$SRC/account-service/migrate_add_access_settings.py"      "$ACC_DIR/"
  run cp -a "$SRC/integration/dnx_system_control_integration.py"       "$ACC_DIR/"
  ok "Paket installiert nach $ACC_DIR/dnx_system_control/"
  return 0
}

copy_frontend() {
  log "=== Schritt 3: Receiver-Frontend ==="
  run mkdir -p "$PLUGIN_DIR"
  run cp -a "$SRC/frontend/dnx_access_control/dnx_system_state.js" "$PLUGIN_DIR/"
  ok "dnx_system_state.js installiert nach $PLUGIN_DIR/"
  return 0
}

do_migrate() {
  if [[ $SKIP_MIGRATE -eq 1 ]]; then warn "Migration uebersprungen (--skip-migrate)"; return 0; fi
  log "=== Schritt 4: Migration access_settings ==="
  if [[ $DRY -eq 1 ]]; then
    python3 "$SRC/account-service/migrate_add_access_settings.py" --db "$ACC_DIR/accounts.sqlite3" --dry-run \
      || warn "Dry-Run der Migration nicht moeglich (DB nicht erreichbar?)"
    return 0
  fi
  python3 "$ACC_DIR/migrate_add_access_settings.py" --db "$ACC_DIR/accounts.sqlite3" \
    --backup-dir "$BACKUP_DIR/db" || die "Migration fehlgeschlagen – nichts geaendert lassen, Backup pruefen"
  ok "Migration abgeschlossen"
  return 0
}

copy_container() {
  if [[ $SKIP_CONTAINER -eq 1 ]]; then warn "Container-Teil uebersprungen"; return 0; fi
  log "=== Schritt 5: OpenWebRX-Container ==="
  run mkdir -p "$OVERRIDE_DIR/system-control"
  run cp -a "$SRC/owrx/dnx_system_verify.py"                      "$OVERRIDE_DIR/system-control/"
  run cp -a "$SRC/account-service/dnx_system_control/settings_store.py" "$OVERRIDE_DIR/system-control/dnx_sys_store.py"
  run cp -a "$SRC/account-service/dnx_system_control/access_rules.py"   "$OVERRIDE_DIR/system-control/dnx_sys_rules.py"

  docker ps --filter "name=$CONTAINER" --format '{{.Names}}' | grep -q "$CONTAINER" || {
    warn "Container laeuft nicht – Override-Kopien liegen bereit unter $OVERRIDE_DIR/system-control"
    return 0
  }
  if [[ $DRY -eq 0 ]]; then
    docker cp "$OVERRIDE_DIR/system-control/dnx_system_verify.py" "$CONTAINER:$OWRX_PKG/dnx_system_verify.py"
    docker cp "$OVERRIDE_DIR/system-control/dnx_sys_store.py"     "$CONTAINER:$OWRX_PKG/dnx_sys_store.py"
    docker cp "$OVERRIDE_DIR/system-control/dnx_sys_rules.py"     "$CONTAINER:$OWRX_PKG/dnx_sys_rules.py"
    ok "Module in den Container kopiert"
    log "Hinweis: nach jeder Container-Neuerstellung erneut ausfuehren (Kapitel 14)"
  else
    log "(dry-run) docker cp nach $CONTAINER:$OWRX_PKG/"
  fi
  return 0
}

# ------------------------------------------------------------------- Checks --
syntax_checks() {
  log "=== Schritt 6: Syntaxchecks ==="
  if [[ $DRY -eq 0 && -d "$ACC_DIR/dnx_system_control" ]]; then
    python3 -m py_compile "$ACC_DIR"/dnx_system_control/*.py "$ACC_DIR/migrate_add_access_settings.py" \
      "$ACC_DIR/dnx_system_control_integration.py" && ok "py_compile Host ok"
  else
    python3 -m py_compile "$SRC"/account-service/dnx_system_control/*.py \
      "$SRC"/account-service/migrate_add_access_settings.py \
      "$SRC"/integration/dnx_system_control_integration.py \
      "$SRC"/owrx/dnx_system_verify.py && ok "py_compile Quelle ok"
  fi
  if command -v node >/dev/null; then
    node --check "$SRC/frontend/dnx_access_control/dnx_system_state.js" && ok "node --check Frontend ok"
    node --check "$SRC/account-service/dnx_system_control/web/dnx_system_control.js" && ok "node --check Panel ok"
  else
    warn "node fehlt – JavaScript-Syntaxcheck uebersprungen"
  fi
  if [[ $SKIP_CONTAINER -eq 0 ]]; then
    docker ps --filter "name=$CONTAINER" --format '{{.Names}}' | grep -q "$CONTAINER" && {
      if [[ $DRY -eq 0 ]]; then
        docker exec "$CONTAINER" python3 -m py_compile \
          "$OWRX_PKG/dnx_system_verify.py" "$OWRX_PKG/dnx_sys_store.py" "$OWRX_PKG/dnx_sys_rules.py" \
          && ok "py_compile Container ok"
      fi
    }
  fi
  return 0
}

restart_service() {
  if [[ $NO_RESTART -eq 1 ]]; then warn "Dienstneustart uebersprungen (--no-restart)"; return 0; fi
  log "=== Schritt 7: Dienst neu starten ==="
  if command -v systemctl >/dev/null; then
    run systemctl restart "$SERVICE"
    sleep 2
    systemctl is-active "$SERVICE" >/dev/null && ok "$SERVICE ist aktiv" \
      || warn "$SERVICE ist NICHT aktiv – sofort rollback.sh pruefen"
  else
    warn "systemctl fehlt – Dienst manuell neu starten"
  fi
  return 0
}

smoke() {
  log "=== Schritt 8: Smoke-Tests ==="
  if [[ -x "$SRC/scripts/smoke_tests.sh" ]]; then
    "$SRC/scripts/smoke_tests.sh" --short || warn "Smoke-Tests mit Warnungen beendet"
  else
    bash "$SRC/scripts/smoke_tests.sh" --short || warn "Smoke-Tests mit Warnungen beendet"
  fi
  return 0
}

manifest() {
  if [[ $DRY -eq 1 ]]; then return 0; fi
  log "=== Schritt 9: Manifest ==="
  {
    echo "# DNX Systemsteuerung $STAMP"
    echo "# Paketversion: 1.2.0"
    find "$ACC_DIR/dnx_system_control" -type f -name '*.py' -o -type f -name '*.js' \
      -o -type f -name '*.css' -o -type f -name '*.html' 2>/dev/null | sort | while read -r f; do
        sha256sum "$f"
      done
    [[ -f "$PLUGIN_DIR/dnx_system_state.js" ]] && sha256sum "$PLUGIN_DIR/dnx_system_state.js"
    [[ -f "$ACC_DIR/dnx_system_control_integration.py" ]] && sha256sum "$ACC_DIR/dnx_system_control_integration.py"
  } > "$BACKUP_DIR/MANIFEST.sha256" 2>/dev/null || true
  ok "Manifest: $BACKUP_DIR/MANIFEST.sha256"
}

app_hint() {
  log "=== app.py-Einbau pruefen ==="
  if [[ -f "$ACC_DIR/app.py" ]] && grep -q "dnx_system_control_integration" "$ACC_DIR/app.py"; then
    ok "app.py bindet die Systemsteuerung bereits ein"
  else
    warn "app.py enthaelt den Einbau noch NICHT. Bitte diese zwei Zeilen ergaenzen:"
    cat <<'EOF'

    # --- DNX Systemsteuerung (v1.2.0) -------------------------------------
    import dnx_system_control_integration as dnx_sc   # nach den bestehenden Imports
    dnx_sc.install(app)                               # direkt nach app = Flask(__name__)
    # -----------------------------------------------------------------------

EOF
    warn "Danach: sudo systemctl restart $SERVICE"
  fi
  return 0
}

check_only() {
  log "=== Ist-Zustand ==="
  [[ -f "$ACC_DIR/dnx_system_control/settings_store.py" ]] && ok "Paket vorhanden" || warn "Paket fehlt"
  [[ -f "$PLUGIN_DIR/dnx_system_state.js" ]] && ok "Frontend-Baustein vorhanden" || warn "Frontend-Baustein fehlt"
  [[ -f "$ACC_DIR/dnx_system_control_integration.py" ]] && ok "Einbau-Helfer vorhanden" || warn "Einbau-Helfer fehlt"
  if [[ -f "$ACC_DIR/app.py" ]]; then
    grep -q "dnx_sc.install(app" "$ACC_DIR/app.py" && ok "app.py: install() gefunden" \
      || warn "app.py: install() fehlt"
    grep -q "dnx_current_user" "$ACC_DIR/app.py" && ok "app.py: Provider fuer dnxac_session vorhanden" \
      || warn "app.py: Provider fehlt (Panel bleibt auf guest) -> scripts/setup_app.py ausfuehren"
    grep -q "dnx_sc.registration_gate" "$ACC_DIR/app.py" && ok "app.py: Schalter verdrahtet" \
      || warn "app.py: Schalter noch nicht verdrahtet -> scripts/setup_app.py ausfuehren"
  fi
  if [[ -f "$ACC_DIR/dnx_system_control_integration.py" ]]; then
    grep -q "def session_options_html" "$ACC_DIR/dnx_system_control_integration.py" \
      && ok "Einbau-Helfer aktuell (session_options_html vorhanden)" \
      || warn "Einbau-Helfer ist eine ALTE Version: setup_app.py wuerde fehlschlagen. Zuerst install.sh --yes"
  fi
  if [[ -f "$ACC_DIR/accounts.sqlite3" ]] && command -v python3 >/dev/null; then
    python3 - "$ACC_DIR/accounts.sqlite3" <<'PY'
import sqlite3, sys
conn = sqlite3.connect(sys.argv[1])
tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")]
if "access_settings" in tables:
    n = conn.execute("SELECT COUNT(*) FROM access_settings").fetchone()[0]
    print("   access_settings: vorhanden, %d Schluessel" % n)
else:
    print("   access_settings: FEHLT -> Migration noetig")
print("   users: %s" % (conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
                         if "users" in tables else "n/a"))
PY
  fi
  command -v systemctl >/dev/null && systemctl is-active "$SERVICE" >/dev/null \
    && ok "$SERVICE aktiv" || warn "$SERVICE nicht aktiv"
  [[ $SKIP_CONTAINER -eq 0 ]] && command -v docker >/dev/null && \
    docker exec "$CONTAINER" test -f "$OWRX_PKG/dnx_system_verify.py" 2>/dev/null \
    && ok "Container-Modul vorhanden" || warn "Container-Modul fehlt"
  curl -s -o /dev/null -w '   /api/system/healthz -> %{http_code}\n' \
    "http://127.0.0.1:$ACCOUNT_PORT/api/system/healthz" || true
}

# ---------------------------------------------------------------------- Main --
main() {
  echo
  echo "=============================================================="
  echo " DNX Receiver Account Control – Systemsteuerung v1.2.0"
  echo "=============================================================="
  preflight
  if [[ $CHECK_ONLY -eq 1 ]]; then check_only; exit 0; fi

  if [[ $DRY -eq 0 && $ASSUME_YES -eq 0 ]]; then
    printf '%sFortfahren mit Installation? Backups werden angelegt. [j/N]%s ' "$c_ylw" "$c_off"
    read -r antwort
    [[ "$antwort" =~ ^[jJyY] ]] || die "Abbruch durch Benutzer"
  fi

  make_backups
  copy_pkg
  copy_frontend
  do_migrate
  copy_container
  syntax_checks
  app_hint
  restart_service
  smoke
  manifest
  echo
  ok "Fertig. Admin-Bereich: http://$(hostname -I 2>/dev/null | awk '{print $1}'):$ACCOUNT_PORT/admin/system"
  log "Rollback bei Problemen: sudo ./scripts/rollback.sh --list"
}

main "$@"
