#!/usr/bin/env bash
# =============================================================================
# DNX Systemsteuerung – Rollback
#
# Spielt ein Backup aus $BACKUP_ROOT zurueck. Ohne --with-db wird die
# accounts.sqlite3 NICHT angetastt (Konten und Logs bleiben erhalten).
#
# Aufruf:
#   sudo ./scripts/rollback.sh --list
#   sudo ./scripts/rollback.sh --dry-run
#   sudo ./scripts/rollback.sh                     # neuestes Backup
#   sudo ./scripts/rollback.sh --restore 20261013-171500
#   sudo ./scripts/rollback.sh --with-db           # inkl. accounts.sqlite3
# =============================================================================
set -euo pipefail

HOST_BASE="${HOST_BASE:-/opt/owrx-docker}"
ACC_DIR="${ACC_DIR:-$HOST_BASE/var/dnx-access-control}"
PLUGIN_DIR="${PLUGIN_DIR:-$HOST_BASE/plugins/receiver/dnx_access_control}"
OVERRIDE_DIR="${OVERRIDE_DIR:-$HOST_BASE/server-overrides}"
CONTAINER="${CONTAINER:-owrx-8013}"
OWRX_PKG="${OWRX_PKG:-/usr/lib/python3/dist-packages/owrx}"
SERVICE="${SERVICE:-dnx-access-control.service}"
BACKUP_ROOT="${BACKUP_ROOT:-$HOME/dnx-system-control-backups}"

DRY=0; WITH_DB=0; TARGET=""; NO_RESTART=0

c_red=$'\033[31m'; c_grn=$'\033[32m'; c_ylw=$'\033[33m'; c_blu=$'\033[36m'; c_off=$'\033[0m'
log()  { printf '%s[%s]%s %s\n' "$c_blu" "INFO" "$c_off" "$*"; }
ok()   { printf '%s[%s]%s %s\n' "$c_grn" " OK " "$c_off" "$*"; }
warn() { printf '%s[%s]%s %s\n' "$c_ylw" "WARN" "$c_off" "$*"; }
die()  { printf '%s[%s]%s %s\n' "$c_red" "FEHL" "$c_off" "$*" >&2; exit 1; }
run()  { if [[ $DRY -eq 1 ]]; then printf '   %s(dry-run)%s %s\n' "$c_ylw" "$c_off" "$*"; return 0; fi; "$@"; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --list)       list_only=1 ;;
    --dry-run)    DRY=1 ;;
    --with-db)    WITH_DB=1 ;;
    --no-restart) NO_RESTART=1 ;;
    --restore)    TARGET="$2"; shift ;;
    --backup-root) BACKUP_ROOT="$2"; shift ;;
    -h|--help)    sed -n '2,16p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "Unbekannte Option: $1" ;;
  esac
  shift
done

[[ -d "$BACKUP_ROOT" ]] || die "Kein Backup-Verzeichnis: $BACKUP_ROOT"

list_backups() {
  log "Verfuegbare Backups in $BACKUP_ROOT:"
  local d
  for d in $(ls -1d "$BACKUP_ROOT"/*/ 2>/dev/null | sort -r); do
    local name size files
    name="$(basename "$d")"
    size="$(du -sh "$d" 2>/dev/null | cut -f1)"
    files="$(find "$d" -type f 2>/dev/null | wc -l)"
    printf '   %s  %-16s %6s  %s Dateien%s\n' "*" "$name" "$size" "$files" \
      "$([[ -f "$d/MANIFEST.sha256" ]] && echo '  + Manifest')"
  done
}

if [[ "${list_only:-0}" -eq 1 ]]; then list_backups; exit 0; fi

if [[ -z "$TARGET" ]]; then
  TARGET="$(ls -1d "$BACKUP_ROOT"/*/ 2>/dev/null | sort -r | head -1 || true)"
  [[ -n "$TARGET" ]] || die "Kein Backup gefunden"
  TARGET="$(basename "$TARGET")"
  log "Kein Backup angegeben – neuestes gewaehlt: $TARGET"
fi

DIR="$BACKUP_ROOT/$TARGET"
[[ -d "$DIR" ]] || die "Backup nicht gefunden: $DIR"

log "=== Rollback aus $DIR ==="
[[ $DRY -eq 1 ]] && warn "DRY-RUN: es wird nichts geschrieben"
list_backups

# ------------------------------------------------------- Dateien zurueckspielen
restore_dir() {
  local sub="$1" dest="$2"
  [[ -d "$DIR/files/$sub" ]] || { warn "keine Backup-Dateien fuer $sub"; return 0; }
  local f
  for f in "$DIR/files/$sub"/*; do
    [[ -e "$f" ]] || continue
    run cp -a "$f" "$dest/"
    log "zurueckgespielt: $(basename "$f") -> $dest/"
  done
}

run mkdir -p "$ACC_DIR" "$PLUGIN_DIR"
restore_dir "account-service" "$ACC_DIR"
restore_dir "plugin"          "$PLUGIN_DIR"

if [[ -d "$DIR/container" && $DRY -eq 0 ]]; then
  if docker ps --filter "name=$CONTAINER" --format '{{.Names}}' | grep -q "$CONTAINER"; then
    for f in "$DIR"/container/*; do
      base="$(basename "$f")"
      case "$base" in
        controllers_settings_bookmarks.py) destf="$OWRX_PKG/controllers/settings/bookmarks.py" ;;
        controllers_visitorstatus.py)      destf="$OWRX_PKG/controllers/visitorstatus.py" ;;
        *)                                 destf="$OWRX_PKG/$base" ;;
      esac
      docker cp "$f" "$CONTAINER:$destf" && log "Container zurueckgespielt: $base"
    done
  else
    warn "Container laeuft nicht – Container-Dateien nicht zurueckgespielt"
  fi
fi

# --------------------------------------------------------- Datenbank (optional)
if [[ $WITH_DB -eq 1 ]]; then
  db_bak="$(ls -1t "$DIR"/db/accounts-*.sqlite3 2>/dev/null | head -1 || true)"
  [[ -n "$db_bak" ]] || die "--with-db gewaehlt, aber kein DB-Backup in $DIR/db"
  warn "Die Datenbank wird zurueckgespielt. Alle Konten/Log-Eintraege NACH dem"
  warn "Backup-Zeitpunkt gehen verloren."
  if [[ $DRY -eq 0 ]]; then
    printf 'Wirklich fortfahren? [j/N] '
    read -r antwort
    [[ "$antwort" =~ ^[jJyY] ]] || die "Abbruch"
    safety="$ACC_DIR/accounts.sqlite3.vor-rollback-$(date +%Y%m%d-%H%M%S)"
    cp -a "$ACC_DIR/accounts.sqlite3" "$safety" && ok "Aktueller Stand gesichert: $safety"
    cp -a "$db_bak" "$ACC_DIR/accounts.sqlite3"
    ok "Datenbank zurueckgespielt aus $db_bak"
  fi
else
  log "Datenbank bleibt unveraendert (kein --with-db). access_settings kann mit"
  log "   python3 $ACC_DIR/migrate_add_access_settings.py --restore <backup>"
  log "separat zurueckgesetzt werden."
fi

# ------------------------------------------------------------ Abschluss-Checks
if [[ $NO_RESTART -eq 0 ]]; then
  if command -v systemctl >/dev/null; then
    run systemctl restart "$SERVICE"
    sleep 2
    systemctl is-active "$SERVICE" >/dev/null && ok "$SERVICE aktiv" || warn "$SERVICE NICHT aktiv"
  fi
fi

if [[ $DRY -eq 0 ]]; then
  python3 -m py_compile "$ACC_DIR/app.py" 2>/dev/null && ok "app.py kompiliert" \
    || warn "app.py kompiliert nicht – Backup pruefen"
  if [[ -f "$ACC_DIR/accounts.sqlite3" ]]; then
    python3 - "$ACC_DIR/accounts.sqlite3" <<'PY'
import sqlite3, sys
conn = sqlite3.connect(sys.argv[1])
print("   integrity_check:", conn.execute("PRAGMA integrity_check").fetchone()[0])
tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")]
for t in ("users", "sessions", "audit_log", "access_settings"):
    if t in tables:
        print("   %-16s %d Zeilen" % (t, conn.execute('SELECT COUNT(*) FROM "%s"' % t).fetchone()[0]))
PY
  fi
fi

ok "Rollback beendet."
