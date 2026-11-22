#!/usr/bin/env bash
# =============================================================================
# DNX Systemsteuerung – Smoke-Tests (vor/nach jeder Aenderung)
#
# Entspricht Kapitel 15 der Uebergabe, erweitert um die neuen Endpunkte der
# Systemsteuerung. Nur lesend: es wird nichts geaendert.
#
#   ./scripts/smoke_tests.sh            # vollstaendig
#   ./scripts/smoke_tests.sh --short    # ohne Container/Node (fuer install.sh)
#   ./scripts/smoke_tests.sh --json     # maschinenlesbar
#
# Exit-Code: 0 = alles ok, 1 = Warnungen, 2 = Fehler
# =============================================================================
set -uo pipefail

HOST_BASE="${HOST_BASE:-/opt/owrx-docker}"
ACC_DIR="${ACC_DIR:-$HOST_BASE/var/dnx-access-control}"
PLUGIN_DIR="${PLUGIN_DIR:-$HOST_BASE/plugins/receiver/dnx_access_control}"
CONTAINER="${CONTAINER:-owrx-8013}"
OWRX_PKG="${OWRX_PKG:-/usr/lib/python3/dist-packages/owrx}"
SERVICE="${SERVICE:-dnx-access-control.service}"
PM_SERVICE="${PM_SERVICE:-dnx-project-manager.service}"
OWRX_PORT="${OWRX_PORT:-8013}"
ACC_PORT="${ACC_PORT:-8096}"
PM_PORT="${PM_PORT:-8094}"
DB="${DB:-$ACC_DIR/accounts.sqlite3}"
PM_DB="${PM_DB:-/opt/dnx-project-manager/database/projects.sqlite3}"

SHORT=0; JSON=0
for arg in "$@"; do
  case "$arg" in
    --short) SHORT=1 ;;
    --json)  JSON=1 ;;
    -h|--help) sed -n '2,16p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
  esac
done

PASS=0; WARN=0; FAIL=0
RESULTS=()

c_grn=$'\033[32m'; c_ylw=$'\033[33m'; c_red=$'\033[31m'; c_off=$'\033[0m'

rec() { # rec STATUS BEREICH NACHRICHT
  RESULTS+=("$1|$2|$3")
  case "$1" in
    PASS) PASS=$((PASS+1)); [[ $JSON -eq 0 ]] && printf '%s[PASS]%s %-14s %s\n' "$c_grn" "$c_off" "$2" "$3" ;;
    WARN) WARN=$((WARN+1)); [[ $JSON -eq 0 ]] && printf '%s[WARN]%s %-14s %s\n' "$c_ylw" "$c_off" "$2" "$3" ;;
    FAIL) FAIL=$((FAIL+1)); [[ $JSON -eq 0 ]] && printf '%s[FAIL]%s %-14s %s\n' "$c_red" "$c_off" "$2" "$3" ;;
  esac
  return 0
}

# --------------------------------------------------------------- Dienste ------
check_service() {
  local svc="$1"
  if ! command -v systemctl >/dev/null; then rec WARN "dienst" "systemctl fehlt: $svc"; return; fi
  local state
  state="$(systemctl is-active "$svc" 2>/dev/null || true)"
  if [[ "$state" == "active" ]]; then rec PASS "dienst" "$svc ist aktiv"
  elif [[ "$state" == "inactive" ]]; then rec FAIL "dienst" "$svc ist inaktiv"
  else rec WARN "dienst" "$svc: Status '$state'"; fi
}
check_service "$SERVICE"
[[ $SHORT -eq 0 ]] && check_service "$PM_SERVICE"

if command -v docker >/dev/null; then
  if docker ps --filter "name=$CONTAINER" --format '{{.Names}} {{.Status}}' | grep -q "$CONTAINER"; then
    rec PASS "container" "$CONTAINER laeuft ($(docker ps --filter "name=$CONTAINER" --format '{{.Status}}'))"
  else
    rec FAIL "container" "$CONTAINER laeuft nicht"
  fi
else
  rec WARN "container" "docker nicht verfuegbar"
fi

# ------------------------------------------------------------------- HTTP -----
http_code() {
  local code
  code="$(curl -s -m 8 -o /dev/null -w '%{http_code}' "$1" 2>/dev/null || true)"
  [[ -z "$code" ]] && code="000"
  printf '%s' "$code"
}
expect_code() { # expect_code URL ERWARTET_BEREICH BESCHREIBUNG
  local url="$1" expected="$2" desc="$3" code
  code="$(http_code "$url")"
  if [[ "$expected" == *"$code"* ]]; then
    rec PASS "http" "$desc -> $code"
  elif [[ "$code" == "000" ]]; then
    rec FAIL "http" "$desc -> keine Antwort ($url)"
  else
    rec WARN "http" "$desc -> $code (erwartet $expected)"
  fi
}
expect_code "http://127.0.0.1:$OWRX_PORT/"                 "200 302" "OpenWebRX"
expect_code "http://127.0.0.1:$ACC_PORT/"                  "200 302 404" "Account-Dienst"
expect_code "http://127.0.0.1:$ACC_PORT/api/system/healthz" "200" "Systemsteuerung healthz"
expect_code "http://127.0.0.1:$ACC_PORT/api/system/state"   "200" "Systemsteuerung Status"
expect_code "http://127.0.0.1:$ACC_PORT/admin/system"       "200 302 403" "Admin-Panel (ohne Login)"
[[ $SHORT -eq 0 ]] && expect_code "http://127.0.0.1:$PM_PORT/" "200 302 404" "Projekt-Manager"

# healthz-Inhalt pruefen
if command -v python3 >/dev/null; then
  health="$(curl -s -m 8 "http://127.0.0.1:$ACC_PORT/api/system/healthz" 2>/dev/null || true)"
  if [[ -n "$health" ]]; then
    python3 - "$health" <<'PY' > /tmp/dnx_health.out 2>/dev/null || true
import json, sys
try:
    d = json.loads(sys.argv[1])
    print("version=%s keys=%s warnings=%s maintenance=%s registration=%s"
          % (d.get("version"), d.get("keys"), d.get("warnings"),
             d.get("maintenance_mode"), d.get("registration_enabled")))
except Exception as exc:
    print("parse-error=%s" % exc)
PY
    out="$(cat /tmp/dnx_health.out 2>/dev/null || true)"
    case "$out" in
      version=1.2.0*) rec PASS "api" "healthz: $out" ;;
      parse-error*)   rec WARN "api" "healthz nicht lesbar: $out" ;;
      "")             rec WARN "api" "healthz ohne Inhalt" ;;
      *)              rec WARN "api" "healthz unerwartet: $out" ;;
    esac
    rm -f /tmp/dnx_health.out
  fi

  # oeffentlicher Status darf keine Interna verraten
  state="$(curl -s -m 8 "http://127.0.0.1:$ACC_PORT/api/system/state" 2>/dev/null || true)"
  if [[ -n "$state" ]]; then
    python3 - "$state" <<'PY' > /tmp/dnx_state.out 2>/dev/null || true
import json, sys
try:
    d = json.loads(sys.argv[1])
    st = d.get("state", {})
    verboten = [k for k in ("max_audit_entries", "max_audit_bytes", "settings_fail_open",
                            "password_min_length", "login_lock_seconds", "audit_timezone")
                if k in st]
    erwartet = [k for k in ("registration_enabled", "maintenance_mode", "account_required",
                            "guest_profile_switch", "profile_control_enabled") if k in st]
    print("ok=%d verboten=%s erwartet=%d" % (0 if verboten else 1, ",".join(verboten) or "-",
                                             len(erwartet)))
except Exception as exc:
    print("parse-error=%s" % exc)
PY
    out="$(cat /tmp/dnx_state.out 2>/dev/null || true)"
    if [[ "$out" == ok=1* && "$out" == *"erwartet=5"* ]]; then
      rec PASS "api" "Status-API: nur oeffentliche Schluessel (5/5)"
    elif [[ "$out" == ok=0* ]]; then
      rec FAIL "api" "Status-API verrät Interna: $out"
    else
      rec WARN "api" "Status-API: $out"
    fi
    rm -f /tmp/dnx_state.out
  fi
fi

# ----------------------------------------------------------------- SQLite -----
check_db() { # check_db PFAD NAME
  local path="$1" name="$2"
  if [[ ! -f "$path" ]]; then rec WARN "sqlite" "$name nicht gefunden ($path)"; return; fi
  if ! command -v python3 >/dev/null; then rec WARN "sqlite" "python3 fehlt fuer $name"; return; fi
  local out
  out="$(python3 - "$path" <<'PY' 2>&1
import sqlite3, sys
try:
    conn = sqlite3.connect("file:%s?mode=ro" % sys.argv[1], uri=True, timeout=10)
    ic = conn.execute("PRAGMA integrity_check").fetchone()[0]
    tables = [r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]
    parts = ["integrity=%s" % ic]
    for t in ("users", "sessions", "audit_log", "access_settings"):
        if t in tables:
            parts.append("%s=%d" % (t, conn.execute('SELECT COUNT(*) FROM "%s"' % t).fetchone()[0]))
    if "access_settings" in tables:
        parts.append("keys=%d" % conn.execute(
            "SELECT COUNT(DISTINCT key) FROM access_settings").fetchone()[0])
    print(" ".join(parts))
except Exception as exc:
    print("error=%s" % exc)
PY
)"
  case "$out" in
    *"integrity=ok"*) rec PASS "sqlite" "$name: $out" ;;
    error=*)          rec FAIL "sqlite" "$name: $out" ;;
    *)                rec WARN "sqlite" "$name: $out" ;;
  esac
}
check_db "$DB" "accounts.sqlite3"
[[ $SHORT -eq 0 ]] && check_db "$PM_DB" "projects.sqlite3"

# access_settings muss alle Pflichtschluessel enthalten
if [[ -f "$DB" ]] && command -v python3 >/dev/null; then
  out="$(python3 - "$DB" <<'PY' 2>&1
import sqlite3, sys
required = ["registration_enabled","new_accounts_active","profile_control_enabled",
            "account_required","guest_profile_switch","role_user_enabled","role_extended_enabled",
            "default_registration_role","maintenance_mode","public_activity_enabled","audit_enabled",
            "allowed_session_browser","allowed_session_day","allowed_session_week",
            "allowed_session_month","allowed_session_forever","max_login_failures",
            "login_lock_seconds","registration_limit","registration_window_seconds",
            "max_audit_entries","max_audit_bytes"]
try:
    conn = sqlite3.connect("file:%s?mode=ro" % sys.argv[1], uri=True, timeout=10)
    tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")]
    if "access_settings" not in tables:
        print("missing_table=access_settings"); raise SystemExit
    have = {r[0] for r in conn.execute("SELECT key FROM access_settings")}
    miss = [k for k in required if k not in have]
    print("ok" if not miss else "missing=%s" % ",".join(miss))
except Exception as exc:
    print("error=%s" % exc)
PY
)"
  case "$out" in
    ok)            rec PASS "settings" "alle 22 Pflichtschluessel vorhanden" ;;
    missing_table*) rec WARN "settings" "access_settings fehlt – Migration ausfuehren" ;;
    missing=*)     rec FAIL "settings" "$out" ;;
    *)             rec WARN "settings" "$out" ;;
  esac
fi

# ------------------------------------------------------------------ Python ----
if command -v python3 >/dev/null; then
  if [[ -f "$ACC_DIR/app.py" ]]; then
    python3 -m py_compile "$ACC_DIR/app.py" 2>/dev/null \
      && rec PASS "python" "app.py kompiliert" || rec FAIL "python" "app.py kompiliert NICHT"
  else
    rec WARN "python" "app.py nicht gefunden"
  fi
  for f in settings_store access_rules admin_api; do
    p="$ACC_DIR/dnx_system_control/$f.py"
    if [[ -f "$p" ]]; then
      python3 -m py_compile "$p" 2>/dev/null && rec PASS "python" "$f.py kompiliert" \
        || rec FAIL "python" "$f.py kompiliert NICHT"
    else
      rec WARN "python" "$f.py fehlt"
    fi
  done
  if [[ -f "$ACC_DIR/dnx_system_control_integration.py" ]]; then
    python3 -m py_compile "$ACC_DIR/dnx_system_control_integration.py" 2>/dev/null \
      && rec PASS "python" "Integrations-Helfer kompiliert" || rec FAIL "python" "Integrations-Helfer defekt"
  fi
fi

if [[ $SHORT -eq 0 ]] && command -v docker >/dev/null && \
   docker ps --filter "name=$CONTAINER" --format '{{.Names}}' | grep -q "$CONTAINER"; then
  if docker exec "$CONTAINER" python3 -m py_compile \
       "$OWRX_PKG/connection.py" "$OWRX_PKG/client.py" "$OWRX_PKG/dnx_access_verify.py" \
       2>/dev/null; then
    rec PASS "container" "connection.py/client.py/dnx_access_verify.py kompilieren"
  else
    rec FAIL "container" "Backend-Patch kompiliert NICHT"
  fi
  if docker exec "$CONTAINER" test -f "$OWRX_PKG/dnx_system_verify.py" 2>/dev/null; then
    docker exec "$CONTAINER" python3 -m py_compile \
      "$OWRX_PKG/dnx_system_verify.py" "$OWRX_PKG/dnx_sys_store.py" "$OWRX_PKG/dnx_sys_rules.py" \
      2>/dev/null && rec PASS "container" "Systemsteuerungs-Module im Container ok" \
                  || rec FAIL "container" "Systemsteuerungs-Module im Container defekt"
    out="$(docker exec "$CONTAINER" python3 -c \
      "import sys; sys.path.insert(0,'$OWRX_PKG/..'); from owrx import dnx_system_verify as d; \
s=d.status(); print('source=%s shared=%s keys=%s' % (s['source'], s['shared_logic'], s['keys']))" \
      2>/dev/null || true)"
    case "$out" in
      *"source=access_settings"*"shared=True"*) rec PASS "container" "liest access_settings: $out" ;;
      "")  rec WARN "container" "Statusauskunft im Container nicht moeglich" ;;
      *)   rec WARN "container" "Container-Status: $out" ;;
    esac
  else
    rec WARN "container" "dnx_system_verify.py fehlt im Container"
  fi
fi

# --------------------------------------------------------------------- JS -----
if [[ $SHORT -eq 0 ]] && command -v node >/dev/null; then
  for f in "$HOST_BASE/plugins/receiver/init.js" "$PLUGIN_DIR/dnx_system_state.js" \
           "$PLUGIN_DIR/dnx_access.js" "$ACC_DIR/dnx_system_control/web/dnx_system_control.js"; do
    if [[ -f "$f" ]]; then
      node --check "$f" >/dev/null 2>&1 && rec PASS "javascript" "$(basename "$f") ok" \
                                        || rec FAIL "javascript" "$(basename "$f") Syntaxfehler"
    fi
  done
else
  [[ $SHORT -eq 1 ]] && rec WARN "javascript" "uebersprungen (--short)"
fi

# -------------------------------------------------------------- Frontend-Datei
if [[ -f "$PLUGIN_DIR/dnx_system_state.js" ]]; then
  rec PASS "frontend" "dnx_system_state.js vorhanden"
  if grep -q "DNX_SYSTEM_STATE_LOADED" "$PLUGIN_DIR/dnx_system_state.js"; then
    rec PASS "frontend" "Doppel-Ladeschutz vorhanden"
  else
    rec WARN "frontend" "kein Doppel-Ladeschutz erkennbar"
  fi
  if grep -qE "setInterval|setTimeout\(.*fetch" "$PLUGIN_DIR/dnx_system_state.js"; then
    rec WARN "frontend" "Intervall entdeckt – Polling vermeiden (Kapitel 14)"
  else
    rec PASS "frontend" "kein Polling-Intervall"
  fi
else
  rec WARN "frontend" "dnx_system_state.js fehlt"
fi

# ---------------------------------------------------------------- app.py-Einbau
if [[ -f "$ACC_DIR/app.py" ]]; then
  if grep -q "dnx_sc.install(app)" "$ACC_DIR/app.py"; then
    rec PASS "einbau" "app.py ruft dnx_sc.install(app) auf"
  else
    rec WARN "einbau" "app.py ruft die Systemsteuerung nicht auf (Panel bleibt 404/403)"
  fi
fi

# -------------------------------------------------------------------- Ausgabe --
echo
if [[ $JSON -eq 1 ]]; then
  printf '{"pass":%d,"warn":%d,"fail":%d,"results":[' "$PASS" "$WARN" "$FAIL"
  first=1
  for r in "${RESULTS[@]}"; do
    IFS='|' read -r st bereich msg <<< "$r"
    [[ $first -eq 0 ]] && printf ','
    printf '{"status":"%s","area":"%s","message":%s}' "$st" "$bereich" \
      "$(python3 -c 'import json,sys;print(json.dumps(sys.argv[1]))' "$msg" 2>/dev/null || echo "\"$msg\"")"
    first=0
  done
  printf ']}\n'
else
  echo "--------------------------------------------------------------"
  printf ' %s%d PASS%s   %s%d WARN%s   %s%d FAIL%s\n' \
    "$c_grn" "$PASS" "$c_off" "$c_ylw" "$WARN" "$c_off" "$c_red" "$FAIL" "$c_off"
  echo "--------------------------------------------------------------"
fi

if [[ $FAIL -gt 0 ]]; then exit 2; fi
if [[ $WARN -gt 0 ]]; then exit 1; fi
exit 0
