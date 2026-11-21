// ============================================================================
// DNX Systemsteuerung – Receiver-Frontend-Status (v1.2.0)
// ----------------------------------------------------------------------------
// Zweck: Das Frontend zeigt den TATSAECHLICHEN Backendstatus der globalen
//        Systemsteuerung (Registrierung, Rollen, Sitzungen, Wartungsmodus,
//        Account-Zwang, oeffentliches Aktivitaetslog) – nichts wird geraten.
//
// Einbau (eine Zeile, KEIN eigenes Polling-Skript):
//   <script src="/static/plugins/receiver/dnx_access_control/dnx_system_state.js"></script>
// oder aus init.js heraus innerhalb des markierten Blocks:
//   // DNX_SYSTEM_CONTROL_START
//   // DNX_SYSTEM_CONTROL_END
//
// Regeln aus der Uebergabe:
//   * keine konkurrierenden Polling-Skripte  -> 1x laden, sonst nur auf Zuruf
//   * keine vertrauenswuerdige Entscheidung im Browser -> der Server entscheidet,
//     hier wird nur angezeigt/ausgeblendet
//   * fail-open: ist der Dienst nicht erreichbar, wird NICHTS blockiert
// ============================================================================
(function () {
  "use strict";

  if (window.DNX_SYSTEM_STATE_LOADED) { return; }
  window.DNX_SYSTEM_STATE_LOADED = true;

  // ---------------------------------------------------------------- CONFIG ---
  var CONFIG = {
    // Account-Dienst (Port 8096). Default: gleicher Host wie der Receiver.
    baseUrl: window.DNX_ACCOUNT_BASE ||
      ("http://" + location.hostname + ":8091"),
    statePath: "/api/system/state",
    timeoutMs: 4000,
    // Nur einmal pro explizitem refresh() holen – kein Intervall!
    refreshOnLoginDialogOpen: true,
    refreshOnVisible: false,
    // Selektoren: bewusst mehrfach abgesichert, damit nichts kaputtgeht,
    // wenn ein Element in einer aelteren OpenWebRX+-Version anders heisst.
    selectors: {
      registerButton: ["#dnx-register-btn", "[data-dnx-register]", ".dnx-register-open"],
      registerForm: ["#dnx-register-form", "[data-dnx-register-form]"],
      loginDialog: ["#dnx-login-dialog", "#dnx-access-dialog", "[data-dnx-login-dialog]"],
      sessionOptions: ["[data-dnx-session]", "#dnx-session-duration option", ".dnx-session-option"],
      activityLink: ["#dnx-activity-link", "[data-dnx-activity]"],
      profileSelect: ["#dnx-profile-select", "[data-dnx-profile-select]"]
    },
    sessionValueMap: {
      browser: ["browser", "session", "0"],
      day: ["1d", "day", "86400", "1"],
      week: ["7d", "week", "604800", "7"],
      month: ["30d", "month", "2592000", "30"],
      forever: ["forever", "unlimited", "0s", "-1", "never"]
    },
    bannerId: "dnx-system-banner",
    bannerClass: "dnx-system-banner"
  };

  var state = {
    ok: false,
    source: "unavailable",
    loadedAt: null,
    state: null,      // oeffentliche Schluessel (state)
    rules: null,      // abgeleitete Regeln (rules)
    error: null,
    role: (window.DNX_ROLE || "guest")
  };

  // ---------------------------------------------------------------- Helfer ---

  function log() {
    if (window.console && console.info) {
      console.info.apply(console, ["[DNX-System]"].concat([].slice.call(arguments)));
    }
  }

  function all(selectorList) {
    var out = [];
    (selectorList || []).forEach(function (sel) {
      try {
        Array.prototype.forEach.call(document.querySelectorAll(sel), function (n) {
          if (out.indexOf(n) < 0) { out.push(n); }
        });
      } catch (e) { /* ungueltiger Selektor ignorieren */ }
    });
    return out;
  }

  function first(selectorList) {
    var nodes = all(selectorList);
    return nodes.length ? nodes[0] : null;
  }

  function hide(nodes, reason) {
    nodes.forEach(function (n) {
      n.setAttribute("data-dnx-hidden-by", "system-control:" + reason);
      n.style.display = "none";
    });
  }

  function show(nodes) {
    nodes.forEach(function (n) {
      if ((n.getAttribute("data-dnx-hidden-by") || "").indexOf("system-control:") === 0) {
        n.removeAttribute("data-dnx-hidden-by");
        n.style.display = "";
      }
    });
  }

  function setDisabled(nodes, disabled, reason) {
    nodes.forEach(function (n) {
      if (disabled) {
        n.setAttribute("disabled", "disabled");
        n.setAttribute("data-dnx-disabled-by", "system-control:" + reason);
      } else if ((n.getAttribute("data-dnx-disabled-by") || "").indexOf("system-control:") === 0) {
        n.removeAttribute("disabled");
        n.removeAttribute("data-dnx-disabled-by");
      }
    });
  }

  function ensureStyles() {
    if (document.getElementById("dnx-system-style")) { return; }
    var css = [
      ".dnx-system-banner{position:fixed;top:0;left:0;right:0;z-index:99998;",
      "padding:8px 14px;font:13px/1.4 system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;",
      "background:#2a1414;color:#ffd9d9;border-bottom:1px solid #6d2b2b;",
      "display:flex;gap:10px;align-items:center;justify-content:center;text-align:center}",
      ".dnx-system-banner.info{background:#241f0e;color:#f6e6b4;border-bottom-color:#6b5a22}",
      ".dnx-system-banner.ok{background:#10241a;color:#cdeedc;border-bottom-color:#2b6b48}",
      ".dnx-system-banner b{letter-spacing:.05em;text-transform:uppercase;font-size:12px}"
    ].join("");
    var st = document.createElement("style");
    st.id = "dnx-system-style";
    st.appendChild(document.createTextNode(css));
    document.head.appendChild(st);
  }

  function banner(kind, title, text) {
    ensureStyles();
    var node = document.getElementById(CONFIG.bannerId);
    if (!text) {
      if (node) { node.remove(); }
      return;
    }
    if (!node) {
      node = document.createElement("div");
      node.id = CONFIG.bannerId;
      document.body.appendChild(node);
    }
    node.className = CONFIG.bannerClass + (kind ? " " + kind : "");
    node.innerHTML = "";
    var b = document.createElement("b");
    b.textContent = title;
    var span = document.createElement("span");
    span.textContent = text;
    node.appendChild(b);
    node.appendChild(span);
  }

  // ------------------------------------------------------------- Laden -------

  function fetchState() {
    var url = CONFIG.baseUrl.replace(/\/$/, "") + CONFIG.statePath;
    var ctrl = (typeof AbortController === "function") ? new AbortController() : null;
    var timer = ctrl ? setTimeout(function () { ctrl.abort(); }, CONFIG.timeoutMs) : null;

    return fetch(url, {
      method: "GET",
      mode: "cors",
      cache: "no-store",
      credentials: "omit",          // oeffentlicher Status, keine Cookies noetig
      signal: ctrl ? ctrl.signal : undefined
    }).then(function (res) {
      if (!res.ok) { throw new Error("HTTP " + res.status); }
      return res.json();
    }).then(function (data) {
      if (timer) { clearTimeout(timer); }
      state.ok = true;
      state.source = (data.state && data.state._meta && data.state._meta.source) || "access_settings";
      state.state = data.state || {};
      state.rules = data.rules || {};
      state.loadedAt = Date.now();
      state.error = null;
      applyState();
      log("Backend-Status aktiv (" + state.source + ")");
      dispatch();
      return state;
    }).catch(function (err) {
      if (timer) { clearTimeout(timer); }
      state.ok = false;
      state.source = "unavailable";
      state.error = String(err && err.message ? err.message : err);
      // FAIL-OPEN: nichts blockieren, UI bleibt wie bisher
      banner(null, "", "");
      log("Status nicht erreichbar – fail-open, UI bleibt unveraendert (" + state.error + ")");
      dispatch();
      return state;
    });
  }

  function dispatch() {
    try {
      document.dispatchEvent(new CustomEvent("dnx:system-state", { detail: publicApi() }));
    } catch (e) { /* alte Browser */ }
  }

  // ------------------------------------------------------- Anwenden ----------

  function applyState() {
    var s = state.state || {};
    var r = state.rules || {};
    var reg = r.registration || {};
    var maint = r.maintenance || {};

    // 1) Registrierung
    if (reg.enabled === false) {
      hide(all(CONFIG.selectors.registerButton), "registration_disabled");
      setDisabled(all(CONFIG.selectors.registerForm), true, "registration_disabled");
    } else {
      show(all(CONFIG.selectors.registerButton));
      setDisabled(all(CONFIG.selectors.registerForm), false);
    }

    // 2) Sitzungsdauern: nur erlaubte Optionen anbieten
    var allowed = {};
    (r.sessions || []).forEach(function (c) {
      allowed[c.id] = true;
      (CONFIG.sessionValueMap[c.id] || []).forEach(function (v) { allowed[v] = true; });
    });
    all(CONFIG.selectors.sessionOptions).forEach(function (node) {
      var v = String(node.getAttribute("data-dnx-session") ||
                     node.getAttribute("value") ||
                     node.textContent || "").trim().toLowerCase();
      if (!v) { return; }
      var ok = allowed[v] || allowed[v.replace(/\s+/g, "")];
      if (ok) {
        show([node]);
        node.removeAttribute("data-dnx-session-blocked");
      } else {
        node.setAttribute("data-dnx-session-blocked", "1");
        if (node.tagName === "OPTION") { node.disabled = true; }
        else { hide([node], "session_not_allowed"); }
      }
    });

    // 3) Wartungsmodus / Account-Zwang / Profilsteuerung
    var kind = null, title = "", text = "";
    if (maint.active) {
      kind = "";
      title = "Wartungsmodus";
      text = maint.message || "Der Empfaenger ist voruebergehend nur fuer Administratoren verfuegbar.";
      if (state.role === "admin" && maint.allowed) {
        kind = "ok";
        title = "Wartungsmodus (Admin-Bypass)";
        text = "Du bist als Admin angemeldet und kannst weiterarbeiten.";
      }
    } else if (s.account_required && state.role === "guest") {
      kind = "info";
      title = "Account erforderlich";
      text = "Hoeren ist nur mit DNX-Konto moeglich. Bitte anmelden oder registrieren.";
    } else if (s.profile_control_enabled === false) {
      kind = "info";
      title = "Profilsteuerung aus";
      text = "Profilwechsel werden serverseitig nicht mehr eingeschraenkt.";
    }
    banner(kind, title, text);

    // 4) Oeffentliches Aktivitaetslog
    if (s.public_activity_enabled === false) {
      hide(all(CONFIG.selectors.activityLink), "public_activity_disabled");
    } else {
      show(all(CONFIG.selectors.activityLink));
    }

    // 5) Profil-Auswahl fuer Gaeste
    var guestBlocked = (state.role === "guest" && s.guest_profile_switch === false &&
                        s.profile_control_enabled !== false);
    setDisabled(all(CONFIG.selectors.profileSelect), guestBlocked, "guest_profile_switch_disabled");
  }

  // -------------------------------------------------- Oeffentliche API -------

  function decide(profileName) {
    // Reine Anzeige-/Vorabentscheidung. Verbindlich entscheidet der Server
    // in owrx/dnx_access_verify.py (verify_profile) – niemals hier.
    var s = state.state || {};
    if (!state.ok) {
      return { allow: true, reason: "state_unavailable_fail_open", local: true };
    }
    if (s.profile_control_enabled === false) {
      return { allow: true, reason: "profile_control_disabled", local: true };
    }
    var maint = (state.rules || {}).maintenance || {};
    if (maint.active && !maint.allowed) {
      return { allow: false, reason: "maintenance_mode", local: true };
    }
    if (s.account_required && state.role === "guest") {
      return { allow: false, reason: "account_required", local: true };
    }
    if (state.role === "guest" && !s.guest_profile_switch) {
      return { allow: false, reason: "guest_profile_switch_disabled", local: true };
    }
    return { allow: true, reason: "local_precheck_ok", profile: profileName, local: true };
  }

  function publicApi() {
    return {
      ok: state.ok,
      source: state.source,
      loadedAt: state.loadedAt,
      error: state.error,
      role: state.role,
      state: state.state,
      rules: state.rules,
      refresh: refresh,
      decide: decide,
      setRole: setRole,
      config: CONFIG
    };
  }

  function refresh() { return fetchState(); }

  function setRole(role) {
    state.role = String(role || "guest").toLowerCase();
    window.DNX_ROLE = state.role;
    if (state.ok) { applyState(); }
  }

  window.DNXSystemState = publicApi();
  window.DNX_SYSTEM_STATE = state;

  // Kein Intervall: nur einmal beim Start und auf ausdruecklichen Zuruf.
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", function () { fetchState(); });
  } else {
    fetchState();
  }

  if (CONFIG.refreshOnLoginDialogOpen) {
    ["dnx:login-dialog-open", "dnx:access-dialog-open"].forEach(function (evt) {
      document.addEventListener(evt, function () { fetchState(); });
    });
    var dlg = first(CONFIG.selectors.loginDialog);
    if (dlg) {
      dlg.addEventListener("transitionend", function () { fetchState(); }, { passive: true });
    }
  }
  if (CONFIG.refreshOnVisible) {
    document.addEventListener("visibilitychange", function () {
      if (!document.hidden) { fetchState(); }
    });
  }
})();
