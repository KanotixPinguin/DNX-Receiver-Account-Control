/* ============================================================================
   DNX Systemsteuerung – Admin-Panel (v1.2.0)
   Vanilla JS, keine Bibliotheken, KEIN Polling.
   Geladen wird: einmal beim Oeffnen (Bootstrap + GET), nach jedem Speichern
   und auf ausdruecklichen Knopfdruck.

   Die Anzeige folgt immer dem Backend: nach dem Speichern wird der vom Dienst
   gelieferte Ist-Zustand uebernommen, nicht der lokale Entwurf.
   ========================================================================== */
(function () {
  "use strict";

  var BOOT = window.DNX_SYSTEM_BOOTSTRAP || {};
  var PREFIX = (window.DNX_SYSTEM_PREFIX || "/admin").replace(/\/$/, "");
  var API = PREFIX + "/api/system";

  var el = {
    groups: document.getElementById("dnxsc-groups"),
    summary: document.getElementById("dnxsc-summary"),
    nav: document.getElementById("dnxsc-nav"),
    alerts: document.getElementById("dnxsc-alerts"),
    impact: document.getElementById("dnxsc-impact"),
    save: document.getElementById("dnxsc-save"),
    reload: document.getElementById("dnxsc-reload"),
    reset: document.getElementById("dnxsc-reset"),
    modal: document.getElementById("dnxsc-modal"),
    modalBody: document.getElementById("dnxsc-modal-body"),
    modalOk: document.getElementById("dnxsc-modal-ok"),
    modalCancel: document.getElementById("dnxsc-modal-cancel"),
    dot: document.getElementById("dnxsc-state-dot"),
    version: document.getElementById("dnxsc-version"),
    meta: document.getElementById("dnxsc-meta-info"),
    user: document.getElementById("dnxsc-user"),
    role: document.getElementById("dnxsc-role")
  };

  var state = {
    settings: {},      // vom Server gelieferter Ist-Zustand
    draft: {},         // Arbeitskopie (noch nicht gespeichert)
    meta: BOOT.meta || { groups: [], fields: [] },
    csrf: BOOT.csrf_token || "",
    warnings: [],
    busy: false
  };

  /* ---------------------------------------------------------------- Helfer */

  function byId(fields) {
    var map = {};
    (fields || []).forEach(function (f) { map[f.key] = f; });
    return map;
  }
  var FIELDS = byId(state.meta.fields);

  function fmtBool(v) { return v ? "AN" : "AUS"; }

  function fmtValue(field, v) {
    if (!field) return String(v);
    if (field.type === "bool") return fmtBool(v);
    if (field.type === "int") return v + (field.unit ? " " + field.unit : "");
    if (field.type === "enum") return String(v);
    return String(v === "" ? "(leer)" : v);
  }

  function fmtBytes(n) {
    if (n === null || n === undefined) return "-";
    var u = ["B", "KiB", "MiB", "GiB", "TiB"], i = 0, v = Number(n);
    while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
    return (i === 0 ? v : v.toFixed(1)) + " " + u[i];
  }

  function h(tag, attrs, children) {
    var node = document.createElement(tag);
    Object.keys(attrs || {}).forEach(function (k) {
      if (k === "class") node.className = attrs[k];
      else if (k === "text") node.textContent = attrs[k];
      else if (k === "html") node.innerHTML = attrs[k];
      else if (k.indexOf("data-") === 0 || k === "role" || k === "title" ||
               k === "aria-checked" || k === "aria-label" || k === "type" ||
               k === "min" || k === "max" || k === "step" || k === "maxlength" ||
               k === "id" || k === "for" || k === "href" || k === "colspan") {
        node.setAttribute(k, attrs[k]);
      }
    });
    (children || []).forEach(function (c) { if (c) node.appendChild(c); });
    return node;
  }

  function setDot(kind, title) {
    if (!el.dot) return;
    el.dot.className = "dnxsc-dot" + (kind ? " " + kind : "");
    el.dot.title = title || "";
  }

  function alert(kind, title, lines) {
    var box = h("div", { "class": "dnxsc-alert " + kind });
    box.appendChild(h("div", {}, [
      h("div", {}, [h("b", { text: title })].concat(
        (lines && lines.length) ? [h("ul", {}, lines.map(function (l) {
          return h("li", { text: l });
        }))] : []))
    ]));
    el.alerts.appendChild(box);
    return box;
  }

  function clearAlerts() { el.alerts.innerHTML = ""; }

  /* ------------------------------------------------------------- Datenladen */

  function request(path, opts) {
    opts = opts || {};
    var headers = { "Accept": "application/json" };
    if (opts.body) {
      headers["Content-Type"] = "application/json";
      if (state.csrf) headers["X-CSRF-Token"] = state.csrf;
    }
    return fetch(PREFIX + path, {
      method: opts.method || "GET",
      headers: headers,
      credentials: "same-origin",
      cache: "no-store",
      body: opts.body ? JSON.stringify(opts.body) : undefined
    }).then(function (res) {
      return res.json().catch(function () { return { ok: false, error: "Antwort ohne JSON" }; })
        .then(function (data) {
          if (!res.ok || data.ok === false) {
            var err = new Error(data.error || ("HTTP " + res.status));
            err.status = res.status;
            err.data = data;
            throw err;
          }
          return data;
        });
    });
  }

  function applyPayload(data) {
    state.settings = data.settings || {};
    state.draft = JSON.parse(JSON.stringify(state.settings));
    if (data.meta && data.meta.fields) {
      state.meta = data.meta;
      FIELDS = byId(data.meta.fields);
    }
    state.csrf = data.csrf_token || state.csrf;
    state.warnings = data.warnings || [];
    state.summary = data.summary || null;
    state.impact = data.impact || null;
    renderAll();
    return data;
  }

  function load(opts) {
    opts = opts || {};
    state.busy = true;
    setDot("warn", "lade ...");
    return request("/api/system/settings")
      .then(function (data) {
        applyPayload(data);
        setDot("ok", "Verbunden mit " + (data.version || "") + " – Ist-Zustand geladen");
        state.busy = false;
        if (opts.notice) alert("ok", opts.notice, data.warnings || []);
        return data;
      })
      .catch(function (err) {
        state.busy = false;
        setDot("err", "Fehler: " + err.message);
        clearAlerts();
        alert("err", "Einstellungen konnten nicht geladen werden",
          [err.message, "Es wurde nichts geaendert. Bitte Dienste pruefen (Kapitel 15 der Uebergabe)."]);
      });
  }

  /* --------------------------------------------------------------- Rendern */

  function renderSummary() {
    el.summary.innerHTML = "";
    var s = state.settings;
    function chip(label, value, kind) {
      return h("span", { "class": "dnxsc-chip " + (kind || "") }, [
        h("span", { text: label }),
        h("b", { "class": "st", text: value })
      ]);
    }
    el.summary.appendChild(chip("Registrierung", fmtBool(s.registration_enabled),
      s.registration_enabled ? "on" : "off"));
    el.summary.appendChild(chip("Neue Konten", s.new_accounts_active ? "sofort aktiv" : "wartend",
      s.new_accounts_active ? "on" : "attention"));
    el.summary.appendChild(chip("Profilsteuerung", fmtBool(s.profile_control_enabled),
      s.profile_control_enabled ? "on" : "attention"));
    el.summary.appendChild(chip("Account-Zwang", fmtBool(s.account_required),
      s.account_required ? "attention" : "off"));
    el.summary.appendChild(chip("Gast-Profilwechsel", fmtBool(s.guest_profile_switch),
      s.guest_profile_switch ? "attention" : "off"));
    el.summary.appendChild(chip("Rolle user", fmtBool(s.role_user_enabled),
      s.role_user_enabled ? "on" : "off"));
    el.summary.appendChild(chip("Rolle extended", fmtBool(s.role_extended_enabled),
      s.role_extended_enabled ? "on" : "off"));
    el.summary.appendChild(chip("Standardrolle", String(s.default_registration_role || "user"), "on"));
    var sess = ["browser", "day", "week", "month", "forever"].filter(function (k) {
      return s["allowed_session_" + k];
    });
    el.summary.appendChild(chip("Sitzungen", sess.length + " von 5 erlaubt",
      sess.length >= 4 ? "on" : "attention"));
    el.summary.appendChild(chip("Login-Sperre",
      (s.max_login_failures || 0) > 0 ? s.max_login_failures + " Versuche" : "aus",
      (s.max_login_failures || 0) > 0 ? "on" : "off"));
    el.summary.appendChild(chip("Reg.-Limit",
      (s.registration_limit || 0) > 0 ? s.registration_limit + "/" + (s.registration_window_seconds || 0) + "s" : "aus",
      (s.registration_limit || 0) > 0 ? "on" : "off"));
    el.summary.appendChild(chip("Oeffentl. Log", fmtBool(s.public_activity_enabled),
      s.public_activity_enabled ? "on" : "off"));
    el.summary.appendChild(chip("Audit", fmtBool(s.audit_enabled),
      s.audit_enabled ? "on" : "off"));
    el.summary.appendChild(chip("Wartung", fmtBool(s.maintenance_mode),
      s.maintenance_mode ? "crit" : "off"));
  }

  function renderBanners() {
    var existing = el.alerts.querySelectorAll(".dnxsc-banner");
    Array.prototype.forEach.call(existing, function (n) { n.remove(); });
    var s = state.settings;
    function banner(cls, big, text) {
      var b = h("div", { "class": "dnxsc-banner " + cls }, [
        h("span", { "class": "big", text: big }),
        h("span", { text: text })
      ]);
      el.alerts.insertBefore(b, el.alerts.firstChild);
    }
    if (s.maintenance_mode) {
      banner("", "Wartungsmodus aktiv",
        (s.maintenance_admin_bypass ? "Admin-Bypass AN. " : "ACHTUNG: Admin-Bypass AUS! ") +
        (s.maintenance_message || ""));
    }
    if (!s.profile_control_enabled) {
      banner("info", "Profilsteuerung AUS",
        "Fail-open aktiv: Profilwechsel werden serverseitig nicht mehr geprueft. " +
        "Es wird dadurch niemand gesperrt, aber jeder erreichbare Profilname geht durch.");
    }
    if (s.account_required && s.guest_profile_switch) {
      banner("info", "Widerspruechliche Schalter",
        "Account-Zwang AN und 'Gast darf Profile wechseln' AN gleichzeitig: " +
        "wirksam bleibt der Account-Zwang, Gaeste werden abgewiesen.");
    }
    if (!s.audit_enabled) {
      banner("info", "Audit-Logging AUS",
        "Es werden keine neuen Ereignisse protokolliert. Einstellungs-aenderungen " +
        "bleiben nur bei 'audit_settings_changes' sichtbar.");
    }
    if (s.allowed_session_forever) {
      banner("info", "Sitzungsdauer 'unbegrenzt' erlaubt",
        "Bestehende unbegrenzte Sitzungen bleiben gueltig, bis sie widerrufen werden.");
    }
  }

  function renderWarnings() {
    var w = state.warnings || [];
    if (!w.length) return;
    alert("warn", "Hinweise des Einstellungsstores", w.slice(0, 8));
  }

  function renderNav() {
    el.nav.innerHTML = "";
    (state.meta.groups || []).forEach(function (g) {
      var a = h("a", { href: "#dnxsc-g-" + g.id, text: g.label, "data-group": g.id });
      el.nav.appendChild(a);
    });
  }

  function makeControl(field) {
    var key = field.key;
    var value = state.draft[key];
    var wrap = h("div", { "class": "dnxsc-control" });

    function commit(newValue) {
      state.draft[key] = newValue;
      markRow(key);
    }

    if (!field.editable) {
      wrap.appendChild(h("input", {
        "class": "dnxsc-input", type: "text", value: String(value), readonly: "readonly"
      }));
      wrap.appendChild(h("span", { "class": "dnxsc-mark lock", text: "schreibgeschuetzt" }));
      return wrap;
    }

    if (field.type === "bool") {
      var txt = h("span", { "class": "dnxsc-switch-text" + (value ? " on" : ""), text: fmtBool(value) });
      var sw = h("button", {
        type: "button",
        "class": "dnxsc-switch",
        role: "switch",
        "aria-checked": value ? "true" : "false",
        "aria-label": field.label,
        title: field.label + " umschalten"
      });
      sw.addEventListener("click", function () {
        var next = !(state.draft[key] === true);
        sw.setAttribute("aria-checked", next ? "true" : "false");
        txt.textContent = fmtBool(next);
        txt.className = "dnxsc-switch-text" + (next ? " on" : "");
        commit(next);
      });
      wrap.appendChild(txt);
      wrap.appendChild(sw);
      return wrap;
    }

    if (field.type === "enum") {
      var sel = h("select", { "class": "dnxsc-select", "aria-label": field.label });
      (field.choices || []).forEach(function (c) {
        var opt = h("option", { value: c, text: c });
        if (String(c) === String(value)) opt.selected = true;
        sel.appendChild(opt);
      });
      sel.addEventListener("change", function () { commit(sel.value); });
      wrap.appendChild(sel);
      return wrap;
    }

    if (field.type === "int") {
      var inp = h("input", {
        "class": "dnxsc-input num", type: "number", value: String(value),
        min: String(field.min === null ? "" : field.min),
        max: String(field.max === null ? "" : field.max),
        step: "1", "aria-label": field.label
      });
      inp.addEventListener("input", function () {
        var n = parseInt(inp.value, 10);
        commit(isNaN(n) ? value : n);
      });
      wrap.appendChild(inp);
      if (field.unit) wrap.appendChild(h("span", { "class": "dnxsc-unit", text: field.unit }));
      wrap.appendChild(h("span", { "class": "dnxsc-range", text: "[" + field.min + " .. " + field.max + "]" }));
      return wrap;
    }

    // str
    var long = (field.max_length || 500) > 120;
    var tin = long
      ? h("textarea", { "class": "dnxsc-textarea", maxlength: String(field.max_length || 500),
                        "aria-label": field.label })
      : h("input", { "class": "dnxsc-input", type: "text",
                     maxlength: String(field.max_length || 500), "aria-label": field.label });
    tin.value = String(value === undefined || value === null ? "" : value);
    tin.addEventListener("input", function () { commit(tin.value); });
    wrap.appendChild(tin);
    return wrap;
  }

  function renderGroups() {
    el.groups.innerHTML = "";
    var groups = state.meta.groups || [];
    groups.forEach(function (g) {
      var fields = (state.meta.fields || []).filter(function (f) { return f.group === g.id; });
      if (!fields.length) return;
      var card = h("section", { "class": "dnxsc-group " + g.id, id: "dnxsc-g-" + g.id });
      card.appendChild(h("h2", {}, [
        h("span", { text: g.label }),
        h("span", { "class": "cnt", text: fields.length + " Einstellungen" })
      ]));
      var rows = h("div", { "class": "dnxsc-rows" });
      fields.forEach(function (f) {
        var row = h("div", { "class": "dnxsc-row", "data-key": f.key, id: "dnxsc-row-" + f.key });
        var labelBox = h("div", { "class": "dnxsc-label" }, [
          h("span", { "class": "name" }, [
            h("span", { text: f.label }),
            f.admin_only ? h("span", { "class": "dnxsc-mark lock", text: "Admin-Zusatz" }) : null
          ].filter(Boolean)),
          f.hint ? h("span", { "class": "hint", text: f.hint }) : null,
          h("span", { "class": "key", text: f.key })
        ].filter(Boolean));
        var controlBox = h("div", { "class": "dnxsc-control-wrap" }, [
          makeControl(f),
          h("div", { "class": "dnxsc-error", id: "dnxsc-err-" + f.key, hidden: "hidden" })
        ]);
        row.appendChild(labelBox);
        row.appendChild(controlBox);
        rows.appendChild(row);
      });
      card.appendChild(rows);
      if (g.id === "advanced") {
        card.appendChild(h("div", { "class": "dnxsc-rows" }, [
          h("div", { "class": "dnxsc-row" }, [
            h("div", { "class": "dnxsc-label" }, [
              h("span", { "class": "name", text: "Warum dieser Bereich?" }),
              h("span", { "class": "hint", text: "Technische Zusatzschalter fuer Admins: Verhalten bei " +
                "abgeschalteten Rollen, Sitzungs-Widerruf, Cache der Container-Profilpruefung, " +
                "Fail-open-Verhalten und API-Strenge. Defaults sind so gewaehlt, dass " +
                "Bestandsuser nicht ausgesperrt werden." })
            ]),
            h("div", { "class": "dnxsc-control" }, [
              h("span", { "class": "dnxsc-unit", text: "nur Rolle admin sichtbar" })
            ])
          ])
        ]));
      }
      el.groups.appendChild(card);
    });
    refreshDirtyUI();
  }

  function markRow(key) { refreshDirtyUI(); }

  function dirtyKeys() {
    return Object.keys(state.draft).filter(function (k) {
      return FIELDS[k] && FIELDS[k].editable && state.draft[k] !== state.settings[k];
    });
  }

  function refreshDirtyUI() {
    var dirty = dirtyKeys();
    var map = {};
    dirty.forEach(function (k) { map[k] = true; });
    Array.prototype.forEach.call(el.groups.querySelectorAll(".dnxsc-row"), function (row) {
      var key = row.getAttribute("data-key");
      if (!key) return;
      row.classList.toggle("dirty", !!map[key]);
    });
    var counts = {};
    dirty.forEach(function (k) {
      var g = (FIELDS[k] || {}).group || "other";
      counts[g] = (counts[g] || 0) + 1;
    });
    Array.prototype.forEach.call(el.nav.querySelectorAll("a"), function (a) {
      var g = a.getAttribute("data-group");
      a.classList.toggle("dirty", !!counts[g]);
      a.textContent = (a.textContent.replace(/ \(\d+\)$/, "")) + (counts[g] ? " (" + counts[g] + ")" : "");
    });
    if (el.save) {
      el.save.disabled = dirty.length === 0 || state.busy;
      el.save.textContent = dirty.length ? ("Speichern (" + dirty.length + ")") : "Speichern";
    }
  }

  function renderImpact() {
    el.impact.innerHTML = "";
    var card = h("div", { "class": "card" });
    card.appendChild(h("h2", { text: "Auswirkung auf Bestandskonten" }));
    card.appendChild(h("p", {
      "class": "note",
      text: "Die Systemsteuerung aendert keine Konten. Bestehende Registrierungen, Rollen und " +
            "Sitzungen bleiben erhalten – abgeschaltete Rollen werden nur wirksam herabgestuft."
    }));
    var imp = state.impact || {};
    if (imp.error) {
      card.appendChild(h("div", { "class": "dnxsc-callout warn", text: "Bestandsdaten nicht lesbar: " + imp.error }));
      el.impact.appendChild(card);
      return;
    }
    var rows = [];
    var byRole = imp.by_role || {};
    Object.keys(byRole).sort().forEach(function (r) {
      rows.push([r, byRole[r]]);
    });
    if (rows.length) {
      var t = h("table", { "class": "dnxsc-table" });
      t.appendChild(h("thead", {}, [h("tr", {}, [
        h("th", { text: "Rolle (Bestand)" }), h("th", { text: "Konten", colspan: "1" })
      ])]));
      var tb = h("tbody");
      rows.forEach(function (r) {
        tb.appendChild(h("tr", {}, [
          h("td", { text: r[0] }), h("td", { "class": "num", text: String(r[1]) })
        ]));
      });
      t.appendChild(tb);
      card.appendChild(t);
    } else {
      card.appendChild(h("p", {
        "class": "note",
        text: "Keine Benutzertabelle mit Rollenspalte erkannt (Tabellen: " +
              ((imp.tables || []).join(", ") || "keine") + ")."
      }));
    }
    if (imp.total_users !== null && imp.total_users !== undefined) {
      card.appendChild(h("div", { "class": "dnxsc-callout",
        text: "Bestandskonten gesamt: " + imp.total_users + " – unveraendert uebernommen." }));
    }
    (imp.downgraded || []).forEach(function (d) {
      card.appendChild(h("div", { "class": "dnxsc-callout warn",
        text: d.count + " Konto(en) mit Rolle '" + d.role + "' zaehlen aktuell wirksam als '" +
              d.effective + "'. " + (d.note || "") }));
    });
    if (imp.settings && imp.settings.audit_enabled) {
      card.appendChild(h("div", { "class": "dnxsc-callout",
        text: "Audit-Grenzen: " + (imp.settings.max_audit_entries || 0).toLocaleString("de-DE") +
              " Zeilen / " + fmtBytes(imp.settings.max_audit_bytes) +
              " – automatische Loeschung " + (imp.settings.audit_auto_purge ? "AN" : "AUS") + "." }));
    }
    el.impact.appendChild(card);
  }

  function renderMeta() {
    if (el.version && state.meta.version) el.version.textContent = state.meta.version;
    if (el.meta) {
      el.meta.textContent = "Tabelle " + (state.meta.table || "access_settings") +
        " · Schema " + (state.meta.schema_version || 1) +
        " · " + (state.meta.fields || []).length + " Schluessel";
    }
  }

  function renderAll() {
    clearAlerts();
    renderSummary();
    renderBanners();
    renderWarnings();
    renderNav();
    renderGroups();
    renderImpact();
    renderMeta();
  }

  /* ------------------------------------------------------------ Speichern */

  function openModal(diffRows, okLabel, onOk) {
    el.modalBody.innerHTML = "";
    diffRows.forEach(function (d) {
      el.modalBody.appendChild(h("div", { "class": "dnxsc-diff" }, [
        h("span", { text: d.label }),
        h("span", { "class": "arrow", text: "→" }),
        h("span", {}, [
          h("span", { "class": "old", text: d.old }),
          h("span", { "class": "new", text: "  " + d.neu })
        ])
      ]));
    });
    el.modalOk.textContent = okLabel;
    el.modal.hidden = false;
    el.modalOk.onclick = function () {
      el.modal.hidden = true;
      el.modalOk.onclick = null;
      onOk();
    };
    el.modalCancel.onclick = function () {
      el.modal.hidden = true;
      el.modalOk.onclick = null;
    };
    el.modalOk.focus();
  }

  function showFieldErrors(fieldErrors) {
    Object.keys(fieldErrors || {}).forEach(function (key) {
      var box = document.getElementById("dnxsc-err-" + key);
      if (box) {
        box.textContent = fieldErrors[key];
        box.hidden = false;
      }
    });
  }

  function clearFieldErrors() {
    Array.prototype.forEach.call(document.querySelectorAll(".dnxsc-error"), function (b) {
      b.textContent = ""; b.hidden = true;
    });
  }

  function validateClientSide() {
    var errors = {};
    dirtyKeys().forEach(function (key) {
      var f = FIELDS[key], v = state.draft[key];
      if (f.type === "int") {
        if (typeof v !== "number" || isNaN(v)) { errors[key] = "Zahl erwartet"; return; }
        if (f.min !== null && v < f.min) errors[key] = "Minimum " + f.min;
        if (f.max !== null && v > f.max) errors[key] = "Maximum " + f.max;
      }
      if (f.type === "enum" && (f.choices || []).indexOf(String(v)) < 0) {
        errors[key] = "Erlaubt: " + (f.choices || []).join(", ");
      }
      if (f.type === "str" && String(v).length > (f.max_length || 500)) {
        errors[key] = "Maximal " + (f.max_length || 500) + " Zeichen";
      }
    });
    return errors;
  }

  function doSave() {
    clearFieldErrors();
    var errors = validateClientSide();
    if (Object.keys(errors).length) {
      showFieldErrors(errors);
      alert("err", "Eingaben ungueltig", Object.keys(errors).map(function (k) {
        return k + ": " + errors[k];
      }));
      return;
    }
    var keys = dirtyKeys();
    if (!keys.length) return;
    var rows = keys.map(function (k) {
      var f = FIELDS[k];
      return {
        label: (f ? f.label : k) + " (" + k + ")",
        old: fmtValue(f, state.settings[k]),
        neu: fmtValue(f, state.draft[k])
      };
    });
    openModal(rows, "Speichern", function () {
      state.busy = true;
      setDot("warn", "speichere ...");
      var payload = {};
      keys.forEach(function (k) { payload[k] = state.draft[k]; });
      request("/api/system/settings", { method: "POST", body: { settings: payload } })
        .then(function (data) {
          state.busy = false;
          clearAlerts();
          applyPayload(data);
          setDot("ok", "gespeichert");
          var changed = Object.keys(data.changed || {});
          alert("ok", "Gespeichert: " + changed.length + " Einstellung(en)",
            changed.map(function (k) {
              var c = data.changed[k];
              return (c.label || k) + ": " + fmtValue(FIELDS[k], c.old) + " → " + fmtValue(FIELDS[k], c.new);
            }).concat(data.audit_written ? [] : ["Hinweis: Es wurde keine Audit-Zeile geschrieben."]));
        })
        .catch(function (err) {
          state.busy = false;
          setDot("err", "Fehler beim Speichern");
          clearAlerts();
          if (err.status === 400 && err.data && err.data.field_errors) {
            showFieldErrors(err.data.field_errors);
            alert("err", "Backend hat Werte abgelehnt",
              Object.keys(err.data.field_errors).map(function (k) {
                return k + ": " + err.data.field_errors[k];
              }));
          } else if (err.status === 403) {
            alert("err", "Abgelehnt (403)", [err.message,
              "Bei CSRF-Fehlern hilft 'Neu laden' – der Token wird dann frisch geholt."]);
          } else if (err.status === 429) {
            alert("warn", "Zu viele Schreibvorgaenge", [err.message]);
          } else {
            alert("err", "Speichern fehlgeschlagen", [err.message,
              "Atomarer Rollback: es wurde nichts geaendert."]);
          }
          refreshDirtyUI();
        });
    });
  }

  function doReset() {
    openModal([{ label: "Alle editierbaren Schalter", old: "aktueller Stand",
                 neu: "Defaults (heutiges Verhalten)" }],
      "Zuruecksetzen", function () {
        request("/api/system/restore-defaults", { method: "POST", body: { confirm: true } })
          .then(function (data) {
            clearAlerts();
            applyPayload(data);
            alert("ok", "Defaults wiederhergestellt",
              Object.keys(data.changed || {}).map(function (k) { return k; }));
          })
          .catch(function (err) {
            clearAlerts();
            alert("err", "Zuruecksetzen fehlgeschlagen", [err.message]);
          });
      });
  }

  /* ------------------------------------------------------------- Bindings */

  if (el.save) el.save.addEventListener("click", doSave);
  if (el.reload) el.reload.addEventListener("click", function () { load({ notice: "Ist-Zustand neu geladen" }); });
  if (el.reset) el.reset.addEventListener("click", doReset);

  document.addEventListener("keydown", function (ev) {
    if ((ev.ctrlKey || ev.metaKey) && ev.key.toLowerCase() === "s") {
      ev.preventDefault();
      if (!el.save.disabled) doSave();
    }
    if (ev.key === "Escape" && el.modal && !el.modal.hidden) {
      el.modal.hidden = true;
    }
  });

  window.addEventListener("beforeunload", function (ev) {
    if (dirtyKeys().length) {
      ev.preventDefault();
      ev.returnValue = "";
    }
  });

  /* ------------------------------------------------------------- Start */

  if (BOOT.settings && BOOT.meta && BOOT.meta.fields) {
    applyPayload(BOOT);
    setDot("ok", "Bootstrap-Daten aktiv, Ist-Zustand wird verifiziert");
    load({});                      // echten Backendstatus nachziehen
  } else {
    load({});
  }
})();
