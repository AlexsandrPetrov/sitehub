(function () {
  "use strict";
  var $ = function (s, r) { return (r || document).querySelector(s); };
  var $$ = function (s, r) { return Array.prototype.slice.call((r || document).querySelectorAll(s)); };

  // clock + greeting
  var clock = $("[data-clock]");
  if (clock) {
    var lang = clock.dataset.lang === "en" ? "en-GB" : "ru-RU";
    var timeEl = $(".clock-time", clock), dateEl = $(".clock-date", clock);
    var g = $("[data-greeting]");
    var tick = function () {
      var d = new Date();
      timeEl.textContent = d.toLocaleTimeString(lang, { hour: "2-digit", minute: "2-digit" });
      dateEl.textContent = d.toLocaleDateString(lang, { weekday: "long", day: "numeric", month: "long" });
      if (g) {
        var h = d.getHours();
        var key = h < 5 ? "gNight" : h < 12 ? "gMorning" : h < 18 ? "gDay" : "gEvening";
        g.textContent = g.dataset[key] + (g.dataset.name ? ", " + g.dataset.name : "");
      }
    };
    tick();
    setInterval(tick, 1000 * 15);
  }

  // view mode
  var sections = $("#sections");
  var setView = function (v) {
    document.body.classList.toggle("view-list", v === "list");
    $$("[data-view]").forEach(function (b) { b.classList.toggle("active", b.dataset.view === v); });
    try { localStorage.setItem("view", v); } catch (e) {}
  };
  var saved = "grid";
  try { saved = localStorage.getItem("view") || "grid"; } catch (e) {}
  setView(saved);
  $$("[data-view]").forEach(function (b) { b.addEventListener("click", function () { setView(b.dataset.view); }); });

  // search
  var q = $("#q");
  var tiles = $$(".tile");
  var kbIndex = -1;
  var visible = function () { return tiles.filter(function (t) { return !t.hidden; }); };
  var mark = function (i) {
    tiles.forEach(function (t) { t.classList.remove("kb"); });
    var v = visible();
    kbIndex = Math.max(-1, Math.min(i, v.length - 1));
    if (kbIndex >= 0) { v[kbIndex].classList.add("kb"); v[kbIndex].scrollIntoView({ block: "nearest" }); }
  };
  var filter = function () {
    var terms = q.value.toLowerCase().trim().split(/\s+/).filter(Boolean);
    tiles.forEach(function (t) {
      var hay = t.dataset.search;
      t.hidden = !terms.every(function (w) { return hay.indexOf(w) !== -1; });
    });
    $$("[data-group]").forEach(function (g) { g.hidden = !$$(".tile", g).some(function (t) { return !t.hidden; }); });
    var empty = $(".empty-search");
    if (empty) empty.hidden = visible().length > 0;
    mark(terms.length ? 0 : -1);
  };
  if (q) {
    q.addEventListener("input", filter);
    q.addEventListener("keydown", function (e) {
      if (e.key === "Escape") { q.value = ""; filter(); q.blur(); }
      else if (e.key === "ArrowDown") { e.preventDefault(); mark(kbIndex + 1); }
      else if (e.key === "ArrowUp") { e.preventDefault(); mark(kbIndex - 1); }
      else if (e.key === "Enter") {
        var v = visible(), t = v[Math.max(0, kbIndex)];
        if (t) { e.preventDefault(); t.click(); }
      }
    });
    document.addEventListener("keydown", function (e) {
      var tag = (document.activeElement || {}).tagName;
      if (e.key === "/" && tag !== "INPUT" && tag !== "TEXTAREA" && tag !== "SELECT") { e.preventDefault(); q.focus(); }
    });
  }

  // click statistics
  tiles.forEach(function (t) {
    t.addEventListener("click", function () {
      if (navigator.sendBeacon) navigator.sendBeacon("/api/click/" + t.dataset.site);
    });
  });

  // live status refresh
  if (!sections || sections.dataset.statusEnabled !== "1") return;
  var ds = sections.dataset;
  var refresh = function () {
    fetch("/api/status", { credentials: "same-origin", cache: "no-store" })
      .then(function (r) { return r.ok ? r.json() : []; })
      .then(function (list) {
        var up = 0, down = 0;
        list.forEach(function (s) {
          if (s.status === 1) up++; else if (s.status === 0) down++;
          $$('[data-status-of="' + s.id + '"]').forEach(function (el) {
            el.classList.remove("up", "down", "unknown");
            el.classList.add(s.status === 1 ? "up" : s.status === 0 ? "down" : "unknown");
            $(".lat", el).textContent = s.status === 1 && s.latency != null ? s.latency + " " + ds.ms : "";
            var title = s.status === 1 ? ds.tUp : s.status === 0 ? ds.tDown + (s.error ? ": " + s.error : "") : "";
            if (s.uptime != null) title += " · " + ds.tUptime + " " + s.uptime + "%";
            el.title = title;
          });
        });
        var cu = $("[data-count-up] b"), cd = $("[data-count-down] b");
        if (cu) cu.textContent = up;
        if (cd) cd.textContent = down;
      })
      .catch(function () {});
  };
  setInterval(function () { if (!document.hidden) refresh(); }, 30000);
  document.addEventListener("visibilitychange", function () { if (!document.hidden) refresh(); });
})();
