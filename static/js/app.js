(function () {
  "use strict";
  var $ = function (s, r) { return (r || document).querySelector(s); };
  var $$ = function (s, r) { return Array.prototype.slice.call((r || document).querySelectorAll(s)); };

  // theme toggle: auto -> light -> dark
  $$("[data-theme-toggle]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var order = ["auto", "light", "dark"];
      var next = order[(order.indexOf(window.SiteHubTheme.get()) + 1) % order.length];
      window.SiteHubTheme.set(next);
    });
  });

  // dropdown menus: close on outside click / Esc, only one open
  var menus = $$("details.menu");
  menus.forEach(function (m) {
    m.addEventListener("toggle", function () {
      if (m.open) menus.forEach(function (o) { if (o !== m) o.open = false; });
    });
  });
  document.addEventListener("click", function (e) {
    menus.forEach(function (m) { if (m.open && !m.contains(e.target)) m.open = false; });
  });
  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape") menus.forEach(function (m) { m.open = false; });
  });

  // toasts
  function hideToast(t) { t.classList.add("hide"); setTimeout(function () { t.remove(); }, 320); }
  $$(".toast").forEach(function (t, i) {
    $(".toast-x", t).addEventListener("click", function () { hideToast(t); });
    if (!t.classList.contains("error")) setTimeout(function () { hideToast(t); }, 5000 + i * 600);
  });
  window.SiteHubToast = function (text, kind) {
    var box = $(".toasts");
    if (!box) { box = document.createElement("div"); box.className = "toasts"; document.body.appendChild(box); }
    var t = document.createElement("div");
    t.className = "toast " + (kind || "ok");
    var s = document.createElement("span"); s.textContent = text; t.appendChild(s);
    box.appendChild(t);
    setTimeout(function () { hideToast(t); }, 3000);
  };

  // confirm dialogs
  $$("form[data-confirm]").forEach(function (f) {
    f.addEventListener("submit", function (e) { if (!confirm(f.dataset.confirm)) e.preventDefault(); });
  });
  $$("input[data-confirm-check]").forEach(function (c) {
    c.addEventListener("change", function () { if (c.checked && !confirm(c.dataset.confirmCheck)) c.checked = false; });
  });

  // busy state for long operations
  $$("form[data-busy]").forEach(function (f) {
    f.addEventListener("submit", function () {
      var b = $("button[type=submit]", f);
      if (b) { b.classList.add("busy"); b.lastChild.textContent = " " + f.dataset.busy; }
    });
  });

  // copy buttons
  $$("[data-copy]").forEach(function (b) {
    b.addEventListener("click", function () {
      var el = $(b.dataset.copy);
      if (!el) return;
      var text = el.innerText.trim().split(/\s+/).join("\n");
      var done = function () { b.classList.add("copied"); window.SiteHubToast && SiteHubToast("✓"); };
      if (navigator.clipboard && window.isSecureContext) navigator.clipboard.writeText(text).then(done);
      else {
        var ta = document.createElement("textarea"); ta.value = text; document.body.appendChild(ta);
        ta.select(); try { document.execCommand("copy"); done(); } catch (e) {} ta.remove();
      }
    });
  });

  // password reveal
  $$("[data-reveal]").forEach(function (b) {
    b.addEventListener("click", function () {
      var inp = b.parentNode.querySelector("input");
      inp.type = inp.type === "password" ? "text" : "password";
      inp.focus();
    });
  });

  // password strength meter
  $$("input[data-strength]").forEach(function (inp) {
    var bar = inp.closest("form").querySelector(".strength span");
    if (!bar) return;
    inp.addEventListener("input", function () {
      var v = inp.value, s = 0;
      if (v.length >= 8) s++; if (v.length >= 12) s++;
      if (/[a-zа-я]/.test(v) && /[A-ZА-Я]/.test(v)) s++;
      if (/\d/.test(v)) s++; if (/[^\w]/.test(v)) s++;
      var colors = ["var(--bad)", "var(--bad)", "var(--warn)", "var(--warn)", "var(--ok)", "var(--ok)"];
      bar.style.width = (v ? Math.max(10, s * 20) : 0) + "%";
      bar.style.background = colors[s];
    });
  });

  // OTP fields: digits only (but allow recovery codes on the login page)
  $$("input.otp").forEach(function (inp) {
    inp.addEventListener("input", function () {
      if (/^[\d\s]*$/.test(inp.value)) inp.value = inp.value.replace(/\D/g, "").slice(0, 6);
    });
  });

  // colour picker with "no colour"
  $$("input[type=color]").forEach(function (c) {
    var reset = c.parentNode.querySelector("[data-color-reset]");
    c.addEventListener("input", function () { c.removeAttribute("data-unset"); });
    if (reset) reset.addEventListener("click", function () { c.setAttribute("data-unset", ""); });
    c.form && c.form.addEventListener("submit", function () { if (c.hasAttribute("data-unset")) c.disabled = true; });
  });

  // restart page: wait for the service and follow it to the new address
  var rs = $("[data-restart]");
  if (rs) {
    var url = rs.dataset.url, tries = 0;
    var ping = function () {
      tries++;
      var probe = url.indexOf("http") === 0 ? url.replace(/\/admin\/server$/, "/healthz") : "/healthz";
      fetch(probe, { mode: "no-cors", cache: "no-store" })
        .then(function () { location.href = url; })
        .catch(function () { if (tries < 20) setTimeout(ping, 1500); else location.href = url; });
    };
    setTimeout(ping, 3500);
  }
})();
