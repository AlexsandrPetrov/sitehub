(function () {
  var d = document.documentElement, pref = "auto";
  try { pref = localStorage.getItem("theme") || "auto"; } catch (e) {}
  var mq = window.matchMedia("(prefers-color-scheme: dark)");
  function apply() {
    d.dataset.themePref = pref;
    d.dataset.theme = pref === "auto" ? (mq.matches ? "dark" : "light") : pref;
  }
  apply();
  if (mq.addEventListener) mq.addEventListener("change", function () { if (pref === "auto") apply(); });
  window.SiteHubTheme = {
    get: function () { return pref; },
    set: function (p) { pref = p; try { localStorage.setItem("theme", p); } catch (e) {} apply(); }
  };
})();
