(function () {
  "use strict";
  var $ = function (s, r) { return (r || document).querySelector(s); };
  var $$ = function (s, r) { return Array.prototype.slice.call((r || document).querySelectorAll(s)); };

  var board = $("#board");
  if (!board) return;

  var dragged = null, kind = null;

  var markEmpty = function () {
    $$(".site-list", board).forEach(function (l) {
      var n = $$(".site-row", l).length;
      l.classList.toggle("is-empty", n === 0);
      var c = l.closest(".board-group").querySelector(".count");
      if (c) c.textContent = n;
    });
  };
  markEmpty();

  var save = function () {
    var groups = $$(".board-group[data-group-id]", board)
      .map(function (g) { return g.dataset.groupId; })
      .filter(Boolean);
    var columns = $$(".site-list", board).map(function (l) {
      return { group: l.dataset.group, sites: $$(".site-row", l).map(function (r) { return r.dataset.siteId; }) };
    });
    fetch("/admin/sites/reorder", {
      method: "POST", credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": board.dataset.csrf },
      body: JSON.stringify({ groups: groups, columns: columns })
    }).then(function (r) {
      if (r.ok && window.SiteHubToast) SiteHubToast(board.dataset.saved);
      else if (!r.ok) SiteHubToast("Error " + r.status, "error");
    });
  };

  var afterElement = function (container, selector, y) {
    var best = null, bestOffset = -Infinity;
    $$(selector, container).forEach(function (el) {
      if (el === dragged) return;
      var box = el.getBoundingClientRect();
      var offset = y - box.top - box.height / 2;
      if (offset < 0 && offset > bestOffset) { bestOffset = offset; best = el; }
    });
    return best;
  };

  // --- sites
  $$(".site-row", board).forEach(function (row) {
    row.addEventListener("dragstart", function (e) {
      if (kind === "group") return;
      e.stopPropagation();
      dragged = row; kind = "site";
      row.classList.add("dragging");
      e.dataTransfer.effectAllowed = "move";
      e.dataTransfer.setData("text/plain", row.dataset.siteId);
    });
    row.addEventListener("dragend", function (e) {
      e.stopPropagation();
      row.classList.remove("dragging");
      $$(".site-list.drop").forEach(function (l) { l.classList.remove("drop"); });
      if (kind === "site") { markEmpty(); save(); }
      dragged = null; kind = null;
    });
  });
  $$(".site-list", board).forEach(function (list) {
    list.addEventListener("dragover", function (e) {
      if (kind !== "site") return;
      e.preventDefault();
      list.classList.add("drop");
      var after = afterElement(list, ".site-row", e.clientY);
      if (after) list.insertBefore(dragged, after); else list.appendChild(dragged);
    });
    list.addEventListener("dragleave", function () { list.classList.remove("drop"); });
    list.addEventListener("drop", function (e) { e.preventDefault(); list.classList.remove("drop"); });
  });

  // --- groups (drag by handle)
  var ungrouped = $(".board-group.ungrouped", board);
  $$(".group-handle", board).forEach(function (h) {
    var section = h.closest(".board-group");
    h.addEventListener("mousedown", function () { section.draggable = true; });
    h.addEventListener("touchstart", function () { section.draggable = true; }, { passive: true });
    section.addEventListener("dragstart", function (e) {
      if (e.target !== section) return;
      dragged = section; kind = "group";
      section.classList.add("dragging");
      e.dataTransfer.effectAllowed = "move";
      e.dataTransfer.setData("text/plain", section.dataset.groupId);
    });
    section.addEventListener("dragend", function (e) {
      if (e.target !== section) return;
      section.draggable = false;
      section.classList.remove("dragging");
      if (kind === "group") save();
      dragged = null; kind = null;
    });
  });
  document.addEventListener("mouseup", function () {
    $$(".board-group[draggable=true]", board).forEach(function (s) { if (kind !== "group") s.draggable = false; });
  });
  board.addEventListener("dragover", function (e) {
    if (kind !== "group") return;
    e.preventDefault();
    var after = afterElement(board, ".board-group:not(.ungrouped)", e.clientY);
    board.insertBefore(dragged, after || ungrouped);
  });
  board.addEventListener("drop", function (e) { if (kind === "group") e.preventDefault(); });
})();
