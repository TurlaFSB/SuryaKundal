// Zoom, pan and hover details for the attacker map. The dots, their positions and every
// value shown are rendered by the server (and escaped there); this file only moves the
// viewBox and copies each dot's data attributes into the tooltip with textContent.
(function () {
  var svg = document.getElementById("map");
  var box = document.getElementById("mapbox");
  var tip = document.getElementById("map-tip");
  var controls = document.getElementById("map-ctl");
  if (!svg || !box || !tip || !svg.viewBox || !svg.viewBox.baseVal) { return; }

  var WORLD = { x: 0, y: 0, w: 960, h: 480 };
  var FULL = (function () {
    var v = svg.viewBox.baseVal;
    return { x: v.x, y: v.y, w: v.width, h: v.height };
  })();
  var MAX_ZOOM = 48;
  var view = { x: FULL.x, y: FULL.y, w: FULL.w, h: FULL.h };
  var dots = Array.prototype.slice.call(svg.querySelectorAll("circle.dot"));
  controls.hidden = false;

  function apply() {
    var zoom = FULL.w / view.w;
    svg.setAttribute("viewBox", view.x + " " + view.y + " " + view.w + " " + view.h);
    var shrink = Math.pow(zoom, 0.75);
    dots.forEach(function (d) {
      d.setAttribute("r", Math.max(1.6, parseFloat(d.dataset.base) / shrink).toFixed(2));
    });
    hideTip();
  }

  function clamp() {
    view.w = Math.min(Math.max(view.w, FULL.w / MAX_ZOOM), FULL.w);
    view.h = view.w * FULL.h / FULL.w;
    view.x = Math.min(Math.max(view.x, WORLD.x), WORLD.x + WORLD.w - view.w);
    view.y = Math.min(Math.max(view.y, FULL.y), FULL.y + FULL.h - view.h);
  }

  // Zoom by `factor` (>1 zooms in) keeping the point (fx, fy), as fractions of the box, fixed.
  function zoomAt(factor, fx, fy) {
    var nw = view.w / factor;
    view.x += (view.w - nw) * fx;
    view.y += (view.h - nw * FULL.h / FULL.w) * fy;
    view.w = nw;
    clamp();
    apply();
  }

  controls.addEventListener("click", function (e) {
    var kind = e.target && e.target.dataset ? e.target.dataset.zoom : null;
    if (kind === "in") { zoomAt(1.8, 0.5, 0.5); }
    else if (kind === "out") { zoomAt(1 / 1.8, 0.5, 0.5); }
    else if (kind === "reset") { view = { x: FULL.x, y: FULL.y, w: FULL.w, h: FULL.h }; apply(); }
  });

  svg.addEventListener("wheel", function (e) {
    e.preventDefault();
    var r = svg.getBoundingClientRect();
    zoomAt(e.deltaY < 0 ? 1.25 : 0.8, (e.clientX - r.left) / r.width, (e.clientY - r.top) / r.height);
  }, { passive: false });

  var drag = null;
  svg.addEventListener("pointerdown", function (e) {
    if (e.button !== 0) { return; }
    drag = { x: e.clientX, y: e.clientY, vx: view.x, vy: view.y, moved: false };
  });
  window.addEventListener("pointermove", function (e) {
    if (!drag) { return; }
    var r = svg.getBoundingClientRect();
    var dx = e.clientX - drag.x, dy = e.clientY - drag.y;
    if (Math.abs(dx) + Math.abs(dy) > 3) { drag.moved = true; svg.classList.add("dragging"); }
    view.x = drag.vx - dx * view.w / r.width;
    view.y = drag.vy - dy * view.h / r.height;
    clamp();
    svg.setAttribute("viewBox", view.x + " " + view.y + " " + view.w + " " + view.h);
  });
  window.addEventListener("pointerup", function () {
    if (drag && drag.moved) { hideTip(); }
    drag = null;
    svg.classList.remove("dragging");
  });

  function line(parent, label, value) {
    if (!value) { return; }
    var row = document.createElement("div");
    var name = document.createElement("span");
    name.textContent = label;
    row.appendChild(name);
    row.appendChild(document.createTextNode(value));
    parent.appendChild(row);
  }

  function showTip(dot) {
    var d = dot.dataset;
    tip.textContent = "";
    var head = document.createElement("strong");
    head.textContent = d.ip;
    tip.appendChild(head);
    line(tip, "Place", d.place);
    line(tip, "Network", d.network);
    line(tip, "Sessions", d.sessions);
    line(tip, "Abuse score", d.abuse === "" ? "not rated" : d.abuse + " / 100");
    line(tip, "Last seen", d.seen);
    tip.hidden = false;
    var b = box.getBoundingClientRect(), c = dot.getBoundingClientRect();
    var left = c.left - b.left + c.width / 2 + 12;
    var top = c.top - b.top - 8;
    if (left + tip.offsetWidth > b.width - 8) { left = c.left - b.left - tip.offsetWidth - 12; }
    tip.style.left = Math.max(8, left) + "px";
    tip.style.top = Math.max(8, Math.min(top, b.height - tip.offsetHeight - 8)) + "px";
  }

  function hideTip() { tip.hidden = true; }

  function open(dot) {
    var href = dot.dataset.href || "";
    if (href.charAt(0) === "/" && href.charAt(1) !== "/") { window.location.assign(href); }
  }

  dots.forEach(function (dot) {
    dot.addEventListener("pointerenter", function () { if (!drag) { showTip(dot); } });
    dot.addEventListener("pointerleave", hideTip);
    dot.addEventListener("focus", function () { showTip(dot); });
    dot.addEventListener("blur", hideTip);
    dot.addEventListener("click", function () { if (!drag || !drag.moved) { open(dot); } });
    dot.addEventListener("keydown", function (e) {
      if (e.key === "Enter" || e.key === " ") { e.preventDefault(); open(dot); }
    });
  });
  apply();
})();
