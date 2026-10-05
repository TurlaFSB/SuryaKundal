// Polls a tiny endpoint and offers a reload when new sessions arrive. No data is rendered here.
(function () {
  var script = document.currentScript;
  var known = parseInt(script && script.dataset.count, 10);
  var banner = document.getElementById("fresh");
  if (isNaN(known) || !banner || !window.fetch || !script.dataset.pulse) { return; }
  setInterval(function () {
    fetch(script.dataset.pulse, { credentials: "same-origin", cache: "no-store" })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (p) { if (p && p.sessions > known) { banner.hidden = false; } })
      .catch(function () {});
  }, 20000);
})();
