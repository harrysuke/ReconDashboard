/* Fit Plotly charts to their cards.
 *
 * react-plotly.js mounts the graph div as `display: inline-block` with no
 * width. Plotly measures that div when it draws, gets 0, and falls back to its
 * 700x450 default - so every chart overflows its card by a fixed amount.
 *
 * Two things are needed:
 *   1. CSS so the graph div is a block that fills its parent.
 *   2. A direct `Plotly.Plots.resize()` call after mount, because
 *      `config.responsive` only listens for window resizes, which never fire on
 *      a static page load.
 *
 * The resize is skipped when the width already matches, so the ResizeObserver
 * cannot feed itself in a loop.
 */
(function () {
  if (window.__reconPlotFit) return;
  window.__reconPlotFit = true;

  var CSS_ID = "recon-plotly-fit-css";
  var CSS =
    ".js-plotly-plot{display:block !important;width:100% !important;}" +
    ".js-plotly-plot .main-svg{max-width:100%;}";

  function ensureCss() {
    if (document.getElementById(CSS_ID)) return;
    var style = document.createElement("style");
    style.id = CSS_ID;
    style.textContent = CSS;
    (document.head || document.documentElement).appendChild(style);
  }

  function resizeAll() {
    ensureCss();
    var Plotly = window.Plotly;
    if (!Plotly || !Plotly.Plots) return;
    var plots = document.querySelectorAll(".js-plotly-plot");
    for (var i = 0; i < plots.length; i += 1) {
      var el = plots[i];
      if (!el._fullLayout) continue; // still drawing
      var target = el.parentElement ? el.parentElement.clientWidth : 0;
      if (!target) continue;
      if (Math.abs((el._fullLayout.width || 0) - target) < 1) continue;
      try {
        Plotly.Plots.resize(el);
      } catch (err) {
        /* a chart mid-teardown is not worth failing over */
      }
    }
  }

  var queued = false;
  function schedule() {
    if (queued) return;
    queued = true;
    window.requestAnimationFrame(function () {
      queued = false;
      resizeAll();
    });
  }

  function watch(el) {
    if (el.__reconObserved) return;
    el.__reconObserved = true;
    if (window.ResizeObserver && el.parentElement) {
      new ResizeObserver(schedule).observe(el.parentElement);
    }
    schedule();
  }

  function scan() {
    ensureCss();
    var plots = document.querySelectorAll(".js-plotly-plot");
    for (var i = 0; i < plots.length; i += 1) watch(plots[i]);
  }

  function boot() {
    scan();
    new MutationObserver(scan).observe(document.body, {
      childList: true,
      subtree: true,
    });
    // Charts mount after the state loads, so re-check a few times as well.
    [80, 300, 900, 1800, 3200].forEach(function (t) {
      window.setTimeout(schedule, t);
    });
    window.addEventListener("resize", schedule);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
