// Measure Plotly containers vs their cards to diagnose sizing overflow.
// Usage: node scripts/measure_plots.mjs http://localhost:3000/
import WebSocket from "../.web/node_modules/ws/index.js";

const URL = process.argv[2] || "http://localhost:3000/";
const TARGET = process.argv[3] || "http://localhost:3000/";

const list = await (await fetch("http://localhost:9222/json/list")).json();
const page = list.find((t) => t.type === "page");
const ws = new WebSocket(page.webSocketDebuggerUrl, { maxPayload: 64 * 1024 * 1024 });

let id = 0;
const pending = new Map();
const send = (method, params = {}) =>
  new Promise((res) => {
    const mid = ++id;
    pending.set(mid, res);
    ws.send(JSON.stringify({ id: mid, method, params }));
  });

ws.on("message", (raw) => {
  const msg = JSON.parse(raw.toString());
  if (msg.id && pending.has(msg.id)) {
    pending.get(msg.id)(msg.result);
    pending.delete(msg.id);
  }
});

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

await new Promise((r) => ws.on("open", r));
await send("Page.enable");
await send("Runtime.enable");
await send("Emulation.setDeviceMetricsOverride", {
  width: 1440, height: 900, deviceScaleFactor: 1, mobile: false,
});
await send("Page.navigate", { url: TARGET });
await sleep(6000);

const expr = `(() => {
  const out = [];
  document.querySelectorAll('.js-plotly-plot').forEach((p, i) => {
    const r = p.getBoundingClientRect();
    let card = p.closest('div[class]');
    // walk up to the nearest element that has a visible border (the card)
    let node = p.parentElement, cardRect = null;
    while (node) {
      const cs = getComputedStyle(node);
      if (cs.borderTopWidth !== '0px' && cs.borderTopStyle === 'solid') {
        cardRect = node.getBoundingClientRect(); break;
      }
      node = node.parentElement;
    }
    out.push({
      i,
      plot: { w: Math.round(r.width), h: Math.round(r.height), x: Math.round(r.x) },
      parent: { w: Math.round(p.parentElement.getBoundingClientRect().width) },
      card: cardRect ? { w: Math.round(cardRect.width), x: Math.round(cardRect.x),
                         right: Math.round(cardRect.right) } : null,
      overflowRight: cardRect ? Math.round(r.right - cardRect.right) : null,
    });
  });
  return JSON.stringify(out, null, 1);
})()`;

const res = await send("Runtime.evaluate", { expression: expr, returnByValue: true });
console.log(res.result.value);
ws.close();
