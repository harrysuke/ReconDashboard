// Watch /targets for real page reloads, socket churn and JS errors.
// Usage: node scripts/diag_targets.mjs [url] [seconds]
import WebSocket from "../.web/node_modules/ws/index.js";

const URL_ = process.argv[2] || "http://localhost:3000/targets";
const SECS = Number(process.argv[3] || 20);

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

const counts = { navigated: 0, loaded: 0, exceptions: 0, consoleErrors: 0, wsClosed: 0, netFailed: 0 };
const samples = [];

ws.on("message", (raw) => {
  const msg = JSON.parse(raw.toString());
  if (msg.id && pending.has(msg.id)) {
    pending.get(msg.id)(msg.result);
    pending.delete(msg.id);
    return;
  }
  const p = msg.params || {};
  switch (msg.method) {
    case "Page.frameNavigated":
      if (!p.frame?.parentId) counts.navigated += 1;
      break;
    case "Page.loadEventFired":
      counts.loaded += 1;
      break;
    case "Runtime.exceptionThrown":
      counts.exceptions += 1;
      samples.push("EXC: " + (p.exceptionDetails?.exception?.description || "").slice(0, 180));
      break;
    case "Runtime.consoleAPICalled":
      if (p.type === "error") {
        counts.consoleErrors += 1;
        samples.push("CONSOLE: " + (p.args || []).map((a) => a.value ?? a.description ?? "").join(" ").slice(0, 180));
      }
      break;
    case "Network.webSocketClosed":
      counts.wsClosed += 1;
      break;
    case "Network.loadingFailed":
      counts.netFailed += 1;
      if (p.errorText && p.errorText !== "net::ERR_ABORTED") samples.push("NET: " + p.errorText);
      break;
  }
});

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

await new Promise((r) => ws.on("open", r));
await send("Page.enable");
await send("Runtime.enable");
await send("Network.enable");
await send("Emulation.setDeviceMetricsOverride", { width: 1440, height: 900, deviceScaleFactor: 1, mobile: false });

await send("Page.navigate", { url: URL_ });
await sleep(SECS * 1000);

const state = await send("Runtime.evaluate", {
  expression: `(() => {
    const input = document.querySelector('input[placeholder*="203.0.113.10"]');
    return JSON.stringify({
      rows: document.querySelectorAll('tbody tr').length,
      hasScopeInput: !!input,
      inputValue: input ? input.value : null,
      bodyLen: document.body.innerText.length,
      socketReady: !!document.querySelector('[data-reflex-root]'),
    });
  })()`,
  returnByValue: true,
});

console.log(`observed ${SECS}s on ${URL_}`);
console.log("counts:", JSON.stringify(counts));
console.log("page:", state.result?.value);
if (samples.length) {
  console.log("samples:");
  [...new Set(samples)].slice(0, 12).forEach((s) => console.log("  " + s));
}
ws.close();
