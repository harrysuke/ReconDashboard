// Evaluate an arbitrary expression in the page and print the result.
// Usage: node scripts/eval_page.mjs "expr" [url]
import WebSocket from "../.web/node_modules/ws/index.js";

const expr = process.argv[2];
const url = process.argv[3] || "http://localhost:3000/";

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
await send("Page.navigate", { url });
await sleep(6500);

const res = await send("Runtime.evaluate", {
  expression: expr,
  returnByValue: true,
  awaitPromise: true,
});
console.log(JSON.stringify(res.result?.value ?? res, null, 1));
ws.close();
