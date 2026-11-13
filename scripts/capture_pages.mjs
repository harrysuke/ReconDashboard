// Capture every route to shots/<name>.png and report console errors.
// Usage: node scripts/capture_pages.mjs [baseUrl] [outDir]
import WebSocket from "../.web/node_modules/ws/index.js";
import { mkdirSync, writeFileSync } from "node:fs";

const BASE = (process.argv[2] || "http://localhost:3000").replace(/\/$/, "");
const OUT = process.argv[3] || "shots";
const ROUTES = [
  ["/", "dashboard"],
  ["/targets", "targets"],
  ["/assets", "assets"],
  ["/vulnerabilities", "vulnerabilities"],
  ["/scans", "scans"],
  ["/settings", "settings"],
];

mkdirSync(OUT, { recursive: true });

const list = await (await fetch("http://localhost:9222/json/list")).json();
const page = list.find((t) => t.type === "page");
const ws = new WebSocket(page.webSocketDebuggerUrl, { maxPayload: 128 * 1024 * 1024 });

let id = 0;
const pending = new Map();
const errors = [];

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
    return;
  }
  if (msg.method === "Runtime.exceptionThrown") {
    errors.push(msg.params.exceptionDetails?.exception?.description?.slice(0, 200) || "exception");
  }
  if (msg.method === "Runtime.consoleAPICalled" && msg.params.type === "error") {
    const text = (msg.params.args || [])
      .map((a) => a.value ?? a.description ?? "")
      .join(" ")
      .slice(0, 200);
    if (text) errors.push(text);
  }
});

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Charts mount, then get re-fitted, then may remount again when the state
// refreshes. Screenshot only once every plot has settled at its parent width.
const SETTLED = `(() => {
  const plots = [...document.querySelectorAll('.js-plotly-plot')];
  const bad = plots.filter((p) => {
    const parent = p.parentElement;
    if (!parent) return false;
    const want = parent.clientWidth;
    const got = p.getBoundingClientRect().width;
    return want > 0 && Math.abs(got - want) > 2;
  });
  return plots.length === 0 ? 'empty' : (bad.length ? 'unstable' : 'ok');
})()`;

async function waitForPlots(timeoutMs = 15000) {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    const res = await send("Runtime.evaluate", { expression: SETTLED, returnByValue: true });
    if (res.result?.value === "ok" || res.result?.value === "empty") return res.result.value;
    await sleep(400);
  }
  return "timeout";
}

await new Promise((r) => ws.on("open", r));
await send("Page.enable");
await send("Runtime.enable");
await send("Emulation.setDeviceMetricsOverride", {
  width: 1440, height: 900, deviceScaleFactor: 1, mobile: false,
});

for (const [route, name] of ROUTES) {
  await send("Page.navigate", { url: BASE + route });
  await sleep(3500);
  const state = await waitForPlots();
  await sleep(400);
  const shot = await send("Page.captureScreenshot", { format: "png" });
  writeFileSync(`${OUT}/${name}.png`, Buffer.from(shot.data, "base64"));
  const title = await send("Runtime.evaluate", {
    expression: "document.querySelector('h1,h2')?.innerText || document.title",
    returnByValue: true,
  });
  console.log(`${name.padEnd(16)} -> ${OUT}/${name}.png  [${title.result.value}] plots=${state}`);
}

if (errors.length) {
  console.log("\nconsole errors:");
  [...new Set(errors)].forEach((e) => console.log("  " + e));
} else {
  console.log("\nno console errors");
}
ws.close();
