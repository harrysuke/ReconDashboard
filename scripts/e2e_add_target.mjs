// End-to-end check for the "Add a scope" form.
//
// Types a scope with real key events (so React's onChange actually fires), then
// clicks "Add target" and asserts the row shows up with no validation error.
// Uses a reserved .example hostname so nothing touches the network.
//
// Usage: node scripts/e2e_add_target.mjs [baseUrl] [scope]
import WebSocket from "../.web/node_modules/ws/index.js";
import { mkdirSync, writeFileSync } from "node:fs";

const BASE = (process.argv[2] || "http://localhost:3000").replace(/\/$/, "");
const SCOPE = process.argv[3] || "smoke-test.example";
const OUT = "shots";

mkdirSync(OUT, { recursive: true });

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
const evalJs = async (expression) => {
  const r = await send("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true });
  return r.result?.value;
};

await new Promise((r) => ws.on("open", r));
await send("Page.enable");
await send("Runtime.enable");
await send("Emulation.setDeviceMetricsOverride", {
  width: 1440, height: 900, deviceScaleFactor: 1, mobile: false,
});

await send("Page.navigate", { url: BASE + "/targets" });
await sleep(5000);

// --- type into the scope field with real events ---------------------------
const focused = await evalJs(`(() => {
  const el = document.querySelector('input[placeholder*="203.0.113.10"]');
  if (!el) return false;
  el.focus();
  el.select && el.select();
  return document.activeElement === el;
})()`);
console.log("scope field focused:", focused);
if (!focused) {
  console.log("FAIL: could not find the scope input");
  ws.close();
  process.exit(1);
}

// Clear whatever is there, then insert the scope as if typed.
await evalJs(`(() => {
  const el = document.activeElement;
  el.value = "";
  el.dispatchEvent(new Event("input", { bubbles: true }));
  return true;
})()`);
await send("Input.insertText", { text: SCOPE });
await sleep(600);

const typed = await evalJs(`document.querySelector('input[placeholder*="203.0.113.10"]').value`);
console.log("field value after typing:", JSON.stringify(typed));

// --- click "Add target" ---------------------------------------------------
const clicked = await evalJs(`(() => {
  const btn = [...document.querySelectorAll('button')]
    .find((b) => b.textContent.trim() === "Add target");
  if (!btn) return false;
  btn.click();
  return true;
})()`);
console.log("clicked add:", clicked);
await sleep(2500);

// --- verify ---------------------------------------------------------------
const result = await evalJs(`(() => {
  const body = document.body.innerText;
  const rows = [...document.querySelectorAll("tbody tr")].map((tr) => tr.innerText.split("\\n")[0]);
  return JSON.stringify({
    scopePresent: rows.some((r) => r.includes(${JSON.stringify(SCOPE)})),
    rows,
    hasFormError: /does not look like|Enter a domain|already being monitored/.test(body),
    toast: (body.match(/Now monitoring \\S+/) || [null])[0],
  });
})()`);
console.log("after add:", result);

const shot = await send("Page.captureScreenshot", { format: "png" });
writeFileSync(`${OUT}/targets-added.png`, Buffer.from(shot.data, "base64"));

const parsed = JSON.parse(result);
const ok = parsed.scopePresent && !parsed.hasFormError;
console.log(ok ? "PASS: scope added via the form" : "FAIL: scope was not added");
ws.close();
process.exit(ok ? 0 : 1);
