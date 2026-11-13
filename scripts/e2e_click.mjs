/**
 * End-to-end UI check via the Chrome DevTools Protocol.
 *
 * Launches nothing itself: expects Edge/Chrome already listening on 9222.
 * Clicks "Run scan" on the overview page and captures the progress bar while
 * the background handler is streaming updates, then the settled state.
 *
 *   node scripts/e2e_click.mjs http://localhost:3000/ shots
 */
import WebSocket from "../.web/node_modules/ws/index.js";
import fs from "node:fs";
import path from "node:path";

const BASE = process.argv[2] || "http://localhost:3000/";
const OUT = process.argv[3] || "shots";
const DEBUG = "http://127.0.0.1:9222";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function pickTarget() {
  const res = await fetch(`${DEBUG}/json/list`);
  const targets = await res.json();
  const page = targets.find((t) => t.type === "page");
  if (!page) throw new Error("no page target");
  return page.webSocketDebuggerUrl;
}

function connect(url) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(url);
    let id = 0;
    const pending = new Map();
    const events = [];
    ws.on("open", () =>
      resolve({
        ws,
        events,
        send(method, params = {}) {
          const msgId = ++id;
          ws.send(JSON.stringify({ id: msgId, method, params }));
          return new Promise((res, rej) => pending.set(msgId, { res, rej }));
        },
      })
    );
    ws.on("message", (raw) => {
      const msg = JSON.parse(raw.toString());
      if (msg.id && pending.has(msg.id)) {
        const { res, rej } = pending.get(msg.id);
        pending.delete(msg.id);
        msg.error ? rej(new Error(msg.error.message)) : res(msg.result);
      } else if (msg.method) {
        events.push(msg);
      }
    });
    ws.on("error", reject);
  });
}

async function evaluate(cdp, expression) {
  const r = await cdp.send("Runtime.evaluate", {
    expression,
    returnByValue: true,
    awaitPromise: true,
  });
  return r.result?.value;
}

async function shot(cdp, name) {
  const { data } = await cdp.send("Page.captureScreenshot", { format: "png" });
  const file = path.join(OUT, name);
  fs.writeFileSync(file, Buffer.from(data, "base64"));
  console.log("saved", file);
}

const clickByText = (text) => `
(() => {
  const els = [...document.querySelectorAll('button, [role="button"], a')];
  const el = els.find(e => (e.innerText || '').trim().toLowerCase().includes(${JSON.stringify(
    text.toLowerCase()
  )}));
  if (!el) return 'not-found';
  el.click();
  return 'clicked';
})()`;

const main = async () => {
  fs.mkdirSync(OUT, { recursive: true });
  const wsUrl = await pickTarget();
  const cdp = await connect(wsUrl);
  await cdp.send("Page.enable");
  await cdp.send("Runtime.enable");
  await cdp.send("Emulation.setDeviceMetricsOverride", {
    width: 1680,
    height: 1200,
    deviceScaleFactor: 1,
    mobile: false,
  });

  await cdp.send("Page.navigate", { url: BASE });
  await sleep(7000); // hydration + on_load

  const ready = await evaluate(
    cdp,
    `document.body.innerText.includes('Exposure overview')`
  );
  console.log("page ready:", ready);

  console.log("click run scan:", await evaluate(cdp, clickByText("Run scan")));
  await sleep(1200);
  const strip = await evaluate(
    cdp,
    `(() => {
       const t = document.body.innerText;
       return t.includes('Scanning') || t.includes('Certificate transparency') || t.includes('CVE correlation');
     })()`
  );
  console.log("progress visible:", strip);
  await shot(cdp, "scan-running.png");

  await sleep(9000);
  const done = await evaluate(
    cdp,
    `(() => {
       const t = document.body.innerText;
       return { scanning: t.includes('Scanning'), hasIdle: t.includes('No scan running'),
                body: t.slice(0, 200) };
     })()`
  );
  console.log("after scan:", JSON.stringify(done));
  await shot(cdp, "scan-done.png");

  // exercise the target form: add an invalid scope, expect the inline error
  await cdp.send("Page.navigate", { url: BASE.replace(/\/$/, "") + "/targets" });
  await sleep(5000);
  await evaluate(
    cdp,
    `(() => {
       const input = document.querySelector('input[placeholder*="example.com"]');
       if (!input) return 'no-input';
       const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
       setter.call(input, 'not a domain!!');
       input.dispatchEvent(new Event('input', { bubbles: true }));
       return 'typed';
     })()`
  );
  await sleep(600);
  console.log("click add:", await evaluate(cdp, clickByText("Add target")));
  await sleep(1500);
  const err = await evaluate(
    cdp,
    `document.body.innerText.includes('does not look like')`
  );
  console.log("validation error shown:", err);
  await shot(cdp, "targets-error.png");

  cdp.ws.close();
  process.exit(0);
};

main().catch((e) => {
  console.error("E2E FAILED:", e.message);
  process.exit(1);
});
