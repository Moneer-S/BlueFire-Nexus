import assert from "node:assert/strict";
import { Readable } from "node:stream";
import test from "node:test";
import { guardRoute, probe, readCapability } from "./run_install_gate_browser_probe.mjs";

test("the bootstrap code is accepted only from a bounded exact stdin document", async () => {
  const capability = "C".repeat(64);
  assert.equal(await readCapability(Readable.from([JSON.stringify({ capability })])), capability);
  for (const raw of ["x".repeat(257), "{}", JSON.stringify({ capability, extra: true }), JSON.stringify({ capability: "wrong" }), JSON.stringify({ capability: [capability] })]) {
    await assert.rejects(readCapability(Readable.from([raw])));
  }
});

function fixture(fail = false, wrongOrigin = false) {
  const events = [];
  const locator = name => ({
    async waitFor() { events.push(["visible", name]); },
    async fill(value) { events.push(["fill", name, value]); },
    async click() { events.push(["click", name]); if (fail) throw new Error("private detail"); },
  });
  const page = name => ({
    address: "about:blank",
    url() { return wrongOrigin ? "http://127.0.0.1:9999/" : this.address; },
    async goto(url) { this.address = url; events.push(["goto", name, url]); },
    async reload() { events.push(["reload", name]); },
    async close() { events.push(["close-page", name]); },
    getByRole(role, options) { return locator(`${role}:${options.name}`); },
    getByLabel(label) { return locator(label); },
    getByText(text) { return locator(text); },
  });
  const main = page("main");
  const context = {
    setDefaultTimeout() {}, setDefaultNavigationTimeout() {},
    async route(_pattern, callback) {
      for (const [url, status, expected] of [["http://127.0.0.1:8765/api/v1/session", 200, "fulfill"], ["http://127.0.0.1:8765/", 302, "abort"], ["http://127.0.0.1:8766/", 200, "abort"], ["https://example.com/", 200, "abort"]]) {
        let action;
        await callback({ request: () => ({ url: () => url }),
          fetch: async options => { assert.deepEqual(options, { maxRedirects: 0, maxRetries: 0, timeout: 15000 }); return { status: () => status, dispose: async () => {} }; },
          fulfill: async () => { action = "fulfill"; }, abort: async () => { action = "abort"; },
        });
        assert.equal(action, expected);
      }
    },
    async routeWebSocket(_pattern, callback) { let closed = false; callback({ close: () => { closed = true; } }); assert.equal(closed, true); },
    pages: () => [main],
    async newPage() { events.push(["new-page"]); return page("separate"); },
    async close() { events.push(["close-context"]); },
  };
  const chromium = { async launchPersistentContext(profile, options) { events.push(["launch", profile, options]); return context; } };
  return { chromium, events };
}

test("the probe uses the connection form, one retained tab, a fresh tab gate, and bounded route scope", async () => {
  const { chromium, events } = fixture();
  const capability = "C".repeat(64);
  const report = await probe(chromium, { profile: "/private/profile", edge: "/trusted/edge", port: 8765 }, capability);
  assert.equal(report.explicit_connection_form, true);
  assert.equal(report.same_tab_reload_authenticated, true);
  assert.equal(report.new_tab_requires_connection, true);
  assert.equal(JSON.stringify(report).includes(capability), false);
  const launch = events.find(event => event[0] === "launch");
  assert.equal(JSON.stringify(launch).includes(capability), false);
  assert.equal(JSON.stringify(launch).includes("remote-debugging-port"), false);
  assert.equal(launch[2].serviceWorkers, "block");
  assert.deepEqual(events.filter(event => event[0] === "fill"), [["fill", "One-time connection code", capability]]);
  assert.deepEqual(events.filter(event => event[0] === "reload"), [["reload", "main"]]);
  assert.deepEqual(events.filter(event => event[0] === "goto").map(event => event.slice(1)), [
    ["main", "http://127.0.0.1:8765/"], ["separate", "http://127.0.0.1:8765/"], ["main", "http://127.0.0.1:8765/#/runs?setup=execute"],
  ]);
  assert.deepEqual(events.at(-1), ["close-context"]);
});

test("a failed interaction closes the owned context instead of reporting success", async () => {
  const { chromium, events } = fixture(true);
  await assert.rejects(probe(chromium, { profile: "/private/profile", edge: "/trusted/edge", port: 8765 }, "C".repeat(64)));
  assert.deepEqual(events.at(-1), ["close-context"]);
});

test("invalid ports and codes never launch a browser", async () => {
  const { chromium, events } = fixture();
  await assert.rejects(probe(chromium, { profile: "/private/profile", edge: "/trusted/edge", port: 0 }, "C".repeat(64)));
  await assert.rejects(probe(chromium, { profile: "/private/profile", edge: "/trusted/edge", port: 8765 }, "bad"));
  assert.equal(events.length, 0);
});

test("a changed connection-page origin is rejected before the code is filled", async () => {
  const { chromium, events } = fixture(false, true);
  await assert.rejects(probe(chromium, { profile: "/private/profile", edge: "/trusted/edge", port: 8765 }, "C".repeat(64)));
  assert.equal(events.some(event => event[0] === "fill"), false);
  assert.deepEqual(events.at(-1), ["close-context"]);
});

test("literal IP destinations and failed requests are aborted without retry or fallback", async () => {
  for (const url of ["http://192.0.2.1/", "http://127.0.0.1:8766/", "http://127.0.0.1:8765/"]) {
    let fetched = false, aborted = false;
    await guardRoute({ request: () => ({ url: () => url }),
      fetch: async options => { fetched = true; assert.equal(options.maxRedirects, 0); assert.equal(options.maxRetries, 0); throw new Error("unavailable"); },
      abort: async () => { aborted = true; },
      fulfill: async () => { assert.fail("a failed request must not be fulfilled"); },
    }, "http://127.0.0.1:8765");
    assert.equal(aborted, true);
    assert.equal(fetched, url === "http://127.0.0.1:8765/");
  }
});
