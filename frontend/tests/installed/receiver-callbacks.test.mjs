import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { spawnSync } from "node:child_process";
import process from "node:process";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { test } from "vitest";
import { closeReceiverWebSocket, handleReceiverRoute, observeReceiverEvent, observeReceiverWait, settleReceiverObservers } from "./receiver-guards.mjs";

const origin = "http://127.0.0.1:4317";

function routeFor(url, method = "GET", actions = {}) {
  const calls = [];
  return {
    calls,
    request: () => ({ url: () => url, method: () => method, postData: () => null, postDataJSON: () => null }),
    abort: async () => { calls.push("abort"); if (actions.abort) throw new Error("private abort failure"); },
    continue: async () => { calls.push("continue"); if (actions.continue) throw new Error("private continue failure"); },
  };
}

function options(overrides = {}) {
  const blocked = [];
  const failures = [];
  return {
    blocked,
    failures,
    expectedOrigin: origin,
    allowedRead: () => true,
    authorizePost: () => true,
    onBlocked: (entry) => blocked.push(entry),
    onFailure: (kind) => failures.push(kind),
    ...overrides,
  };
}

test("route callback preserves exact denial and aborts a classifier failure", async () => {
  const foreign = routeFor("https://outside.example/private?secret=hidden");
  const denied = options({ allowedRead: () => { throw new Error("must not reach read policy"); } });
  await handleReceiverRoute(foreign, denied);
  assert.deepEqual(foreign.calls, ["abort"]);
  assert.deepEqual(denied.blocked, [{ method: "GET", path: "non_loopback", reason: "non_loopback" }]);
  assert.deepEqual(denied.failures, []);

  const failed = routeFor(`${origin}/api/v1/session`);
  const classifier = options({ allowedRead: () => { throw new Error("private callback value"); } });
  await handleReceiverRoute(failed, classifier);
  assert.deepEqual(failed.calls, ["abort"]);
  assert.deepEqual(classifier.failures, ["request_route_failed"]);
  assert.deepEqual(classifier.blocked, []);

  const sameOriginSecret = routeFor(`${origin}/private-capability-in-path`, "DELETE");
  const invalid = options();
  await handleReceiverRoute(sameOriginSecret, invalid);
  assert.deepEqual(sameOriginSecret.calls, ["abort"]);
  assert.deepEqual(invalid.blocked, [{ method: "OTHER", path: "loopback", reason: "method_not_allowlisted" }]);
  assert.equal(JSON.stringify(invalid.blocked).includes("private-capability"), false);
});

test("route callback never continues after a failed action or abort", async () => {
  const continued = routeFor(`${origin}/api/v1/session`, "GET", { continue: true });
  const first = options();
  await handleReceiverRoute(continued, first);
  assert.deepEqual(continued.calls, ["continue", "abort"]);
  assert.deepEqual(first.failures, ["request_route_failed"]);

  const refused = routeFor("https://outside.example/private", "GET", { abort: true });
  const second = options();
  await handleReceiverRoute(refused, second);
  assert.deepEqual(refused.calls, ["abort", "abort"]);
  assert.deepEqual(second.failures, ["request_route_failed", "request_abort_failed"]);
  assert.equal(refused.calls.includes("continue"), false);
});

test("websocket callback records a failed closure without connecting", async () => {
  const blocked = [];
  const failures = [];
  await closeReceiverWebSocket({ close: async () => { throw new Error("private socket detail"); } }, {
    onBlocked: () => blocked.push("blocked"),
    onFailure: (kind) => failures.push(kind),
  });
  assert.deepEqual(blocked, ["blocked"]);
  assert.deepEqual(failures, ["websocket_close_failed"]);
});

test("EventEmitter observer catches synchronous and asynchronous callback failures", async () => {
  const emitter = new EventEmitter();
  const pending = new Set();
  const failures = [];
  emitter.on("response", observeReceiverEvent(async () => { throw new Error("private response URL"); },
    () => failures.push("response_observer_failed"), pending));
  emitter.on("console", observeReceiverEvent(() => { throw new Error("private console text"); },
    () => failures.push("console_observer_failed"), pending));
  emitter.emit("response");
  emitter.emit("console");
  await Promise.allSettled([...pending]);
  assert.deepEqual(failures.sort(), ["console_observer_failed", "response_observer_failed"]);
  assert.equal(pending.size, 0);
});

test("observer drain has a ref'ed finite timeout and reports unsettled work", async () => {
  const pending = new Set();
  const emitter = new EventEmitter();
  emitter.on("response", observeReceiverEvent(() => new Promise(() => {}), () => {}, pending));
  emitter.emit("response");
  const started = Date.now();
  assert.equal(await settleReceiverObservers(pending, 15), false);
  assert.ok(Date.now() - started < 500);
  assert.equal(pending.size, 1);
});

test("page wait observer preserves original success and failure for its awaiting caller", async () => {
  const pending = new Set();
  const failures = [];
  const response = { ok: true };
  const success = Promise.resolve(response);
  assert.equal(observeReceiverWait(success, () => failures.push("unexpected"), pending), success);
  assert.equal(await success, response);

  const error = new Error("private response URL and capability");
  const failure = Promise.reject(error);
  assert.equal(observeReceiverWait(failure, () => failures.push("page_wait_failed"), pending), failure);
  await assert.rejects(failure, actual => actual === error);
  assert.equal(await settleReceiverObservers(pending, 1000), true);
  assert.deepEqual(failures, ["page_wait_failed"]);
  assert.equal(pending.size, 0);
});

test("unawaited page wait rejection during closure retains failure and completes cleanup under strict Node handling", () => {
  const guardsUrl = pathToFileURL(resolve("tests/installed/receiver-guards.mjs")).href;
  const child = spawnSync(process.execPath, ["--unhandled-rejections=strict", "--input-type=module", "--eval", `
    import assert from "node:assert/strict";
    import { setImmediate } from "node:timers/promises";
    import { observeReceiverWait, settleReceiverObservers } from ${JSON.stringify(guardsUrl)};
    const pending = new Set();
    const report = { status: "failed_or_incomplete", errors: [], cleanup: [] };
    let rejectWait;
    const wait = new Promise((_resolve, reject) => { rejectWait = reject; });
    const owned = observeReceiverWait(wait, () => report.errors.push({
      stage: "composition-review", kind: "page_wait_failed", method: "waitForResponse",
    }), pending);
    assert.equal(owned, wait);
    try {
      // The intervening UI action fails before the deferred wait can be awaited.
      throw new Error("private UI action path");
    } catch {
      report.errors.push({ stage: "composition-review", kind: "journey_failed" });
    } finally {
      rejectWait(new Error("private response URL and capability"));
      await setImmediate();
      report.cleanup.push("context_closed", "browser_closed");
      assert.equal(await settleReceiverObservers(pending, 1000), true);
      assert.equal(pending.size, 0);
      console.log(JSON.stringify(report));
    }
  `], { encoding: "utf8", timeout: 5000, maxBuffer: 4096 });
  assert.equal(child.status, 0, child.stderr);
  assert.equal(child.signal, null);
  assert.equal(child.stderr, "");
  const report = JSON.parse(child.stdout);
  assert.deepEqual(report, {
    status: "failed_or_incomplete",
    errors: [
      { stage: "composition-review", kind: "journey_failed" },
      { stage: "composition-review", kind: "page_wait_failed", method: "waitForResponse" },
    ],
    cleanup: ["context_closed", "browser_closed"],
  });
  assert.equal(child.stdout.includes("private"), false);
});

test("unsettled page waits stay bounded and are not mistaken for completed observers", async () => {
  const pending = new Set();
  let resolveWait;
  observeReceiverWait(new Promise(resolve => { resolveWait = resolve; }), () => {}, pending);
  assert.equal(await settleReceiverObservers(pending, 15), false);
  assert.equal(pending.size, 1);
  resolveWait();
  assert.equal(await settleReceiverObservers(pending, 1000), true);
});
