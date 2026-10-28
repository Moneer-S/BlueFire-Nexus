import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { test } from "vitest";
import { closeReceiverWebSocket, handleReceiverRoute, observeReceiverEvent, settleReceiverObservers } from "./receiver-guards.mjs";

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
