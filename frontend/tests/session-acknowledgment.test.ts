import { expect, it } from "vitest";
import { acknowledgedSessionAbort } from "./e2e/session-acknowledgment";

it("accepts only a timely acknowledged bodyless session abort and rejects unproven transport failures", () => {
  const acknowledged = { url: "http://127.0.0.1:9001/api/v1/session", expectedOrigin: "http://127.0.0.1:9001", method: "GET", resourceType: "fetch", failure: "net::ERR_ABORTED", responseStatus: 204, elapsedMs: 10 };
  expect(acknowledgedSessionAbort(acknowledged)).toBe(true);
  expect(acknowledgedSessionAbort({ ...acknowledged, method: "POST", elapsedMs: 26 })).toBe(true);
  const unproven = [
    { responseStatus: undefined }, ...[200, 401, 403, 500].map(responseStatus => ({ responseStatus })),
    ...[undefined, -1, 5_000, 5_001, NaN, Infinity].map(elapsedMs => ({ elapsedMs })),
    { url: "http://127.0.0.1:9002/api/v1/session" }, { url: `${acknowledged.url}/extra` },
    { url: `${acknowledged.url}?retry=1` }, { url: `${acknowledged.url}#context` },
    { url: acknowledged.url.replace("127.0.0.1", "operator@127.0.0.1") }, { url: "invalid" },
    { method: "DELETE" }, { method: "get" }, { resourceType: "document" },
    { failure: "net::ERR_CONNECTION_RESET" }, { failure: "net::ERR_TIMED_OUT" }, { failure: "unknown" },
  ];
  for (const changed of unproven) expect(acknowledgedSessionAbort({ ...acknowledged, ...changed }), JSON.stringify(changed)).toBe(false);
});
