import { isDeepStrictEqual } from "node:util";

// Saved JSON objects may be canonicalized; array order and exact values still matter.
export const sameJson = isDeepStrictEqual;

export function consumeRequestBudget(counts, limits, key) {
  if (!Object.hasOwn(limits, key) || counts[key] >= limits[key]) return false;
  counts[key] += 1;
  return true;
}

export function classifyRequest({ origin, expectedOrigin, method, url, body, bodyError, allowedRead, authorizePost }) {
  if (origin !== expectedOrigin) return { allowed: false, reason: "non_loopback" };
  if (method === "GET" || method === "HEAD") {
    return allowedRead(url)
      ? { allowed: true }
      : { allowed: false, reason: "read_not_allowlisted" };
  }
  if (method === "POST") {
    if (bodyError) return { allowed: false, reason: "invalid_json_body" };
    return authorizePost(url, body)
      ? { allowed: true }
      : { allowed: false, reason: "write_not_allowlisted_or_budget_exceeded" };
  }
  return { allowed: false, reason: "method_not_allowlisted" };
}
