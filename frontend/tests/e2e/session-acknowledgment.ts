/** An acknowledged bodyless session response can end with Chromium ERR_ABORTED. */
export function acknowledgedSessionAbort(value: {
  url: string; expectedOrigin: string; method: string; resourceType: string;
  failure: string; responseStatus?: number; elapsedMs?: number;
}): boolean {
  let url: URL;
  try { url = new URL(value.url); } catch { return false; }
  return url.origin === value.expectedOrigin && url.pathname === "/api/v1/session"
    && !url.search && !url.hash && !url.username && !url.password
    && (value.method === "GET" || value.method === "POST") && value.resourceType === "fetch"
    && value.failure === "net::ERR_ABORTED" && value.responseStatus === 204
    && typeof value.elapsedMs === "number" && Number.isFinite(value.elapsedMs)
    && value.elapsedMs >= 0 && value.elapsedMs < 5_000;
}
