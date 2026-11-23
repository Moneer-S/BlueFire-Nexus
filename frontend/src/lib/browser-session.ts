const SESSION_KEY = "bluefire.browser-session.v1";
const SESSION_HEADER = "X-BlueFire-Session";
const BOOTSTRAP_HEADER = "X-BlueFire-Browser-Bootstrap";
const TOKEN = /^[A-Za-z0-9_-]{64}$/;
let retained: { origin: string; session: string; persisted: boolean } | undefined;

function session(): string | undefined {
  const origin = window.location.origin;
  if (retained?.origin !== origin) retained = undefined;
  if (retained && !retained.persisted) return retained.session;
  try {
    const value = window.sessionStorage.getItem(SESSION_KEY);
    if (value && TOKEN.test(value)) retained = { origin, session: value, persisted: true };
    else if (retained?.persisted) retained = undefined;
  } catch { /* A storage-disabled tab can still retain its session in memory. */ }
  return retained?.session;
}

function retain(value: string): void {
  retained = { origin: window.location.origin, session: value, persisted: false };
  try {
    window.sessionStorage.setItem(SESSION_KEY, value);
    retained.persisted = true;
  } catch { /* Reload then needs a fresh launch. */ }
}

function forget(expected: string | undefined): void {
  if (session() !== expected) return;
  retained = undefined;
  try { window.sessionStorage.removeItem(SESSION_KEY); } catch { /* No durable session was required. */ }
}

async function boundedFetch(path: string, options: RequestInit, capability?: string): Promise<Response> {
  let target: URL;
  try { target = new URL(path, window.location.href); } catch { throw new Error("The local API address is invalid."); }
  if (target.origin !== window.location.origin || target.username || target.password || target.hash
    || !target.pathname.startsWith("/api/v1/")) throw new Error("The local API address is invalid.");
  const headers = new Headers(options.headers);
  headers.delete(SESSION_HEADER);
  headers.delete(BOOTSTRAP_HEADER);
  const token = capability === undefined ? session() : undefined;
  if (token) headers.set(SESSION_HEADER, token);
  if (capability !== undefined) headers.set(BOOTSTRAP_HEADER, capability);
  const response = await fetch(`${target.pathname}${target.search}`, {
    ...options, headers, credentials: "omit", redirect: "error", cache: "no-store", referrerPolicy: "no-referrer",
  });
  if (response.status === 401 && token) forget(token);
  return response;
}

/** Never let an ambient cookie or redirect carry authority to another listener. */
export function browserApiFetch(path: string, options: RequestInit = {}): Promise<Response> {
  return boundedFetch(path, options);
}

export async function exchangeBrowserCapability(capability: string): Promise<void> {
  if (!TOKEN.test(capability)) throw new Error("The connection code is invalid.");
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), 15_000);
  try {
    const response = await boundedFetch("/api/v1/session", {
      method: "POST", headers: { Accept: "application/json" }, signal: controller.signal,
    }, capability);
    if (!response.ok) throw new Error("The connection code is unavailable or expired.");
    const payload: unknown = await response.json();
    if (!payload || typeof payload !== "object" || Array.isArray(payload)
      || Object.keys(payload).length !== 1 || !("session" in payload)
      || typeof payload.session !== "string" || !TOKEN.test(payload.session)) throw new Error("The local session response is invalid.");
    retain(payload.session);
  } finally { window.clearTimeout(timeout); }
}
