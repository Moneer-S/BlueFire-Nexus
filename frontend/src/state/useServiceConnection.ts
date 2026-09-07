import { useQuery } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { api, type ApiError, DEMO_MODE } from "../lib/api";

// Liveness is independent of cached catalogs and saved operation authority.
export function useServiceConnection() {
  const connection = useQuery({
    queryKey: ["service-connection"], queryFn: ({ signal }) => api.serviceConnection(signal),
    enabled: !DEMO_MODE, retry: false, staleTime: 0, networkMode: "always",
    refetchInterval: 15_000, refetchIntervalInBackground: false,
    refetchOnWindowFocus: "always", refetchOnReconnect: "always",
  });
  const checkedAt = connection.data?.checkedAt;
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (DEMO_MODE) return;
    const update = () => setNow(Date.now());
    const timer = checkedAt === undefined ? undefined : window.setTimeout(update, Math.max(0, checkedAt + 30_000 - Date.now()));
    document.addEventListener("visibilitychange", update);
    return () => { window.clearTimeout(timer); document.removeEventListener("visibilitychange", update); };
  }, [checkedAt]);
  const fresh = checkedAt !== undefined && Math.max(now, Date.now()) - checkedAt >= 0 && Math.max(now, Date.now()) - checkedAt < 30_000;
  const sessionUnavailable = (connection.error as ApiError | null)?.code === "browser_session_unavailable";
  const state = DEMO_MODE ? "demo" : sessionUnavailable ? "session" : connection.isError ? "disconnected" : fresh ? "connected" : checkedAt !== undefined ? "stale" : "checking";
  const label = { demo: "Demo", session: "Session unavailable", disconnected: "Disconnected", connected: "Connected", stale: "Connection unchecked", checking: "Checking connection" }[state];
  const title = state === "connected" ? "Local service connected" : state === "disconnected" ? "Local service unreachable" : state === "demo" ? "Demo workspace" : label;
  const detail = state === "session" ? "Relaunch with bluefire ui and reopen this page. Cached work is retained; no operation restarts automatically."
    : state === "disconnected" ? "The last check failed. Check the terminal that opened BlueFire. Cached work is retained."
    : state === "stale" ? "The last successful check is no longer current. Checking the connection does not restart work."
    : state === "connected" ? `Browser session checked at ${new Date(checkedAt!).toLocaleTimeString()}. Runner and provider readiness are checked separately.`
    : state === "demo" ? "No local service connection is made." : "Checking the local service and this browser session.";
  const tone = state === "connected" ? "success" : state === "disconnected" || state === "session" ? "danger" : state === "demo" ? "violet" : "warning";
  const light = state === "connected" ? "ready" : state === "disconnected" || state === "session" ? "error" : "pending";
  return { state, label, title, detail, tone, light, checking: connection.isFetching, check: () => { void connection.refetch(); } } as const;
}
