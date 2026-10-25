import { useEffect, useMemo, useSyncExternalStore } from "react";
import { DEMO_MODE } from "../lib/api";
import { parseActiveWorkReference, type ActiveWorkReference } from "../lib/active-defensive-work";
import type { WorkFamily } from "../lib/saved-defensive-work";

const key = "bluefire.local.active-defensive-work.v1";
const changed = "bluefire:active-defensive-work";
let memoryFallback: string | undefined;

function snapshot() {
  if (memoryFallback !== undefined) return memoryFallback;
  try { return window.localStorage.getItem(key) ?? ""; } catch { return ""; }
}

function subscribe(callback: () => void) {
  const onStorage = (event: StorageEvent) => {
    if (event.key === key || event.key === null) { memoryFallback = undefined; callback(); }
  };
  window.addEventListener(changed, callback);
  window.addEventListener("storage", onStorage);
  return () => { window.removeEventListener(changed, callback); window.removeEventListener("storage", onStorage); };
}

/** A navigation preference only. Evidence and permissions are always loaded afresh. */
export function rememberActiveDefensiveWork(value: ActiveWorkReference | undefined) {
  const reference = value === undefined ? undefined : parseActiveWorkReference(value);
  if (value !== undefined && !reference) return;
  const serialized = reference ? JSON.stringify({ family: reference.family, id: reference.id }) : "";
  if (snapshot() === serialized) return;
  try {
    if (serialized) window.localStorage.setItem(key, serialized);
    else window.localStorage.removeItem(key);
    memoryFallback = undefined;
  } catch { memoryFallback = serialized; }
  window.dispatchEvent(new Event(changed));
}

export function useActiveDefensiveWork() {
  const serialized = useSyncExternalStore(subscribe, snapshot, () => "");
  return useMemo(() => {
    try { return serialized.length <= 512 ? parseActiveWorkReference(JSON.parse(serialized)) : undefined; }
    catch { return undefined; }
  }, [serialized]);
}

/** Register only an identity whose existing workflow query has validated its record. */
export function useRememberDefensiveWork(family: WorkFamily, verifiedId: string | undefined) {
  useEffect(() => {
    if (!DEMO_MODE && verifiedId) rememberActiveDefensiveWork({ family, id: verifiedId });
  }, [family, verifiedId]);
}
