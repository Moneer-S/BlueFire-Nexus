import { useRef, useState } from "react";

const prefix = "bluefire.detection-draft.v1:";
const maximum = 2 * 1024 * 1024;
const fallback = new Map<string, { value: Record<string, unknown>; blocked: boolean; warning: string }>();

export function detectionDraftIdentity(value: unknown): string {
  const ordered = (item: unknown): unknown => Array.isArray(item) ? item.map(ordered)
    : item && typeof item === "object" ? Object.fromEntries(Object.entries(item).sort(([a], [b]) => a.localeCompare(b)).map(([key, child]) => [key, ordered(child)])) : item;
  return JSON.stringify(ordered(value));
}

function valid<T extends Record<string, unknown>>(value: unknown, defaults: T): value is T {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  if ("tab" in defaults && !["candidate", "revisions", "evaluations", "fixtures", "observed", "history"].includes(String(record.tab))) return false;
  if ("role" in defaults && !["attack", "benign", "replay", "heldout"].includes(String(record.role))) return false;
  if ("revisionKind" in defaults && !["clone", "tune"].includes(String(record.revisionKind))) return false;
  return Object.keys(record).length === Object.keys(defaults).length && Object.entries(defaults).every(([key, example]) =>
    Array.isArray(example) ? Array.isArray(record[key]) && record[key].length <= 128 && record[key].every(item => typeof item === "string" && item.length <= 1024)
      : typeof record[key] === typeof example && typeof record[key] === "string" && record[key].length <= maximum);
}

/** Editable text only. Reading or retaining a draft never calls a product action. */
export function useDetectionDraft<T extends Record<string, unknown>>(binding: string, defaults: T) {
  const key = prefix + binding;
  const read = () => {
    const memory = fallback.get(key);
    // This map contains only this session's explicit editor updates, never parsed storage.
    if (memory) return { key, value: memory.value as T, blocked: memory.blocked, warning: memory.warning, retained: false };
    try {
      const raw = sessionStorage.getItem(key);
      if (!raw) return { key, value: defaults, blocked: false, warning: "", retained: false };
      if (raw.length > maximum) throw new Error("oversized");
      const record: unknown = JSON.parse(raw);
      if (!record || typeof record !== "object" || Object.keys(record).length !== 2 || !("binding" in record) || record.binding !== binding || !("value" in record) || !valid(record.value, defaults)) throw new Error("invalid");
      return { key, value: record.value as T, blocked: false, warning: "", retained: true };
    } catch {
      return { key, value: defaults, blocked: true, warning: "The retained draft could not be read. Its stored bytes have been left untouched. New edits stay in this open session until you explicitly discard the retained draft.", retained: false };
    }
  };
  const [state, setState] = useState(read);
  const current = useRef(state);
  // A changed evidence context must not render or submit a previous context's inputs.
  if (state.key !== key) { const next = read(); current.current = next; setState(next); }
  else current.current = state;
  const update = <K extends keyof T>(field: K, value: T[K]) => {
    const prior = current.current;
    const next = { ...prior, value: { ...prior.value, [field]: value } };
    try {
      const raw = JSON.stringify({ binding, value: next.value });
      if (prior.blocked || raw.length > maximum || !valid(next.value, defaults)) throw new Error("cannot retain");
      sessionStorage.setItem(key, raw);
      fallback.delete(key); next.retained = true; next.warning = "";
    } catch {
      next.retained = false;
      if (!prior.blocked) next.warning = "These inputs could not be kept in browser storage. They are kept only for this open session; export them before closing or reloading.";
      fallback.set(key, { value: next.value, blocked: prior.blocked, warning: next.warning });
    }
    current.current = next; setState(next);
  };
  const discard = () => {
    let warning = "";
    try { sessionStorage.removeItem(key); fallback.delete(key); }
    catch { warning = "The stored draft could not be removed. It may return after reload; this open session now shows the saved definition."; fallback.set(key, { value: defaults, blocked: true, warning }); }
    const next = { key, value: defaults, blocked: Boolean(warning), warning, retained: false };
    current.current = next; setState(next);
  };
  return { value: current.current.value, update, discard, warning: current.current.warning, retained: current.current.retained };
}
