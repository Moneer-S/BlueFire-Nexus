import { useCallback, useLayoutEffect, useRef, useState } from "react";

export interface GraphDeletionSummary { steps: string[]; connections: string[]; }
interface Elements<N, E> { nodes: N[]; edges: E[]; }
interface Context { revision: unknown; scope: string; readOnly: boolean; }
type FocusTarget = HTMLElement | SVGElement;
interface Request<N, E> extends Context {
  elements: Elements<N, E>;
  resolve: (result: Elements<N, E> | false) => void;
}

// React Flow captures its delete callbacks before awaiting onBeforeDelete. Keep
// the decision bound through its later removal callbacks, not just the dialog.
export function useGraphDeletion<N extends { id: string }, E extends { id: string }>(options: Context & {
  currentRevision: () => unknown;
  focusFallback: (elements: Elements<N, E>) => FocusTarget | null;
  focusContainer: () => HTMLElement | null;
  removalCommitted: (elements: Elements<N, E>) => boolean;
}) {
  const latest = useRef(options);
  latest.current = options;
  const mounted = useRef(false);
  const pending = useRef<Request<N, E> | null>(null);
  const confirmed = useRef<Request<N, E> | null>(null);
  const returnFocus = useRef<{ element: FocusTarget | null; elements: Elements<N, E>; revision: unknown; accepted: boolean; applied: boolean; ready: boolean } | null>(null);
  const focusObserver = useRef<MutationObserver | null>(null);
  const [summary, setSummary] = useState<GraphDeletionSummary | null>(null);
  const isCurrent = useCallback((context: Context) => mounted.current && !context.readOnly && !latest.current.readOnly
    && context.revision === latest.current.currentRevision() && context.scope === latest.current.scope, []);
  const finishFocus = useCallback(function finishFocus() {
    const returning = returnFocus.current;
    if (!mounted.current || pending.current || !returning?.ready) return;
    if (returning.accepted && !returning.applied) return;
    if (returning.applied && (latest.current.revision === returning.revision || !latest.current.removalCommitted(returning.elements))) {
      const container = latest.current.focusContainer();
      if (container && !focusObserver.current) {
        focusObserver.current = new MutationObserver(finishFocus);
        focusObserver.current.observe(container, { childList: true, subtree: true, attributes: true });
      }
      return;
    }
    focusObserver.current?.disconnect();
    focusObserver.current = null;
    returnFocus.current = null;
    const origin = returning.element;
    const available = origin?.isConnected && origin !== document.body && origin !== document.documentElement && !origin.closest("[hidden], [inert]") && !("disabled" in origin && origin.disabled);
    (available ? origin : latest.current.focusFallback(returning.elements))?.focus({ preventScroll: true });
  }, []);
  const cancel = useCallback(() => {
    const request = pending.current;
    pending.current = null;
    confirmed.current = null;
    if (returnFocus.current) returnFocus.current.accepted = false;
    request?.resolve(false);
    if (mounted.current) setSummary(null);
    finishFocus();
  }, [finishFocus]);
  useLayoutEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      pending.current?.resolve(false);
      pending.current = null;
      confirmed.current = null;
      returnFocus.current = null;
      focusObserver.current?.disconnect();
      focusObserver.current = null;
    };
  }, []);
  useLayoutEffect(() => {
    if ((pending.current && !isCurrent(pending.current)) || (confirmed.current && !isCurrent(confirmed.current))) cancel();
  }, [options.revision, options.scope, options.readOnly, cancel, isCurrent]);
  // A controlled React Flow render may finish after the dialog's close event.
  // Observe that actual removal instead of guessing with a focus timeout.
  useLayoutEffect(() => { finishFocus(); });

  const request = useCallback((elements: Elements<N, E>, description: GraphDeletionSummary): Promise<Elements<N, E> | false> => {
    const context = { revision: options.revision, scope: options.scope, readOnly: options.readOnly };
    if (!isCurrent(context) || pending.current || confirmed.current || (!elements.nodes.length && !elements.edges.length)) return Promise.resolve(false);
    focusObserver.current?.disconnect();
    focusObserver.current = null;
    returnFocus.current = { elements, revision: options.revision, accepted: false, applied: false, ready: false, element: document.activeElement instanceof HTMLElement || document.activeElement instanceof SVGElement ? document.activeElement : null };
    return new Promise((resolve) => {
      pending.current = { ...context, elements, resolve };
      setSummary(description);
    });
  }, [options.revision, options.scope, options.readOnly, isCurrent]);
  const confirm = useCallback(() => {
    const request = pending.current;
    if (!request || !isCurrent(request)) { cancel(); return; }
    pending.current = null;
    confirmed.current = request;
    if (returnFocus.current) returnFocus.current.accepted = true;
    setSummary(null);
    request.resolve(request.elements);
  }, [cancel, isCurrent]);
  const isPending = useCallback(() => Boolean(pending.current || confirmed.current), []);
  const allowsRemoval = useCallback((kind: "nodes" | "edges", id: string) => {
    const request = confirmed.current;
    return Boolean(request && isCurrent(request) && request.elements[kind].some(item => item.id === id));
  }, [isCurrent]);
  const consume = useCallback((elements: Elements<N, E>) => {
    const request = confirmed.current;
    confirmed.current = null;
    const matches = Boolean(request && isCurrent(request) && (["nodes", "edges"] as const).every(kind => {
      const ids = new Set(request.elements[kind].map(item => item.id));
      return elements[kind].length === ids.size && elements[kind].every(item => ids.has(item.id));
    }));
    if (request && returnFocus.current) { returnFocus.current.applied = matches; returnFocus.current.accepted = matches; }
    finishFocus();
    return matches;
  }, [isCurrent, finishFocus]);
  const restoreFocus = useCallback(() => {
    if (returnFocus.current) returnFocus.current.ready = true;
    finishFocus();
  }, [finishFocus]);
  return { summary, request, confirm, cancel, isPending, allowsRemoval, consume, restoreFocus };
}
