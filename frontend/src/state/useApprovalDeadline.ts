import { useCallback, useEffect, useRef, useState } from "react";
import { approvalDeadline } from "../lib/approvalReview";

export function useApprovalDeadline(expiresAt: unknown) {
  const deadline = approvalDeadline(expiresAt);
  const [observedAt, setObservedAt] = useState(() => Date.now());
  const latestObservedAt = useRef(observedAt);
  const recheck = useCallback(() => {
    // A backward clock correction must not revive an approval already expired
    // in this mounted review. The server remains the final clock authority.
    latestObservedAt.current = Math.max(latestObservedAt.current, Date.now());
    setObservedAt(latestObservedAt.current);
    return Number.isFinite(deadline) && deadline > latestObservedAt.current;
  }, [deadline]);
  useEffect(() => {
    let timer: number | undefined;
    const refresh = () => {
      window.clearTimeout(timer);
      if (recheck()) {
        // One deadline timer, clamped to the browser's signed timer limit.
        // Long deadlines reschedule only at that bound; no periodic polling.
        timer = window.setTimeout(refresh, Math.min(deadline - latestObservedAt.current, 2_147_483_647));
      }
    };
    refresh();
    window.addEventListener("focus", refresh);
    window.addEventListener("pageshow", refresh);
    document.addEventListener("visibilitychange", refresh);
    return () => {
      window.clearTimeout(timer);
      window.removeEventListener("focus", refresh);
      window.removeEventListener("pageshow", refresh);
      document.removeEventListener("visibilitychange", refresh);
    };
  }, [deadline, recheck]);
  return { valid: Number.isFinite(deadline), current: Number.isFinite(deadline) && deadline > Math.max(observedAt, Date.now()), recheck };
}
