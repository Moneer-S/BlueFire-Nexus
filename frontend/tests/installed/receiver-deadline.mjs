export function createDeadlineBudget(startedAt, journeyMs, cleanupMs) {
  const journeyDeadline = startedAt + journeyMs;
  const runDeadline = journeyDeadline + cleanupMs;
  let activeDeadline = journeyDeadline;

  return {
    remaining(now) {
      return Math.max(0, activeDeadline - now);
    },
    bounded(requested, now) {
      const remaining = activeDeadline - now;
      if (remaining <= 0) return 0;
      return Number.isFinite(requested) ? Math.min(requested, remaining) : remaining;
    },
    beginCleanup(now) {
      activeDeadline = Math.min(now + cleanupMs, runDeadline);
      return activeDeadline;
    },
  };
}

export function boundedLocalTimeout(localDeadline, now, sharedRemaining) {
  if (![localDeadline, now, sharedRemaining].every(Number.isFinite) || sharedRemaining <= 0) return 0;
  return Math.max(0, Math.min(localDeadline - now, sharedRemaining));
}
