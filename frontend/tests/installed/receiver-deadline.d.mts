export function createDeadlineBudget(startedAt: number, journeyMs: number, cleanupMs: number): {
  remaining(now: number): number;
  bounded(requested: number | undefined, now: number): number;
  beginCleanup(now: number): number;
};
