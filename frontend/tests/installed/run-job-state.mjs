async function waitForJobState({
  jobId,
  targetState,
  transientStates,
  deadline,
  readJob,
  sleep,
  now = Date.now,
}) {
  while (now() < deadline) {
    const remainingMs = deadline - now();
    const job = await readJob(jobId, remainingMs);
    if (now() >= deadline) break;
    if (job?.job_id !== jobId) {
      throw new Error("The polled job identity did not match the submitted job.");
    }
    if (job.state === targetState) return job;
    if (!transientStates.includes(job.state)) {
      throw new Error("The job left its expected transient states before reaching the target.");
    }
    const waitMs = Math.min(250, Math.max(0, deadline - now()));
    if (waitMs > 0) await sleep(waitMs);
  }
  throw new Error("The job did not reach its expected state before the bounded deadline.");
}

export function waitForRunApproval({ jobId, deadline, readJob, sleep, now }) {
  return waitForJobState({
    jobId,
    targetState: "awaiting_approval",
    transientStates: ["queued", "planning"],
    deadline,
    readJob,
    sleep,
    now,
  });
}
