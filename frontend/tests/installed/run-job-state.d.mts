export interface PolledJob {
  job_id: string;
  state: string;
  [key: string]: unknown;
}

export interface WaitForRunApprovalOptions {
  jobId: string;
  deadline: number;
  readJob: (jobId: string, timeoutMs: number) => Promise<PolledJob>;
  sleep: (milliseconds: number) => Promise<void>;
  now?: () => number;
}

export function waitForRunApproval(options: WaitForRunApprovalOptions): Promise<PolledJob>;
