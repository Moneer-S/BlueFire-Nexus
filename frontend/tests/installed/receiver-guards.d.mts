export function sameJson(left: unknown, right: unknown): boolean;
export const receiverApprovalAcknowledgementName: RegExp;
export function receiverCompositionCleanupState(objective: unknown): "settled" | "no_grant" | "unresolved";

export interface ReceiverContextExpectation {
  selection: unknown;
  workflow: string;
  sourceControl: unknown | null;
  profileIdsByMode: Record<string, string[]>;
  scopeRefs: string[];
  collectors: string[];
  finalRunIntent: unknown;
}

export function receiverContextRequestAllowed(body: unknown, expected: ReceiverContextExpectation): boolean;
export function receiverContextRequestIsFinal(body: unknown, expected: ReceiverContextExpectation): boolean;
export function receiverContextResponseMatchesRequest(
  requestBody: unknown,
  finalRequest: unknown,
  responseBody: unknown,
): boolean;
export function receiverOwnerContextMatches(
  ownerBody: unknown,
  finalRequest: unknown,
  finalResponse: unknown,
): boolean;
export function receiverOwnerAdmissionState(
  owner: unknown,
  ownerId: string,
  finalRequest: unknown,
  finalResponse: unknown,
): "pending" | "accepted" | "invalid";
export function receiverRunIsNotDemo(run: unknown): boolean;
export function receiverCompletedPhase(owner: unknown, phaseName: string): Record<string, unknown> | null;

export function consumeRequestBudget(
  counts: Record<string, number>,
  limits: Record<string, number>,
  key: string,
): boolean;

export function classifyRequest(args: {
  origin: string;
  expectedOrigin: string;
  method: string;
  url: URL;
  body?: unknown;
  bodyError?: boolean;
  allowedRead: (url: URL) => boolean;
  authorizePost: (url: URL, body: unknown) => boolean;
}): { allowed: true } | { allowed: false; reason: string };

export function handleReceiverRoute(route: {
  request: () => { url: () => string; method: () => string; postData: () => string | null; postDataJSON: () => unknown };
  abort: () => Promise<void>;
  continue: () => Promise<void>;
}, options: {
  expectedOrigin: string;
  allowedRead: (url: URL) => boolean;
  authorizePost: (url: URL, body: unknown) => boolean;
  onBlocked: (entry: { method: string; path: string; reason: string }) => void;
  onFailure: (kind: "request_route_failed" | "request_abort_failed") => void;
}): Promise<void>;

export function closeReceiverWebSocket(socket: { close: () => Promise<void> }, options: {
  onBlocked: () => void;
  onFailure: (kind: "websocket_record_failed" | "websocket_close_failed") => void;
}): Promise<void>;

export function observeReceiverEvent<T extends unknown[]>(
  handler: (...args: T) => void | Promise<void>,
  onFailure: () => void,
  pending: Set<Promise<void>>,
): (...args: T) => void;

export function settleReceiverObservers(pending: Set<Promise<void>>, timeoutMs: number): Promise<boolean>;

export function observeReceiverWait<T>(
  wait: Promise<T>,
  onFailure: () => void,
  pending: Set<Promise<void>>,
): Promise<T>;
