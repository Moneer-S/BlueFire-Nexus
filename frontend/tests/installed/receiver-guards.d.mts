export function sameJson(left: unknown, right: unknown): boolean;
export const receiverApprovalAcknowledgementName: RegExp;

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
