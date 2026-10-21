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
