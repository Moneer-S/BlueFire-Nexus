export interface GraphNodeTitle {
  fullTitle: string;
  title: string;
  method?: string;
}

/** Present only an existing short method suffix; never infer a method from identity. */
export function graphNodeTitle(fullTitle: string, executionState?: string, invalid = false): GraphNodeTitle {
  const unchanged = { fullTitle, title: fullTitle };
  if (invalid || executionState !== "action") return unchanged;
  const match = /^(.*?)\s+(\(([^()]*)\))$/u.exec(fullTitle);
  // The 24-character bound includes the parentheses. Keep longer, nested or
  // non-plain suffixes in the original title instead of reinterpreting them.
  if (!match || !match[1]!.trim() || [...match[2]!].length > 24
    || match[3] !== match[3]!.trim()
    || !/^[\p{L}\p{N}][\p{L}\p{N} ._+/-]*$/u.test(match[3]!)) return unchanged;
  return { fullTitle, title: match[1]!, method: match[2]! };
}
