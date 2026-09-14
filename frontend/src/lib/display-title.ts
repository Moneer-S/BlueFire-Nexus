/** Readable titles only: never apply this projection to IDs, editor values or evidence. */
export function displayTitle(value: string): string {
  return value.replace(/\s*(?:\u2014|&mdash;|&#0*8212;|&#x0*2014;|\\u2014)\s*/gi, ": ");
}
