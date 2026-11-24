// The list entries of the shipped recordings, which the build works out from
// their files (frontend/shipped-summaries.ts), each with its file's name and
// SHA-256. The demo reads each entry as it reads one from the service's list.
declare module "virtual:shipped-recording-summaries" {
  const entries: readonly { file: string; sha256: string; summary: unknown }[];
  export default entries;
}
