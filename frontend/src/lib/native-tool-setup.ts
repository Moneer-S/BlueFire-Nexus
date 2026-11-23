/** Closed setup choices for the reviewed Linux amd64 native tool adapters. */
export const NATIVE_TOOL_SETUP = {
  "sandbox.permission.chmod.v1": {
    name: "GNU chmod", command: "chmod", toolId: "gnu.coreutils.chmod.v1",
    packageName: "coreutils", packageVersions: ["9.4-3ubuntu6.1"], location: "/usr/bin/chmod",
  },
  "sandbox.collection.atomic-gzip.v1": {
    name: "GNU gzip", command: "gzip", toolId: "gnu.gzip.v1",
    packageName: "gzip", packageVersions: ["1.12-1ubuntu3.1", "1.12-1ubuntu3.2"], location: "/usr/bin/gzip",
  },
} as const;

export type NativeToolActionId = keyof typeof NATIVE_TOOL_SETUP;
export const NATIVE_TOOL_ACTIONS = Object.keys(NATIVE_TOOL_SETUP) as NativeToolActionId[];
