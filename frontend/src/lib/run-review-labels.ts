/** Presentation only. The original profile and scope references remain authoritative. */
export function profileLabel(id: string) {
  const names: Record<string, string> = {
    "sandbox-simulate.v1": "Local simulation",
    "sandbox-execute.v1": "Workspace actions",
    "sandbox-restricted-owned.v1": "Workspace actions · restricted",
    "sandbox-observe-only.v1": "Read-only observation",
  };
  return names[id] ?? readableReference(id);
}

export function scopeLabel(reference: string) {
  return ({ "sandbox.workspace": "Files in the selected workspace", "network.loopback": "Connections to the local lab receiver" } as Record<string, string>)[reference] ?? readableReference(reference);
}

export function collectorLabel(reference: string) {
  return ({ "collector.filesystem.sandbox.v1": "Created files and cleanup", "collector.collection-semantics.sandbox.v1": "Collection contents and redaction" } as Record<string, string>)[reference] ?? readableReference(reference);
}

function readableReference(value: string) {
  const text = value.replace(/\.v\d+$/, "").replace(/[_.-]+/g, " ");
  return text ? text[0]!.toUpperCase() + text.slice(1) : "Not selected";
}
