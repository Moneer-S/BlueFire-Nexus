import { Archive, BookOpen, Cpu, FilePlus2, FileSearch, FileText, ScanSearch, Send, ShieldAlert, SlidersHorizontal, Trash2, type LucideIcon } from "lucide-react";
import type { Behavior } from "../types";

// First match wins: the most specific kind of work a step performs. Icons only
// classify the registered behavior; they never imply an outcome or permission.
const kinds: [test: (capability: string, id: string) => boolean, icon: LucideIcon][] = [
  [(capability, id) => capability.includes("cleanup") || /\.cleanup\./.test(id), Trash2],
  [(capability) => capability.startsWith("research."), BookOpen],
  [(capability) => capability.includes("permission") || capability.includes("restricted"), ShieldAlert],
  [(capability) => capability.startsWith("network.") || capability === "sandbox.network" || capability === "sandbox.peer", Send],
  [(capability) => /collection|archive|export/.test(capability), Archive],
  [(capability) => capability.startsWith("process."), Cpu],
  [(capability) => capability.includes("discovery") || capability.includes("identity"), ScanSearch],
  [(_, id) => /\.transform\./.test(id), SlidersHorizontal],
  [(capability) => capability === "sandbox.fixture" || capability === "material.seed", FilePlus2],
  [(capability) => capability === "filesystem.read" || capability === "material.inspect", FileSearch],
];

export function graphNodeIcon(behavior?: Behavior): LucideIcon {
  if (!behavior) return FileText;
  for (const [test, icon] of kinds) if (behavior.capabilities.some(capability => test(capability, behavior.id))) return icon;
  return FileText;
}
