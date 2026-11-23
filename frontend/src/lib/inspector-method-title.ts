import { displayTitle } from "./display-title";
import type { ActionDefinition, Behavior } from "../types";

const conciseNativeMethodLabels = {
  "native JSONL": "Native JSONL",
  "native TAR": "Native TAR",
} as const;

/** Use a concise card label only when one registered action and its behavior share an exact native-method title. */
export function inspectorMethodTitle(behavior: Behavior, actions: ReadonlyMap<string, ActionDefinition>): string {
  const fullTitle = displayTitle(behavior.title);
  if (behavior.action_ids.length !== 1) return fullTitle;
  const action = actions.get(behavior.action_ids[0]!);
  if (!action || displayTitle(action.title) !== fullTitle) return fullTitle;
  const qualifier = /\s+\((native JSONL|native TAR)\)$/u.exec(action.title)?.[1] as keyof typeof conciseNativeMethodLabels | undefined;
  return qualifier ? conciseNativeMethodLabels[qualifier] : fullTitle;
}
