export const objectives = [
  {
    id: "data-handoff",
    label: "Controlled data handoff",
    path: "/compare",
    query: { receiver: "1" },
    question: "Can a redaction requirement stop unredacted records while allowing legitimate redacted use?",
    environment: "Prepared Linux lab and authenticated receiver",
    data: "Generated records and redacted variants",
    change: "Retained receiver redaction policy",
  },
  {
    id: "file-access",
    label: "Excess file access",
    path: "/file-access",
    query: {},
    question: "Can we remove a test identity's file access while preserving the application's access?",
    environment: "Prepared host workspace with a dedicated non-owner test identity",
    data: "Generated application file",
    change: "File permission correction",
  },
  {
    id: "ad-access",
    label: "Excess domain access",
    path: "/ad-smb",
    query: {},
    question: "Can we remove the probe identity's share access while preserving legitimate domain reads?",
    environment: "Enrolled Windows domain, member, client and protected credential channel",
    data: "Generated primary and health files on a disposable share",
    change: "Scoped share permission correction",
  },
  {
    id: "s3-access",
    label: "Excess S3 access",
    path: "/s3-access",
    query: {},
    question: "Can we remove the probe role's S3 access while preserving legitimate reads?",
    environment: "Authorized AWS account, region, bucket and dedicated test roles",
    data: "Generated primary and health objects",
    change: "Scoped bucket-policy correction",
  },
] as const;

export type ObjectiveId = (typeof objectives)[number]["id"];
export type Objective = (typeof objectives)[number];

export function objectiveById(value: string | null): Objective | undefined {
  return objectives.find((objective) => objective.id === value);
}

export function objectiveHref(objective: Objective, context = new URLSearchParams()): string {
  const query = new URLSearchParams(context);
  query.delete("goal");
  Object.entries(objective.query).forEach(([key, value]) => query.set(key, value));
  query.set("goal", objective.id);
  return `${objective.path}?${query.toString()}`;
}

export function objectiveReturnHref(objective: Objective, context = new URLSearchParams()): string {
  const query = new URLSearchParams(context);
  const routeState: Record<ObjectiveId, string[]> = {
    "data-handoff": ["receiver_job"],
    "file-access": ["control", "operation"],
    "ad-access": ["workflow"],
    "s3-access": ["exercise", "setup"],
  };
  routeState[objective.id].forEach(key => query.delete(key));
  query.delete("goal");
  query.set("goal", objective.id);
  return `/getting-started?${query.toString()}`;
}
