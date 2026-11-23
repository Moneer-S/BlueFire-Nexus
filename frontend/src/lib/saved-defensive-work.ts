import { api } from "./api";
import { adSmbApi, checkedAdList } from "./ad-smb";
import { checkedFileAccessList, fileAccessApi } from "./file-access";
import { phaseTitle, receiverJobValid } from "./receiver-defense";
import { checkedList, s3Api } from "./s3-access";

export const workFamilies = [
  { id: "handoff", label: "Data handoff", href: "/compare?receiver=1" },
  { id: "file", label: "File access", href: "/file-access" },
  { id: "domain", label: "Domain access", href: "/ad-smb" },
  { id: "cloud", label: "S3 access", href: "/s3-access" },
] as const;
export type WorkFamily = typeof workFamilies[number]["id"];
export interface SavedWorkRow { id: string; title: string; href: string; state: string; detail: string; attention: boolean }
export interface SavedWorkList { rows: SavedWorkRow[]; more: boolean }

export async function loadSavedWork(family: WorkFamily): Promise<SavedWorkList> {
  if (family === "handoff") {
    const value = await api.receiverTests();
    if (value?.schema_version !== "bluefire.receiver-defense-list.v1" || !Array.isArray(value.jobs) || value.jobs.length > 128
      || typeof value.truncated !== "boolean" || value.truncated !== (value.next_cursor !== null)
      || (value.next_cursor !== null && !receiverJobValid(value.next_cursor))
      || new Set(value.jobs.map(job => job?.job_id)).size !== value.jobs.length
      || value.jobs.some(job => !job || !receiverJobValid(job.job_id) || typeof job.title !== "string" || typeof job.status !== "string"
        || (job.phase !== null && !Object.hasOwn(phaseTitle, job.phase)))) throw new Error("The saved handoff list is incomplete.");
    return { more: value.truncated || value.jobs.length > 5, rows: value.jobs.slice(0, 5).map(job => ({
      id: job.job_id, title: job.title, href: `/compare?receiver_job=${encodeURIComponent(job.job_id)}`,
      state: job.status, detail: job.phase ? phaseTitle[job.phase] : "Saved control test", attention: job.status === "blocked",
    })) };
  }
  if (family === "file") {
    const value = checkedFileAccessList(await fileAccessApi.list());
    const controls = [...value.controls].reverse();
    return { more: controls.length > 5, rows: controls.slice(0, 5).map(control => ({
      id: control.control_owner_id, title: "Generated file access", href: `/file-access?control=${encodeURIComponent(control.control_owner_id)}`,
      state: control.status, detail: `Revision ${control.revision} / ${control.control_owner_id.slice(-8)}`,
      attention: ["uncertain", "recovery_required"].includes(control.status),
    })) };
  }
  if (family === "domain") {
    const value = checkedAdList(await adSmbApi.list());
    const workflows = [...value].reverse();
    return { more: workflows.length > 5, rows: workflows.slice(0, 5).map(workflow => ({
      id: workflow.id, title: workflow.environment.member, href: `/ad-smb?workflow=${encodeURIComponent(workflow.id)}`,
      state: workflow.pending ? "unsettled_operation" : workflow.stopped ? "new_work_stopped" : workflow.policy,
      detail: `${workflow.environment.provenance === "synthetic_fixture" ? "Synthetic fixture" : "Runner-reported"} / revision ${workflow.revision}`,
      attention: Boolean(workflow.pending) || workflow.policy === "unknown",
    })) };
  }
  const value = checkedList(await s3Api.list());
  return { more: value.truncated || value.exercises.length > 5, rows: value.exercises.slice(0, 5).map(exercise => ({
    id: exercise.workflow_job_id, title: exercise.name, href: `/s3-access?exercise=${encodeURIComponent(exercise.workflow_job_id)}`,
    state: exercise.policy_state, detail: exercise.bucket, attention: ["uncertain", "drift"].includes(exercise.policy_state),
  })) };
}
