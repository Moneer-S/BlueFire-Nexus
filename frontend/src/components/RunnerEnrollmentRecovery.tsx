import { Link } from "react-router-dom";
import { runnerDiagnosticsPath } from "../lib/runner-diagnostics";
import { profileChoiceLabel, profileLabel } from "../lib/run-review-labels";
import type { RunnerLifecycleStatus, RunnerProfile } from "../types";
import { Callout } from "./Primitives";

/** A recovery explanation, never authority to enroll or act through another profile. */
export function RunnerEnrollmentRecovery({ status, profileId, profiles }: {
  status?: RunnerLifecycleStatus;
  profileId?: string;
  profiles?: RunnerProfile[];
}) {
  if (!profileId || status?.profile_id !== profileId || status.state !== "unavailable" || status.profile_enrollment?.state !== "not_enrolled") return null;
  const enrolled = status.profile_enrollment.enrolled_profile_ids;
  const available = profiles?.filter((profile) => profile.mode === "execute" && enrolled.includes(profile.id));
  const pendingUpgrade = status.upgrade_recovery_required === true;
  return <Callout tone="warning" title="This profile is not enrolled">
    <p>{profileLabel(profileId)} was not included when this runner was enrolled. Activating a profile does not change existing runner trust.</p>
    {profiles ? <>
      <p>{pendingUpgrade ? "An interrupted runner update must be completed before changing enrollment." : "Use an enrolled profile to inspect the shared host and stop it safely before changing trust."}</p>
      {available?.length ? <ul>{available.map((profile) => <li key={profile.id}><Link to={runnerDiagnosticsPath(profile.id)}>Inspect enrolled profile: {profileChoiceLabel(profile.id, profiles)}</Link></li>)}</ul> : <p>No active enrolled profile is available. Resolve the configured profiles before continuing recovery.</p>}
      {pendingUpgrade ? <p>In <Link to="/runner-profiles">Runner profiles</Link>, restore the profiles and settings used for the interrupted update, including deactivating profiles added since then. Select an enrolled profile, review and apply the exact update, then reactivate the desired profile and return here to review enrollment recovery.</p> : <>
        <p>Once the host is stopped, explicitly revoke trust and remove revoked trust with the exact runner ID. Then return to this profile, verify and enroll again, and start the host explicitly.</p>
        <p>Removal clears runner transport history after safety checks. Saved experiments and profiles remain; unresolved tasks or cleanup block removal. A runner upgrade cannot add this profile to the existing enrollment.</p>
      </>}
    </> : <p><Link to={runnerDiagnosticsPath(profileId)}>Review enrollment recovery</Link> before preparing this profile. This status check did not start a runner or experiment.</p>}
  </Callout>;
}
