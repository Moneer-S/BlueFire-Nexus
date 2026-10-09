//! Fixed cloud operation dispatch using authenticated native authority.

use crate::contract::TaskResult;
use crate::s3_admission::VerifiedS3Admission;

pub fn execute_admitted(admission: VerifiedS3Admission) -> TaskResult {
    #[cfg(target_os = "linux")]
    {
        execute_linux(admission)
    }
    #[cfg(not(target_os = "linux"))]
    {
        refused(&admission, "runtime_unavailable")
    }
}

fn refused(admission: &VerifiedS3Admission, problem: &'static str) -> TaskResult {
    use crate::actions::ActionFailure;
    use crate::contract::{utc_now, TaskStatus};
    let mut result = crate::runner::failure_result(
        admission.manifest(),
        admission.profile(),
        utc_now(),
        ActionFailure {
            status: TaskStatus::Refused,
            code: "s3_admission_refused",
            message: "The exact protected S3 runtime or reservation is unavailable.".into(),
        },
    );
    result.output = serde_json::json!({"s3_execution":{
        "schema_version":"bluefire.s3-execution.v1", "request_digest":admission.binding().digest(),
        "admission":{"accepted":false,"problem":problem}, "dispatch":"not_started", "send_debits":0,
        "result":null,"cleanup":"verified","provenance":"runner_reported","reservation_digest":null,
    }});
    result
}

#[cfg(target_os = "linux")]
fn execute_linux(mut admission: VerifiedS3Admission) -> TaskResult {
    use crate::actions::ActionOutcome;
    use crate::contract::{utc_now, BoundedOutput, ErrorRecord, TaskStatus};
    use crate::s3_reservation::{PolicyPosition, S3ReservationStore};
    use crate::s3_runtime::S3Runtime;
    use crate::s3_worker_process::LinuxWorker;
    use std::sync::atomic::AtomicBool;
    use std::time::{Duration, Instant};

    let started = utc_now();
    let origin = Instant::now();
    let remaining = (admission.expires_at() - started.fixed_offset())
        .to_std()
        .unwrap_or_default();
    let allowance = remaining.min(Duration::from_millis(
        admission.manifest().limits.timeout_ms,
    ));
    let Some(end) = origin.checked_add(allowance) else {
        return refused(&admission, "admission_refused");
    };
    // Cleanup is part of the original finite interval, never a renewed budget.
    let Some(deadline) = end
        .checked_sub(Duration::from_secs(2))
        .filter(|time| *time > origin)
    else {
        return refused(&admission, "admission_refused");
    };
    let runtime = match S3Runtime::inspect(
        admission.runtime_root().to_str().unwrap_or(""),
        admission.binding().runtime_digest(),
        admission.binding().worker_generation(),
        deadline,
    ) {
        Ok(value) => value,
        Err(()) => return refused(&admission, "runtime_unavailable"),
    };
    let secret = match admission.take_credentials() {
        Some(value) => value,
        None => return refused(&admission, "admission_refused"),
    };
    let store = match S3ReservationStore::open(&admission) {
        Ok(value) => value,
        Err(_) => return refused(&admission, "admission_refused"),
    };
    let reservation = match store.reserve(&admission, utc_now().fixed_offset()) {
        Ok(value) => value,
        Err(_) => return refused(&admission, "admission_refused"),
    };
    let reservation_digest = reservation.digest().to_string();
    let mut worker = match LinuxWorker::spawn(&runtime, deadline) {
        Ok(value) => value,
        Err(()) => {
            let clean = reservation
                .complete(
                    &serde_json::Value::Null,
                    false,
                    PolicyPosition::Unknown,
                    true,
                )
                .is_ok();
            let mut result = refused(&admission, "admission_refused");
            result.output["s3_execution"]["admission"] =
                serde_json::json!({"accepted":true,"problem":null});
            result.output["s3_execution"]["reservation_digest"] =
                serde_json::json!(reservation_digest);
            result.output["s3_execution"]["cleanup"] =
                serde_json::json!(if clean { "verified" } else { "unknown" });
            return result;
        }
    };
    let execution = crate::s3_worker_protocol::supervise(
        &mut worker,
        reservation,
        secret,
        deadline,
        end,
        &AtomicBool::new(false),
    );
    let success =
        execution["result"]["outcome"] == "observed" && execution["cleanup"] == "verified";
    crate::runner::outcome_result(admission.manifest(), admission.profile(), started, ActionOutcome {
        status: if success {TaskStatus::Success} else {TaskStatus::Failed},
        output: serde_json::json!({"s3_execution":execution}), stdout:BoundedOutput::default(), stderr:BoundedOutput::default(),
        receipt_ids:Vec::new(), cleanup:None,
        error:(!success).then(|| ErrorRecord { code:"s3_operation_incomplete".into(), message:"The fixed S3 operation did not establish a complete clean observation.".into() }),
        limitations:vec!["AWS replies and runner accounting are not independent audit evidence.".into(),
            "Policy mutations require explicit workflow rollback or reconciliation, not sandbox receipt cleanup.".into()],
    })
}
