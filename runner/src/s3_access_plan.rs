//! Pure ordinary call-plan data; no execution, permits or worker dispatch.

use serde::Serialize;

use crate::s3_fixture_binding::FixtureOperation;

/// A finite operation description, not a send permit or execution capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct S3PlannedCall {
    pub service: &'static str,
    pub operation: &'static str,
    pub role: &'static str,
}

impl S3PlannedCall {
    pub(crate) fn new(service: &'static str, operation: &'static str, role: &'static str) -> Self {
        Self {
            service,
            operation,
            role,
        }
    }
}

pub(crate) fn ordinary_plan(
    selected: &str,
    fixture: Option<&FixtureOperation>,
) -> Vec<S3PlannedCall> {
    if let Some(fixture) = fixture {
        return fixture
            .operations(selected)
            .into_iter()
            .map(|operation| {
                S3PlannedCall::new(
                    if operation == "GetCallerIdentity" {
                        "sts"
                    } else {
                        "s3"
                    },
                    operation,
                    "controller",
                )
            })
            .collect();
    }
    let mut plan = vec![S3PlannedCall::new("sts", "GetCallerIdentity", "controller")];
    if ["probe_read", "legitimate_read"].contains(&selected) {
        let reader = if selected == "probe_read" {
            "probe"
        } else {
            "legitimate"
        };
        plan.push(S3PlannedCall::new("sts", "AssumeRole", "controller"));
        plan.push(S3PlannedCall::new("sts", "GetCallerIdentity", reader));
        plan.push(S3PlannedCall::new("s3", "GetObject", reader));
        if reader == "legitimate" {
            plan.push(S3PlannedCall::new("s3", "GetObject", reader));
        }
    } else {
        plan.push(S3PlannedCall::new("s3", "GetBucketPolicy", "controller"));
        if !["inspect_policy", "reconcile_policy"].contains(&selected) {
            plan.push(S3PlannedCall::new("s3", "PutBucketPolicy", "controller"));
            plan.push(S3PlannedCall::new("s3", "GetBucketPolicy", "controller"));
        }
    }
    plan
}
