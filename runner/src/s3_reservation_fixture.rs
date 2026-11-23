//! Fixture object state and cleanup reserves, separate from bucket-policy state.

use super::state::{FixturePosition, PolicyPosition, Reserved, Retained};
use super::{Error, Result};

fn fixture_history<'a>(history: &[&'a Retained]) -> Vec<&'a Retained> {
    history
        .iter()
        .copied()
        .filter(|old| old.reserved.fixture.is_some())
        .collect()
}

fn position<'a>(history: &[&'a Retained], purpose: &str) -> Option<&'a FixturePosition> {
    let mut position = None;
    for old in history {
        if old
            .reserved
            .fixture
            .as_ref()
            .is_some_and(|f| f.purpose == purpose)
        {
            if old.write_debited {
                position = None;
            }
            if matches!(old.completion, Some((true, _, true))) {
                if let Some(observed) = &old.fixture_position {
                    position = Some(observed);
                }
            }
        }
    }
    position
}

fn policy_position(history: &[&Retained]) -> PolicyPosition {
    let mut position = PolicyPosition::Before;
    for old in history.iter().filter(|old| old.reserved.fixture.is_none()) {
        if old.write_debited {
            position = PolicyPosition::Unknown;
        }
        if let Some((true, observed, true)) = old.completion {
            if matches!(
                old.reserved.operation.as_str(),
                "inspect_policy" | "apply_policy" | "rollback_policy" | "reconcile_policy"
            ) {
                position = observed;
            }
        }
    }
    position
}

pub(super) fn required_calls(history: &[&Retained], next: &Reserved) -> Result<u64> {
    let fixture = next.fixture.as_ref().ok_or(Error::Conflict)?;
    let health = fixture.purpose == "health";
    let stages: std::collections::BTreeSet<_> = history
        .iter()
        .filter(|old| old.reserved.operation == "cleanup_fixture")
        .map(|old| old.reserved.operation_id.as_str())
        .collect();
    let stage = stages.len() + usize::from(!stages.contains(next.operation_id.as_str()));
    Ok(match next.operation.as_str() {
        "prepare_fixture" => {
            if health {
                64
            } else {
                70
            }
        }
        "cleanup_fixture" if stage == 1 => {
            if health {
                41
            } else {
                48
            }
        }
        "cleanup_fixture" if stage == 2 => {
            if health {
                17
            } else {
                24
            }
        }
        "reconcile_fixture" if stages.is_empty() => {
            if health {
                53
            } else {
                58
            }
        }
        "reconcile_fixture" if stages.len() == 1 => {
            if health {
                29
            } else {
                34
            }
        }
        "reconcile_fixture" if stages.len() == 2 => {
            if health {
                5
            } else {
                10
            }
        }
        _ => return Err(Error::Conflict),
    })
}

pub(super) fn check(history: &[&Retained], next: &Reserved) -> Result<()> {
    if !next
        .fixture_authority_digest
        .as_deref()
        .is_some_and(super::digest)
    {
        return Err(Error::Conflict);
    }
    let fixtures = fixture_history(history);
    let cleanup_started = fixtures
        .iter()
        .any(|old| old.reserved.operation == "cleanup_fixture");
    let Some(fixture) = &next.fixture else {
        // Existing policy reconciliation must remain reachable even if object
        // observations are unresolved. Its own lifecycle/budget checks follow.
        if next.operation == "reconcile_policy" {
            return Ok(());
        }
        // A prepared object result is a worker observation, not independent audit.
        // Nevertheless business work cannot consume cleanup authority before both
        // exact generated objects have a retained, settled owned observation.
        if cleanup_started
            || ["primary", "health"]
                .iter()
                .any(|purpose| !position(&fixtures, purpose).is_some_and(|p| p.state == "owned"))
        {
            return Err(Error::Lifecycle);
        }
        return Ok(());
    };
    // Do not spend policy-recovery authority on fixture reads or writes while
    // its position is unsettled. Settled hardening is retained, not rolled back.
    if !matches!(
        policy_position(history),
        PolicyPosition::Before | PolicyPosition::After
    ) {
        return Err(Error::ReconcileRequired);
    }
    if fixture.schema_version != "bluefire.s3-fixture-operation.v2"
        || !crate::s3_access_scope::lower_hex(&fixture.intent_id, 64)
        || !matches!(fixture.purpose.as_str(), "primary" | "health")
        || fixture
            .expected_etag
            .as_deref()
            .is_some_and(|tag| !crate::s3_fixture_binding::etag(tag))
        || fixtures.iter().any(|old| {
            old.reserved
                .fixture
                .as_ref()
                .is_some_and(|f| f.intent_id != fixture.intent_id)
        })
    {
        return Err(Error::Conflict);
    }
    let expected_phase = match next.operation.as_str() {
        "prepare_fixture" => "prepare",
        "reconcile_fixture" => "reconcile_fixtures",
        "cleanup_fixture" => "cleanup",
        _ => return Err(Error::Conflict),
    };
    if next.phase != expected_phase {
        return Err(Error::Conflict);
    }
    if fixture.purpose == "health"
        && !fixtures.iter().any(|old| {
            old.reserved.operation_id == next.operation_id
                && old.reserved.operation == next.operation
                && old.reserved.revision == next.revision
                && old
                    .reserved
                    .fixture
                    .as_ref()
                    .is_some_and(|f| f.purpose == "primary")
                && matches!(old.completion, Some((true, _, true)))
        })
    {
        return Err(Error::Lifecycle);
    }
    let same = |old: &&Retained| {
        old.reserved
            .fixture
            .as_ref()
            .is_some_and(|f| f.purpose == fixture.purpose)
    };
    let prior: Vec<_> = fixtures.iter().copied().filter(same).collect();
    match next.operation.as_str() {
        "prepare_fixture" => {
            if fixture.expected_etag.is_some()
                || !prior.is_empty()
                || cleanup_started
                || history.iter().any(|old| old.reserved.fixture.is_none())
                || (fixture.purpose == "primary" && !fixtures.is_empty())
                || (fixture.purpose == "health"
                    && !position(&fixtures, "primary").is_some_and(|p| p.state == "owned"))
            {
                return Err(Error::Lifecycle);
            }
        }
        "reconcile_fixture" => {
            if fixtures.is_empty() {
                return Err(Error::Lifecycle);
            }
        }
        "cleanup_fixture" => {
            let stages: std::collections::BTreeSet<_> = fixtures
                .iter()
                .filter(|old| old.reserved.operation == "cleanup_fixture")
                .map(|old| old.reserved.operation_id.as_str())
                .collect();
            if stages.len() >= 2 && !stages.contains(next.operation_id.as_str()) {
                return Err(Error::Lifecycle);
            }
            if fixture.expected_etag.is_some()
                && prior.iter().any(|old| {
                    old.reserved.operation == "cleanup_fixture"
                        && old
                            .reserved
                            .fixture
                            .as_ref()
                            .is_some_and(|f| f.expected_etag.is_some())
                })
            {
                return Err(Error::AlreadyReserved);
            }
            let known = position(&fixtures, &fixture.purpose).ok_or(Error::ReconcileRequired)?;
            if !matches!(known.state.as_str(), "owned" | "absent")
                || known.etag != fixture.expected_etag
            {
                return Err(Error::Conflict);
            }
            // A second stage can verify a settled absence, never repeat a delete.
            // Require a later reconciliation before rechecking that purpose.
            if prior
                .iter()
                .any(|old| old.reserved.operation == "cleanup_fixture")
                && prior.last().is_none_or(|old| {
                    old.reserved.operation != "reconcile_fixture"
                        || !matches!(old.completion, Some((true, _, true)))
                })
            {
                return Err(Error::ReconcileRequired);
            }
            if fixture.purpose == "health"
                && !position(&fixtures, "primary").is_some_and(|p| p.state == "absent")
            {
                return Err(Error::Lifecycle);
            }
        }
        _ => return Err(Error::Conflict),
    }
    Ok(())
}
