//! Replay the actual pure journal transitions, without files or cloud calls.

use super::*;
use crate::s3_fixture_binding::FixtureOperation;

fn fixture_operation(
    index: u64,
    stage: u64,
    name: &str,
    purpose: &str,
    tag: Option<&str>,
) -> Reserved {
    let phase = match name {
        "prepare_fixture" => "prepare",
        "cleanup_fixture" => "cleanup",
        _ => "reconcile_fixtures",
    };
    let mut value = operation(index, phase, name);
    value.operation_id = format!("operation-{stage}");
    value.revision = stage;
    value.max_sends = match name {
        "prepare_fixture" => 6,
        "cleanup_fixture" => 7,
        _ => 5,
    };
    value.fixture_authority_digest = Some(format!("sha256:{}", "8".repeat(64)));
    value.fixture = Some(FixtureOperation {
        schema_version: "bluefire.s3-fixture-operation.v2".into(),
        intent_id: "a".repeat(64),
        purpose: purpose.into(),
        expected_etag: tag.map(str::to_owned),
    });
    value
}

fn complete_fixture(
    ledger: &mut Ledger,
    hash: &str,
    state: Option<&str>,
    tag: Option<&str>,
    cleanup: bool,
) {
    let row = ledger
        .requests
        .values()
        .find(|old| old.digest == hash)
        .unwrap()
        .reserved
        .clone();
    let count = if row.operation == "cleanup_fixture"
        && row.fixture.as_ref().unwrap().expected_etag.is_none()
    {
        5
    } else {
        row.max_sends
    };
    for sequence in 1..=count {
        ledger
            .apply(
                Record::Debit {
                    reservation_digest: hash.into(),
                    sequence,
                    preview_digest: format!("sha256:{}", "6".repeat(64)),
                    is_write: sequence == 5
                        && (row.operation == "prepare_fixture"
                            || (row.operation == "cleanup_fixture"
                                && row.fixture.as_ref().unwrap().expected_etag.is_some())),
                },
                String::new(),
            )
            .unwrap();
    }
    ledger
        .apply(
            Record::Completion {
                reservation_digest: hash.into(),
                result_digest: format!("sha256:{}", "7".repeat(64)),
                observed: state.is_some(),
                policy_position: PolicyPosition::Unknown,
                cleanup_verified: cleanup,
                fixture_position: state.map(|state| FixturePosition {
                    state: state.into(),
                    etag: tag.map(str::to_owned),
                }),
            },
            String::new(),
        )
        .unwrap();
}

fn owned_pair(api_limit: u64) -> Ledger {
    let mut ledger = Ledger::load(&[], &format!("sha256:{}", "e".repeat(64))).unwrap();
    for (index, purpose) in [(1, "primary"), (2, "health")] {
        let mut row = fixture_operation(index, 1, "prepare_fixture", purpose, None);
        row.api_limit = api_limit;
        let hash = reserve_state(&mut ledger, row);
        complete_fixture(&mut ledger, &hash, Some("owned"), Some("\"owned\""), true);
    }
    ledger
}

#[test]
fn fixture_intent_and_generation_are_retained_and_cannot_be_rebound_or_replayed() {
    let ledger = owned_pair(300);
    let prepare = fixture_operation(3, 2, "prepare_fixture", "primary", None);
    assert!(ledger.check_reserve(&prepare).is_err());
    for field in ["intent", "authority", "etag"] {
        let mut next = fixture_operation(3, 2, "cleanup_fixture", "primary", Some("\"owned\""));
        match field {
            "intent" => next.fixture.as_mut().unwrap().intent_id = "b".repeat(64),
            "authority" => {
                next.fixture_authority_digest = Some(format!("sha256:{}", "9".repeat(64)))
            }
            _ => next.fixture.as_mut().unwrap().expected_etag = Some("\"different\"".into()),
        }
        assert!(ledger.check_reserve(&next).is_err(), "{field}");
    }
    let health = fixture_operation(3, 2, "cleanup_fixture", "health", Some("\"owned\""));
    assert!(ledger.check_reserve(&health).is_err());
}

#[test]
fn unknown_prepare_requires_reconciliation_and_never_reissues_mutation() {
    let mut ledger = Ledger::load(&[], &format!("sha256:{}", "e".repeat(64))).unwrap();
    let hash = reserve_state(
        &mut ledger,
        fixture_operation(1, 1, "prepare_fixture", "primary", None),
    );
    complete_fixture(&mut ledger, &hash, None, None, true);
    assert!(ledger
        .check_reserve(&fixture_operation(2, 2, "prepare_fixture", "primary", None))
        .is_err());
    assert!(ledger
        .check_reserve(&fixture_operation(
            2,
            2,
            "cleanup_fixture",
            "primary",
            Some("\"owned\"")
        ))
        .is_err());
    let reconcile = reserve_state(
        &mut ledger,
        fixture_operation(2, 2, "reconcile_fixture", "primary", None),
    );
    complete_fixture(&mut ledger, &reconcile, Some("absent"), None, true);
    let cleanup = reserve_state(
        &mut ledger,
        fixture_operation(3, 3, "cleanup_fixture", "primary", None),
    );
    complete_fixture(&mut ledger, &cleanup, Some("absent"), None, true);
    let retained = ledger
        .requests
        .values()
        .find(|old| old.digest == cleanup)
        .unwrap();
    assert_eq!(retained.reserved.max_sends, 7);
    assert_eq!(retained.debits, 5);
    assert!(!retained.write_debited);
    assert!(ledger
        .check_reserve(&fixture_operation(4, 4, "cleanup_fixture", "primary", None))
        .is_err());
}

#[test]
fn cleanup_is_separate_from_policy_restore_and_final_reconciliation_is_readonly() {
    for policy in [PolicyPosition::Before, PolicyPosition::After] {
        let mut ledger = owned_pair(300);
        let mut inspect = operation(3, "inspect", "inspect_policy");
        inspect.fixture_authority_digest = Some(format!("sha256:{}", "8".repeat(64)));
        let policy_hash = reserve_state(&mut ledger, inspect);
        complete_state(&mut ledger, &policy_hash, policy);
        for (index, purpose) in [(4, "primary"), (5, "health")] {
            let hash = reserve_state(
                &mut ledger,
                fixture_operation(index, 4, "cleanup_fixture", purpose, Some("\"owned\"")),
            );
            complete_fixture(&mut ledger, &hash, Some("absent"), None, true);
        }
        assert_eq!(
            ledger
                .requests
                .values()
                .find(|old| old.digest == policy_hash)
                .unwrap()
                .completion,
            Some((true, policy, true))
        );
        assert!(ledger
            .check_reserve(&fixture_operation(
                6,
                5,
                "reconcile_fixture",
                "primary",
                None
            ))
            .is_ok());
        let mut business = operation(6, "inspect", "inspect_policy");
        business.fixture_authority_digest = Some(format!("sha256:{}", "8".repeat(64)));
        assert!(ledger.check_reserve(&business).is_err());
    }
}

#[test]
fn unsettled_policy_with_nonowned_fixture_can_only_reconcile_existing_policy() {
    for policy in [PolicyPosition::Unknown, PolicyPosition::Drift] {
        let mut ledger = owned_pair(300);
        for (index, phase, name) in [
            (3, "inspect", "inspect_policy"),
            (4, "baseline", "probe_read"),
            (5, "baseline", "legitimate_read"),
        ] {
            let mut row = operation(index, phase, name);
            row.fixture_authority_digest = Some(format!("sha256:{}", "8".repeat(64)));
            let hash = reserve_state(&mut ledger, row);
            complete_state(&mut ledger, &hash, PolicyPosition::Before);
        }
        let hash = reserve_state(
            &mut ledger,
            fixture_operation(6, 6, "reconcile_fixture", "primary", None),
        );
        complete_fixture(&mut ledger, &hash, Some("drift"), None, true);
        let mut read = operation(7, "reconcile", "reconcile_policy");
        read.fixture_authority_digest = Some(format!("sha256:{}", "8".repeat(64)));
        let hash = reserve_state(&mut ledger, read);
        complete_state(&mut ledger, &hash, policy);
        for name in ["reconcile_fixture", "cleanup_fixture"] {
            assert_eq!(
                ledger.check_reserve(&fixture_operation(8, 8, name, "primary", None)),
                Err(Error::ReconcileRequired)
            );
        }
        let mut read = operation(8, "reconcile", "reconcile_policy");
        read.fixture_authority_digest = Some(format!("sha256:{}", "8".repeat(64)));
        assert!(ledger.check_reserve(&read).is_ok());
        let mut apply = operation(8, "apply", "apply_policy");
        apply.fixture_authority_digest = Some(format!("sha256:{}", "8".repeat(64)));
        assert!(ledger.check_reserve(&apply).is_err());
        let hash = reserve_state(&mut ledger, read);
        complete_state(&mut ledger, &hash, PolicyPosition::After);
        assert!(ledger
            .check_reserve(&fixture_operation(
                9,
                9,
                "reconcile_fixture",
                "primary",
                None
            ))
            .is_ok());
    }
}

#[test]
fn cleanup_unknown_blocks_all_new_reservations_including_readonly_reconciliation() {
    let mut ledger = owned_pair(300);
    let hash = reserve_state(
        &mut ledger,
        fixture_operation(3, 2, "cleanup_fixture", "primary", Some("\"owned\"")),
    );
    complete_fixture(&mut ledger, &hash, None, None, false);
    assert_eq!(
        ledger.check_reserve(&fixture_operation(
            4,
            3,
            "reconcile_fixture",
            "primary",
            None
        )),
        Err(Error::RecoveryRequired)
    );
}

#[test]
fn fixture_policy_budget_never_borrows_reserved_object_cleanup_allowance() {
    let mut ledger = owned_pair(70);
    for index in 3..=7 {
        let mut inspect = operation(index, "inspect", "inspect_policy");
        inspect.api_limit = 70;
        inspect.fixture_authority_digest = Some(format!("sha256:{}", "8".repeat(64)));
        let hash = reserve_state(&mut ledger, inspect);
        complete_state(&mut ledger, &hash, PolicyPosition::Before);
    }
    let mut inspect = operation(8, "inspect", "inspect_policy");
    inspect.api_limit = 70;
    inspect.fixture_authority_digest = Some(format!("sha256:{}", "8".repeat(64)));
    assert_eq!(ledger.check_reserve(&inspect), Err(Error::Budget));
    assert_eq!(
        ledger
            .requests
            .values()
            .map(|old| old.reserved.max_sends)
            .sum::<u64>(),
        22
    );
}

#[test]
fn minimum70_retains_partial_cleanup_continuation_and69_refuses_before_reservation() {
    let mut ledger = Ledger::load(&[], &format!("sha256:{}", "e".repeat(64))).unwrap();
    let mut too_small = fixture_operation(1, 1, "prepare_fixture", "primary", None);
    too_small.api_limit = 69;
    assert_eq!(ledger.check_reserve(&too_small), Err(Error::Budget));
    assert!(ledger.requests.is_empty());
    for (index, stage, name, purpose, tag, state, observed_tag) in [
        (
            1,
            1,
            "prepare_fixture",
            "primary",
            None,
            Some("owned"),
            Some("\"owned\""),
        ),
        (2, 1, "prepare_fixture", "health", None, None, None),
        (
            3,
            2,
            "reconcile_fixture",
            "primary",
            None,
            Some("owned"),
            Some("\"owned\""),
        ),
        (
            4,
            2,
            "reconcile_fixture",
            "health",
            None,
            Some("owned"),
            Some("\"owned\""),
        ),
        (
            5,
            3,
            "cleanup_fixture",
            "primary",
            Some("\"owned\""),
            None,
            None,
        ),
        (
            6,
            4,
            "reconcile_fixture",
            "primary",
            None,
            Some("absent"),
            None,
        ),
        (
            7,
            4,
            "reconcile_fixture",
            "health",
            None,
            Some("owned"),
            Some("\"owned\""),
        ),
        (
            8,
            5,
            "cleanup_fixture",
            "primary",
            None,
            Some("absent"),
            None,
        ),
        (
            9,
            5,
            "cleanup_fixture",
            "health",
            Some("\"owned\""),
            None,
            None,
        ),
        (
            10,
            6,
            "reconcile_fixture",
            "primary",
            None,
            Some("absent"),
            None,
        ),
        (
            11,
            6,
            "reconcile_fixture",
            "health",
            None,
            Some("absent"),
            None,
        ),
    ] {
        let mut row = fixture_operation(index, stage, name, purpose, tag);
        row.api_limit = 70;
        let hash = reserve_state(&mut ledger, row);
        complete_fixture(&mut ledger, &hash, state, observed_tag, true);
    }
    assert_eq!(
        ledger
            .requests
            .values()
            .map(|old| old.reserved.max_sends)
            .sum::<u64>(),
        63
    );
    let readonly = ledger
        .requests
        .values()
        .find(|old| old.reserved.request_id == format!("{:064x}", 8))
        .unwrap();
    assert_eq!(readonly.reserved.max_sends, 7);
    assert_eq!(readonly.debits, 5);
    assert!(!readonly.write_debited);
    let mut exhausted = fixture_operation(12, 7, "reconcile_fixture", "primary", None);
    exhausted.api_limit = 70;
    assert_eq!(ledger.check_reserve(&exhausted), Err(Error::Budget));
}
