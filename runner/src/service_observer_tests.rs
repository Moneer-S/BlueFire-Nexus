//! Authored parsing vectors only: no queries, effects or authentic observations.

use super::*;
use serde_json::{json, Value};

fn document() -> Value {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../tests_platform/fixtures/service_operation_binding_v1.json"
    ))
    .unwrap();
    fixture["valid"][0]["document"].clone()
}

fn target(document: &Value) -> ObservationTarget {
    let binding =
        ServiceOperationBinding::from_json(&serde_json::to_vec(document).unwrap()).unwrap();
    ObservationTarget::from_binding(&binding).unwrap()
}

fn absent() -> [Vec<u8>; 4] {
    [
        b"Id=user@1000.service\nLoadState=loaded\nActiveState=active\nInvocationID=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nMainPID=42\nControlGroup=/user.slice/user-1000.slice/user@1000.service\n".to_vec(),
        b"ControlGroup=/user.slice/user-1000.slice/user@1000.service\nUnitPath=/home/bluefire/.config/systemd/user /etc/systemd/user /usr/lib/systemd/user\n".to_vec(),
        b"Id=bluefire-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.service\nNames=bluefire-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.service\nLoadState=not-found\nActiveState=inactive\nControlGroup=\nFragmentPath=\nDropInPaths=\nUnitFileState=\nTransient=no\nNeedDaemonReload=no\n".to_vec(),
        b"populated 0\nfrozen 0\n".to_vec(),
    ]
}

fn complete(bytes: &[u8]) -> ReadOutcome<'_> {
    ReadOutcome::Finished {
        bytes,
        exit_code: 0,
        truncated: false,
    }
}

fn parse(
    target: &ObservationTarget,
    data: &[Vec<u8>; 4],
) -> Result<ReportedServiceProperties, ObservationIssue> {
    target.parse_reported_properties(
        complete(&data[0]),
        complete(&data[1]),
        complete(&data[2]),
        complete(&data[3]),
    )
}

fn replace(data: &mut Vec<u8>, name: &str, value: &str) {
    let prefix = format!("{name}=");
    *data = String::from_utf8(data.clone())
        .unwrap()
        .lines()
        .map(|line| {
            if line.starts_with(&prefix) {
                format!("{prefix}{value}\n")
            } else {
                format!("{line}\n")
            }
        })
        .collect::<String>()
        .into_bytes();
}

fn loaded() -> [Vec<u8>; 4] {
    let mut data = absent();
    replace(&mut data[2], "LoadState", "loaded");
    replace(&mut data[2], "ActiveState", "active");
    replace(&mut data[2], "ControlGroup", "/user.slice/user-1000.slice/user@1000.service/app.slice/bluefire-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.service");
    replace(
        &mut data[2],
        "FragmentPath",
        "/home/bluefire/.config/systemd/user/bluefire-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.service",
    );
    replace(&mut data[2], "UnitFileState", "enabled");
    data[3] = b"populated 1\nfrozen 0\n".to_vec();
    data
}

#[test]
fn queries_and_user_bus_are_fixed_and_derive_only_from_the_binding() {
    let target = target(&document());
    assert_eq!(
        target.unit_name(),
        "bluefire-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.service"
    );
    assert_eq!(
        target.query_arguments(PropertyQuery::OwnerManager),
        [
            "--system",
            "--no-pager",
            "--no-ask-password",
            "show",
            "--all",
            "--property=Id,LoadState,ActiveState,InvocationID,MainPID,ControlGroup",
            "user@1000.service",
        ]
    );
    assert_eq!(
        target.query_arguments(PropertyQuery::UserManager),
        [
            "--user",
            "--no-pager",
            "--no-ask-password",
            "show",
            "--all",
            "--property=ControlGroup,UnitPath",
        ]
    );
    assert_eq!(target.query_arguments(PropertyQuery::OwnedUnit), [
        "--user", "--no-pager", "--no-ask-password", "show", "--all",
        "--property=Id,Names,LoadState,ActiveState,ControlGroup,FragmentPath,DropInPaths,UnitFileState,Transient,NeedDaemonReload",
        "bluefire-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.service",
    ]);
    assert_eq!(
        target.user_bus_environment(),
        [
            ("SYSTEMCTL_FORCE_BUS", "1".to_string()),
            (
                "DBUS_SESSION_BUS_ADDRESS",
                "unix:path=/run/user/1000/bus".to_string()
            ),
            ("XDG_RUNTIME_DIR", "/run/user/1000".to_string()),
        ]
    );
}

#[test]
fn complete_absent_and_loaded_reports_keep_distinct_resource_states() {
    let target = target(&document());
    let empty = parse(&target, &absent()).unwrap();
    assert_eq!(
        (
            empty.unit_load_state,
            empty.unit_active_state,
            empty.cgroup_state
        ),
        ("absent", "inactive", "empty")
    );
    assert_eq!(empty.manager_pid, 42);
    assert!(empty.fragment_path.is_none() && empty.unit_control_group.is_none());
    let reordered = absent().map(|bytes| {
        std::str::from_utf8(&bytes)
            .unwrap()
            .lines()
            .rev()
            .map(|line| format!("{line}\n"))
            .collect::<String>()
            .into_bytes()
    });
    assert_eq!(parse(&target, &reordered).unwrap(), empty);
    let active = parse(&target, &loaded()).unwrap();
    assert_eq!(
        (
            active.unit_load_state,
            active.unit_active_state,
            active.cgroup_state
        ),
        ("loaded", "active", "populated")
    );
    assert_eq!(active.manager_unit_file_state, "enabled");
    assert_eq!(active.unit_search_paths.len(), 3);
    assert!(active.unit_control_group.is_some() && active.fragment_path.is_some());
    assert!(crate::actions::find_action(crate::service_admission::SERVICE_ACTION_ID).is_none());
}

#[test]
fn property_scope_exposes_validated_paths_without_inventing_cgroup_data() {
    let target = target(&document());
    let data = loaded();
    let scope = target
        .parse_property_scope(complete(&data[0]), complete(&data[1]), complete(&data[2]))
        .unwrap();
    assert_eq!(&scope.binding, target.binding());
    assert_eq!(scope.manager_pid, 42);
    assert_eq!(scope.manager_control_group, "/user.slice/user-1000.slice/user@1000.service");
    assert_eq!(scope.unit_search_paths, [
        "/home/bluefire/.config/systemd/user", "/etc/systemd/user", "/usr/lib/systemd/user",
    ]);
    assert_eq!(scope.unit_control_group.as_deref(), Some(
        "/user.slice/user-1000.slice/user@1000.service/app.slice/bluefire-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.service"
    ));
    assert_eq!(scope.fragment_path.as_deref(), Some(
        "/home/bluefire/.config/systemd/user/bluefire-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.service"
    ));
    assert_eq!(scope.with_cgroup_events(ReadOutcome::Unavailable),
        Err(ObservationIssue::Unavailable("cgroup")));
}

#[test]
fn staged_completion_and_public_wrapper_require_complete_cgroup_input() {
    let target = target(&document());
    for data in [absent(), loaded()] {
        let scope = || target
            .parse_property_scope(complete(&data[0]), complete(&data[1]), complete(&data[2]))
            .unwrap();
        for (input, expected) in [
            (ReadOutcome::Unavailable, ObservationIssue::Unavailable("cgroup")),
            (complete(b""), ObservationIssue::Unknown("cgroup")),
            (complete(b"populated 0\n"), ObservationIssue::Unknown("cgroup")),
            (complete(b"populated 0\nfrozen 2\n"), ObservationIssue::Unknown("cgroup_value")),
            (ReadOutcome::Finished { bytes: &data[3], exit_code: 1, truncated: false },
                ObservationIssue::Unknown("cgroup")),
            (ReadOutcome::Finished { bytes: &data[3], exit_code: 0, truncated: true },
                ObservationIssue::Unknown("cgroup")),
        ] {
            assert_eq!(scope().with_cgroup_events(input), Err(expected));
            assert_eq!(target.parse_reported_properties(
                complete(&data[0]), complete(&data[1]), complete(&data[2]), input,
            ), Err(expected));
        }
        let reported = scope().with_cgroup_events(complete(b"populated 1\nfrozen 1\n")).unwrap();
        assert_eq!(reported.cgroup_state, "populated");
        assert!(reported.cgroup_frozen);
        assert_eq!(reported.binding(), target.binding());
    }
}

#[test]
fn property_scope_refuses_incomplete_inputs_and_foreign_resource_paths() {
    let target = target(&document());
    let baseline = loaded();
    for index in 0..3 {
        for input in [ReadOutcome::Unavailable, ReadOutcome::Finished {
            bytes: &baseline[index], exit_code: 0, truncated: true,
        }] {
            let mut reads = baseline.each_ref().map(|bytes| complete(bytes));
            reads[index] = input;
            assert!(matches!(target.parse_property_scope(reads[0], reads[1], reads[2]),
                Err(ObservationIssue::Unavailable(_) | ObservationIssue::Unknown(_))));
        }
    }
    for (index, field, value) in [
        (0, "InvocationID", "cccccccccccccccccccccccccccccccc"),
        (1, "ControlGroup", "/user.slice/user-1001.slice/user@1001.service"),
        (2, "ControlGroup", "/user.slice/user-1000.slice/user@1000.service/unrelated.service"),
        (2, "FragmentPath", "/tmp/bluefire-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.service"),
    ] {
        let mut data = baseline.clone();
        replace(&mut data[index], field, value);
        assert!(matches!(target.parse_property_scope(
            complete(&data[0]), complete(&data[1]), complete(&data[2]),
        ), Err(ObservationIssue::IdentityMismatch(_))));
    }
}

#[test]
fn changed_identity_rederives_queries_and_cannot_reuse_the_previous_manager() {
    let mut changed = document();
    changed["identity"]["owner_uid"] = json!(2001);
    changed["identity"]["unit_nonce"] = json!("dddddddddddddddddddddddddddddddd");
    changed["identity_digest"] = json!(crate::canonical::canonical_hash(&changed["identity"]));
    let changed_target = target(&changed);
    assert_eq!(
        changed_target
            .query_arguments(PropertyQuery::OwnerManager)
            .last()
            .unwrap(),
        "user@2001.service"
    );
    assert_eq!(
        changed_target
            .query_arguments(PropertyQuery::OwnedUnit)
            .last()
            .unwrap(),
        "bluefire-dddddddddddddddddddddddddddddddd.service"
    );
    assert_eq!(
        changed_target.user_bus_environment()[1].1,
        "unix:path=/run/user/2001/bus"
    );
    assert_eq!(
        parse(&changed_target, &absent()),
        Err(ObservationIssue::IdentityMismatch("manager_unit"))
    );
}

#[test]
fn complete_binding_retains_authorization_profile_target_and_operation_identity() {
    let original = document();
    let mut changed = original.clone();
    changed["identity"]["authorization_digest"] = json!(format!("sha256:{}", "1".repeat(64)));
    changed["identity"]["runner_profile_id"] = json!("another-profile");
    changed["identity"]["workspace_id"] = json!("another-workspace");
    changed["identity"]["target_scope_digest"] = json!(format!("sha256:{}", "2".repeat(64)));
    changed["identity"]["boot_id"] = json!("87654321-1234-1234-1234-123456789abc");
    changed["identity_digest"] = json!(crate::canonical::canonical_hash(&changed["identity"]));
    changed["operation_id"] = json!(format!("op-{}", "3".repeat(32)));
    changed["reviewed_scope_digest"] = json!(format!("sha256:{}", "4".repeat(64)));
    let first = target(&original);
    let second = target(&changed);
    let report = parse(&second, &absent()).unwrap();
    assert_eq!(report.binding(), second.binding());
    assert_ne!(report.binding().digest(), first.binding().digest());
    assert_eq!(
        serde_json::from_str::<Value>(report.binding().canonical_json()).unwrap(),
        changed
    );
}

#[test]
fn failure_truncation_and_unavailability_never_yield_an_absent_report() {
    let target = target(&document());
    let data = absent();
    for index in 0..4 {
        for (exit_code, truncated) in [(1, false), (-1, false), (0, true)] {
            let mut reads = data.each_ref().map(|bytes| complete(bytes));
            reads[index] = ReadOutcome::Finished {
                bytes: &data[index],
                exit_code,
                truncated,
            };
            assert!(matches!(
                target.parse_reported_properties(reads[0], reads[1], reads[2], reads[3]),
                Err(ObservationIssue::Unknown(_))
            ));
        }
        let mut reads = data.each_ref().map(|bytes| complete(bytes));
        reads[index] = ReadOutcome::Unavailable;
        assert!(matches!(
            target.parse_reported_properties(reads[0], reads[1], reads[2], reads[3]),
            Err(ObservationIssue::Unavailable(_))
        ));
    }
}

#[test]
fn every_required_field_must_be_complete_unique_and_recognized() {
    let target = target(&document());
    let baseline = absent();
    for index in 0..4 {
        let lines: Vec<_> = std::str::from_utf8(&baseline[index])
            .unwrap()
            .split_inclusive('\n')
            .collect();
        for missing in 0..lines.len() {
            let mut data = baseline.clone();
            data[index] = lines
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != missing)
                .map(|(_, line)| *line)
                .collect::<String>()
                .into_bytes();
            assert!(matches!(
                parse(&target, &data),
                Err(ObservationIssue::Unknown(_))
            ));
        }
        for suffix in [lines[0], if index == 3 { "other 0\n" } else { "Other=\n" }] {
            let mut data = baseline.clone();
            data[index].extend_from_slice(suffix.as_bytes());
            assert!(matches!(
                parse(&target, &data),
                Err(ObservationIssue::Unknown(_))
            ));
        }
    }
}

#[test]
fn output_bounds_encoding_and_line_framing_are_fail_closed() {
    let target = target(&document());
    for index in 0..4 {
        let baseline = absent();
        let mut no_newline = baseline[index].clone();
        no_newline.pop();
        let mut bom = b"\xef\xbb\xbf".to_vec();
        bom.extend_from_slice(&baseline[index]);
        for bad in [
            vec![],
            vec![b'x'; MAX_QUERY_BYTES + 1],
            vec![0xff],
            bom,
            no_newline,
            baseline[index]
                .iter()
                .flat_map(|byte| {
                    if *byte == b'\n' {
                        vec![b'\r', b'\n']
                    } else {
                        vec![*byte]
                    }
                })
                .collect(),
        ] {
            let mut data = baseline.clone();
            data[index] = bad;
            assert!(matches!(
                parse(&target, &data),
                Err(ObservationIssue::Unknown(_))
            ));
        }
    }
}

#[test]
fn unavailable_manager_is_distinct_from_a_replaced_or_indeterminate_manager() {
    let target = target(&document());
    for active in ["inactive", "failed"] {
        let mut data = absent();
        replace(&mut data[0], "ActiveState", active);
        assert_eq!(
            parse(&target, &data),
            Err(ObservationIssue::Unavailable("manager_inactive"))
        );
    }
    for (field, value) in [
        ("Id", "user@1001.service"),
        ("InvocationID", "cccccccccccccccccccccccccccccccc"),
    ] {
        let mut data = absent();
        replace(&mut data[0], field, value);
        assert!(matches!(
            parse(&target, &data),
            Err(ObservationIssue::IdentityMismatch(_))
        ));
    }
    for (field, value) in [
        ("ActiveState", "activating"),
        ("InvocationID", "00000000000000000000000000000000"),
        ("MainPID", "0"),
        ("MainPID", "0042"),
        ("MainPID", "-1"),
        ("MainPID", "4294967295"),
    ] {
        let mut data = absent();
        replace(&mut data[0], field, value);
        assert!(matches!(
            parse(&target, &data),
            Err(ObservationIssue::Unknown(_))
        ));
    }
}

#[test]
fn canonical_manager_replacement_is_not_hidden_by_inactive_or_indeterminate_state() {
    let target = target(&document());
    for (load, active) in [
        ("loaded", "active"),
        ("loaded", "inactive"),
        ("loaded", "failed"),
        ("not-found", "inactive"),
        ("loaded", "activating"),
    ] {
        let mut data = absent();
        replace(&mut data[0], "LoadState", load);
        replace(&mut data[0], "ActiveState", active);
        replace(
            &mut data[0],
            "InvocationID",
            "cccccccccccccccccccccccccccccccc",
        );
        replace(&mut data[0], "MainPID", "0");
        replace(&mut data[0], "ControlGroup", "");
        assert_eq!(
            target.parse_reported_properties(
                complete(&data[0]),
                ReadOutcome::Unavailable,
                ReadOutcome::Unavailable,
                ReadOutcome::Unavailable,
            ),
            Err(ObservationIssue::IdentityMismatch("manager_invocation")),
            "{load}/{active}"
        );
    }
}

#[test]
fn inactive_manager_without_a_canonical_replacement_keeps_unavailable_semantics() {
    let target = target(&document());
    for (load, active) in [
        ("loaded", "inactive"),
        ("loaded", "failed"),
        ("not-found", "inactive"),
    ] {
        for invocation in [
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "",
            "00000000000000000000000000000000",
            "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
            "ccccccccccccccccccccccccccccccc",
            "cccccccccccccccccccccccccccccccg",
        ] {
            let mut data = absent();
            replace(&mut data[0], "LoadState", load);
            replace(&mut data[0], "ActiveState", active);
            replace(&mut data[0], "InvocationID", invocation);
            replace(&mut data[0], "MainPID", "0");
            replace(&mut data[0], "ControlGroup", "");
            assert_eq!(
                parse(&target, &data),
                Err(ObservationIssue::Unavailable("manager_inactive")),
                "{load}/{active}/{invocation}"
            );
            data[0] = String::from_utf8(data[0].clone())
                .unwrap()
                .lines()
                .filter(|line| !line.starts_with("InvocationID="))
                .map(|line| format!("{line}\n"))
                .collect::<String>()
                .into_bytes();
            assert_eq!(
                parse(&target, &data),
                Err(ObservationIssue::Unknown("manager"))
            );
        }
    }
    for invocation in [
        "",
        "00000000000000000000000000000000",
        "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
        "ccccccccccccccccccccccccccccccc",
        "cccccccccccccccccccccccccccccccg",
    ] {
        let mut data = absent();
        replace(&mut data[0], "InvocationID", invocation);
        assert_eq!(
            parse(&target, &data),
            Err(ObservationIssue::Unknown("manager_invocation"))
        );
    }
}

#[test]
fn manager_namespace_and_unit_search_paths_cannot_be_substituted() {
    let target = target(&document());
    let mut changed = absent();
    replace(
        &mut changed[1],
        "ControlGroup",
        "/user.slice/user-1001.slice/user@1001.service",
    );
    assert_eq!(
        parse(&target, &changed),
        Err(ObservationIssue::IdentityMismatch("user_manager_cgroup"))
    );
    for path in [
        "",
        "/",
        "relative",
        "/tmp/../home",
        "/tmp//home",
        "/tmp/",
        "/tmp /tmp",
        "/tmp\\x20home",
    ] {
        let mut data = absent();
        replace(&mut data[1], "UnitPath", path);
        assert!(matches!(
            parse(&target, &data),
            Err(ObservationIssue::Unknown(_))
        ));
    }
    let mut too_many = absent();
    replace(
        &mut too_many[1],
        "UnitPath",
        &(0..33)
            .map(|i| format!("/path{i}"))
            .collect::<Vec<_>>()
            .join(" "),
    );
    assert!(matches!(
        parse(&target, &too_many),
        Err(ObservationIssue::Unknown(_))
    ));
}

#[test]
fn aliases_dropins_and_foreign_resource_paths_are_identity_mismatches() {
    let target = target(&document());
    for (field, value) in [
        ("Id", "unrelated.service"), ("Names", "bluefire-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.service alias.service"),
        ("DropInPaths", "/etc/systemd/user/service.d/override.conf"), ("Transient", "yes"),
        ("FragmentPath", "/tmp/bluefire-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.service"),
        ("ControlGroup", "/user.slice/user-1001.slice/user@1001.service/app.slice/bluefire-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.service"),
        ("ControlGroup", "/user.slice/user-1000.slice/user@1000.service/app.slice/unrelated.service"),
    ] {
        let mut data = loaded(); replace(&mut data[2], field, value);
        assert!(matches!(parse(&target, &data), Err(ObservationIssue::IdentityMismatch(_))), "{field}");
    }
}

#[test]
fn contradictory_or_stale_unit_properties_never_mean_absent() {
    let target = target(&document());
    for (field, value) in [
        ("LoadState", "error"),
        ("ActiveState", "active"),
        ("ActiveState", "deactivating"),
        ("FragmentPath", "/etc/systemd/user/unrelated.service"),
        ("UnitFileState", "disabled"),
        ("ControlGroup", "/retained"),
        ("NeedDaemonReload", "yes"),
        ("Transient", "maybe"),
    ] {
        let mut data = absent();
        replace(&mut data[2], field, value);
        assert!(
            matches!(parse(&target, &data), Err(ObservationIssue::Unknown(_))),
            "{field}"
        );
    }
    for (field, value) in [
        ("FragmentPath", ""),
        ("UnitFileState", "masked"),
        ("ControlGroup", ""),
    ] {
        let mut data = loaded();
        replace(&mut data[2], field, value);
        assert!(matches!(
            parse(&target, &data),
            Err(ObservationIssue::Unknown(_))
        ));
    }
}

#[test]
fn cgroup_population_is_independent_of_manager_absence_and_freezing() {
    let target = target(&document());
    let mut data = absent();
    data[3] = b"frozen 1\npopulated 1\n".to_vec();
    let report = parse(&target, &data).unwrap();
    assert_eq!(report.unit_load_state, "absent");
    assert_eq!(report.cgroup_state, "populated");
    assert!(report.cgroup_frozen);
    for invalid in [
        "populated 00\nfrozen 0\n",
        "populated -1\nfrozen 0\n",
        "populated 0\nfrozen 2\n",
        "populated 0 \nfrozen 0\n",
        "populated 0\nfrozen 0\npopulated 1\n",
        "populated 0\n",
    ] {
        data[3] = invalid.as_bytes().to_vec();
        assert!(matches!(
            parse(&target, &data),
            Err(ObservationIssue::Unknown(_))
        ));
    }
}
