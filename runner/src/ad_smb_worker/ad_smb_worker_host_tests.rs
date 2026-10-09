use super::*;
use serde_json::json;

fn entry(name: &str, value: &str) -> PolicyValue {
    PolicyValue {
        name: name.to_owned(),
        kind: 1,
        data: value
            .encode_utf16()
            .chain(Some(0))
            .flat_map(u16::to_le_bytes)
            .collect(),
    }
}

const TARGET: &str = "\\\\member.example.test\\bf_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const REQUIRED: &str = "RequireMutualAuthentication=1,RequireIntegrity=1,RequirePrivacy=1";

fn fixture(role: &str) -> (Value, Facts) {
    let fqdn = format!("{role}.example.test");
    let version = if role == "member" {
        [10, 0, 20348, 3807]
    } else {
        [10, 0, 19045, 6332]
    };
    let scope = json!({"hosts":{role:{"architecture":"x86_64","fqdn":fqdn,"os_build":version.map(|p| p.to_string()).join(".")}},"domain":{"dns":"example.test","sid":"S-1-5-21-101-202-303"},"share":{"unc":TARGET}});
    let facts = Facts {
        fqdn,
        domain_dns: "example.test".into(),
        domain_sid: "S-1-5-21-101-202-303".into(),
        process_machine: 0,
        native_machine: 0x8664,
        version,
        product_type: if role == "member" { 3 } else { 1 },
        policy: vec![entry(TARGET, REQUIRED)],
    };
    (scope, facts)
}

#[test]
fn exact_member_and_client_local_premises_match_without_os_calls() {
    for role in ["member", "client"] {
        let (scope, mut facts) = fixture(role);
        assert!(matches(&scope, role, &facts).is_ok());
        facts.fqdn.make_ascii_uppercase();
        facts.domain_dns.make_ascii_uppercase();
        assert!(matches(&scope, role, &facts).is_ok());
    }
}

#[test]
fn every_host_identity_version_and_machine_mismatch_is_refused() {
    for mutation in 0..14 {
        let (scope, mut facts) = fixture("member");
        match mutation {
            0 => facts.fqdn = "alias.example.test".into(),
            1 => facts.fqdn.push('.'),
            2 => facts.domain_dns = "other.test".into(),
            3 => facts.domain_sid.push_str("-1"),
            4 => facts.domain_dns.clear(),
            5 => facts.domain_sid.clear(),
            6..=9 => facts.version[mutation - 6] += 1,
            10 => facts.process_machine = 0x14c,
            11 => facts.native_machine = 0xaa64,
            12 => facts.product_type = 2,
            _ => facts.fqdn = "member\0.example.test".into(),
        }
        assert_eq!(
            matches(&scope, "member", &facts),
            Err(Code::PreconditionFailed),
            "mutation {mutation}"
        );
    }
    let (mut scope, facts) = fixture("client");
    scope["hosts"]["client"]["architecture"] = json!("arm64");
    assert!(matches(&scope, "client", &facts).is_err());
    assert!(matches(&scope, "dc", &facts).is_err());
}

#[test]
fn exact_policy_supports_order_and_unrelated_documented_patterns_only() {
    let rows = vec![
        entry(
            TARGET,
            " RequirePrivacy=1,RequireMutualAuthentication=1, RequireIntegrity=1 ",
        ),
        entry("\\\\*\\SYSVOL", REQUIRED),
        entry("\\\\*\\NETLOGON", REQUIRED),
        entry("\\\\unrelated.example.test\\*", REQUIRED),
    ];
    assert!(policy(&rows, TARGET).is_ok());
    assert!(policy(&[entry(&TARGET.to_ascii_uppercase(), REQUIRED)], TARGET).is_ok());
}

#[test]
fn overlapping_or_unsupported_policy_patterns_never_infer_precedence() {
    for name in [
        "\\\\*\\*",
        "\\\\member.example.test\\*",
        "\\\\*\\bf_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "\\\\mem*.example.test\\unrelated",
        "\\\\member.example.test\\unrelated\\subpath",
        "\\\\member.example.test\\bf_????????",
        "invalid",
        TARGET,
    ] {
        assert!(
            policy(&[entry(TARGET, REQUIRED), entry(name, REQUIRED)], TARGET).is_err(),
            "{name}"
        );
    }
    assert!(policy(&[entry("\\\\*\\*", REQUIRED)], TARGET).is_err());
}

#[test]
fn every_missing_weak_duplicate_or_unknown_policy_requirement_is_refused() {
    for value in [
        "RequireIntegrity=1,RequirePrivacy=1",
        "RequireMutualAuthentication=1,RequirePrivacy=1",
        "RequireMutualAuthentication=1,RequireIntegrity=1",
        "RequireMutualAuthentication=0,RequireIntegrity=1,RequirePrivacy=1",
        "RequireMutualAuthentication=1,RequireIntegrity=1,RequirePrivacy=0",
        "RequireMutualAuthentication=1,RequireIntegrity=0,RequirePrivacy=1",
        "RequireMutualAuthentication=1,RequireIntegrity=1,RequirePrivacy=1,Unknown=1",
        "RequireMutualAuthentication=1,RequireIntegrity=1,RequirePrivacy=1,requireprivacy=1",
        "RequireMutualAuthentication=1,RequireIntegrity=1,RequirePrivacy=true",
        "RequireMutualAuthentication=1,RequireIntegrity=1,RequirePrivacy=1,",
    ] {
        assert!(policy(&[entry(TARGET, value)], TARGET).is_err(), "{value}");
    }
}

#[test]
fn policy_binary_and_allocation_bounds_are_strict() {
    for mutation in 0..8 {
        let mut row = entry(TARGET, REQUIRED);
        match mutation {
            0 => row.kind = 2,
            1 => {
                row.data.pop();
            }
            2 => {
                row.data.truncate(row.data.len() - 2);
            }
            3 => row.data = vec![0, 0],
            4 => row.data.splice(0..2, [0, 0]).for_each(drop),
            5 => row.data = vec![0; MAX_DATA + 2],
            6 => row.name = "x".repeat(MAX_NAME + 1),
            _ => row.data = vec![0x00, 0xd8, 0, 0],
        }
        assert!(policy(&[row], TARGET).is_err(), "mutation {mutation}");
    }
    assert!(policy(&[], TARGET).is_err());
    assert!(policy(
        &(0..=MAX_VALUES)
            .map(|_| entry(TARGET, REQUIRED))
            .collect::<Vec<_>>(),
        TARGET
    )
    .is_err());
}
