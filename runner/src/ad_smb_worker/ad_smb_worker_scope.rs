use serde_json::{json, Value};
use std::collections::BTreeSet;

use super::json::*;
use super::{Code, Result};

pub(super) fn dns(value: &str) -> bool {
    (3..=253).contains(&value.len())
        && value.contains('.')
        && value.parse::<std::net::IpAddr>().is_err()
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.as_bytes()[0].is_ascii_alphanumeric()
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

pub(super) fn sid(value: &str) -> bool {
    let parts = value.split('-').collect::<Vec<_>>();
    (4..=18).contains(&parts.len())
        && parts[..2] == ["S", "1"]
        && parts[2]
            .parse::<u64>()
            .is_ok_and(|n| n < (1 << 48) && n.to_string() == parts[2])
        && parts[3..]
            .iter()
            .all(|p| p.parse::<u32>().is_ok_and(|n| n.to_string() == *p))
}

pub(super) fn validate(scope: &Value) -> Result<()> {
    exact(
        scope,
        &[
            "schema_version",
            "scope_id",
            "domain",
            "hosts",
            "principals",
            "share",
            "files",
            "authentication",
            "network",
            "limits",
            "created_at",
            "expires_at",
            "ownership_receipt_digest",
            "readiness_receipt_digest",
            "exclusive_writer_receipt_digest",
            "native_parser_digest",
        ],
    )?;
    ensure(
        scope["schema_version"] == "bluefire.ad-smb-scope.v1" && hex(text(&scope["scope_id"])?, 32),
    )?;
    for key in [
        "ownership_receipt_digest",
        "readiness_receipt_digest",
        "exclusive_writer_receipt_digest",
        "native_parser_digest",
    ] {
        digest(&scope[key])?;
    }
    let limits = &scope["limits"];
    let caps = [
        ("generated_bytes", 65_536),
        ("returned_payload_bytes", 1_048_576),
        ("business_attempts", 6),
        ("sessions", 6),
        ("session_seconds", 900),
        ("business_seconds", 1800),
        ("audit_seconds", 600),
        ("cleanup_seconds", 900),
        ("operation_seconds", 60),
        ("audit_events", 1000),
        ("audit_bytes", 4_194_304),
        ("share_changes", 1),
        ("rollbacks", 1),
    ];
    exact(limits, &caps.iter().map(|r| r.0).collect::<Vec<_>>())?;
    for (name, maximum) in caps {
        number(&limits[name], 1, maximum)?;
    }
    ensure(
        limits["operation_seconds"].as_u64() <= limits["session_seconds"].as_u64()
            && limits["session_seconds"].as_u64() <= limits["business_seconds"].as_u64(),
    )?;
    let duration = time(&scope["expires_at"])? - time(&scope["created_at"])?;
    let maximum = ["business_seconds", "audit_seconds", "cleanup_seconds"]
        .iter()
        .map(|k| limits[k].as_i64().unwrap_or(0))
        .sum();
    ensure(duration > chrono::Duration::zero() && duration <= chrono::Duration::seconds(maximum))?;
    exact(&scope["domain"], &["dns", "sid"])?;
    let domain = text(&scope["domain"]["dns"])?;
    let domain_sid = text(&scope["domain"]["sid"])?;
    ensure(
        dns(domain)
            && sid(domain_sid)
            && domain_sid.starts_with("S-1-5-21-")
            && domain_sid.split('-').count() == 7,
    )?;
    hosts(scope, domain)?;
    principals(scope, domain_sid)?;
    resources(scope)?;
    authentication(scope)?;
    network(scope)
}

fn hosts(scope: &Value, domain: &str) -> Result<()> {
    exact(&scope["hosts"], &["dc", "member", "client"])?;
    let mut identities = BTreeSet::new();
    let mut names = BTreeSet::new();
    let mut addresses = BTreeSet::new();
    for role in ["dc", "member", "client"] {
        let row = &scope["hosts"][role];
        exact(
            row,
            &[
                "host_id",
                "fqdn",
                "ipv4",
                "os_product",
                "os_build",
                "architecture",
                "identity_receipt_digest",
            ],
        )?;
        digest(&row["host_id"])?;
        digest(&row["identity_receipt_digest"])?;
        let fqdn = text(&row["fqdn"])?;
        ensure(dns(fqdn) && fqdn.ends_with(&format!(".{domain}")))?;
        let address = text(&row["ipv4"])?;
        let ip = address
            .parse::<std::net::Ipv4Addr>()
            .map_err(|_| Code::RequestInvalid)?;
        ensure(ip.is_private() && ip.to_string() == address)?;
        ensure(
            identities.insert(text(&row["host_id"])?)
                && names.insert(fqdn)
                && addresses.insert(address),
        )?;
        ensure(
            row["architecture"] == "x86_64"
                && row["os_product"]
                    == if role == "client" {
                        "windows_client"
                    } else {
                        "windows_server_2022"
                    },
        )?;
        let build = text(&row["os_build"])?;
        let parts = build.split('.').collect::<Vec<_>>();
        ensure(
            parts.len() == 4
                && parts[..2] == ["10", "0"]
                && (4..=6).contains(&parts[2].len())
                && !parts[2].starts_with('0')
                && (1..=8).contains(&parts[3].len())
                && parts[2..]
                    .iter()
                    .all(|p| p.bytes().all(|b| b.is_ascii_digit()))
                && (role == "client" || parts[2] == "20348"),
        )?;
    }
    Ok(())
}

fn principals(scope: &Value, domain: &str) -> Result<()> {
    exact(&scope["principals"], &["controller", "probe", "legitimate"])?;
    let mut sids = BTreeSet::new();
    let mut handles = BTreeSet::new();
    for role in ["controller", "probe", "legitimate"] {
        let row = &scope["principals"][role];
        exact(
            row,
            &[
                "sid",
                "kind",
                "credential_handle",
                "group_sids",
                "sid_history",
                "identity_receipt_digest",
            ],
        )?;
        let id = text(&row["sid"])?;
        let prefix = format!("{domain}-");
        ensure(
            sid(id)
                && id
                    .strip_prefix(&prefix)
                    .is_some_and(|rid| rid.parse::<u32>().is_ok_and(|n| n >= 1000))
                && sids.insert(id),
        )?;
        ensure(row["kind"] == "domain_user" && row["sid_history"] == json!([]))?;
        let handle = text(&row["credential_handle"])?;
        ensure(
            handle
                .strip_prefix("credential-")
                .is_some_and(|v| hex(v, 32))
                && handles.insert(handle),
        )?;
        digest(&row["identity_receipt_digest"])?;
        let groups = row["group_sids"].as_array().ok_or(Code::RequestInvalid)?;
        ensure(groups.len() <= 64)?;
        let mut previous = None;
        for group in groups {
            let value = text(group)?;
            ensure(sid(value) && previous.is_none_or(|old| old < value))?;
            ensure(
                !["controller", "probe", "legitimate"]
                    .iter()
                    .any(|r| scope["principals"][r]["sid"] == *group),
            )?;
            if role != "controller" {
                ensure(
                    [
                        format!("{domain}-513"),
                        "S-1-1-0".into(),
                        "S-1-5-11".into(),
                        "S-1-5-32-545".into(),
                    ]
                    .iter()
                    .any(|s| s == value),
                )?;
            }
            previous = Some(value);
        }
    }
    Ok(())
}

fn resources(scope: &Value) -> Result<()> {
    let share = &scope["share"];
    exact(
        share,
        &[
            "name",
            "local_root",
            "unc",
            "identity_digest",
            "root_file_id",
            "volume_serial",
            "root_ntfs_digest",
            "baseline_descriptor_digest",
            "dfs",
            "administrative",
        ],
    )?;
    let root = text(&share["local_root"])?;
    let target = crate::ad_smb_share::LocalShareTarget::new(
        text(&scope["scope_id"])?,
        root.chars().next().ok_or(Code::RequestInvalid)?,
    )
    .map_err(|_| Code::RequestInvalid)?;
    ensure(
        root == target.path()
            && share["name"] == target.name()
            && share["unc"]
                == format!(
                    "\\\\{}\\{}",
                    text(&scope["hosts"]["member"]["fqdn"])?,
                    target.name()
                )
            && share["dfs"] == false
            && share["administrative"] == false,
    )?;
    for key in [
        "identity_digest",
        "root_ntfs_digest",
        "baseline_descriptor_digest",
    ] {
        digest(&share[key])?;
    }
    ensure(hex(text(&share["root_file_id"])?, 32) && hex(text(&share["volume_serial"])?, 16))?;
    let files = scope["files"].as_array().ok_or(Code::RequestInvalid)?;
    ensure(files.len() == 2)?;
    let mut ids = BTreeSet::from([text(&share["root_file_id"])?]);
    let mut bytes = 0;
    for (index, (purpose, name)) in [("primary", "records.jsonl"), ("health", "health.jsonl")]
        .iter()
        .enumerate()
    {
        let row = &files[index];
        exact(
            row,
            &[
                "purpose",
                "name",
                "file_id",
                "volume_serial",
                "sha256",
                "size_bytes",
                "records",
                "ntfs_digest",
            ],
        )?;
        ensure(
            row["purpose"] == *purpose
                && row["name"] == *name
                && hex(text(&row["file_id"])?, 32)
                && ids.insert(text(&row["file_id"])?)
                && row["volume_serial"] == share["volume_serial"],
        )?;
        digest(&row["sha256"])?;
        digest(&row["ntfs_digest"])?;
        bytes += number(&row["size_bytes"], 1, 65_536)?;
        number(&row["records"], 1, if index == 0 { 32 } else { 1 })?;
    }
    ensure(bytes <= number(&scope["limits"]["generated_bytes"], 1, 65_536)?)
}

fn authentication(scope: &Value) -> Result<()> {
    let row = &scope["authentication"];
    exact(
        row,
        &[
            "package",
            "spn",
            "signing_required",
            "encryption_required",
            "ntlm_fallback",
            "mutual_authentication_required",
            "hardened_unc_receipt_digest",
        ],
    )?;
    ensure(
        row["package"] == "Kerberos"
            && row["spn"] == format!("cifs/{}", text(&scope["hosts"]["member"]["fqdn"])?)
            && row["signing_required"] == true
            && row["encryption_required"] == true
            && row["ntlm_fallback"] == false
            && row["mutual_authentication_required"] == true,
    )?;
    digest(&row["hardened_unc_receipt_digest"])
}

fn network(scope: &Value) -> Result<()> {
    let row = &scope["network"];
    exact(
        row,
        &["flows", "policy_receipt_digest", "kernel_traffic_metered"],
    )?;
    digest(&row["policy_receipt_digest"])?;
    ensure(row["kernel_traffic_metered"] == false)?;
    let flows = row["flows"].as_array().ok_or(Code::RequestInvalid)?;
    ensure((3..=24).contains(&flows.len()))?;
    let mut entries = Vec::new();
    for flow in flows {
        exact(
            flow,
            &[
                "source",
                "destination",
                "transport",
                "port_from",
                "port_through",
            ],
        )?;
        let source = text(&flow["source"])?;
        let dest = text(&flow["destination"])?;
        let transport = text(&flow["transport"])?;
        let first = number(&flow["port_from"], 1, 65_535)?;
        let last = number(&flow["port_through"], first, 65_535)?;
        let business = source == "client"
            && dest == "member"
            && transport == "tcp"
            && first == 445
            && last == 445;
        let infra = ["client", "member"].contains(&source)
            && dest == "dc"
            && match transport {
                "tcp" => {
                    (first == last && [53, 88, 135, 389, 445, 636].contains(&first))
                        || (first >= 49_152 && last - first < 256)
                }
                "udp" => first == last && [53, 88, 123, 389].contains(&first),
                _ => false,
            };
        ensure(business || infra)?;
        let entry = (source, dest, transport, first, last);
        ensure(!entries.iter().any(|old: &(&str, &str, &str, u64, u64)| {
            old.0 == source
                && old.1 == dest
                && old.2 == transport
                && first <= old.4
                && last >= old.3
        }))?;
        ensure(entries.last().is_none_or(|old| old < &entry))?;
        entries.push(entry);
    }
    ensure(
        [
            ("client", "member", "tcp", 445, 445),
            ("client", "dc", "udp", 53, 53),
            ("client", "dc", "tcp", 88, 88),
        ]
        .iter()
        .all(|r| entries.contains(r)),
    )
}

pub(super) fn target(request: &Value) -> Result<()> {
    let scope = &request["scope"];
    let step = text(&request["step"])?;
    if !step.starts_with("read_") {
        return ensure(request["target"].is_null());
    }
    let (_, rest) = step.split_once('_').ok_or(Code::RequestInvalid)?;
    let (reader, purpose) = rest.split_once('_').ok_or(Code::RequestInvalid)?;
    let index = if purpose == "primary" { 0 } else { 1 };
    let expected = json!({"schema_version":"bluefire.ad-smb-read-target.v1", "scope_digest":request["scope_digest"], "scope_id":scope["scope_id"], "reader":reader, "expected_remote_sid":scope["principals"][reader]["sid"], "member_host_id":scope["hosts"]["member"]["host_id"], "client_host_id":scope["hosts"]["client"]["host_id"], "member_fqdn":scope["hosts"]["member"]["fqdn"], "share_unc":scope["share"]["unc"], "file":scope["files"][index], "hardened_unc_receipt_digest":scope["authentication"]["hardened_unc_receipt_digest"], "admission_verified":false,"authenticated_remote_reader":false,"effective_access_claim":false});
    ensure(request["target"] == expected)
}
