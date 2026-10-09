use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::json::*;
use super::{Code, Result};

pub(super) fn bytes(projection: &Value) -> Result<Vec<u8>> {
    let value = text(&projection["binary_b64"])?;
    ensure(!value.is_empty() && value.len() <= 87_384 && value.len() % 4 == 0)?;
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = Vec::with_capacity(value.len() / 4 * 3);
    for (index, chunk) in value.as_bytes().as_chunks::<4>().0.iter().enumerate() {
        let last = (index + 1) * 4 == value.len();
        let mut bits = [0u8; 4];
        let padding = if chunk[2..] == *b"==" {
            2
        } else if chunk[3] == b'=' {
            1
        } else {
            0
        };
        ensure(last || padding == 0)?;
        for i in 0..4 - padding {
            bits[i] = alphabet
                .iter()
                .position(|c| *c == chunk[i])
                .ok_or(Code::RequestInvalid)? as u8;
        }
        ensure((padding != 2 || bits[1] & 15 == 0) && (padding != 1 || bits[2] & 3 == 0))?;
        output.push((bits[0] << 2) | (bits[1] >> 4));
        if padding < 2 {
            output.push((bits[1] << 4) | (bits[2] >> 2));
        }
        if padding == 0 {
            output.push((bits[2] << 6) | bits[3]);
        }
    }
    ensure(
        (20..=65_536).contains(&output.len())
            && projection["sha256"] == format!("sha256:{:x}", Sha256::digest(&output)),
    )?;
    Ok(output)
}

fn projection(value: &Value, scope: &Value, hardened: bool) -> Result<()> {
    exact(
        value,
        &[
            "binary_b64",
            "sha256",
            "revision",
            "control",
            "owner_sid",
            "group_sid",
            "dacl",
            "sacl",
        ],
    )?;
    bytes(value)?;
    ensure(
        value["revision"] == 1
            && [json!(0x8004), json!(0x9004)].contains(&value["control"])
            && value["sacl"].is_null(),
    )?;
    ensure(
        super::scope::sid(text(&value["owner_sid"])?)
            && super::scope::sid(text(&value["group_sid"])?),
    )?;
    ensure(
        !["probe", "legitimate"]
            .iter()
            .any(|role| value["owner_sid"] == scope["principals"][role]["sid"]),
    )?;
    exact(&value["dacl"], &["revision", "aces"])?;
    ensure(value["dacl"]["revision"] == 2)?;
    let aces = value["dacl"]["aces"]
        .as_array()
        .ok_or(Code::RequestInvalid)?;
    ensure(aces.len() == if hardened { 2 } else { 3 })?;
    let mut seen = Vec::new();
    for ace in aces {
        exact(
            ace,
            &[
                "ace_type",
                "flags",
                "trustee_sid",
                "smb_right",
                "raw_ace_digest",
            ],
        )?;
        ensure(
            ace["ace_type"] == "access_allowed"
                && ace["flags"] == 0
                && !seen.contains(&ace["trustee_sid"]),
        )?;
        digest(&ace["raw_ace_digest"])?;
        let role = ["probe", "legitimate", "controller"]
            .into_iter()
            .find(|role| ace["trustee_sid"] == scope["principals"][role]["sid"])
            .ok_or(Code::RequestInvalid)?;
        ensure(
            !(hardened && role == "probe")
                && ace["smb_right"] == if role == "controller" { "Full" } else { "Read" },
        )?;
        seen.push(ace["trustee_sid"].clone());
    }
    Ok(())
}

pub(super) fn validate_change(request: &Value) -> Result<()> {
    let change = &request["change"];
    let scope = &request["scope"];
    exact(
        change,
        &[
            "schema_version",
            "scope_digest",
            "before",
            "after_descriptor",
            "removed_ace",
            "before_digest",
            "after_digest",
            "native_projection_verified",
            "effective_access_claim",
        ],
    )?;
    ensure(
        change["schema_version"] == "bluefire.ad-smb-acl-change.v1"
            && change["scope_digest"] == request["scope_digest"]
            && change["native_projection_verified"] == false
            && change["effective_access_claim"] == false,
    )?;
    let snapshot = &change["before"];
    exact(
        snapshot,
        &[
            "schema_version",
            "scope_digest",
            "native_parser_digest",
            "source_receipt_digest",
            "observed_at",
            "resource",
            "descriptor",
        ],
    )?;
    ensure(
        snapshot["schema_version"] == "bluefire.ad-smb-snapshot.v1"
            && snapshot["scope_digest"] == request["scope_digest"]
            && snapshot["native_parser_digest"] == scope["native_parser_digest"]
            && snapshot["resource"]
                == json!({"member_host_id":scope["hosts"]["member"]["host_id"],"share":scope["share"],"files":scope["files"]}),
    )?;
    digest(&snapshot["source_receipt_digest"])?;
    let observed = time(&snapshot["observed_at"])?;
    ensure(time(&scope["created_at"])? <= observed && observed <= time(&request["requested_at"])?)?;
    let before = &snapshot["descriptor"];
    let after = &change["after_descriptor"];
    projection(before, scope, false)?;
    projection(after, scope, true)?;
    ensure(
        before["sha256"] == scope["share"]["baseline_descriptor_digest"]
            && change["before_digest"] == hash(before)?
            && change["after_digest"] == hash(after)?
            && before["sha256"] != after["sha256"],
    )?;
    let probe = &scope["principals"]["probe"]["sid"];
    let aces = before["dacl"]["aces"]
        .as_array()
        .ok_or(Code::RequestInvalid)?;
    ensure(aces.iter().find(|ace| ace["trustee_sid"] == *probe) == Some(&change["removed_ace"]))?;
    let mut expected = before.clone();
    expected["dacl"]["aces"] = Value::Array(
        aces.iter()
            .filter(|ace| ace["trustee_sid"] != *probe)
            .cloned()
            .collect(),
    );
    expected["binary_b64"] = after["binary_b64"].clone();
    expected["sha256"] = after["sha256"].clone();
    ensure(*after == expected)
}

pub(super) fn native_pair(request: &Value) -> Result<(Vec<u8>, Vec<u8>)> {
    let before = &request["change"]["before"]["descriptor"];
    let after = &request["change"]["after_descriptor"];
    let raw = bytes(before)?;
    let parsed = crate::ad_smb_descriptor::Descriptor::from_bytes(&raw)
        .map_err(|_| Code::PreconditionFailed)?;
    ensure(serde_json::to_value(parsed.projection()).map_err(|_| Code::NativeFailed)? == *before)?;
    let principals = &request["scope"]["principals"];
    let derived = parsed
        .propose_probe_removal(
            text(&principals["probe"]["sid"])?,
            text(&principals["legitimate"]["sid"])?,
            text(&principals["controller"]["sid"])?,
        )
        .map_err(|_| Code::PreconditionFailed)?;
    ensure(
        serde_json::to_value(derived.projection()).map_err(|_| Code::NativeFailed)? == *after
            && derived.bytes() == bytes(after)?,
    )?;
    Ok((raw, derived.bytes().to_vec()))
}
