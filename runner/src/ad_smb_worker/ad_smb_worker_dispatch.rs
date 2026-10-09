use serde_json::{json, Value};
use std::sync::atomic::AtomicBool;

use super::framing::Begin;
use super::json::*;
use super::{acl, wire::Packet, Code, Result};
use crate::ad_smb_read::{
    FilePurpose, PreparedRead, ReadBindings, ReadTarget, Reader, SecretCredential,
};
use crate::ad_smb_share::{LocalShareTarget, ShareObservation};

pub(super) fn execute(packet: &Packet, begin: Begin) -> Result<Value> {
    if !cfg!(target_os = "windows") {
        return Err(Code::NativeUnavailable);
    }
    packet.current()?;
    let request = packet.request();
    if !request["change"].is_null() {
        acl::native_pair(request)?;
    }
    match (text(&request["step"])?, begin) {
        ("inspect_member", Begin::Member) => inspect(packet),
        ("harden_share", Begin::Member) => write(packet, false),
        ("rollback_share", Begin::Member) => write(packet, true),
        ("collect_audit", Begin::Member) => audit(packet),
        (
            "read_probe_primary" | "read_legitimate_primary" | "read_legitimate_health",
            Begin::Client { upn, password },
        ) => {
            let name = std::str::from_utf8(&upn.0).map_err(|_| Code::BeginInvalid)?;
            read(packet, name, &password.0)
        }
        _ => Err(Code::BeginInvalid),
    }
}

fn target(scope: &Value) -> Result<LocalShareTarget> {
    LocalShareTarget::new(
        text(&scope["scope_id"])?,
        text(&scope["share"]["local_root"])?
            .chars()
            .next()
            .ok_or(Code::RequestInvalid)?,
    )
    .map_err(|_| Code::RequestInvalid)
}

fn share(packet: &Packet) -> Result<ShareObservation> {
    packet.current()?;
    let scope = &packet.request()["scope"];
    let observed =
        crate::ad_smb_share::observe_local(target(scope)?).map_err(|_| Code::NativeFailed)?;
    packet.current()?;
    let projection = observed.projection();
    let metadata = serde_json::to_value(&projection.metadata).map_err(|_| Code::NativeFailed)?;
    if hash(&metadata)? != text(&scope["share"]["identity_digest"])?
        || !projection.metadata.encrypt_data_flag
    {
        return Err(Code::PreconditionFailed);
    }
    Ok(observed)
}

fn files(packet: &Packet) -> Result<crate::ad_smb_files::LocalFilesAttempt> {
    packet.current()?;
    let scope = &packet.request()["scope"];
    let attempt = crate::ad_smb_files::observe_generated(&target(scope)?);
    packet.current()?;
    if !attempt.owned_handles_closed || attempt.issue.is_some() {
        return Err(Code::NativeFailed);
    }
    let observed = attempt.observation.as_ref().ok_or(Code::NativeFailed)?;
    if observed.objects.len() != 6
        || observed.files.len() != 2
        || !observed.selected_facts_unchanged
    {
        return Err(Code::PreconditionFailed);
    }
    let root = &observed.objects[3];
    if root.file_id != text(&scope["share"]["root_file_id"])?
        || root.volume_serial != text(&scope["share"]["volume_serial"])?
        || root
            .selected_security
            .finite_descriptor
            .as_ref()
            .map(|d| d.sha256.as_str())
            != Some(text(&scope["share"]["root_ntfs_digest"])?)
    {
        return Err(Code::PreconditionFailed);
    }
    for (index, file) in observed.files.iter().enumerate() {
        let expected = &scope["files"][index];
        let object = &observed.objects[4 + index];
        if file.name != text(&expected["name"])?
            || file.bytes != number(&expected["size_bytes"], 1, 65_536)?
            || file.sha256 != text(&expected["sha256"])?
            || object.file_id != text(&expected["file_id"])?
            || object.volume_serial != text(&expected["volume_serial"])?
            || object
                .selected_security
                .finite_descriptor
                .as_ref()
                .map(|d| d.sha256.as_str())
                != Some(text(&expected["ntfs_digest"])?)
        {
            return Err(Code::PreconditionFailed);
        }
    }
    Ok(attempt)
}

fn principals(scope: &Value) -> Result<[&str; 3]> {
    Ok([
        text(&scope["principals"]["probe"]["sid"])?,
        text(&scope["principals"]["legitimate"]["sid"])?,
        text(&scope["principals"]["controller"]["sid"])?,
    ])
}

fn inspect(packet: &Packet) -> Result<Value> {
    let observed = share(packet)?;
    let projection = observed.projection();
    let scope = &packet.request()["scope"];
    if projection.descriptor.sha256 != text(&scope["share"]["baseline_descriptor_digest"])? {
        return Err(Code::PreconditionFailed);
    }
    let [probe, legitimate, controller] = principals(scope)?;
    let prepared = observed
        .propose_probe_removal(probe, legitimate, controller)
        .map_err(|_| Code::PreconditionFailed)?;
    let after = crate::ad_smb_descriptor::Descriptor::from_bytes(prepared.after_descriptor())
        .map_err(|_| Code::NativeFailed)?;
    let files = files(packet)?;
    let reread = share(packet)?;
    if reread.projection().metadata != projection.metadata
        || reread.projection().descriptor != projection.descriptor
    {
        return Err(Code::PreconditionFailed);
    }
    packet.current()?;
    Ok(json!({"share":projection,"files":files,"after_descriptor":after.projection()}))
}

fn write(packet: &Packet, restore: bool) -> Result<Value> {
    let request = packet.request();
    let (before, after) = acl::native_pair(request)?;
    let observed = share(packet)?;
    // Native file identities and selected NTFS bytes must still match before a write.
    // These observations are not an exclusive-writer guarantee or atomic CAS.
    files(packet)?;
    packet.current()?;
    let roles = principals(&request["scope"])?;
    let proof = if restore {
        observed
            .reviewed_rollback(&before, &after, roles)
            .map_err(|_| Code::PreconditionFailed)?
            .rollback_before(packet.monotonic_deadline)
    } else {
        observed
            .reviewed_change(&before, &after, roles)
            .map_err(|_| Code::PreconditionFailed)?
            .apply_before(packet.monotonic_deadline)
            .proof
    };
    // A late native response cannot become a settled success after the original bound.
    packet.current()?;
    serde_json::to_value(proof).map_err(|_| Code::NativeFailed)
}

fn read(packet: &Packet, upn: &str, password: &[u16]) -> Result<Value> {
    let request = packet.request();
    let scope = &request["scope"];
    let target_row = &request["target"];
    let file = &target_row["file"];
    let purpose = if file["purpose"] == "primary" {
        FilePurpose::Primary
    } else {
        FilePurpose::Health
    };
    let reader = if target_row["reader"] == "probe" {
        Reader::Probe
    } else {
        Reader::Legitimate
    };
    let target = ReadTarget::new(
        text(&scope["hosts"]["member"]["fqdn"])?,
        text(&scope["scope_id"])?,
        purpose,
        text(&file["file_id"])?,
        u64::from_str_radix(text(&file["volume_serial"])?, 16).map_err(|_| Code::RequestInvalid)?,
        text(&file["sha256"])?,
        number(&file["size_bytes"], 1, 65_536)? as usize,
    )
    .map_err(|_| Code::PreconditionFailed)?;
    let bindings = ReadBindings::new(
        text(&request["scope_digest"])?,
        text(&packet.value["client_identity_digest"])?,
        text(&scope["authentication"]["hardened_unc_receipt_digest"])?,
        text(&packet.value["credential_binding_digest"])?,
    )
    .map_err(|_| Code::PreconditionFailed)?;
    let prior = packet.value["prior_local_authentication_ids"]
        .as_array()
        .ok_or(Code::RequestInvalid)?
        .iter()
        .map(|value| u64::from_str_radix(text(value)?, 16).map_err(|_| Code::RequestInvalid))
        .collect::<Result<Vec<_>>>()?;
    let prepared = PreparedRead::new(
        text(&request["request_id"])?,
        target,
        reader,
        text(&target_row["expected_remote_sid"])?,
        upn,
        bindings,
        &prior,
        60,
    )
    .map_err(|_| Code::PreconditionFailed)?
    .with_original_deadline(packet.monotonic_deadline)
    .map_err(|_| Code::Deadline)?;
    let secret = SecretCredential::new(upn, password).map_err(|_| Code::BeginInvalid)?;
    packet.current()?;
    let proof = prepared.read(secret, &|| packet.current().is_err());
    packet.current()?;
    serde_json::to_value(proof).map_err(|_| Code::NativeFailed)
}

fn audit(packet: &Packet) -> Result<Value> {
    let request = packet.request();
    let scope = &request["scope"];
    let window = crate::ad_smb_events::AuditWindow::new(
        text(&scope["created_at"])?,
        text(&request["requested_at"])?,
        text(&scope["principals"]["probe"]["sid"])?,
        text(&scope["principals"]["legitimate"]["sid"])?,
    )
    .map_err(|_| Code::PreconditionFailed)?;
    packet.current()?;
    let events = number(&scope["limits"]["audit_events"], 1, 1000)? as usize;
    let bytes = super::wire::audit_limit(
        packet.output_limit,
        events,
        number(&scope["limits"]["audit_bytes"], 1, 4_194_304)? as usize,
    )?;
    let capture = crate::ad_smb_events::collect_local_bounded(
        &window,
        &AtomicBool::new(false),
        packet.monotonic_deadline,
        events,
        bytes,
    )
    .map_err(|_| Code::NativeFailed)?;
    packet.current()?;
    serde_json::to_value(capture).map_err(|_| Code::NativeFailed)
}
