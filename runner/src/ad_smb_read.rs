//! Finite fresh-context SMB read primitive; not admission or remote-authentication proof.
//!
//! Callers must bind the exact enrolled client, protected credential, effective
//! Hardened UNC policy, original scope/deadline and durable one-use reservation
//! before entering a disposable, externally supervised process. Receipt digests
//! below bind those external premises; they do not establish their truth. No
//! action or credential delivery mechanism registers this component.
//!
//! NEW_CREDENTIALS clones the local token. Its TokenUser is deliberately reported
//! separately from the expected outbound SID. A successful logon or file open
//! does not prove a fresh Kerberos server logon or independent audit observation.

use serde::Serialize;
use sha2::{Digest, Sha256};
use std::sync::atomic::{compiler_fence, Ordering};
use std::time::{Duration, Instant};

#[cfg(target_os = "windows")]
mod ffi;
#[cfg(test)]
#[path = "ad_smb_read/ad_smb_read_tests.rs"]
mod tests;
#[cfg(target_os = "windows")]
mod windows;

const MAX_FILE_BYTES: usize = 65_536;
const MAX_PRIOR_LUIDS: usize = 5;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Reader {
    Probe,
    Legitimate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FilePurpose {
    Primary,
    Health,
}

pub struct ReadTarget {
    share: String,
    file: String,
    file_id: [u8; 16],
    volume_serial: u64,
    digest: [u8; 32],
    size: usize,
    purpose: FilePurpose,
}

impl ReadTarget {
    pub fn new(
        member_fqdn: &str,
        scope_id: &str,
        purpose: FilePurpose,
        file_id: &str,
        volume_serial: u64,
        sha256: &str,
        size_bytes: usize,
    ) -> Result<Self, &'static str> {
        if !dns(member_fqdn)
            || !lower_hex(scope_id, 32)
            || !(1..=MAX_FILE_BYTES).contains(&size_bytes)
        {
            return Err("target_outside_generated_recipe");
        }
        let file_id = hex_array(file_id).ok_or("file_identity_invalid")?;
        let digest = digest_bytes(sha256).ok_or("file_digest_invalid")?;
        let share = format!("\\\\{member_fqdn}\\bf_{scope_id}");
        let name = match purpose {
            FilePurpose::Primary => "records.jsonl",
            FilePurpose::Health => "health.jsonl",
        };
        Ok(Self {
            file: format!("{share}\\{name}"),
            share,
            file_id,
            volume_serial,
            digest,
            size: size_bytes,
            purpose,
        })
    }
}

/// Opaque external admission bindings, not a policy checker or enrollment API.
pub struct ReadBindings {
    scope_digest: String,
    client_identity_digest: String,
    hardened_unc_receipt_digest: String,
    credential_binding_digest: String,
}

impl ReadBindings {
    pub fn new(
        scope: &str,
        client: &str,
        hardened_unc: &str,
        credential: &str,
    ) -> Result<Self, &'static str> {
        if [scope, client, hardened_unc, credential]
            .iter()
            .any(|value| digest_bytes(value).is_none())
        {
            return Err("read_bindings_invalid");
        }
        Ok(Self {
            scope_digest: scope.into(),
            client_identity_digest: client.into(),
            hardened_unc_receipt_digest: hardened_unc.into(),
            credential_binding_digest: credential.into(),
        })
    }
}

/// Consumed in memory once; durable reuse prevention belongs to dispatch admission.
pub struct PreparedRead {
    request_id: String,
    target: ReadTarget,
    reader: Reader,
    expected_remote_sid: String,
    expected_upn: String,
    bindings: ReadBindings,
    prior_luids: Vec<u64>,
    budget: Duration,
    admitted_at: Instant,
}

impl PreparedRead {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        request_id: &str,
        target: ReadTarget,
        reader: Reader,
        expected_remote_sid: &str,
        expected_upn: &str,
        bindings: ReadBindings,
        prior_luids: &[u64],
        remaining_seconds: u64,
    ) -> Result<Self, &'static str> {
        if !lower_hex(request_id, 32)
            || !domain_user_sid(expected_remote_sid)
            || !upn(expected_upn)
            || !(1..=60).contains(&remaining_seconds)
            || prior_luids.len() > MAX_PRIOR_LUIDS
            || prior_luids.contains(&0)
            || prior_luids
                .iter()
                .enumerate()
                .any(|(i, id)| prior_luids[..i].contains(id))
            || (reader == Reader::Probe && target.purpose == FilePurpose::Health)
        {
            return Err("read_request_invalid");
        }
        Ok(Self {
            request_id: request_id.into(),
            target,
            reader,
            expected_remote_sid: expected_remote_sid.into(),
            expected_upn: expected_upn.into(),
            bindings,
            prior_luids: prior_luids.to_vec(),
            budget: Duration::from_secs(remaining_seconds),
            admitted_at: Instant::now(),
        })
    }

    /// Must run only in an admitted, disposable externally supervised process.
    /// The supervisor, not synchronous Win32 calls, enforces a blocked-call bound.
    pub fn read(self, secret: SecretCredential, cancelled: &dyn Fn() -> bool) -> ReadProof {
        let clock = SystemClock {
            started: self.admitted_at,
            cancelled,
        };
        #[cfg(target_os = "windows")]
        return self.read_with(secret, &mut windows::WindowsBackend::default(), &clock);
        #[cfg(not(target_os = "windows"))]
        {
            self.read_with(secret, &mut Unsupported, &clock)
        }
    }

    fn read_with(
        self,
        secret: SecretCredential,
        backend: &mut impl Backend,
        clock: &impl Clock,
    ) -> ReadProof {
        let mut proof = ReadProof::new(&self);
        if secret.upn_string != self.expected_upn {
            proof.issue = Some("credential_upn_binding_mismatch");
            return proof;
        }
        let result = read_once(&self, &secret, backend, clock, &mut proof);
        drop(secret);
        if let Err(error) = result {
            proof.state = match error.issue {
                "cancelled" => ReadState::Cancelled,
                "deadline" => ReadState::Deadline,
                _ if error.stage == "open" && error.win32 == Some(5) => ReadState::OpenAccessDenied,
                _ => ReadState::Unknown,
            };
            proof.issue = Some(error.issue);
            proof.failed_stage = Some(error.stage);
            proof.win32_error = error.win32;
        }
        proof.cleanup = backend.cleanup(&self.target.share);
        // Even a matched payload cannot be returned as clean when local ownership is unknown.
        if !proof.cleanup.local_resources_released() {
            proof.state = ReadState::Unknown;
            proof.issue = Some("local_cleanup_unknown");
        }
        proof
    }
}

/// Never Debug/Clone/Serialize. The private delivery layer must also erase its input.
pub struct SecretCredential {
    upn_string: String,
    upn: Vec<u16>,
    password: Vec<u16>,
}

impl SecretCredential {
    pub fn new(upn_value: &str, password: &[u16]) -> Result<Self, &'static str> {
        if !upn(upn_value)
            || password.is_empty()
            || password.len() > 256
            || password.contains(&0)
            || std::char::decode_utf16(password.iter().copied()).any(|unit| unit.is_err())
        {
            return Err("private_credential_invalid");
        }
        let mut upn = upn_value.encode_utf16().collect::<Vec<_>>();
        upn.push(0);
        let mut owned_password = Vec::with_capacity(password.len() + 1);
        owned_password.extend_from_slice(password);
        owned_password.push(0);
        Ok(Self {
            upn_string: upn_value.into(),
            upn,
            password: owned_password,
        })
    }
}

impl Drop for SecretCredential {
    fn drop(&mut self) {
        for value in self.upn.iter_mut().chain(self.password.iter_mut()) {
            // Volatile stores prevent removal of the owned secret-buffer erasure.
            unsafe { std::ptr::write_volatile(value, 0) };
        }
        compiler_fence(Ordering::SeqCst);
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct LocalLogon {
    pub authentication_id: u64,
    pub local_token_user_sid: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProtocolFacts {
    pub version: u16,
    pub size: u16,
    pub protocol: u32,
    pub major: u16,
    pub flags: u32,
}

impl ProtocolFacts {
    fn permitted(&self) -> bool {
        // Documented FILE_REMOTE_PROTOCOL_INFO flags: privacy and mutual auth.
        (2..=3).contains(&self.version)
            && self.size == 116
            && self.protocol == 0x0002_0000
            && self.major == 3
            && self.flags & 0x03 == 0
            && self.flags & 0x28 == 0x28
            && self.flags & !0x3f == 0
    }
}

struct FileFacts {
    protocol: ProtocolFacts,
    file_id: [u8; 16],
    volume_serial: u64,
    size: u64,
    is_regular: bool,
    final_path: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadState {
    NotStarted,
    BytesMatched,
    OpenAccessDenied,
    Cancelled,
    Deadline,
    Unknown,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct CleanupFacts {
    pub file_closed: Option<bool>,
    pub exact_unc_cancel_status: Option<u32>,
    pub impersonation_reverted: Option<bool>,
    pub token_closed: Option<bool>,
    pub observation_tokens_closed: Option<bool>,
    pub owned_process_exit_required: bool,
    /// Always unknown here, including WNet success or ERROR_NOT_CONNECTED.
    pub server_session_closed: Option<bool>,
}

impl CleanupFacts {
    fn local_resources_released(&self) -> bool {
        !self.owned_process_exit_required
            && ![
                self.file_closed,
                self.impersonation_reverted,
                self.token_closed,
                self.observation_tokens_closed,
            ]
            .contains(&Some(false))
    }
}

#[derive(Debug, Serialize)]
pub struct ReadProof {
    pub schema_version: &'static str,
    pub request_id: String,
    pub reader: Reader,
    pub purpose: FilePurpose,
    pub scope_digest: String,
    pub client_identity_digest: String,
    pub hardened_unc_receipt_digest: String,
    pub credential_binding_digest: String,
    pub expected_remote_sid: String,
    pub state: ReadState,
    pub local_logon: Option<LocalLogon>,
    pub file_open_attempted: bool,
    pub protocol: Option<ProtocolFacts>,
    pub bytes_read: usize,
    pub expected_volume_serial: u64,
    pub observed_volume_serial: Option<u64>,
    pub observed_sha256: Option<String>,
    pub failed_stage: Option<&'static str>,
    pub win32_error: Option<u32>,
    pub issue: Option<&'static str>,
    pub cleanup: CleanupFacts,
    pub authenticated_remote_reader: bool,
    pub fresh_server_logon: bool,
    pub independent_observation: bool,
    pub effective_access_claim: bool,
}

impl ReadProof {
    fn new(read: &PreparedRead) -> Self {
        Self {
            schema_version: "bluefire.ad-smb-fresh-read.v1",
            request_id: read.request_id.clone(),
            reader: read.reader,
            purpose: read.target.purpose,
            scope_digest: read.bindings.scope_digest.clone(),
            client_identity_digest: read.bindings.client_identity_digest.clone(),
            hardened_unc_receipt_digest: read.bindings.hardened_unc_receipt_digest.clone(),
            credential_binding_digest: read.bindings.credential_binding_digest.clone(),
            expected_remote_sid: read.expected_remote_sid.clone(),
            state: ReadState::NotStarted,
            local_logon: None,
            file_open_attempted: false,
            protocol: None,
            bytes_read: 0,
            expected_volume_serial: read.target.volume_serial,
            observed_volume_serial: None,
            observed_sha256: None,
            failed_stage: None,
            win32_error: None,
            issue: None,
            cleanup: CleanupFacts::default(),
            authenticated_remote_reader: false,
            fresh_server_logon: false,
            independent_observation: false,
            effective_access_claim: false,
        }
    }
}

struct Failure {
    stage: &'static str,
    issue: &'static str,
    win32: Option<u32>,
}
impl Failure {
    fn new(stage: &'static str, issue: &'static str) -> Self {
        Self {
            stage,
            issue,
            win32: None,
        }
    }
    #[cfg(target_os = "windows")]
    fn native(stage: &'static str, code: u32) -> Self {
        Self {
            stage,
            issue: "win32_failure",
            win32: Some(code),
        }
    }
}
trait Clock {
    fn elapsed(&self) -> Duration;
    fn cancelled(&self) -> bool;
}
struct SystemClock<'a> {
    started: Instant,
    cancelled: &'a dyn Fn() -> bool,
}
impl Clock for SystemClock<'_> {
    fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }
    fn cancelled(&self) -> bool {
        (self.cancelled)()
    }
}

trait Backend {
    fn caller(&mut self) -> Result<LocalLogon, Failure>;
    fn logon(&mut self, secret: &SecretCredential) -> Result<LocalLogon, Failure>;
    fn impersonate(&mut self) -> Result<(), Failure>;
    fn open(&mut self, exact_path: &str) -> Result<(), Failure>;
    fn facts(&mut self) -> Result<FileFacts, Failure>;
    fn read(&mut self, output: &mut [u8]) -> Result<usize, Failure>;
    fn cleanup(&mut self, exact_share: &str) -> CleanupFacts;
}

fn check(read: &PreparedRead, clock: &impl Clock, stage: &'static str) -> Result<(), Failure> {
    if clock.cancelled() {
        return Err(Failure::new(stage, "cancelled"));
    }
    if clock.elapsed() >= read.budget {
        return Err(Failure::new(stage, "deadline"));
    }
    Ok(())
}

fn read_once(
    read: &PreparedRead,
    secret: &SecretCredential,
    backend: &mut impl Backend,
    clock: &impl Clock,
    proof: &mut ReadProof,
) -> Result<(), Failure> {
    check(read, clock, "caller")?;
    let caller = backend.caller()?;
    check(read, clock, "logon")?;
    let logon = backend.logon(secret)?;
    proof.local_logon = Some(logon.clone());
    if logon.authentication_id == 0
        || logon.authentication_id == caller.authentication_id
        || read.prior_luids.contains(&logon.authentication_id)
        || logon.local_token_user_sid != caller.local_token_user_sid
    {
        return Err(Failure::new("logon", "fresh_local_context_mismatch"));
    }
    check(read, clock, "impersonate")?;
    backend.impersonate()?;
    check(read, clock, "open")?;
    proof.file_open_attempted = true;
    backend.open(&read.target.file)?;
    check(read, clock, "metadata")?;
    let facts = backend.facts()?;
    proof.protocol = Some(facts.protocol.clone());
    proof.observed_volume_serial = Some(facts.volume_serial);
    if !facts.protocol.permitted() {
        return Err(Failure::new("metadata", "smb_protection_unverified"));
    }
    if !facts.is_regular
        || facts.file_id != read.target.file_id
        || facts.volume_serial != read.target.volume_serial
        || facts.size != read.target.size as u64
        || !facts
            .final_path
            .eq_ignore_ascii_case(&format!("\\\\?\\UNC\\{}", &read.target.file[2..]))
    {
        return Err(Failure::new("metadata", "file_identity_mismatch"));
    }
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 8192];
    while proof.bytes_read < read.target.size {
        check(read, clock, "read")?;
        let limit = buffer.len().min(read.target.size - proof.bytes_read);
        let count = backend.read(&mut buffer[..limit])?;
        if count == 0 || count > limit {
            return Err(Failure::new("read", "incomplete_or_invalid_read"));
        }
        hash.update(&buffer[..count]);
        buffer[..count].fill(0);
        proof.bytes_read += count;
    }
    check(read, clock, "eof")?;
    if backend.read(&mut buffer[..1])? != 0 {
        return Err(Failure::new("eof", "file_exceeds_expected_length"));
    }
    check(read, clock, "complete")?;
    let digest: [u8; 32] = hash.finalize().into();
    proof.observed_sha256 = Some(format!("sha256:{}", hex::encode(digest)));
    if digest != read.target.digest {
        return Err(Failure::new("complete", "file_content_mismatch"));
    }
    proof.state = ReadState::BytesMatched;
    Ok(())
}

fn lower_hex(value: &str, size: usize) -> bool {
    value.len() == size
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn hex_array<const N: usize>(value: &str) -> Option<[u8; N]> {
    if !lower_hex(value, N * 2) {
        return None;
    }
    hex::decode(value).ok()?.try_into().ok()
}
fn digest_bytes(value: &str) -> Option<[u8; 32]> {
    hex_array(value.strip_prefix("sha256:")?)
}
fn dns(value: &str) -> bool {
    (3..=253).contains(&value.len())
        && value.contains('.')
        && value.parse::<std::net::IpAddr>().is_err()
        && value.split('.').all(|p| {
            !p.is_empty()
                && p.len() <= 63
                && p.as_bytes()[0].is_ascii_alphanumeric()
                && p.as_bytes().last().is_some_and(u8::is_ascii_alphanumeric)
                && p.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}
fn upn(value: &str) -> bool {
    if value.len() > 318 {
        return false;
    }
    let Some((name, domain)) = value.split_once('@') else {
        return false;
    };
    !name.is_empty()
        && name.len() <= 64
        && name.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
        })
        && dns(domain)
}
fn domain_user_sid(value: &str) -> bool {
    if value.len() > 184 {
        return false;
    }
    let Some(tail) = value.strip_prefix("S-1-5-21-") else {
        return false;
    };
    let fields = tail.split('-').collect::<Vec<_>>();
    fields.len() == 4
        && fields
            .iter()
            .all(|part| part.parse::<u32>().is_ok_and(|n| n.to_string() == *part))
        && fields[3].parse::<u32>().is_ok_and(|rid| rid >= 1000)
}

#[cfg(not(target_os = "windows"))]
struct Unsupported;
#[cfg(not(target_os = "windows"))]
impl Backend for Unsupported {
    fn caller(&mut self) -> Result<LocalLogon, Failure> {
        Err(Failure::new("caller", "windows_unavailable"))
    }
    fn logon(&mut self, _: &SecretCredential) -> Result<LocalLogon, Failure> {
        Err(Failure::new("logon", "windows_unavailable"))
    }
    fn impersonate(&mut self) -> Result<(), Failure> {
        Err(Failure::new("impersonate", "windows_unavailable"))
    }
    fn open(&mut self, _: &str) -> Result<(), Failure> {
        Err(Failure::new("open", "windows_unavailable"))
    }
    fn facts(&mut self) -> Result<FileFacts, Failure> {
        Err(Failure::new("metadata", "windows_unavailable"))
    }
    fn read(&mut self, _: &mut [u8]) -> Result<usize, Failure> {
        Err(Failure::new("read", "windows_unavailable"))
    }
    fn cleanup(&mut self, _: &str) -> CleanupFacts {
        CleanupFacts::default()
    }
}
