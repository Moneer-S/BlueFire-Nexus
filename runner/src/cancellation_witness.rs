#[cfg(windows)]
use std::fs::{self, File, OpenOptions};
#[cfg(windows)]
use std::io::{self, Read, Write};
#[cfg(windows)]
use std::path::{Path, PathBuf};
#[cfg(windows)]
use std::process::{Child, Command, Stdio};
#[cfg(windows)]
use std::thread;
use std::time::Duration;
#[cfg(windows)]
use std::time::Instant;

#[cfg(any(windows, test))]
use serde_json::json;

#[cfg(any(windows, test))]
use crate::contract::canonical_json;
use crate::safety::SafeRoot;

pub const INTERNAL_DESCENDANT_VERB: &str = "internal-cancellation-descendant-v1";
pub const CONTROL_PARENT_DIRECTORY: &str = ".bluefire-cancellation-witness-v1";

const READY_NAME: &str = "ready.json";
const REQUEST_NAME: &str = "cancel.request";
const ACK_NAME: &str = "cancel.ack";
const LEASE_NAME: &str = ".lease";
#[cfg(windows)]
const LEASE_ENV_NAME: &str = "BLUEFIRE_CANCELLATION_LEASE_TOKEN";
#[cfg(windows)]
const LEASE_PREFIX: &[u8] = b"lease:";
#[cfg(windows)]
const READY_STAGING_NAME: &str = ".ready.json.bluefire-staging";
#[cfg(windows)]
const ACK_STAGING_NAME: &str = ".cancel.ack.bluefire-staging";
#[cfg(any(windows, test))]
const READY_SCHEMA_VERSION: &str = "bluefire.process-tree-cancellation-ready.v1";
#[cfg(any(windows, test))]
const REQUEST_PREFIX: &[u8] = b"cancel:";
#[cfg(any(windows, test))]
const ACK_PREFIX: &[u8] = b"ack:";
const NONCE_HEX_BYTES: usize = 64;
#[cfg(any(windows, test))]
const REQUEST_BYTES: usize = REQUEST_PREFIX.len() + NONCE_HEX_BYTES + 1;
#[cfg(windows)]
const DESCENDANT_SLEEP: Duration = Duration::from_secs(600);
#[cfg(windows)]
const DESCENDANT_REAP_TIMEOUT: Duration = Duration::from_secs(2);
#[cfg(windows)]
const REQUEST_POLL_INTERVAL: Duration = Duration::from_millis(10);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessLayout {
    pub request_hash: String,
    pub task_id: String,
    pub task_relative_path: String,
    pub lease_relative_path: String,
    pub ready_relative_path: String,
    pub request_relative_path: String,
    pub ack_relative_path: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(windows), allow(dead_code))]
pub enum WitnessFailureKind {
    Blocked,
    Failed,
    TimedOut,
}

#[derive(Debug)]
pub struct WitnessFailure {
    pub kind: WitnessFailureKind,
    pub message: String,
}

impl WitnessFailure {
    fn blocked(message: impl Into<String>) -> Self {
        Self {
            kind: WitnessFailureKind::Blocked,
            message: message.into(),
        }
    }

    #[cfg(windows)]
    fn failed(message: impl Into<String>) -> Self {
        Self {
            kind: WitnessFailureKind::Failed,
            message: message.into(),
        }
    }

    #[cfg(windows)]
    fn timed_out(message: impl Into<String>) -> Self {
        Self {
            kind: WitnessFailureKind::TimedOut,
            message: message.into(),
        }
    }
}

pub fn witness_layout(request_hash: &str) -> Result<WitnessLayout, WitnessFailure> {
    let Some(request_hash_hex) = request_hash.strip_prefix("sha256:") else {
        return Err(WitnessFailure::blocked(
            "the sealed request hash must use the sha256:<hex> encoding",
        ));
    };
    if request_hash_hex.len() != NONCE_HEX_BYTES
        || !request_hash_hex
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(WitnessFailure::blocked(
            "the sealed request hash suffix must be exactly 64 lowercase hexadecimal bytes",
        ));
    }
    let task_id = format!("execute-{request_hash_hex}");
    let task_relative_path = format!("{CONTROL_PARENT_DIRECTORY}/{request_hash_hex}");
    Ok(WitnessLayout {
        request_hash: request_hash.to_string(),
        task_id,
        lease_relative_path: format!("{task_relative_path}/{LEASE_NAME}"),
        ready_relative_path: format!("{task_relative_path}/{READY_NAME}"),
        request_relative_path: format!("{task_relative_path}/{REQUEST_NAME}"),
        ack_relative_path: format!("{task_relative_path}/{ACK_NAME}"),
        task_relative_path,
    })
}

#[cfg(windows)]
struct DescendantGuard {
    child: Child,
    stop_attempted: bool,
}

#[cfg(windows)]
impl DescendantGuard {
    fn spawn() -> Result<Self, WitnessFailure> {
        let executable = std::env::current_exe().map_err(|error| {
            WitnessFailure::failed(format!(
                "cannot resolve the current runner executable: {error}"
            ))
        })?;
        verify_runner_executable(&executable)?;

        let mut command = Command::new(&executable);
        command
            .arg(INTERNAL_DESCENDANT_VERB)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            command.creation_flags(CREATE_NO_WINDOW);
        }
        let child = command.spawn().map_err(|error| {
            WitnessFailure::failed(format!(
                "cannot start the fixed cancellation descendant: {error}"
            ))
        })?;
        let mut guard = Self {
            child,
            stop_attempted: false,
        };
        thread::sleep(REQUEST_POLL_INTERVAL);
        match guard.child.try_wait() {
            Ok(None) => Ok(guard),
            Ok(Some(status)) => Err(WitnessFailure::failed(format!(
                "the fixed cancellation descendant exited before readiness with {status}"
            ))),
            Err(error) => Err(WitnessFailure::failed(format!(
                "cannot inspect the fixed cancellation descendant: {error}"
            ))),
        }
    }

    fn id(&self) -> u32 {
        self.child.id()
    }

    fn stop_bounded(&mut self) -> bool {
        self.stop_attempted = true;
        if matches!(self.child.try_wait(), Ok(Some(_))) {
            return true;
        }
        let _ = self.child.kill();
        let deadline = Instant::now() + DESCENDANT_REAP_TIMEOUT;
        while Instant::now() < deadline {
            match self.child.try_wait() {
                Ok(Some(_)) => return true,
                Err(_) => return false,
                Ok(None) => thread::sleep(REQUEST_POLL_INTERVAL),
            }
        }
        false
    }
}

#[cfg(windows)]
impl Drop for DescendantGuard {
    fn drop(&mut self) {
        if !self.stop_attempted {
            let _ = self.stop_bounded();
        }
    }
}

#[cfg(windows)]
fn is_link_or_reparse(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
    metadata.file_type().is_symlink()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(windows)]
fn verify_runner_executable(executable: &Path) -> Result<(), WitnessFailure> {
    let metadata = fs::symlink_metadata(executable).map_err(|error| {
        WitnessFailure::failed(format!(
            "cannot inspect the current runner executable: {error}"
        ))
    })?;
    if is_link_or_reparse(&metadata) || !metadata.is_file() {
        return Err(WitnessFailure::blocked(
            "the current runner executable is not a regular non-link file",
        ));
    }
    Ok(())
}

#[cfg(windows)]
mod cancellation_witness_files;
#[cfg(windows)]
use self::cancellation_witness_files as secure_files;

#[cfg(windows)]
fn take_outer_lease_token() -> Result<Option<String>, WitnessFailure> {
    let Some(raw) = std::env::var_os(LEASE_ENV_NAME) else {
        return Ok(None);
    };
    std::env::remove_var(LEASE_ENV_NAME);
    let token = raw.into_string().map_err(|_| {
        WitnessFailure::blocked("the trusted outer cancellation lease token is not UTF-8")
    })?;
    if token.len() != NONCE_HEX_BYTES
        || !token
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(WitnessFailure::blocked(
            "the trusted outer cancellation lease token is invalid",
        ));
    }
    Ok(Some(token))
}

#[cfg(windows)]
struct ControlDirectory {
    task_path: PathBuf,
    root_handle: File,
    parent_handle: File,
    task_handle: File,
    task_owned: bool,
    lease_file: Option<File>,
}

#[cfg(windows)]
fn create_control_directory(
    root: &SafeRoot,
    layout: &WitnessLayout,
    lease_token: Option<&str>,
) -> Result<ControlDirectory, WitnessFailure> {
    let root_path = root.path();
    let root_handle =
        secure_files::open_directory_pinned(root_path, "the sandbox root", false, false)?;
    let parent_path = root_path.join(CONTROL_PARENT_DIRECTORY);
    let create_parent = match fs::symlink_metadata(&parent_path) {
        Ok(metadata) if !is_link_or_reparse(&metadata) && metadata.is_dir() => false,
        Ok(_) => {
            return Err(WitnessFailure::blocked(
                "the cancellation infrastructure parent is not a regular non-reparse directory",
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => true,
        Err(error) => {
            return Err(WitnessFailure::failed(format!(
                "cannot inspect the cancellation infrastructure parent: {error}"
            )))
        }
    };
    if create_parent {
        match fs::create_dir(&parent_path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(WitnessFailure::failed(format!(
                    "cannot create the cancellation infrastructure parent: {error}"
                )))
            }
        }
    }
    let parent_handle = secure_files::open_directory_pinned(
        &parent_path,
        "the cancellation infrastructure parent",
        false,
        false,
    )?;
    let canonical_parent = fs::canonicalize(&parent_path).map_err(|error| {
        WitnessFailure::failed(format!(
            "cannot canonicalize the cancellation infrastructure parent: {error}"
        ))
    })?;
    if canonical_parent.parent() != Some(root_path) || canonical_parent != parent_path {
        return Err(WitnessFailure::blocked(
            "the cancellation infrastructure parent escaped its fixed sandbox location",
        ));
    }

    let task_path = root_path.join(&layout.task_relative_path);
    let task_owned = match fs::symlink_metadata(&task_path) {
        Ok(metadata) if !is_link_or_reparse(&metadata) && metadata.is_dir() => {
            if lease_token.is_none() {
                return Err(WitnessFailure::blocked(
                    "the request-bound cancellation task directory already exists without a trusted outer lease",
                ));
            }
            false
        }
        Ok(_) => {
            return Err(WitnessFailure::blocked(
                "the request-bound cancellation task object is not a regular non-reparse directory",
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            if lease_token.is_some() {
                return Err(WitnessFailure::blocked(
                    "the trusted outer cancellation lease directory is absent",
                ));
            }
            fs::create_dir(&task_path).map_err(|error| {
                if error.kind() == io::ErrorKind::AlreadyExists {
                    WitnessFailure::blocked(
                        "the request-bound cancellation task directory appeared concurrently",
                    )
                } else {
                    WitnessFailure::failed(format!(
                        "cannot create the request-bound cancellation task directory: {error}"
                    ))
                }
            })?;
            true
        }
        Err(error) => {
            return Err(WitnessFailure::failed(format!(
                "cannot inspect the request-bound cancellation task directory: {error}"
            )))
        }
    };
    let task_handle = match secure_files::open_directory_pinned(
        &task_path,
        "the request-bound cancellation task directory",
        task_owned,
        !task_owned,
    ) {
        Ok(handle) => handle,
        Err(error) => {
            if task_owned {
                let _ = fs::remove_dir(&task_path);
            }
            return Err(error);
        }
    };
    let canonical_task = match fs::canonicalize(&task_path) {
        Ok(path) => path,
        Err(error) => {
            if task_owned {
                let _ = secure_files::mark_delete_on_close(
                    &task_handle,
                    "the request-bound cancellation task directory",
                );
            }
            return Err(WitnessFailure::failed(format!(
                "cannot canonicalize the request-bound cancellation task directory: {error}"
            )));
        }
    };
    if canonical_task.parent() != Some(parent_path.as_path()) || canonical_task != task_path {
        if task_owned {
            let _ = secure_files::mark_delete_on_close(
                &task_handle,
                "the request-bound cancellation task directory",
            );
        }
        return Err(WitnessFailure::blocked(
            "the request-bound cancellation task directory escaped its derived sandbox location",
        ));
    }
    let mut entries = fs::read_dir(&task_path).map_err(|error| {
        WitnessFailure::failed(format!(
            "cannot inspect the request-bound cancellation task contents: {error}"
        ))
    })?;
    let first = entries.next().transpose().map_err(|error| {
        WitnessFailure::failed(format!(
            "cannot inspect the request-bound cancellation task contents: {error}"
        ))
    })?;
    let second = entries.next().transpose().map_err(|error| {
        WitnessFailure::failed(format!(
            "cannot inspect the request-bound cancellation task contents: {error}"
        ))
    })?;
    let lease_file = match lease_token {
        Some(token) => {
            if first.as_ref().map(|entry| entry.file_name()) != Some(LEASE_NAME.into())
                || second.is_some()
            {
                return Err(WitnessFailure::blocked(
                    "the trusted outer cancellation lease directory has unexpected contents",
                ));
            }
            let mut file = secure_files::open_existing_pinned(
                &task_path.join(LEASE_NAME),
                "the trusted outer cancellation lease",
            )?;
            let mut payload = Vec::with_capacity(LEASE_PREFIX.len() + NONCE_HEX_BYTES + 1);
            Read::by_ref(&mut file)
                .take((LEASE_PREFIX.len() + NONCE_HEX_BYTES + 2) as u64)
                .read_to_end(&mut payload)
                .map_err(|error| {
                    WitnessFailure::failed(format!(
                        "cannot read the trusted outer cancellation lease: {error}"
                    ))
                })?;
            let expected = format!("lease:{token}\n").into_bytes();
            if payload != expected {
                return Err(WitnessFailure::blocked(
                    "the trusted outer cancellation lease token does not match",
                ));
            }
            Some(file)
        }
        None => {
            if first.is_some() {
                return Err(WitnessFailure::blocked(
                    "the self-owned cancellation task directory is not empty",
                ));
            }
            None
        }
    };
    Ok(ControlDirectory {
        task_path,
        root_handle,
        parent_handle,
        task_handle,
        task_owned,
        lease_file,
    })
}

#[cfg(windows)]
fn write_pinned(file: &mut File, bytes: &[u8], subject: &str) -> Result<(), WitnessFailure> {
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|error| WitnessFailure::failed(format!("cannot publish {subject}: {error}")))
}

#[cfg(windows)]
struct OwnedControlFile {
    file: File,
    subject: &'static str,
}

#[cfg(windows)]
struct ControlTaskGuard {
    files: Vec<OwnedControlFile>,
    task_handle: Option<File>,
    parent_handle: Option<File>,
    root_handle: Option<File>,
    delete_task_on_cleanup: bool,
}

#[cfg(windows)]
impl ControlTaskGuard {
    fn new(
        root_handle: File,
        parent_handle: File,
        task_handle: File,
        delete_task_on_cleanup: bool,
    ) -> Self {
        Self {
            files: Vec::new(),
            task_handle: Some(task_handle),
            parent_handle: Some(parent_handle),
            root_handle: Some(root_handle),
            delete_task_on_cleanup,
        }
    }

    fn retain_file(&mut self, file: File, subject: &'static str) -> usize {
        let index = self.files.len();
        self.files.push(OwnedControlFile { file, subject });
        index
    }

    fn file_mut(&mut self, index: usize) -> &mut File {
        &mut self
            .files
            .get_mut(index)
            .expect("retained control-file index is internal and fixed")
            .file
    }

    fn publish(
        &mut self,
        task_path: &Path,
        staging_name: &str,
        final_name: &str,
        bytes: &[u8],
        staging_subject: &'static str,
        final_subject: &'static str,
    ) -> Result<(), WitnessFailure> {
        let file = secure_files::create_new_pinned(&task_path.join(staging_name), staging_subject)?;
        let index = self.retain_file(file, staging_subject);
        write_pinned(self.file_mut(index), bytes, staging_subject)?;
        secure_files::rename_no_replace(
            &self.files[index].file,
            &task_path.join(final_name),
            final_subject,
        )?;
        self.files[index].subject = final_subject;
        Ok(())
    }

    fn cleanup(&mut self) -> Result<(), WitnessFailure> {
        let mut first_error = None;
        for owned in self.files.drain(..) {
            if let Err(error) = secure_files::mark_delete_on_close(&owned.file, owned.subject) {
                first_error.get_or_insert(error);
            }
            drop(owned.file);
        }
        if let Some(task_handle) = self.task_handle.take() {
            if self.delete_task_on_cleanup {
                if let Err(error) = secure_files::mark_delete_on_close(
                    &task_handle,
                    "the request-bound cancellation task directory",
                ) {
                    first_error.get_or_insert(error);
                }
            }
            drop(task_handle);
        }
        drop(self.parent_handle.take());
        drop(self.root_handle.take());
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

#[cfg(windows)]
impl Drop for ControlTaskGuard {
    fn drop(&mut self) {
        if self.task_handle.is_some() {
            let _ = self.cleanup();
        }
    }
}

#[cfg(any(windows, test))]
fn parse_request_nonce(bytes: &[u8]) -> Result<&[u8], WitnessFailure> {
    if bytes.len() != REQUEST_BYTES
        || !bytes.starts_with(REQUEST_PREFIX)
        || bytes.last() != Some(&b'\n')
    {
        return Err(WitnessFailure::blocked(
            "the cancellation request does not match the fixed protocol",
        ));
    }
    let nonce = &bytes[REQUEST_PREFIX.len()..REQUEST_PREFIX.len() + NONCE_HEX_BYTES];
    if !nonce
        .iter()
        .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(WitnessFailure::blocked(
            "the cancellation request nonce must be 64 lowercase hexadecimal bytes",
        ));
    }
    Ok(nonce)
}

#[cfg(any(windows, test))]
fn ready_record_bytes(
    layout: &WitnessLayout,
    parent_process_id: u32,
    descendant_process_id: u32,
) -> Vec<u8> {
    let mut bytes = canonical_json(&json!({
        "schema_version": READY_SCHEMA_VERSION,
        "parent_process_id": parent_process_id,
        "descendant_process_id": descendant_process_id,
        "request_hash": layout.request_hash,
        "task_id": layout.task_id,
    }))
    .into_bytes();
    bytes.push(b'\n');
    bytes
}

#[cfg(windows)]
fn require_absent(path: &Path, subject: &str) -> Result<(), WitnessFailure> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(WitnessFailure::blocked(format!(
            "{subject} appeared outside the fixed cancellation protocol"
        ))),
        Err(error) => Err(WitnessFailure::failed(format!(
            "cannot inspect {subject} before timeout cleanup: {error}"
        ))),
    }
}

#[cfg(windows)]
fn stop_descendant_and_cleanup(
    mut descendant: DescendantGuard,
    control: &mut ControlTaskGuard,
) -> Result<(), WitnessFailure> {
    let descendant_error = (!descendant.stop_bounded()).then(|| {
        WitnessFailure::failed(
            "the fixed cancellation descendant did not terminate within its bounded reap window",
        )
    });
    drop(descendant);
    let cleanup = control.cleanup();
    if let Some(error) = descendant_error {
        Err(error)
    } else {
        cleanup
    }
}

#[cfg(windows)]
pub fn run_process_tree_cancellation_witness(
    root: &SafeRoot,
    remaining: Duration,
    layout: &WitnessLayout,
) -> Result<serde_json::Value, WitnessFailure> {
    let deadline = Instant::now()
        .checked_add(remaining)
        .ok_or_else(|| WitnessFailure::failed("the cancellation deadline overflowed"))?;
    let checked_layout = witness_layout(&layout.request_hash)?;
    if &checked_layout != layout {
        return Err(WitnessFailure::blocked(
            "the cancellation witness layout is not derived exactly from the sealed request hash",
        ));
    }
    let lease_token = take_outer_lease_token()?;
    let ControlDirectory {
        task_path,
        root_handle,
        parent_handle,
        task_handle,
        task_owned,
        lease_file,
    } = create_control_directory(root, layout, lease_token.as_deref())?;
    let mut control = ControlTaskGuard::new(root_handle, parent_handle, task_handle, task_owned);
    if let Some(file) = lease_file {
        control.retain_file(file, "the trusted outer cancellation lease");
    }
    let request_path = task_path.join(REQUEST_NAME);
    let ack_path = task_path.join(ACK_NAME);
    for (path, subject) in [
        (task_path.join(READY_NAME), "the cancellation ready record"),
        (
            task_path.join(READY_STAGING_NAME),
            "the cancellation ready staging file",
        ),
        (request_path.clone(), "the cancellation request"),
        (ack_path.clone(), "the cancellation acknowledgement"),
        (
            task_path.join(ACK_STAGING_NAME),
            "the cancellation acknowledgement staging file",
        ),
    ] {
        require_absent(&path, subject)?;
    }

    let descendant = DescendantGuard::spawn()?;
    let ready_bytes = ready_record_bytes(layout, std::process::id(), descendant.id());
    control.publish(
        &task_path,
        READY_STAGING_NAME,
        READY_NAME,
        &ready_bytes,
        "the cancellation ready staging file",
        "the cancellation ready record",
    )?;

    let request_index = loop {
        if Instant::now() >= deadline {
            if let secure_files::RequestOpen::Open(file) =
                secure_files::open_request_pinned(&request_path)?
            {
                control.retain_file(file, "the cancellation request");
            }
            require_absent(&ack_path, "the cancellation acknowledgement")?;
            stop_descendant_and_cleanup(descendant, &mut control)?;
            return Err(WitnessFailure::timed_out(
                "the fixed cancellation request did not arrive before the manifest deadline",
            ));
        }
        match secure_files::open_request_pinned(&request_path)? {
            secure_files::RequestOpen::MissingOrBusy => thread::sleep(REQUEST_POLL_INTERVAL),
            secure_files::RequestOpen::Open(file) => {
                break control.retain_file(file, "the cancellation request")
            }
        }
    };
    let mut request_bytes = Vec::with_capacity(REQUEST_BYTES + 1);
    Read::by_ref(control.file_mut(request_index))
        .take((REQUEST_BYTES + 1) as u64)
        .read_to_end(&mut request_bytes)
        .map_err(|error| {
            WitnessFailure::failed(format!("cannot read the cancellation request: {error}"))
        })?;
    let nonce = parse_request_nonce(&request_bytes)?;

    let mut ack_bytes = Vec::with_capacity(ACK_PREFIX.len() + NONCE_HEX_BYTES + 1);
    ack_bytes.extend_from_slice(ACK_PREFIX);
    ack_bytes.extend_from_slice(nonce);
    ack_bytes.push(b'\n');
    control.publish(
        &task_path,
        ACK_STAGING_NAME,
        ACK_NAME,
        &ack_bytes,
        "the cancellation acknowledgement staging file",
        "the cancellation acknowledgement",
    )?;

    // The cooperative protocol is now complete. Remain alive only until the
    // remaining sealed deadline, retaining every identity-pinning handle. The
    // external Windows Job watchdog must terminate this runner and its fixed
    // descendant before then to prove forced process-tree containment.
    while Instant::now() < deadline {
        let sleep_for = deadline
            .saturating_duration_since(Instant::now())
            .min(Duration::from_secs(1));
        thread::sleep(sleep_for);
    }
    stop_descendant_and_cleanup(descendant, &mut control)?;
    Err(WitnessFailure::timed_out(
        "the external watchdog did not terminate the acknowledged cancellation witness before the manifest deadline",
    ))
}

#[cfg(not(windows))]
pub fn run_process_tree_cancellation_witness(
    _root: &SafeRoot,
    _remaining: Duration,
    _layout: &WitnessLayout,
) -> Result<serde_json::Value, WitnessFailure> {
    Err(WitnessFailure::blocked(
        "the process-tree cancellation witness is available only on Windows",
    ))
}

pub fn run_internal_cancellation_descendant() -> Result<i32, String> {
    #[cfg(windows)]
    {
        thread::sleep(DESCENDANT_SLEEP);
        Ok(0)
    }
    #[cfg(not(windows))]
    {
        Err("the internal cancellation descendant is available only on Windows".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancellation_request_protocol_is_exact_and_lowercase() {
        let mut request = b"cancel:".to_vec();
        request
            .extend_from_slice(b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
        request.push(b'\n');
        assert_eq!(
            parse_request_nonce(&request).unwrap().len(),
            NONCE_HEX_BYTES
        );

        let mut uppercase = request.clone();
        uppercase[REQUEST_PREFIX.len()] = b'A';
        assert!(parse_request_nonce(&uppercase).is_err());
        assert!(parse_request_nonce(&request[..request.len() - 1]).is_err());
    }

    #[test]
    fn cancellation_protocol_paths_and_verb_are_compiled_constants() {
        let request_hash_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let request_hash = format!("sha256:{request_hash_hex}");
        let layout = witness_layout(&request_hash).unwrap();
        assert_eq!(
            layout.task_relative_path,
            format!("{CONTROL_PARENT_DIRECTORY}/{request_hash_hex}")
        );
        assert_eq!(
            layout.ready_relative_path,
            format!("{}/{READY_NAME}", layout.task_relative_path)
        );
        assert_eq!(
            layout.lease_relative_path,
            format!("{}/{LEASE_NAME}", layout.task_relative_path)
        );
        assert_eq!(
            layout.request_relative_path,
            format!("{}/{REQUEST_NAME}", layout.task_relative_path)
        );
        assert_eq!(
            layout.ack_relative_path,
            format!("{}/{ACK_NAME}", layout.task_relative_path)
        );
        assert_eq!(layout.request_hash, request_hash);
        assert_eq!(layout.task_id, format!("execute-{request_hash_hex}"));
        assert!(witness_layout(request_hash_hex).is_err());
        assert!(witness_layout(&format!("sha256:{}", request_hash_hex.to_uppercase())).is_err());
        assert_eq!(
            String::from_utf8(ready_record_bytes(&layout, 11, 22)).unwrap(),
            format!(
                "{{\"descendant_process_id\":22,\"parent_process_id\":11,\"request_hash\":\"sha256:{request_hash_hex}\",\"schema_version\":\"bluefire.process-tree-cancellation-ready.v1\",\"task_id\":\"execute-{request_hash_hex}\"}}\n"
            )
        );
        assert_eq!(
            INTERNAL_DESCENDANT_VERB,
            "internal-cancellation-descendant-v1"
        );
    }

    #[cfg(windows)]
    #[test]
    fn direct_timeout_reaps_descendant_and_deletes_owned_control_objects() {
        let unique = format!(
            "bluefire-cancellation-witness-test-{}-{}",
            std::process::id(),
            crate::contract::utc_now().timestamp_nanos_opt().unwrap()
        );
        let root_path = std::env::temp_dir().join(unique);
        fs::create_dir(&root_path).unwrap();
        let root = SafeRoot::open(&root_path).unwrap();

        let request_hash =
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let layout = witness_layout(request_hash).unwrap();
        let error =
            run_process_tree_cancellation_witness(&root, Duration::from_millis(40), &layout)
                .expect_err("a request-free witness must reach its direct timeout");
        assert_eq!(error.kind, WitnessFailureKind::TimedOut, "{error:?}");
        assert!(!root_path.join(&layout.task_relative_path).exists());
        let parent = root_path.join(CONTROL_PARENT_DIRECTORY);
        assert_eq!(fs::read_dir(&parent).unwrap().count(), 0);

        drop(root);
        fs::remove_dir(parent).unwrap();
        fs::remove_dir(root_path).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn malformed_request_is_rejected_without_leaving_task_residue() {
        let unique = format!(
            "bluefire-cancellation-malformed-test-{}-{}",
            std::process::id(),
            crate::contract::utc_now().timestamp_nanos_opt().unwrap()
        );
        let root_path = std::env::temp_dir().join(unique);
        fs::create_dir(&root_path).unwrap();
        let request_hash =
            "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let layout = witness_layout(request_hash).unwrap();
        let worker_root = root_path.clone();
        let worker_layout = layout.clone();
        let worker = thread::spawn(move || {
            let root = SafeRoot::open(&worker_root).unwrap();
            run_process_tree_cancellation_witness(&root, Duration::from_secs(5), &worker_layout)
        });

        let ready_path = root_path.join(&layout.ready_relative_path);
        let wait_deadline = Instant::now() + Duration::from_secs(3);
        while !ready_path.exists() && Instant::now() < wait_deadline {
            thread::sleep(REQUEST_POLL_INTERVAL);
        }
        assert!(
            ready_path.exists(),
            "the witness never published readiness: {:?}",
            worker.is_finished()
        );
        fs::write(
            root_path.join(&layout.request_relative_path),
            b"cancel:not-a-valid-private-nonce\n",
        )
        .unwrap();

        let error = worker
            .join()
            .unwrap()
            .expect_err("the malformed request must be rejected");
        assert_eq!(error.kind, WitnessFailureKind::Blocked);
        assert!(!root_path.join(&layout.task_relative_path).exists());
        let parent = root_path.join(CONTROL_PARENT_DIRECTORY);
        assert_eq!(fs::read_dir(&parent).unwrap().count(), 0);
        fs::remove_dir(parent).unwrap();
        fs::remove_dir(root_path).unwrap();
    }
}
