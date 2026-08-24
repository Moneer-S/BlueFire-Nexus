use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::contract::{
    sha256_hex, utc_now, ExecutionManifest, NetworkDestination, RunnerProfile, TargetScope,
};

const RECEIPT_SCHEMA: &str = "bluefire.receipt/v1";
const RECEIPT_COMMIT_SCHEMA: &str = "bluefire.receipt-commit/v1";
pub const RECEIPT_PROTOCOL_VERSION: &str = "bluefire.runner-receipt-wal.v2";
const STATE_DIR: &str = ".bluefire";
const RECEIPT_DIR: &str = "receipts";
const RECEIPT_COMMIT_DIR: &str = "receipt-commits";
const STAGING_DIR: &str = "staging";
const MAX_RECEIPT_BYTES: u64 = 256 * 1024;

#[derive(Debug)]
pub struct SafeRoot {
    root: PathBuf,
}

#[derive(Debug)]
pub struct PreparedPath {
    pub absolute: PathBuf,
    pub relative: String,
    pub created_directories: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ReceiptIntent {
    receipt_id: String,
    runner_profile_id: String,
    workspace_id: String,
}

impl ReceiptIntent {
    pub fn id(&self) -> &str {
        &self.receipt_id
    }
}

#[derive(Debug)]
struct StateDirs {
    receipts: PathBuf,
    commits: PathBuf,
    staging: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OwnedPathKind {
    File,
    Directory,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnedPath {
    pub relative_path: String,
    pub kind: OwnedPathKind,
    #[serde(default)]
    pub sha256: Option<String>,
    #[serde(default)]
    pub size: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptRecord {
    pub schema_version: String,
    pub receipt_id: String,
    pub request_hash: String,
    pub action_id: String,
    pub runner_profile_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_id: Option<String>,
    pub created_at: chrono::DateTime<Utc>,
    pub paths: Vec<OwnedPath>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiptCommitRecord {
    schema_version: String,
    receipt_id: String,
    runner_profile_id: String,
    workspace_id: String,
    committed_at: chrono::DateTime<Utc>,
}

fn receipt_identity(
    request_hash: &str,
    action_id: &str,
    runner_profile_id: &str,
    workspace_id: &str,
    created_at: &chrono::DateTime<Utc>,
    paths: &[OwnedPath],
) -> String {
    let identity = serde_json::json!({
        "schema_version": RECEIPT_SCHEMA,
        "request_hash": request_hash,
        "action_id": action_id,
        "runner_profile_id": runner_profile_id,
        "workspace_id": workspace_id,
        "created_at": created_at,
        "paths": paths,
    });
    sha256_hex(crate::contract::canonical_json(&identity).as_bytes())
}

fn metadata_is_link_or_reparse(metadata: &fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    {
        false
    }
}

fn invalid_windows_name(component: &str) -> bool {
    let trimmed = component.trim_end_matches(['.', ' ']);
    let base = trimmed.split('.').next().unwrap_or("").to_ascii_uppercase();
    matches!(base.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (base.len() == 4
            && (base.starts_with("COM") || base.starts_with("LPT"))
            && matches!(base.as_bytes()[3], b'1'..=b'9'))
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), String> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("cannot sync runner directory: {error}"))
}

#[cfg(windows)]
fn sync_directory(_path: &Path) -> Result<(), String> {
    // Windows does not expose a generally usable directory FlushFileBuffers
    // operation. Publication uses MoveFileExW(MOVEFILE_WRITE_THROUGH) below,
    // which provides the corresponding write-through rename guarantee.
    Ok(())
}

#[cfg(unix)]
fn publish_no_replace(source: &Path, destination: &Path, parent: &Path) -> Result<(), String> {
    fs::hard_link(source, destination)
        .map_err(|error| format!("cannot publish durable file without overwrite: {error}"))?;
    sync_directory(parent)?;
    fs::remove_file(source)
        .map_err(|error| format!("cannot remove durable staging file: {error}"))?;
    let source_parent = source
        .parent()
        .ok_or_else(|| "durable staging file has no parent".to_string())?;
    sync_directory(source_parent)
}

#[cfg(windows)]
fn publish_no_replace(source: &Path, destination: &Path, _parent: &Path) -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;

    const MOVEFILE_WRITE_THROUGH: u32 = 0x0000_0008;
    #[link(name = "Kernel32")]
    extern "system" {
        fn MoveFileExW(existing: *const u16, new: *const u16, flags: u32) -> i32;
    }

    let existing = source
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let new = destination
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    // MOVEFILE_REPLACE_EXISTING is deliberately absent: publication must fail
    // closed when any object already occupies the final path.
    let moved = unsafe { MoveFileExW(existing.as_ptr(), new.as_ptr(), MOVEFILE_WRITE_THROUGH) };
    if moved == 0 {
        Err(format!(
            "cannot publish durable file without overwrite: {}",
            io::Error::last_os_error()
        ))
    } else {
        Ok(())
    }
}

fn valid_receipt_id(receipt_id: &str) -> bool {
    receipt_id.len() == 64
        && receipt_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

/// Normalize a platform-independent, sandbox-relative path. Both slash styles
/// are treated as separators so a manifest cannot be safe on one host but
/// traverse on another.
pub fn normalize_relative(raw: &str, allow_root: bool) -> Result<String, String> {
    if raw.is_empty() || raw.contains('\0') {
        return Err("path is empty or contains NUL".to_string());
    }
    if raw.starts_with('/') || raw.starts_with('\\') || raw.contains(':') {
        return Err(
            "absolute, drive-relative, UNC, device, and stream paths are forbidden".to_string(),
        );
    }
    let portable = raw.replace('\\', "/");
    if portable == "." && allow_root {
        return Ok(".".to_string());
    }
    if portable.ends_with('/') || portable.contains("//") {
        return Err("empty path components are forbidden".to_string());
    }

    let mut components = Vec::new();
    for component in portable.split('/') {
        if component.is_empty() || component == "." || component == ".." {
            return Err("dot and empty path components are forbidden".to_string());
        }
        if component.eq_ignore_ascii_case(STATE_DIR) {
            return Err("the runner state directory is reserved".to_string());
        }
        if component.ends_with('.') || component.ends_with(' ') || invalid_windows_name(component) {
            return Err(
                "a path component is not portable or is a reserved device name".to_string(),
            );
        }
        components.push(component);
    }
    if components.is_empty() {
        return Err("path has no usable components".to_string());
    }
    Ok(components.join("/"))
}

pub fn path_in_scope(path: &str, scope: &[String]) -> Result<bool, String> {
    let path = normalize_relative(path, true)?;
    for candidate in scope {
        let candidate = normalize_relative(candidate, true)?;
        if candidate == "."
            || path == candidate
            || path
                .strip_prefix(candidate.as_str())
                .is_some_and(|suffix| suffix.starts_with('/'))
        {
            return Ok(true);
        }
    }
    Ok(false)
}

pub fn scope_is_subset(requested: &TargetScope, allowed: &TargetScope) -> Result<bool, String> {
    for requested_path in &requested.filesystem {
        if !path_in_scope(requested_path, &allowed.filesystem)? {
            return Ok(false);
        }
    }
    for requested_destination in &requested.network {
        if !allowed.network.contains(requested_destination) {
            return Ok(false);
        }
    }
    Ok(true)
}

pub fn validate_loopback_destination(destination: &NetworkDestination) -> Result<IpAddr, String> {
    if destination.port == 0 {
        return Err("network destination port 0 is not executable".to_string());
    }
    let address: IpAddr = destination
        .host
        .parse()
        .map_err(|_| "network destinations must be literal IP addresses".to_string())?;
    if !address.is_loopback() {
        return Err("only literal loopback destinations are permitted".to_string());
    }
    Ok(address)
}

impl SafeRoot {
    pub fn open(configured_root: &Path) -> Result<Self, String> {
        let metadata = fs::symlink_metadata(configured_root)
            .map_err(|error| format!("sandbox root is unavailable: {error}"))?;
        if metadata_is_link_or_reparse(&metadata) {
            return Err("sandbox root must not be a symlink or reparse point".to_string());
        }
        if !metadata.is_dir() {
            return Err("sandbox root is not a directory".to_string());
        }
        let root = fs::canonicalize(configured_root)
            .map_err(|error| format!("sandbox root cannot be canonicalized: {error}"))?;
        Ok(Self { root })
    }

    pub fn path(&self) -> &Path {
        &self.root
    }

    fn verify_contained(&self, candidate: &Path) -> Result<(), String> {
        let canonical = fs::canonicalize(candidate)
            .map_err(|error| format!("path cannot be canonicalized: {error}"))?;
        if !canonical.starts_with(&self.root) {
            return Err("canonical path escapes the sandbox root".to_string());
        }
        Ok(())
    }

    fn verify_existing_components(&self, relative: &str) -> Result<PathBuf, String> {
        let normalized = normalize_relative(relative, true)?;
        if normalized == "." {
            return Ok(self.root.clone());
        }
        let mut current = self.root.clone();
        for component in normalized.split('/') {
            current.push(component);
            let metadata = fs::symlink_metadata(&current)
                .map_err(|error| format!("path component is unavailable: {error}"))?;
            if metadata_is_link_or_reparse(&metadata) {
                return Err("symlink and reparse-point traversal is forbidden".to_string());
            }
            self.verify_contained(&current)?;
        }
        Ok(current)
    }

    pub fn resolve_existing(&self, relative: &str) -> Result<PathBuf, String> {
        self.verify_existing_components(relative)
    }

    pub fn prepare_new_file(&self, relative: &str) -> Result<PreparedPath, String> {
        let normalized = normalize_relative(relative, false)?;
        let components = normalized.split('/').collect::<Vec<_>>();
        let mut current = self.root.clone();
        let mut created_directories = Vec::new();
        let mut parent_missing = false;

        for (index, component) in components.iter().enumerate() {
            current.push(component);
            let is_final = index + 1 == components.len();
            if parent_missing {
                if !is_final {
                    created_directories.push(components[..=index].join("/"));
                }
                continue;
            }
            match fs::symlink_metadata(&current) {
                Ok(metadata) => {
                    if metadata_is_link_or_reparse(&metadata) {
                        return Err("symlink and reparse-point traversal is forbidden".to_string());
                    }
                    if is_final {
                        return Err(
                            "destination already exists; overwrite is forbidden".to_string()
                        );
                    }
                    if !metadata.is_dir() {
                        return Err("a destination parent is not a directory".to_string());
                    }
                    self.verify_contained(&current)?;
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    if !is_final {
                        created_directories.push(components[..=index].join("/"));
                        parent_missing = true;
                    }
                }
                Err(error) => return Err(format!("cannot inspect destination: {error}")),
            }
        }

        Ok(PreparedPath {
            absolute: current,
            relative: normalized,
            created_directories,
        })
    }

    fn workspace_id(&self) -> String {
        let portable = self.root.to_string_lossy().replace('\\', "/");
        sha256_hex(portable.as_bytes())
    }

    fn ensure_state_dirs(&self) -> Result<StateDirs, String> {
        let state = self.root.join(STATE_DIR);
        let receipts = state.join(RECEIPT_DIR);
        let commits = state.join(RECEIPT_COMMIT_DIR);
        let staging = state.join(STAGING_DIR);
        for path in [&state, &receipts, &commits, &staging] {
            match fs::symlink_metadata(path) {
                Ok(metadata) => {
                    if metadata_is_link_or_reparse(&metadata) || !metadata.is_dir() {
                        return Err("runner state path is unsafe".to_string());
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    fs::create_dir(path)
                        .map_err(|error| format!("cannot create runner state path: {error}"))?;
                    let parent = path
                        .parent()
                        .ok_or_else(|| "runner state path has no parent".to_string())?;
                    sync_directory(parent)?;
                }
                Err(error) => return Err(format!("cannot inspect runner state path: {error}")),
            }
            self.verify_contained(path)?;
        }
        Ok(StateDirs {
            receipts,
            commits,
            staging,
        })
    }

    fn atomic_persist_new(
        &self,
        staging_directory: &Path,
        destination_directory: &Path,
        destination: &Path,
        temporary_name: &str,
        bytes: &[u8],
    ) -> Result<(), String> {
        let temporary = staging_directory.join(temporary_name);
        let mut temporary_created = false;
        let result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary)
                .map_err(|error| format!("cannot create durable metadata staging file: {error}"))?;
            temporary_created = true;
            file.write_all(bytes)
                .map_err(|error| format!("cannot write durable metadata: {error}"))?;
            file.sync_all()
                .map_err(|error| format!("cannot sync durable metadata: {error}"))?;
            publish_no_replace(&temporary, destination, destination_directory)
        })();
        if result.is_err() && temporary_created {
            let _ = fs::remove_file(&temporary);
        }
        result
    }

    pub fn begin_receipt(
        &self,
        manifest: &ExecutionManifest,
        profile: &RunnerProfile,
        paths: Vec<OwnedPath>,
    ) -> Result<ReceiptIntent, String> {
        if paths.is_empty() {
            return Err("a receipt must own at least one created path".to_string());
        }
        let mut unique_paths = BTreeSet::new();
        let intended_files = paths
            .iter()
            .filter(|owned| owned.kind == OwnedPathKind::File)
            .map(|owned| normalize_relative(&owned.relative_path, false))
            .collect::<Result<Vec<_>, _>>()?;
        for owned in &paths {
            let normalized = normalize_relative(&owned.relative_path, false)?;
            if normalized != owned.relative_path {
                return Err("receipt paths must use normalized separators".to_string());
            }
            if !unique_paths.insert(normalized) {
                return Err("a receipt cannot own the same path twice".to_string());
            }
            match owned.kind {
                OwnedPathKind::File => {
                    ensure_path_authorized(manifest, &owned.relative_path)?;
                    let digest = owned
                        .sha256
                        .as_deref()
                        .ok_or_else(|| "owned file intent lacks a content hash".to_string())?;
                    if !valid_receipt_id(digest) || owned.size.is_none() {
                        return Err("owned file intent has invalid content metadata".to_string());
                    }
                }
                OwnedPathKind::Directory => {
                    if !intended_files.iter().any(|file| {
                        file.strip_prefix(owned.relative_path.as_str())
                            .is_some_and(|suffix| suffix.starts_with('/'))
                    }) {
                        return Err("owned directory intent is not an ancestor of an owned file"
                            .to_string());
                    }
                    if owned.sha256.is_some() || owned.size.is_some() {
                        return Err(
                            "owned directory intent has unexpected file metadata".to_string()
                        );
                    }
                }
            }
        }
        let created_at = utc_now();
        let workspace_id = self.workspace_id();
        let receipt_id = receipt_identity(
            &manifest.request_hash,
            &manifest.action_id,
            &profile.profile_id,
            &workspace_id,
            &created_at,
            &paths,
        );
        let record = ReceiptRecord {
            schema_version: RECEIPT_SCHEMA.to_string(),
            receipt_id: receipt_id.clone(),
            request_hash: manifest.request_hash.clone(),
            action_id: manifest.action_id.clone(),
            runner_profile_id: profile.profile_id.clone(),
            workspace_id: Some(workspace_id),
            created_at,
            paths,
        };
        let encoded = serde_json::to_vec_pretty(&record)
            .map_err(|error| format!("cannot serialize receipt: {error}"))?;
        if encoded.len() as u64 > MAX_RECEIPT_BYTES {
            return Err("receipt exceeds its size limit".to_string());
        }
        let dirs = self.ensure_state_dirs()?;
        let receipt_path = dirs.receipts.join(format!("{receipt_id}.json"));
        self.atomic_persist_new(
            &dirs.staging,
            &dirs.receipts,
            &receipt_path,
            &format!(".{receipt_id}.intent.tmp"),
            &encoded,
        )?;
        Ok(ReceiptIntent {
            receipt_id,
            runner_profile_id: profile.profile_id.clone(),
            workspace_id: self.workspace_id(),
        })
    }

    fn staging_path(&self, receipt_id: &str, relative_path: &str) -> PathBuf {
        let path_id = sha256_hex(relative_path.as_bytes());
        self.root
            .join(STATE_DIR)
            .join(STAGING_DIR)
            .join(format!("{receipt_id}-{path_id}.stage"))
    }

    fn create_planned_directories(&self, target: &PreparedPath) -> Result<(), String> {
        for directory in &target.created_directories {
            let absolute = self
                .root
                .join(directory.replace('/', std::path::MAIN_SEPARATOR_STR));
            match fs::symlink_metadata(&absolute) {
                Ok(metadata) => {
                    if metadata_is_link_or_reparse(&metadata) || !metadata.is_dir() {
                        return Err("destination parent failed safety verification".to_string());
                    }
                    self.verify_contained(&absolute)?;
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    let parent = absolute
                        .parent()
                        .ok_or_else(|| "destination parent has no parent".to_string())?;
                    self.verify_contained(parent)?;
                    fs::create_dir(&absolute)
                        .map_err(|error| format!("cannot create destination parent: {error}"))?;
                    let metadata = fs::symlink_metadata(&absolute)
                        .map_err(|error| format!("cannot verify destination parent: {error}"))?;
                    if metadata_is_link_or_reparse(&metadata) || !metadata.is_dir() {
                        return Err("new destination parent failed safety verification".to_string());
                    }
                    self.verify_contained(&absolute)?;
                    sync_directory(parent)?;
                }
                Err(error) => return Err(format!("cannot inspect destination parent: {error}")),
            }
        }
        Ok(())
    }

    fn receipt_owns_file(
        &self,
        intent: &ReceiptIntent,
        target: &PreparedPath,
        bytes: &[u8],
    ) -> Result<(), String> {
        let record = self
            .load_receipt(intent.id())?
            .ok_or_else(|| "durable receipt intent is unavailable".to_string())?;
        if record.runner_profile_id != intent.runner_profile_id
            || record.workspace_id.as_deref() != Some(intent.workspace_id.as_str())
            || intent.workspace_id != self.workspace_id()
        {
            return Err("durable receipt intent identity is invalid".to_string());
        }
        let expected_hash = sha256_hex(bytes);
        if record.paths.iter().any(|owned| {
            owned.relative_path == target.relative
                && owned.kind == OwnedPathKind::File
                && owned.sha256.as_deref() == Some(expected_hash.as_str())
                && owned.size == Some(bytes.len() as u64)
        }) {
            Ok(())
        } else {
            Err("durable receipt intent does not own the exact destination bytes".to_string())
        }
    }

    /// Materialize one intent-owned file without ever exposing partial bytes
    /// at its final path. The fully-synced staging inode is hard-linked into
    /// place with no-overwrite semantics, so every published file is either
    /// absent or hash-identical to its durable pre-effect intent.
    pub fn write_new(
        &self,
        target: &PreparedPath,
        bytes: &[u8],
        intent: &ReceiptIntent,
    ) -> Result<(), String> {
        self.receipt_owns_file(intent, target, bytes)?;
        self.create_planned_directories(target)?;
        let parent = target
            .absolute
            .parent()
            .ok_or_else(|| "destination has no parent".to_string())?;
        self.verify_contained(parent)?;

        let dirs = self.ensure_state_dirs()?;
        let staging_path = self.staging_path(intent.id(), &target.relative);
        let mut staging = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&staging_path)
            .map_err(|error| format!("cannot create receipt-owned staging file: {error}"))?;
        staging
            .write_all(bytes)
            .map_err(|error| format!("cannot write receipt-owned staging file: {error}"))?;
        staging
            .sync_all()
            .map_err(|error| format!("cannot sync receipt-owned staging file: {error}"))?;
        sync_directory(&dirs.staging)?;

        publish_no_replace(&staging_path, &target.absolute, parent)?;
        let metadata = fs::symlink_metadata(&target.absolute)
            .map_err(|error| format!("cannot verify destination: {error}"))?;
        if metadata_is_link_or_reparse(&metadata) || !metadata.is_file() {
            return Err("destination failed post-write safety verification".to_string());
        }
        self.verify_contained(&target.absolute)?;
        if metadata.len() != bytes.len() as u64
            || hash_file(&target.absolute, bytes.len() as u64)? != sha256_hex(bytes)
        {
            return Err("published destination differs from its durable intent".to_string());
        }

        sync_directory(&dirs.staging)
    }

    pub fn commit_receipt(
        &self,
        intent: &ReceiptIntent,
        profile: &RunnerProfile,
    ) -> Result<String, String> {
        let record = self
            .load_receipt(intent.id())?
            .ok_or_else(|| "durable receipt intent is unavailable".to_string())?;
        if record.runner_profile_id != profile.profile_id {
            return Err("receipt intent belongs to another runner profile".to_string());
        }
        let workspace_id = self.workspace_id();
        if intent.runner_profile_id != profile.profile_id
            || intent.workspace_id != workspace_id
            || record.workspace_id.as_deref() != Some(workspace_id.as_str())
        {
            return Err("receipt intent belongs to another workspace".to_string());
        }
        for owned in &record.paths {
            let absolute = match self.resolve_existing(&owned.relative_path) {
                Ok(absolute) => absolute,
                Err(error) if error.contains("unavailable") => continue,
                Err(error) => return Err(format!("cannot validate committed path: {error}")),
            };
            let metadata = fs::symlink_metadata(&absolute)
                .map_err(|error| format!("cannot inspect committed path: {error}"))?;
            match owned.kind {
                OwnedPathKind::File => {
                    if metadata_is_link_or_reparse(&metadata)
                        || !metadata.is_file()
                        || owned.size != Some(metadata.len())
                    {
                        return Err("an existing path differs from its receipt intent".to_string());
                    }
                    let actual_hash = hash_file(&absolute, metadata.len())?;
                    if owned.sha256.as_deref() != Some(actual_hash.as_str()) {
                        return Err("an existing path differs from its receipt intent".to_string());
                    }
                }
                OwnedPathKind::Directory => {
                    if metadata_is_link_or_reparse(&metadata) || !metadata.is_dir() {
                        return Err(
                            "an existing directory differs from its receipt intent".to_string()
                        );
                    }
                }
            }
        }
        let commit = ReceiptCommitRecord {
            schema_version: RECEIPT_COMMIT_SCHEMA.to_string(),
            receipt_id: intent.id().to_string(),
            runner_profile_id: profile.profile_id.clone(),
            workspace_id: workspace_id.clone(),
            committed_at: utc_now(),
        };
        let encoded = serde_json::to_vec_pretty(&commit)
            .map_err(|error| format!("cannot serialize receipt commit: {error}"))?;
        let dirs = self.ensure_state_dirs()?;
        let commit_path = dirs.commits.join(format!("{}.json", intent.id()));
        match fs::symlink_metadata(&commit_path) {
            Ok(metadata) if !metadata_is_link_or_reparse(&metadata) && metadata.is_file() => {
                if metadata.len() > MAX_RECEIPT_BYTES {
                    return Err("receipt commit exceeds its size limit".to_string());
                }
                self.verify_contained(&commit_path)?;
                let existing: ReceiptCommitRecord = serde_json::from_slice(
                    &fs::read(&commit_path)
                        .map_err(|error| format!("cannot read receipt commit: {error}"))?,
                )
                .map_err(|error| format!("receipt commit schema is invalid: {error}"))?;
                if existing.schema_version != RECEIPT_COMMIT_SCHEMA
                    || existing.receipt_id != intent.id()
                    || existing.runner_profile_id != profile.profile_id
                    || existing.workspace_id != workspace_id
                {
                    return Err("receipt commit identity is invalid".to_string());
                }
                return Ok(intent.id().to_string());
            }
            Ok(_) => return Err("receipt commit path is unsafe".to_string()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("cannot inspect receipt commit: {error}")),
        }
        self.atomic_persist_new(
            &dirs.staging,
            &dirs.commits,
            &commit_path,
            &format!(".{}.commit.tmp", intent.id()),
            &encoded,
        )?;
        Ok(intent.id().to_string())
    }

    pub fn load_receipt(&self, receipt_id: &str) -> Result<Option<ReceiptRecord>, String> {
        if !valid_receipt_id(receipt_id) {
            return Err("receipt ID must be a 64-character hexadecimal digest".to_string());
        }
        let receipt_path = self
            .root
            .join(STATE_DIR)
            .join(RECEIPT_DIR)
            .join(format!("{receipt_id}.json"));
        let metadata = match fs::symlink_metadata(&receipt_path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(format!("cannot inspect receipt: {error}")),
        };
        if metadata_is_link_or_reparse(&metadata) || !metadata.is_file() {
            return Err("receipt is not a regular runner-owned file".to_string());
        }
        if metadata.len() > MAX_RECEIPT_BYTES {
            return Err("receipt exceeds its size limit".to_string());
        }
        self.verify_contained(&receipt_path)?;
        let bytes =
            fs::read(&receipt_path).map_err(|error| format!("cannot read receipt: {error}"))?;
        let record: ReceiptRecord = serde_json::from_slice(&bytes)
            .map_err(|error| format!("receipt schema is invalid: {error}"))?;
        if record.schema_version != RECEIPT_SCHEMA || record.receipt_id != receipt_id {
            return Err("receipt identity is invalid".to_string());
        }
        if let Some(workspace_id) = record.workspace_id.as_deref() {
            let expected = receipt_identity(
                &record.request_hash,
                &record.action_id,
                &record.runner_profile_id,
                workspace_id,
                &record.created_at,
                &record.paths,
            );
            if expected != receipt_id {
                return Err("receipt content digest is invalid".to_string());
            }
        }
        if record
            .workspace_id
            .as_deref()
            .is_some_and(|workspace_id| workspace_id != self.workspace_id())
        {
            return Err("receipt belongs to another workspace".to_string());
        }
        Ok(Some(record))
    }

    pub fn delete_receipt(&self, receipt_id: &str) -> Result<(), String> {
        if !valid_receipt_id(receipt_id) {
            return Err("receipt ID must be a 64-character hexadecimal digest".to_string());
        }
        let state = self.root.join(STATE_DIR);
        let receipts = state.join(RECEIPT_DIR);
        let commits = state.join(RECEIPT_COMMIT_DIR);
        let staging = state.join(STAGING_DIR);
        for path in [
            commits.join(format!("{receipt_id}.json")),
            receipts.join(format!("{receipt_id}.json")),
        ] {
            match fs::symlink_metadata(&path) {
                Ok(metadata) => {
                    if metadata_is_link_or_reparse(&metadata) || !metadata.is_file() {
                        return Err("runner receipt metadata path is unsafe".to_string());
                    }
                    self.verify_contained(&path)?;
                    fs::remove_file(&path)
                        .map_err(|error| format!("cannot remove consumed receipt: {error}"))?;
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(format!("cannot inspect receipt metadata: {error}")),
            }
        }
        if let Ok(entries) = fs::read_dir(&staging) {
            let prefix = format!("{receipt_id}-");
            let intent_temporary = format!(".{receipt_id}.intent.tmp");
            let commit_temporary = format!(".{receipt_id}.commit.tmp");
            for entry in entries {
                let entry =
                    entry.map_err(|error| format!("cannot inspect staging entry: {error}"))?;
                let name = entry.file_name();
                let Some(name) = name.to_str() else {
                    return Err("runner staging entry is not portable UTF-8".to_string());
                };
                if (name.starts_with(&prefix) && name.ends_with(".stage"))
                    || name == intent_temporary
                    || name == commit_temporary
                {
                    let path = entry.path();
                    let metadata = fs::symlink_metadata(&path)
                        .map_err(|error| format!("cannot inspect staging entry: {error}"))?;
                    if metadata_is_link_or_reparse(&metadata) || !metadata.is_file() {
                        return Err("runner staging entry is unsafe".to_string());
                    }
                    self.verify_contained(&path)?;
                    fs::remove_file(path)
                        .map_err(|error| format!("cannot remove staging entry: {error}"))?;
                }
            }
        }
        for directory in [&receipts, &commits, &staging, &state] {
            let _ = fs::remove_dir(directory);
        }
        Ok(())
    }

    pub fn remove_staging_for_owned(
        &self,
        receipt_id: &str,
        owned: &OwnedPath,
    ) -> Result<(), String> {
        if !valid_receipt_id(receipt_id) {
            return Err("receipt ID must be a 64-character hexadecimal digest".to_string());
        }
        if owned.kind != OwnedPathKind::File {
            return Ok(());
        }
        let staging = self.staging_path(receipt_id, &owned.relative_path);
        match fs::symlink_metadata(&staging) {
            Ok(metadata) => {
                if metadata_is_link_or_reparse(&metadata) || !metadata.is_file() {
                    return Err("receipt-owned staging path is unsafe".to_string());
                }
                self.verify_contained(&staging)?;
                fs::remove_file(&staging).map_err(|error| {
                    format!("cannot remove receipt-owned staging file: {error}")
                })?;
                if let Some(parent) = staging.parent() {
                    sync_directory(parent)?;
                }
                Ok(())
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(format!(
                "cannot inspect receipt-owned staging file: {error}"
            )),
        }
    }

    pub fn remove_owned(&self, owned: &OwnedPath) -> Result<Option<String>, String> {
        let normalized = normalize_relative(&owned.relative_path, false)?;
        let absolute = match self.resolve_existing(&normalized) {
            Ok(path) => path,
            Err(error) if error.contains("unavailable") => return Ok(None),
            Err(error) => return Err(error),
        };
        let metadata = fs::symlink_metadata(&absolute)
            .map_err(|error| format!("cannot inspect owned path: {error}"))?;
        if metadata_is_link_or_reparse(&metadata) {
            return Err("owned path was replaced by a link or reparse point".to_string());
        }
        match owned.kind {
            OwnedPathKind::File => {
                if !metadata.is_file() {
                    return Err("owned file was replaced with another object type".to_string());
                }
                if owned.size != Some(metadata.len()) {
                    return Err("owned file size changed; cleanup refused".to_string());
                }
                let expected = owned
                    .sha256
                    .as_deref()
                    .ok_or_else(|| "owned file receipt lacks a content hash".to_string())?;
                let actual = hash_file(&absolute, metadata.len())?;
                if actual != expected {
                    return Err("owned file content changed; cleanup refused".to_string());
                }
                fs::remove_file(&absolute)
                    .map_err(|error| format!("cannot remove owned file: {error}"))?;
            }
            OwnedPathKind::Directory => {
                if !metadata.is_dir() {
                    return Err("owned directory was replaced with another object type".to_string());
                }
                fs::remove_dir(&absolute)
                    .map_err(|error| format!("cannot remove owned directory: {error}"))?;
            }
        }
        Ok(Some(normalized))
    }
}

pub fn read_file_bounded(path: &Path, max_bytes: u64) -> Result<Vec<u8>, String> {
    let metadata = fs::metadata(path).map_err(|error| format!("cannot inspect file: {error}"))?;
    if !metadata.is_file() {
        return Err("path is not a regular file".to_string());
    }
    if metadata.len() > max_bytes {
        return Err("file exceeds the action's artifact byte limit".to_string());
    }
    let file = File::open(path).map_err(|error| format!("cannot open file: {error}"))?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read file: {error}"))?;
    if bytes.len() as u64 > max_bytes {
        return Err("file grew beyond the action's artifact byte limit".to_string());
    }
    Ok(bytes)
}

pub fn hash_file(path: &Path, max_bytes: u64) -> Result<String, String> {
    let mut file =
        File::open(path).map_err(|error| format!("cannot open file for hashing: {error}"))?;
    let mut digest = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| format!("cannot hash file: {error}"))?;
        if read == 0 {
            break;
        }
        total = total.saturating_add(read as u64);
        if total > max_bytes {
            return Err("file exceeds the hashing byte limit".to_string());
        }
        digest.update(&buffer[..read]);
    }
    Ok(hex::encode(digest.finalize()))
}

pub fn owned_file(relative: String, bytes: &[u8]) -> OwnedPath {
    OwnedPath {
        relative_path: relative,
        kind: OwnedPathKind::File,
        sha256: Some(sha256_hex(bytes)),
        size: Some(bytes.len() as u64),
    }
}

pub fn owned_directories(directories: &[String]) -> Vec<OwnedPath> {
    directories
        .iter()
        .rev()
        .map(|relative_path| OwnedPath {
            relative_path: relative_path.clone(),
            kind: OwnedPathKind::Directory,
            sha256: None,
            size: None,
        })
        .collect()
}

pub fn ensure_path_authorized(manifest: &ExecutionManifest, path: &str) -> Result<(), String> {
    if path_in_scope(path, &manifest.target_scope.filesystem)? {
        Ok(())
    } else {
        Err("path is outside the manifest's declared filesystem scope".to_string())
    }
}

pub fn ensure_network_authorized(
    manifest: &ExecutionManifest,
    profile: &RunnerProfile,
    destination: &NetworkDestination,
) -> Result<IpAddr, String> {
    let address = validate_loopback_destination(destination)?;
    if !manifest.target_scope.network.contains(destination) {
        return Err("destination is outside the manifest's declared network scope".to_string());
    }
    if !profile.target_scope.network.contains(destination) {
        return Err("destination is outside the runner profile's network scope".to_string());
    }
    Ok(address)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_portable_traversal_and_absolute_forms() {
        for path in [
            "../escape",
            "..\\escape",
            "/absolute",
            "\\\\server\\share",
            "C:\\escape",
            "C:relative",
            "safe//file",
            "safe/./file",
            ".bluefire/receipts/x",
            "safe/CON.txt",
        ] {
            assert!(normalize_relative(path, false).is_err(), "accepted {path}");
        }
        assert_eq!(
            normalize_relative("safe\\file.txt", false).unwrap(),
            "safe/file.txt"
        );
    }

    #[test]
    fn scope_checks_component_boundaries() {
        let allowed = vec!["artifacts".to_string()];
        assert!(path_in_scope("artifacts/a.txt", &allowed).unwrap());
        assert!(!path_in_scope("artifacts-other/a.txt", &allowed).unwrap());
    }

    #[test]
    fn loopback_requires_literal_address() {
        assert!(validate_loopback_destination(&NetworkDestination {
            host: "127.0.0.1".to_string(),
            port: 8080,
        })
        .is_ok());
        assert!(validate_loopback_destination(&NetworkDestination {
            host: "localhost".to_string(),
            port: 8080,
        })
        .is_err());
        assert!(validate_loopback_destination(&NetworkDestination {
            host: "192.0.2.1".to_string(),
            port: 8080,
        })
        .is_err());
    }
}
