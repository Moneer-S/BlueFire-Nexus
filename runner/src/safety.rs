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
const STATE_DIR: &str = ".bluefire";
const RECEIPT_DIR: &str = "receipts";
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
    pub created_at: chrono::DateTime<Utc>,
    pub paths: Vec<OwnedPath>,
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

        for (index, component) in components.iter().enumerate() {
            current.push(component);
            let is_final = index + 1 == components.len();
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
                        fs::create_dir(&current).map_err(|error| {
                            format!("cannot create destination parent: {error}")
                        })?;
                        let metadata = fs::symlink_metadata(&current).map_err(|error| {
                            format!("cannot verify new destination parent: {error}")
                        })?;
                        if metadata_is_link_or_reparse(&metadata) || !metadata.is_dir() {
                            return Err(
                                "new destination parent failed safety verification".to_string()
                            );
                        }
                        self.verify_contained(&current)?;
                        created_directories.push(components[..=index].join("/"));
                    }
                }
                Err(error) => return Err(format!("cannot inspect destination: {error}")),
            }
        }

        if let Some(parent) = current.parent() {
            self.verify_contained(parent)?;
        }
        Ok(PreparedPath {
            absolute: current,
            relative: normalized,
            created_directories,
        })
    }

    pub fn write_new(&self, target: &PreparedPath, bytes: &[u8]) -> Result<(), String> {
        let mut created_file = false;
        let result = (|| {
            if let Some(parent) = target.absolute.parent() {
                self.verify_contained(parent)?;
            }
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&target.absolute)
                .map_err(|error| format!("cannot create destination: {error}"))?;
            created_file = true;
            file.write_all(bytes)
                .map_err(|error| format!("cannot write destination: {error}"))?;
            file.sync_all()
                .map_err(|error| format!("cannot sync destination: {error}"))?;
            let metadata = fs::symlink_metadata(&target.absolute)
                .map_err(|error| format!("cannot verify destination: {error}"))?;
            if metadata_is_link_or_reparse(&metadata) || !metadata.is_file() {
                return Err("destination failed post-write safety verification".to_string());
            }
            self.verify_contained(&target.absolute)
        })();
        if result.is_err() {
            self.rollback_created(target, created_file);
        }
        result
    }

    pub fn rollback_prepared(&self, target: &PreparedPath) {
        self.rollback_created(target, true);
    }

    fn rollback_created(&self, target: &PreparedPath, remove_final_file: bool) {
        if remove_final_file {
            if let Ok(metadata) = fs::symlink_metadata(&target.absolute) {
                if metadata.is_file() && !metadata_is_link_or_reparse(&metadata) {
                    let _ = fs::remove_file(&target.absolute);
                }
            }
        }
        for directory in target.created_directories.iter().rev() {
            let absolute = self
                .root
                .join(directory.replace('/', std::path::MAIN_SEPARATOR_STR));
            if let Ok(metadata) = fs::symlink_metadata(&absolute) {
                if metadata.is_dir() && !metadata_is_link_or_reparse(&metadata) {
                    let _ = fs::remove_dir(absolute);
                }
            }
        }
    }

    fn ensure_state_dirs(&self) -> Result<PathBuf, String> {
        let state = self.root.join(STATE_DIR);
        let receipts = state.join(RECEIPT_DIR);
        for path in [&state, &receipts] {
            match fs::symlink_metadata(path) {
                Ok(metadata) => {
                    if metadata_is_link_or_reparse(&metadata) || !metadata.is_dir() {
                        return Err("runner state path is unsafe".to_string());
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    fs::create_dir(path)
                        .map_err(|error| format!("cannot create runner state path: {error}"))?;
                }
                Err(error) => return Err(format!("cannot inspect runner state path: {error}")),
            }
            self.verify_contained(path)?;
        }
        Ok(receipts)
    }

    pub fn store_receipt(
        &self,
        manifest: &ExecutionManifest,
        profile: &RunnerProfile,
        paths: Vec<OwnedPath>,
    ) -> Result<String, String> {
        if paths.is_empty() {
            return Err("a receipt must own at least one created path".to_string());
        }
        let seed = serde_json::json!({
            "request_hash": &manifest.request_hash,
            "action_id": &manifest.action_id,
            "profile_id": &profile.profile_id,
            "at": utc_now(),
            "pid": std::process::id(),
            "paths": &paths,
        });
        let receipt_id =
            crate::contract::sha256_hex(crate::contract::canonical_json(&seed).as_bytes());
        let record = ReceiptRecord {
            schema_version: RECEIPT_SCHEMA.to_string(),
            receipt_id: receipt_id.clone(),
            request_hash: manifest.request_hash.clone(),
            action_id: manifest.action_id.clone(),
            runner_profile_id: profile.profile_id.clone(),
            created_at: utc_now(),
            paths,
        };
        let encoded = serde_json::to_vec_pretty(&record)
            .map_err(|error| format!("cannot serialize receipt: {error}"))?;
        let receipts_dir = self.ensure_state_dirs()?;
        let receipt_path = receipts_dir.join(format!("{receipt_id}.json"));
        let mut created = false;
        let persisted = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&receipt_path)
                .map_err(|error| format!("cannot persist receipt: {error}"))?;
            created = true;
            file.write_all(&encoded)
                .map_err(|error| format!("cannot write receipt: {error}"))?;
            file.sync_all()
                .map_err(|error| format!("cannot sync receipt: {error}"))
        })();
        if let Err(error) = persisted {
            if created {
                let _ = fs::remove_file(&receipt_path);
            }
            let _ = fs::remove_dir(&receipts_dir);
            let _ = fs::remove_dir(self.root.join(STATE_DIR));
            return Err(error);
        }
        Ok(receipt_id)
    }

    pub fn load_receipt(&self, receipt_id: &str) -> Result<Option<ReceiptRecord>, String> {
        if receipt_id.len() != 64 || !receipt_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
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
        Ok(Some(record))
    }

    pub fn delete_receipt(&self, receipt_id: &str) -> Result<(), String> {
        if receipt_id.len() != 64 || !receipt_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err("receipt ID must be a 64-character hexadecimal digest".to_string());
        }
        let path = self
            .root
            .join(STATE_DIR)
            .join(RECEIPT_DIR)
            .join(format!("{receipt_id}.json"));
        match fs::remove_file(path) {
            Ok(()) => {
                let receipts = self.root.join(STATE_DIR).join(RECEIPT_DIR);
                let state = self.root.join(STATE_DIR);
                let _ = fs::remove_dir(receipts);
                let _ = fs::remove_dir(state);
                Ok(())
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(format!("cannot remove consumed receipt: {error}")),
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
