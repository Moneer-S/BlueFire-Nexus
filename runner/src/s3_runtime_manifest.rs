//! Closed protected-runtime metadata; this parser does not install or enroll it.

use crate::canonical::{canonical_hash, canonical_json};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) const MAX_MANIFEST: usize = 2 * 1024 * 1024;
pub(crate) const MAX_FILES: usize = 8192;
pub(crate) const MAX_FILE: u64 = 64 * 1024 * 1024;
pub(crate) const MAX_TOTAL: u64 = 512 * 1024 * 1024;
// Exact reviewed five-distribution payload, including installer metadata. This
// binds observed source bytes, not merely version labels or an ambient install.
const SDK_INVENTORY: &str =
    "sha256:3a0b54afdb950def6428f2e0b837d254918757f3b0b145bfea376bc7ac68536b";
pub(crate) const WORKER_FILES: [&str; 10] = [
    "s3_access_runtime.py",
    "s3_access_worker_entry.py",
    "s3_access_contract.py",
    "s3_access_policy.py",
    "s3_access_wire.py",
    "s3_access_sdk.py",
    "s3_access_sdk_boundary.py",
    "s3_access_sdk_transport.py",
    "s3_access_worker.py",
    "util.py",
];

fn compiled_worker_generation() -> String {
    let sources: [(&str, &[u8]); 10] = [
        (
            "s3_access_runtime.py",
            include_bytes!("../../bluefire/s3_access_runtime.py"),
        ),
        (
            "s3_access_worker_entry.py",
            include_bytes!("../../bluefire/s3_access_worker_entry.py"),
        ),
        (
            "s3_access_contract.py",
            include_bytes!("../../bluefire/s3_access_contract.py"),
        ),
        (
            "s3_access_policy.py",
            include_bytes!("../../bluefire/s3_access_policy.py"),
        ),
        (
            "s3_access_wire.py",
            include_bytes!("../../bluefire/s3_access_wire.py"),
        ),
        (
            "s3_access_sdk.py",
            include_bytes!("../../bluefire/s3_access_sdk.py"),
        ),
        (
            "s3_access_sdk_boundary.py",
            include_bytes!("../../bluefire/s3_access_sdk_boundary.py"),
        ),
        (
            "s3_access_sdk_transport.py",
            include_bytes!("../../bluefire/s3_access_sdk_transport.py"),
        ),
        (
            "s3_access_worker.py",
            include_bytes!("../../bluefire/s3_access_worker.py"),
        ),
        ("util.py", include_bytes!("../../bluefire/util.py")),
    ];
    // Packaged Python source is LF-normalized, independent of the compiler
    // checkout's Windows text conversion. Runtime inventories still bind raw LF bytes.
    let rows: BTreeMap<_, _> = sources.into_iter().map(|(name, bytes)| {
        let canonical: Vec<u8> = bytes.iter().enumerate().filter_map(|(index, byte)|
            if *byte == b'\r' && bytes.get(index + 1) == Some(&b'\n') { None } else { Some(*byte) }).collect();
        (name, json!({"sha256":crate::canonical::sha256_hex(&canonical),"size_bytes":canonical.len()}))
    }).collect();
    canonical_hash(&serde_json::to_value(rows).expect("fixed source inventory"))
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FileRecord {
    pub(crate) sha256: String,
    pub(crate) size_bytes: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PythonRecord {
    pub(crate) path: String,
    pub(crate) sha256: String,
    pub(crate) size_bytes: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuntimeManifest {
    schema_version: String,
    pub(crate) python: PythonRecord,
    pub(crate) stdlib_root: String,
    pub(crate) sdk_root: String,
    pub(crate) worker_root: String,
    ca_bundle: String,
    distributions: BTreeMap<String, String>,
    pub(crate) files: BTreeMap<String, FileRecord>,
    pub(crate) worker_generation: String,
}

fn require(value: bool) -> Result<(), ()> {
    if value {
        Ok(())
    } else {
        Err(())
    }
}
fn hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub(crate) fn absolute(value: &str) -> bool {
    value.len() <= 4096
        && value.is_ascii()
        && value.starts_with('/')
        && !value.contains(['\\', '\0'])
        && !value
            .split('/')
            .skip(1)
            .any(|s| s.is_empty() || s == "." || s == "..")
}
fn relative(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && value.is_ascii()
        && !value.contains(['\\', '\0'])
        && !value
            .split('/')
            .any(|s| s.is_empty() || s == "." || s == ".." || s == "__pycache__")
        && !value.ends_with(".pyc")
        && !value.ends_with(".pth")
}

impl RuntimeManifest {
    pub(crate) fn parse(
        bytes: &[u8],
        root: &str,
        expected: &str,
        generation: &str,
    ) -> Result<Self, ()> {
        require(generation == compiled_worker_generation())?;
        require(!bytes.is_empty() && bytes.len() <= MAX_MANIFEST && absolute(root))?;
        let value: Value = serde_json::from_slice(bytes).map_err(|_| ())?;
        require(canonical_json(&value).as_bytes() == bytes && canonical_hash(&value) == expected)?;
        let manifest: Self = serde_json::from_slice(bytes).map_err(|_| ())?;
        require(
            manifest.schema_version == "bluefire.s3-sdk-runtime.v1"
                && manifest.worker_generation == generation
                && manifest.ca_bundle == "botocore/cacert.pem"
                && absolute(&manifest.python.path)
                && hash(&manifest.python.sha256)
                && (1..=MAX_FILE).contains(&manifest.python.size_bytes)
                && !manifest.files.is_empty()
                && manifest.files.len() <= MAX_FILES,
        )?;
        let roots = [
            &manifest.stdlib_root,
            &manifest.sdk_root,
            &manifest.worker_root,
        ];
        for (index, path) in roots.iter().enumerate() {
            require(absolute(path) && path.starts_with(&format!("{root}/")))?;
            for other in roots.iter().skip(index + 1) {
                require(
                    path != other
                        && !path.starts_with(&format!("{other}/"))
                        && !other.starts_with(&format!("{path}/")),
                )?;
            }
        }
        let versions: BTreeMap<String, String> = serde_json::from_value(json!({
            "botocore":"1.43.110", "jmespath":"1.1.0", "python-dateutil":"2.9.0.post0",
            "urllib3":"2.8.0", "six":"1.17.0",
        }))
        .map_err(|_| ())?;
        require(manifest.distributions == versions)?;
        let mut total = 0_u64;
        let mut workers = BTreeMap::new();
        let mut sdk = BTreeMap::new();
        let mut groups = BTreeSet::new();
        for (name, record) in &manifest.files {
            let (group, path) = name.split_once('/').ok_or(())?;
            require(
                ["stdlib", "sdk", "worker"].contains(&group)
                    && relative(path)
                    && hash(&record.sha256)
                    && record.size_bytes <= MAX_FILE,
            )?;
            groups.insert(group);
            total = total.checked_add(record.size_bytes).ok_or(())?;
            require(total <= MAX_TOTAL)?;
            if group == "worker" {
                require(WORKER_FILES.contains(&path))?;
                workers.insert(
                    path,
                    json!({"sha256":record.sha256,"size_bytes":record.size_bytes}),
                );
            } else if group == "sdk" {
                sdk.insert(
                    path,
                    json!({"sha256":record.sha256,"size_bytes":record.size_bytes}),
                );
            }
        }
        require(
            groups.len() == 3
                && workers.len() == WORKER_FILES.len()
                && manifest.files.contains_key("sdk/botocore/cacert.pem")
                && canonical_hash(&serde_json::to_value(sdk).map_err(|_| ())?) == SDK_INVENTORY
                && canonical_hash(&serde_json::to_value(workers).map_err(|_| ())?) == generation,
        )?;
        Ok(manifest)
    }
}
