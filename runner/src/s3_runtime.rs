//! Descriptor-relative read-only verification of the enrolled fixed SDK runtime.

use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::ffi::CString;
use std::fs::File;
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{FileExt, MetadataExt};
use std::time::Instant;

use crate::native_tool_inspection::{inspect_candidate, InspectedNativeTool};
use crate::s3_runtime_manifest::{absolute, RuntimeManifest, MAX_FILES, MAX_MANIFEST};

pub(crate) struct S3Runtime {
    pub(crate) python: InspectedNativeTool,
    pub(crate) python_path: String,
    pub(crate) entry: String,
    pub(crate) root: String,
    pub(crate) digest: String,
}

fn require(value: bool) -> Result<(), ()> {
    if value {
        Ok(())
    } else {
        Err(())
    }
}
fn identity(value: &std::fs::Metadata) -> (u64, u64, u32, u32, u64, i64, i64, i64, i64) {
    (
        value.dev(),
        value.ino(),
        value.mode(),
        value.uid(),
        value.len(),
        value.mtime(),
        value.mtime_nsec(),
        value.ctime(),
        value.ctime_nsec(),
    )
}
fn protected(file: &File, directory: bool) -> Result<(), ()> {
    let meta = file.metadata().map_err(|_| ())?;
    require(
        meta.uid() == 0
            && meta.mode() & 0o7022 == 0
            && if directory {
                meta.is_dir()
            } else {
                meta.is_file() && meta.nlink() >= 1
            },
    )
}
fn openat(parent: i32, name: &str, directory: bool) -> Result<File, ()> {
    let name = CString::new(name).map_err(|_| ())?;
    let flags = libc::O_RDONLY
        | libc::O_CLOEXEC
        | libc::O_NOFOLLOW
        | libc::O_NONBLOCK
        | if directory { libc::O_DIRECTORY } else { 0 };
    let fd = unsafe { libc::openat(parent, name.as_ptr(), flags) };
    require(fd >= 0)?;
    let file = unsafe { File::from_raw_fd(fd) };
    protected(&file, directory)?;
    Ok(file)
}
fn directory(path: &str, deadline: Instant) -> Result<File, ()> {
    require(absolute(path) && Instant::now() < deadline)?;
    let mut current = openat(libc::AT_FDCWD, "/", true)?;
    for name in path.split('/').skip(1) {
        require(Instant::now() < deadline)?;
        current = openat(current.as_raw_fd(), name, true)?;
    }
    Ok(current)
}
fn content(file: &File, maximum: usize, deadline: Instant) -> Result<Vec<u8>, ()> {
    let before = file.metadata().map_err(|_| ())?;
    require(before.len() <= maximum as u64 && Instant::now() < deadline)?;
    let mut bytes = Vec::new();
    file.take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ())?;
    require(
        bytes.len() <= maximum
            && identity(&before) == identity(&file.metadata().map_err(|_| ())?)
            && Instant::now() < deadline,
    )?;
    Ok(bytes)
}
fn hash(file: &File, size: u64, deadline: Instant) -> Result<String, ()> {
    let before = file.metadata().map_err(|_| ())?;
    require(before.len() == size)?;
    let mut digest = Sha256::new();
    let mut offset = 0_u64;
    let mut chunk = [0_u8; 65536];
    loop {
        require(Instant::now() < deadline)?;
        let length =
            (size.saturating_add(1).saturating_sub(offset)).min(chunk.len() as u64) as usize;
        let count = file.read_at(&mut chunk[..length], offset).map_err(|_| ())?;
        if count == 0 {
            break;
        }
        offset += count as u64;
        require(offset <= size)?;
        digest.update(&chunk[..count]);
    }
    require(offset == size && identity(&before) == identity(&file.metadata().map_err(|_| ())?))?;
    Ok(hex::encode(digest.finalize()))
}
fn tree(
    file: &File,
    prefix: &str,
    manifest: &RuntimeManifest,
    seen: &mut BTreeSet<String>,
    directories: &mut usize,
    deadline: Instant,
) -> Result<(), ()> {
    require(Instant::now() < deadline && *directories <= MAX_FILES)?;
    let before = file.metadata().map_err(|_| ())?;
    for row in std::fs::read_dir(format!("/proc/self/fd/{}", file.as_raw_fd())).map_err(|_| ())? {
        require(Instant::now() < deadline)?;
        let row = row.map_err(|_| ())?;
        let name = row.file_name().into_string().map_err(|_| ())?;
        require(!name.contains(['/', '\\', '\0']) && name.is_ascii() && name != "__pycache__")?;
        let key = format!("{prefix}/{name}");
        require(key.len() <= 520)?;
        let kind = row.file_type().map_err(|_| ())?;
        if kind.is_dir() {
            *directories += 1;
            let child = openat(file.as_raw_fd(), &name, true)?;
            tree(&child, &key, manifest, seen, directories, deadline)?;
        } else {
            require(kind.is_file() && seen.len() < MAX_FILES && seen.insert(key.clone()))?;
            let record = manifest.files.get(&key).ok_or(())?;
            let child = openat(file.as_raw_fd(), &name, false)?;
            require(hash(&child, record.size_bytes, deadline)? == record.sha256)?;
        }
    }
    require(identity(&before) == identity(&file.metadata().map_err(|_| ())?))
}

impl S3Runtime {
    pub(crate) fn inspect(
        root: &str,
        expected: &str,
        generation: &str,
        deadline: Instant,
    ) -> Result<Self, ()> {
        let root_fd = directory(root, deadline)?;
        let manifest_fd = openat(root_fd.as_raw_fd(), "runtime.json", false)?;
        let bytes = content(&manifest_fd, MAX_MANIFEST, deadline)?;
        let manifest = RuntimeManifest::parse(&bytes, root, expected, generation)?;
        let mut seen = BTreeSet::new();
        let mut directories = 0;
        for (group, path) in [
            ("stdlib", &manifest.stdlib_root),
            ("sdk", &manifest.sdk_root),
            ("worker", &manifest.worker_root),
        ] {
            let base = directory(path, deadline)?;
            tree(
                &base,
                group,
                &manifest,
                &mut seen,
                &mut directories,
                deadline,
            )?;
        }
        require(seen.len() == manifest.files.len())?;
        let python = inspect_candidate(
            &manifest.python.path,
            std::env::consts::ARCH,
            expected.to_string(),
            deadline.saturating_duration_since(Instant::now()),
        )
        .map_err(|_| ())?;
        require(
            python.observed_identity()
                == (
                    format!("sha256:{}", manifest.python.sha256).as_str(),
                    manifest.python.size_bytes,
                ),
        )?;
        python.recheck().map_err(|_| ())?;
        require(Instant::now() < deadline)?;
        Ok(Self {
            python,
            python_path: manifest.python.path,
            entry: format!("{}/s3_access_worker_entry.py", manifest.worker_root),
            root: root.into(),
            digest: expected.into(),
        })
    }
}
