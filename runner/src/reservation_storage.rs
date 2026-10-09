//! Descriptor-relative private storage shared by the two fixed reservation ledgers.

use std::ffi::{c_char, c_int, CString, OsStr};
use std::fs::{File, Metadata};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::canonical::canonical_json;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Error {
    InvalidConfiguration,
    StorageUnsafe,
    StorageCorrupt,
    StorageIo,
    StorageFull,
    Busy,
}

#[derive(Clone, Copy)]
pub(crate) enum JournalKind {
    Service,
    S3,
}
impl JournalKind {
    fn schema(self) -> &'static str {
        match self {
            Self::Service => "bluefire.service-reservation-store.v1",
            Self::S3 => "bluefire.s3-send-store.v1",
        }
    }
}

fn encoded(value: &impl Serialize) -> Result<Vec<u8>, Error> {
    let value = serde_json::to_value(value).map_err(|_| Error::StorageCorrupt)?;
    Ok(canonical_json(&value).into_bytes())
}

const O_RDWR: c_int = 2;
const O_CREAT: c_int = 0x40;
const O_EXCL: c_int = 0x80;
const O_APPEND: c_int = 0x400;
const O_NONBLOCK: c_int = 0x800;
const O_DIRECTORY: c_int = 0x10000;
const O_NOFOLLOW: c_int = 0x20000;
const O_CLOEXEC: c_int = 0x80000;
const LOCK_EX: c_int = 2;
const LOCK_NB: c_int = 4;

extern "C" {
    #[link_name = "open"]
    fn c_open(path: *const c_char, flags: c_int, ...) -> c_int;
    fn openat(directory: c_int, path: *const c_char, flags: c_int, ...) -> c_int;
    fn flock(descriptor: c_int, operation: c_int) -> c_int;
    fn geteuid() -> u32;
    fn getuid() -> u32;
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Identity {
    device: u64,
    inode: u64,
}

fn identity(metadata: &Metadata) -> Identity {
    Identity {
        device: metadata.dev(),
        inode: metadata.ino(),
    }
}

fn owner() -> Result<u32, Error> {
    // SAFETY: these identity reads have no preconditions or side effects.
    let (real, effective) = unsafe { (getuid(), geteuid()) };
    if real != effective {
        return Err(Error::StorageUnsafe);
    }
    Ok(effective)
}

fn owned_file(descriptor: c_int) -> Result<File, Error> {
    if descriptor < 0 {
        return Err(Error::StorageUnsafe);
    }
    // SAFETY: each successful open/openat result is a new owned descriptor.
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

fn component(parent: &File, name: &OsStr, directory: bool, flags: c_int) -> Result<File, Error> {
    let name = CString::new(name.as_bytes()).map_err(|_| Error::StorageUnsafe)?;
    // SAFETY: the name is a single NUL-terminated component, parent is alive,
    // and the fixed mode argument is provided for exclusive file creation.
    owned_file(unsafe {
        openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            flags | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK | if directory { O_DIRECTORY } else { 0 },
            0o600_u32,
        )
    })
}

fn private_file(file: &File, uid: u32) -> Result<Metadata, Error> {
    let metadata = file.metadata().map_err(|_| Error::StorageIo)?;
    if !metadata.is_file()
        || metadata.uid() != uid
        || metadata.mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(Error::StorageUnsafe);
    }
    Ok(metadata)
}

fn private_root(path: &Path, uid: u32) -> Result<File, Error> {
    if !path.is_absolute() || path.parent().is_none() {
        return Err(Error::InvalidConfiguration);
    }
    let root = CString::new("/").expect("fixed root");
    // SAFETY: root is NUL terminated; no creation or variadic mode is needed.
    let mut directory =
        owned_file(unsafe { c_open(root.as_ptr(), O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC) })?;
    for part in path.components() {
        let name = match part {
            Component::RootDir => continue,
            Component::Normal(name) => name,
            _ => return Err(Error::InvalidConfiguration),
        };
        let metadata = directory.metadata().map_err(|_| Error::StorageIo)?;
        // Sticky shared ancestors protect a child owned by this user/root.
        if !metadata.is_dir()
            || ![0, uid].contains(&metadata.uid())
            || (metadata.mode() & 0o022 != 0 && metadata.mode() & 0o1000 == 0)
        {
            return Err(Error::StorageUnsafe);
        }
        directory = component(&directory, name, true, 0)?;
    }
    let metadata = directory.metadata().map_err(|_| Error::StorageIo)?;
    if !metadata.is_dir() || metadata.uid() != uid || metadata.mode() & 0o7777 != 0o700 {
        return Err(Error::StorageUnsafe);
    }
    Ok(directory)
}

fn create_or_open(parent: &File, name: &str) -> Result<(File, bool), Error> {
    let name_c = CString::new(name).map_err(|_| Error::StorageUnsafe)?;
    // SAFETY: fixed name and flags; the parent descriptor stays alive.
    let descriptor = unsafe {
        openat(
            parent.as_raw_fd(),
            name_c.as_ptr(),
            O_RDWR | O_CREAT | O_EXCL | O_APPEND | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK,
            0o600_u32,
        )
    };
    if descriptor >= 0 {
        return Ok((owned_file(descriptor)?, true));
    }
    if std::io::Error::last_os_error().kind() != std::io::ErrorKind::AlreadyExists {
        return Err(Error::StorageIo);
    }
    Ok((
        component(parent, OsStr::new(name), false, O_RDWR | O_APPEND)?,
        false,
    ))
}

fn exclusive(file: &File) -> Result<(), Error> {
    // SAFETY: this fresh open description belongs to this lease. Closing it
    // releases the lock on every return/unwind; no stale lock-file deletion.
    if unsafe { flock(file.as_raw_fd(), LOCK_EX | LOCK_NB) } != 0 {
        return Err(
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::WouldBlock {
                Error::Busy
            } else {
                Error::StorageIo
            },
        );
    }
    Ok(())
}

#[derive(Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Header {
    schema_version: String,
    enrollment_digest: String,
    root: Identity,
    lock: Identity,
}

pub(crate) struct Storage {
    path: PathBuf,
    root: File,
    root_identity: Identity,
    lock_identity: Identity,
    ledger_identity: Identity,
    owner_uid: u32,
    header: Vec<u8>,
    max_bytes: usize,
}

pub(crate) struct Lease<'a> {
    store: &'a Storage,
    _lock: File,
    ledger: File,
}

impl Storage {
    pub(crate) fn open(
        path: &Path,
        enrollment_digest: &str,
        max_bytes: usize,
        kind: JournalKind,
    ) -> Result<Self, Error> {
        let owner_uid = owner()?;
        let root = private_root(path, owner_uid)?;
        let root_identity = identity(&root.metadata().map_err(|_| Error::StorageIo)?);
        let (lock, _) = create_or_open(&root, "reservation.lock")?;
        let metadata = private_file(&lock, owner_uid)?;
        if metadata.len() != 0 {
            return Err(Error::StorageUnsafe);
        }
        let lock_identity = identity(&metadata);
        exclusive(&lock)?;
        let (mut ledger, created) = create_or_open(&root, "reservations.jsonl")?;
        let ledger_identity = identity(&private_file(&ledger, owner_uid)?);
        let mut header = encoded(&Header {
            schema_version: kind.schema().into(),
            enrollment_digest: enrollment_digest.into(),
            root: root_identity,
            lock: lock_identity,
        })?;
        header.push(b'\n');
        if created {
            ledger.write_all(&header).map_err(|_| Error::StorageIo)?;
            ledger.sync_all().map_err(|_| Error::StorageIo)?;
            root.sync_all().map_err(|_| Error::StorageIo)?;
        }
        let store = Self {
            path: path.to_path_buf(),
            root,
            root_identity,
            lock_identity,
            ledger_identity,
            owner_uid,
            header,
            max_bytes,
        };
        let mut lease = Lease {
            store: &store,
            _lock: lock,
            ledger,
        };
        lease.read()?; // An interrupted or truncated header is never initialized again.
        drop(lease);
        Ok(store)
    }

    pub(crate) fn owner_uid(&self) -> u32 {
        self.owner_uid
    }

    fn check(&self) -> Result<(), Error> {
        if owner()? != self.owner_uid {
            return Err(Error::StorageUnsafe);
        }
        let root = private_root(&self.path, self.owner_uid)?;
        if identity(&root.metadata().map_err(|_| Error::StorageIo)?) != self.root_identity
            || identity(&self.root.metadata().map_err(|_| Error::StorageIo)?) != self.root_identity
        {
            return Err(Error::StorageUnsafe);
        }
        Ok(())
    }

    pub(crate) fn lease(&self) -> Result<Lease<'_>, Error> {
        self.check()?;
        let lock = component(&self.root, OsStr::new("reservation.lock"), false, O_RDWR)?;
        let metadata = private_file(&lock, self.owner_uid)?;
        if identity(&metadata) != self.lock_identity || metadata.len() != 0 {
            return Err(Error::StorageUnsafe);
        }
        exclusive(&lock)?;
        let ledger = component(
            &self.root,
            OsStr::new("reservations.jsonl"),
            false,
            O_RDWR | O_APPEND,
        )?;
        let lease = Lease {
            store: self,
            _lock: lock,
            ledger,
        };
        lease.check()?;
        Ok(lease)
    }
}

impl Lease<'_> {
    fn check(&self) -> Result<(), Error> {
        self.store.check()?;
        let named_lock = component(
            &self.store.root,
            OsStr::new("reservation.lock"),
            false,
            O_RDWR,
        )?;
        let named_ledger = component(
            &self.store.root,
            OsStr::new("reservations.jsonl"),
            false,
            O_RDWR,
        )?;
        for (file, expected) in [
            (&self._lock, self.store.lock_identity),
            (&named_lock, self.store.lock_identity),
            (&self.ledger, self.store.ledger_identity),
            (&named_ledger, self.store.ledger_identity),
        ] {
            if identity(&private_file(file, self.store.owner_uid)?) != expected {
                return Err(Error::StorageUnsafe);
            }
        }
        Ok(())
    }

    pub(crate) fn read(&mut self) -> Result<Vec<u8>, Error> {
        self.check()?;
        if self.ledger.metadata().map_err(|_| Error::StorageIo)?.len() > self.store.max_bytes as u64
        {
            return Err(Error::StorageFull);
        }
        self.ledger
            .seek(SeekFrom::Start(0))
            .map_err(|_| Error::StorageIo)?;
        let mut bytes = Vec::new();
        (&mut self.ledger)
            .take(self.store.max_bytes as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| Error::StorageIo)?;
        if bytes.len() > self.store.max_bytes {
            return Err(Error::StorageFull);
        }
        if !bytes.starts_with(&self.store.header) || !bytes.ends_with(b"\n") {
            return Err(Error::StorageCorrupt);
        }
        self.check()?;
        Ok(bytes[self.store.header.len()..].to_vec())
    }

    pub(crate) fn append(&mut self, record: &[u8], previous_bytes: usize) -> Result<(), Error> {
        self.check()?;
        let expected = self
            .store
            .header
            .len()
            .checked_add(previous_bytes)
            .ok_or(Error::StorageFull)?;
        if record.len() > 16 * 1024
            || expected
                .checked_add(record.len())
                .is_none_or(|total| total > self.store.max_bytes)
        {
            return Err(Error::StorageFull);
        }
        if self.ledger.metadata().map_err(|_| Error::StorageIo)?.len() != expected as u64 {
            return Err(Error::StorageCorrupt);
        }
        self.ledger
            .write_all(record)
            .map_err(|_| Error::StorageIo)?;
        self.ledger.sync_all().map_err(|_| Error::StorageIo)?;
        self.store.root.sync_all().map_err(|_| Error::StorageIo)?;
        self.check()?;
        if self.ledger.metadata().map_err(|_| Error::StorageIo)?.len()
            != (expected + record.len()) as u64
        {
            return Err(Error::StorageCorrupt);
        }
        Ok(())
    }
}
