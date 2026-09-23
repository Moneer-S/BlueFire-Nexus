//! Protected, read-only inspection of one reviewed Linux native tool.

#[cfg(target_os = "linux")]
use std::fs::File;
use std::time::Duration;
#[cfg(target_os = "linux")]
use std::time::Instant;

use crate::native_tool_installations::NativeToolInstallation;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NativeToolInspectionError {
    pub(crate) code: &'static str,
    pub(crate) message: &'static str,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MetadataIdentity {
    device: u64,
    inode: u128,
    mode: u32,
    uid: u32,
    gid: u32,
    size: u64,
    mtime_ns: i128,
    ctime_ns: i128,
    links: u64,
}

#[derive(Debug)]
pub(crate) struct InspectedNativeTool {
    #[cfg(target_os = "linux")]
    file: File,
    pub(crate) installation_digest: String,
    pub(crate) content_sha256: String,
    pub(crate) size_bytes: u64,
    #[cfg(target_os = "linux")]
    edges: Vec<(File, String, MetadataIdentity, bool)>,
    #[cfg(target_os = "linux")]
    identity: MetadataIdentity,
    #[cfg(target_os = "linux")]
    deadline: Instant,
}

impl InspectedNativeTool {
    pub(crate) fn observed_identity(&self) -> (&str, u64) {
        (&self.content_sha256, self.size_bytes)
    }
}

#[cfg(target_os = "linux")]
impl InspectedNativeTool {
    #[cfg(target_os = "linux")]
    pub(crate) fn fd(&self) -> std::os::fd::RawFd {
        use std::os::fd::AsRawFd;
        self.file.as_raw_fd()
    }

    pub(crate) fn recheck(&self) -> Result<(), NativeToolInspectionError> {
        #[cfg(target_os = "linux")]
        {
            if Instant::now() >= self.deadline {
                return Err(timeout_error());
            }
            let metadata = self.file.metadata().map_err(|_| unavailable())?;
            protected(&self.file, false)?;
            if identity(&metadata) != self.identity || metadata.len() != self.size_bytes {
                return Err(changed());
            }
            if hash_file(&self.file, self.size_bytes, self.deadline)? != self.content_sha256 {
                return Err(changed());
            }
            without_capabilities(&self.file)?;
            let after = self.file.metadata().map_err(|_| unavailable())?;
            if identity(&after) != self.identity || after.len() != self.size_bytes {
                return Err(changed());
            }
            for (parent, name, expected, directory) in &self.edges {
                if Instant::now() >= self.deadline {
                    return Err(timeout_error());
                }
                protected(parent, true)?;
                let child = openat_file(parent, name, *directory).map_err(|_| changed())?;
                let current = child.metadata().map_err(|_| changed())?;
                protected(&child, *directory)?;
                if identity(&current) != *expected {
                    return Err(changed());
                }
            }
            if Instant::now() >= self.deadline {
                return Err(timeout_error());
            }
            Ok(())
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(unsupported())
        }
    }
}

pub(crate) fn inspect(
    installation: &NativeToolInstallation,
    timeout: Duration,
) -> Result<InspectedNativeTool, NativeToolInspectionError> {
    #[cfg(target_os = "linux")]
    {
        inspect_linux(installation, timeout)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (installation, timeout);
        Err(unsupported())
    }
}

pub(crate) fn inspect_candidate(
    installation_location: &str,
    architecture: &str,
    candidate_digest: String,
    timeout: Duration,
) -> Result<InspectedNativeTool, NativeToolInspectionError> {
    #[cfg(target_os = "linux")]
    {
        inspect_linux_core(
            installation_location,
            architecture,
            None,
            candidate_digest,
            timeout,
        )
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (
            installation_location,
            architecture,
            candidate_digest,
            timeout,
        );
        Err(unsupported())
    }
}

#[cfg(target_os = "linux")]
fn inspect_linux(
    installation: &NativeToolInstallation,
    timeout: Duration,
) -> Result<InspectedNativeTool, NativeToolInspectionError> {
    installation.validate().map_err(|_| invalid())?;
    let host_arch = match std::env::consts::ARCH {
        "x86_64" => "x86_64",
        "aarch64" => "aarch64",
        _ => return Err(unsupported()),
    };
    if installation.platform != "linux" || installation.architecture != host_arch {
        return Err(unsupported());
    }
    let inspected = inspect_linux_core(
        &installation.installation_location,
        &installation.architecture,
        Some((
            installation.size_bytes,
            installation.content_sha256.as_str(),
        )),
        installation.digest(),
        timeout,
    )?;
    // The observed bytes must also be a known GNU build. A stable, protected
    // ELF and an operator-declared version alone do not establish tool identity.
    crate::reviewed_native_builds::verify(installation).map_err(|error| {
        NativeToolInspectionError {
            code: error.code,
            message: error.message,
        }
    })?;
    Ok(inspected)
}

#[cfg(target_os = "linux")]
fn inspect_linux_core(
    installation_location: &str,
    architecture: &str,
    expected: Option<(u64, &str)>,
    installation_digest: String,
    timeout: Duration,
) -> Result<InspectedNativeTool, NativeToolInspectionError> {
    let host_arch = match std::env::consts::ARCH {
        "x86_64" => "x86_64",
        "aarch64" => "aarch64",
        _ => return Err(unsupported()),
    };
    if architecture != host_arch {
        return Err(unsupported());
    }
    let started = Instant::now();
    check_deadline(started, timeout)?;
    let root = open_root().map_err(|_| unavailable())?;
    protected(&root, true)?;
    if !installation_location.starts_with('/') {
        return Err(invalid());
    }
    let components: Vec<&str> = installation_location.split('/').skip(1).collect();
    if components.is_empty()
        || components
            .iter()
            .any(|part| part.is_empty() || *part == "." || *part == "..")
    {
        return Err(invalid());
    }
    let mut parent = root.try_clone().map_err(|_| unavailable())?;
    let mut edges = Vec::new();
    for component in &components[..components.len() - 1] {
        check_deadline(started, timeout)?;
        let child = openat_file(&parent, component, true).map_err(|_| unavailable())?;
        let metadata = child.metadata().map_err(|_| unavailable())?;
        protected(&child, true)?;
        let held = identity(&metadata);
        edges.push((
            parent.try_clone().map_err(|_| unavailable())?,
            (*component).to_string(),
            held,
            true,
        ));
        parent = child;
    }
    let file = openat_file(
        &parent,
        components.last().copied().ok_or_else(invalid)?,
        false,
    )
    .map_err(|_| unavailable())?;
    protected(&file, false)?;
    let before = file.metadata().map_err(|_| unavailable())?;
    if !(1..=crate::native_tool_installations::MAX_SIZE_BYTES).contains(&before.len()) {
        return Err(size_mismatch());
    }
    if let Some((size, _)) = expected {
        if before.len() != size {
            return Err(size_mismatch());
        }
    }
    without_capabilities(&file)?;
    let digest = hash_file(
        &file,
        before.len(),
        started.checked_add(timeout).unwrap_or(started),
    )?;
    let after = file.metadata().map_err(|_| unavailable())?;
    if identity(&before) != identity(&after) {
        return Err(changed());
    }
    let expected_machine = if architecture == "x86_64" { 62 } else { 183 };
    let mut header = [0_u8; 64];
    use std::os::unix::fs::FileExt;
    if file.read_at(&mut header, 0).map_err(|_| unavailable())? != header.len() {
        return Err(unsupported_binary());
    }
    validate_elf_header(&header, expected_machine)?;
    if let Some((_, content)) = expected {
        if digest != content {
            return Err(digest_mismatch());
        }
    }
    without_capabilities(&file)?;
    edges.push((
        parent,
        components.last().unwrap().to_string(),
        identity(&before),
        false,
    ));
    protected(&root, true)?;
    check_deadline(started, timeout)?;
    let inspected = InspectedNativeTool {
        file,
        installation_digest,
        content_sha256: digest,
        size_bytes: before.len(),
        edges,
        identity: identity(&before),
        deadline: started.checked_add(timeout).unwrap_or(started),
    };
    inspected.recheck()?;
    Ok(inspected)
}

#[cfg(target_os = "linux")]
fn hash_file(
    file: &File,
    size: u64,
    deadline: Instant,
) -> Result<String, NativeToolInspectionError> {
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::FileExt;
    let mut digest = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 65_536];
    while total <= size {
        if Instant::now() >= deadline {
            return Err(timeout_error());
        }
        let remaining = size.saturating_add(1).saturating_sub(total);
        let chunk_len = remaining.min(buffer.len() as u64) as usize;
        let read = file
            .read_at(&mut buffer[..chunk_len], total)
            .map_err(|_| unavailable())?;
        if read == 0 {
            break;
        }
        total += read as u64;
        digest.update(&buffer[..read]);
        if total > size {
            return Err(changed());
        }
    }
    if total != size {
        return Err(changed());
    }
    Ok(format!("sha256:{}", hex::encode(digest.finalize())))
}

#[cfg(target_os = "linux")]
fn check_deadline(started: Instant, timeout: Duration) -> Result<(), NativeToolInspectionError> {
    if started.elapsed() >= timeout {
        Err(timeout_error())
    } else {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn identity(metadata: &std::fs::Metadata) -> MetadataIdentity {
    use std::os::unix::fs::MetadataExt;
    MetadataIdentity {
        device: metadata.dev(),
        inode: metadata.ino() as u128,
        mode: metadata.mode(),
        uid: metadata.uid(),
        gid: metadata.gid(),
        size: metadata.size(),
        mtime_ns: metadata.mtime() as i128 * 1_000_000_000 + metadata.mtime_nsec() as i128,
        ctime_ns: metadata.ctime() as i128 * 1_000_000_000 + metadata.ctime_nsec() as i128,
        links: metadata.nlink(),
    }
}

#[cfg(target_os = "linux")]
fn protected(file: &File, directory: bool) -> Result<(), NativeToolInspectionError> {
    use std::os::unix::fs::MetadataExt;
    let metadata = file.metadata().map_err(|_| unavailable())?;
    let mode = metadata.mode();
    if (directory && (!metadata.is_dir() || metadata.uid() != 0 || mode & 0o022 != 0))
        || (!directory
            && (!metadata.is_file()
                || metadata.uid() != 0
                || mode & 0o7022 != 0
                || mode & 0o111 == 0
                || metadata.nlink() < 1))
    {
        return Err(unsafe_installation());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn without_capabilities(file: &File) -> Result<(), NativeToolInspectionError> {
    use std::os::fd::AsRawFd;
    // SAFETY: the descriptor is borrowed and the static attribute name is NUL terminated.
    let size = unsafe {
        fgetxattr(
            file.as_raw_fd(),
            c"security.capability".as_ptr(),
            std::ptr::null_mut(),
            0,
        )
    };
    if size == 0 {
        return Ok(());
    }
    if size < 0 && std::io::Error::last_os_error().raw_os_error() == Some(61) {
        return Ok(());
    }
    Err(unsafe_installation())
}

#[cfg(target_os = "linux")]
fn open_root() -> Result<File, std::io::Error> {
    open_path("/")
}

#[cfg(target_os = "linux")]
fn openat_file(parent: &File, name: &str, directory: bool) -> Result<File, std::io::Error> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd};
    let name = CString::new(name).map_err(|_| std::io::Error::from_raw_os_error(22))?;
    let flags = 0x0008_0000 | 0x0002_0000 | if directory { 0x0001_0000 } else { 0x0000_0800 };
    // SAFETY: parent is a live directory descriptor and name is a NUL-terminated component.
    let fd = unsafe { openat(parent.as_raw_fd(), name.as_ptr(), flags) };
    if fd < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}

#[cfg(target_os = "linux")]
fn open_path(path: &str) -> Result<File, std::io::Error> {
    use std::ffi::CString;
    use std::os::fd::FromRawFd;
    let path = CString::new(path).unwrap();
    // SAFETY: path is a NUL-terminated constant and flags do not request creation.
    let fd = unsafe { open(path.as_ptr(), 0x0008_0000 | 0x0001_0000 | 0x0002_0000) };
    if fd < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}

#[cfg(target_os = "linux")]
fn invalid() -> NativeToolInspectionError {
    NativeToolInspectionError {
        code: "invalid_installation",
        message: "The native tool installation record is invalid.",
    }
}
fn unsupported() -> NativeToolInspectionError {
    NativeToolInspectionError {
        code: "unsupported_platform",
        message: "Tool inspection requires its supported Linux host.",
    }
}
#[cfg(target_os = "linux")]
fn unavailable() -> NativeToolInspectionError {
    NativeToolInspectionError {
        code: "inspection_unavailable",
        message: "The protected tool installation could not be inspected.",
    }
}
#[cfg(target_os = "linux")]
fn unsafe_installation() -> NativeToolInspectionError {
    NativeToolInspectionError {
        code: "unsafe_installation",
        message: "The tool installation is not protected.",
    }
}
#[cfg(target_os = "linux")]
fn size_mismatch() -> NativeToolInspectionError {
    NativeToolInspectionError {
        code: "size_mismatch",
        message: "The installed tool differs from its reviewed size.",
    }
}
#[cfg(target_os = "linux")]
fn changed() -> NativeToolInspectionError {
    NativeToolInspectionError {
        code: "installation_changed",
        message: "The tool installation changed during inspection.",
    }
}
#[cfg(target_os = "linux")]
fn digest_mismatch() -> NativeToolInspectionError {
    NativeToolInspectionError {
        code: "digest_mismatch",
        message: "The installed tool differs from its reviewed digest.",
    }
}
#[cfg(target_os = "linux")]
fn unsupported_binary() -> NativeToolInspectionError {
    NativeToolInspectionError {
        code: "unsupported_binary",
        message: "The tool is not a supported native executable.",
    }
}
#[cfg(target_os = "linux")]
fn timeout_error() -> NativeToolInspectionError {
    NativeToolInspectionError {
        code: "inspection_timeout",
        message: "Tool inspection exceeded its setup budget.",
    }
}

#[cfg(target_os = "linux")]
fn validate_elf_header(
    header: &[u8; 64],
    expected_machine: u16,
) -> Result<(), NativeToolInspectionError> {
    if &header[..7] != b"\x7fELF\x02\x01\x01"
        || !matches!(u16::from_le_bytes([header[16], header[17]]), 2 | 3)
        || u16::from_le_bytes([header[18], header[19]]) != expected_machine
    {
        Err(unsupported_binary())
    } else {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
extern "C" {
    fn open(path: *const std::os::raw::c_char, flags: i32, ...) -> i32;
    fn openat(dirfd: i32, path: *const std::os::raw::c_char, flags: i32, ...) -> i32;
    fn fgetxattr(
        fd: i32,
        name: *const std::os::raw::c_char,
        value: *mut std::ffi::c_void,
        size: usize,
    ) -> isize;
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use sha2::Digest;
    use std::io::{Seek, SeekFrom, Write};
    use std::os::unix::fs::PermissionsExt;

    fn temp_path(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "bluefire-native-inspection-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[test]
    fn bounded_hash_preserves_original_position() {
        let path = temp_path("hash");
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        file.write_all(b"0123456789").unwrap();
        file.seek(SeekFrom::Start(4)).unwrap();
        let before = file.stream_position().unwrap();
        let digest = hash_file(
            &file,
            10,
            Instant::now().checked_add(Duration::from_secs(1)).unwrap(),
        )
        .unwrap();
        assert_eq!(
            digest,
            format!(
                "sha256:{}",
                hex::encode(sha2::Sha256::digest(b"0123456789"))
            )
        );
        assert_eq!(file.stream_position().unwrap(), before);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn hash_detects_changed_content() {
        let path = temp_path("changed");
        std::fs::write(&path, b"before").unwrap();
        let file = File::open(&path).unwrap();
        let expected = hash_file(
            &file,
            6,
            Instant::now().checked_add(Duration::from_secs(1)).unwrap(),
        )
        .unwrap();
        std::fs::write(&path, b"after!").unwrap();
        let actual = hash_file(
            &file,
            6,
            Instant::now().checked_add(Duration::from_secs(1)).unwrap(),
        )
        .unwrap();
        assert_ne!(actual, expected);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn elf_header_accepts_reviewed_architecture_and_rejects_magic_or_architecture() {
        let mut header = [0_u8; 64];
        header[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        header[16..18].copy_from_slice(&2_u16.to_le_bytes());
        header[18..20].copy_from_slice(&62_u16.to_le_bytes());
        assert!(validate_elf_header(&header, 62).is_ok());
        assert!(validate_elf_header(&header, 183).is_err());
        header[0] = 0;
        assert!(validate_elf_header(&header, 62).is_err());
    }

    #[test]
    fn invalid_record_and_timeout_refuse_before_path_inspection() {
        let mut installation = NativeToolInstallation {
            schema_version: crate::native_tool_installations::SCHEMA.into(),
            adapter_id: "sandbox.permission.chmod.v1".into(),
            adapter_version: "1.0.0".into(),
            adapter_contract_digest: format!("sha256:{}", "a".repeat(64)),
            tool_id: "gnu.coreutils.chmod.v1".into(),
            tool_version: "9.5".into(),
            platform: "windows".into(),
            architecture: "x86_64".into(),
            content_sha256: format!("sha256:{}", "b".repeat(64)),
            size_bytes: 1,
            installation_location: "/does/not/exist".into(),
        };
        assert_eq!(
            inspect(&installation, Duration::from_secs(1))
                .unwrap_err()
                .code,
            "invalid_installation"
        );
        installation.platform = "linux".into();
        assert_eq!(
            inspect(&installation, Duration::ZERO).unwrap_err().code,
            "inspection_timeout"
        );
    }

    #[test]
    fn writable_owned_temp_executable_is_refused() {
        let root = temp_path("unsafe");
        let bin = root.join("tool");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(&bin, b"not-an-elf").unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o777)).unwrap();
        let installation = NativeToolInstallation {
            schema_version: crate::native_tool_installations::SCHEMA.into(),
            adapter_id: "sandbox.permission.chmod.v1".into(),
            adapter_version: "1.0.0".into(),
            adapter_contract_digest: format!("sha256:{}", "a".repeat(64)),
            tool_id: "gnu.coreutils.chmod.v1".into(),
            tool_version: "9.5".into(),
            platform: "linux".into(),
            architecture: "x86_64".into(),
            content_sha256: format!("sha256:{}", "b".repeat(64)),
            size_bytes: 9,
            installation_location: bin.to_string_lossy().replace('\\', "/"),
        };
        let result = inspect(&installation, Duration::from_secs(1));
        assert!(matches!(
            result.unwrap_err().code,
            "unsafe_installation" | "inspection_unavailable"
        ));
        let _ = std::fs::remove_file(bin);
        let _ = std::fs::remove_dir(root);
    }
}
