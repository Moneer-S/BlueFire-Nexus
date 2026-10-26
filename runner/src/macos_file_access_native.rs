//! Public Darwin 25 arm64 ABI only; this module never adopts creator custody.

use super::{Entry, REFUSAL};

#[derive(Debug, PartialEq, Eq)]
pub(super) struct Recipe {
    pub(super) held: i32,
    pub(super) channel: i32,
    pub(super) original_deadline_ns: u64,
    pub(super) uid: u32,
    pub(super) gid: u32,
    pub(super) groups: Vec<u32>,
}

#[cfg(any(test, all(target_os = "macos", target_arch = "aarch64")))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum StartupFailureStage {
    RuntimeSupportedCheck,
    InitialClockOrDeadline,
    InitialDescriptorInventory,
    ReadonlyDescriptor,
    CredentialSelection,
    PostDropDescriptorInventory,
    InitialResourceValidation,
    ChannelInitialization,
}

#[cfg(any(test, all(target_os = "macos", target_arch = "aarch64")))]
impl StartupFailureStage {
    pub(super) const fn exit_code(self) -> i32 {
        match self {
            Self::RuntimeSupportedCheck => 80,
            Self::InitialClockOrDeadline => 81,
            Self::InitialDescriptorInventory => 82,
            Self::ReadonlyDescriptor => 83,
            Self::CredentialSelection => 84,
            Self::PostDropDescriptorInventory => 85,
            Self::InitialResourceValidation => 86,
            Self::ChannelInitialization => 87,
        }
    }
}

#[cfg(any(test, all(target_os = "macos", target_arch = "aarch64")))]
pub(super) fn startup_step<T>(
    stage: StartupFailureStage,
    result: Result<T, ()>,
) -> Result<T, StartupFailureStage> {
    result.map_err(|_| stage)
}

fn decimal(value: &str) -> Result<u64, String> {
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(REFUSAL.into());
    }
    value.parse().map_err(|_| REFUSAL.into())
}

pub(super) fn recipe(args: &[String], entry: Entry) -> Result<Recipe, String> {
    if args.len() != 12
        || args[4] != "--original-deadline-ns"
        || args[6] != "--uid"
        || args[8] != "--gid"
        || args[10] != "--groups"
    {
        return Err(REFUSAL.into());
    }
    let (held, channel) = descriptors(&args[..4], entry)?;
    let original_deadline_ns = decimal(&args[5])?;
    if original_deadline_ns == 0 {
        return Err(REFUSAL.into());
    }
    let id = |value: &str| -> Result<u32, String> {
        let number = decimal(value)?;
        if number == 0 || number >= u32::MAX as u64 {
            return Err(REFUSAL.into());
        }
        Ok(number as u32)
    };
    let uid = id(&args[7])?;
    let gid = id(&args[9])?;
    let groups = args[11].split(',').map(id).collect::<Result<Vec<_>, _>>()?;
    if groups.is_empty()
        || groups.len() > 64
        || !groups.windows(2).all(|pair| pair[0] < pair[1])
        || !groups.contains(&gid)
    {
        return Err(REFUSAL.into());
    }
    Ok(Recipe {
        held,
        channel,
        original_deadline_ns,
        uid,
        gid,
        groups,
    })
}

#[cfg(any(test, all(target_os = "macos", target_arch = "aarch64")))]
pub(super) trait CredentialDrop {
    fn observe(&mut self) -> Result<super::Credentials, ()>;
    fn set_groups(&mut self, groups: &[u32]) -> Result<(), ()>;
    fn set_gid(&mut self, gid: u32) -> Result<(), ()>;
    fn set_uid(&mut self, uid: u32) -> Result<(), ()>;
}

#[cfg(any(test, all(target_os = "macos", target_arch = "aarch64")))]
pub(super) fn select_principal(
    backend: &mut impl CredentialDrop,
    recipe: &Recipe,
) -> Result<(), ()> {
    let expected = super::Credentials {
        real_uid: recipe.uid,
        effective_uid: recipe.uid,
        saved_uid: recipe.uid,
        real_gid: recipe.gid,
        effective_gid: recipe.gid,
        saved_gid: recipe.gid,
        groups: recipe.groups.clone(),
    };
    let initial = backend.observe()?;
    if initial.real_uid == 0
        && initial.effective_uid == 0
        && initial.saved_uid == 0
        && initial.real_gid == 0
        && initial.effective_gid == 0
        && initial.saved_gid == 0
    {
        backend.set_groups(&recipe.groups)?;
        backend.set_gid(recipe.gid)?;
        backend.set_uid(recipe.uid)?;
    } else if initial != expected {
        return Err(());
    }
    let actual = backend.observe()?;
    actual.validate().map_err(|_| ())?;
    if actual != expected {
        return Err(());
    }
    Ok(())
}

#[cfg(any(test, all(target_os = "macos", target_arch = "aarch64")))]
pub(super) fn inventory(
    rows: &[(i32, u32)],
    held: i32,
    channel: i32,
    read: Option<i32>,
) -> Result<(), ()> {
    let mut expected = vec![
        (0, None),
        (1, None),
        (2, None),
        (held, Some(1)),
        (channel, Some(2)),
    ];
    if let Some(fd) = read {
        if fd < 3 || fd == held || fd == channel {
            return Err(());
        }
        expected.push((fd, Some(1)));
    }
    if rows.len() != expected.len() {
        return Err(());
    }
    let mut actual = rows.to_vec();
    actual.sort_unstable();
    expected.sort_unstable();
    for ((fd, kind), (wanted, required)) in actual.iter().zip(&expected) {
        if fd != wanted
            || required.is_some_and(|value| *kind != value)
            || (required.is_none() && !matches!(*kind, 1 | 6))
        {
            return Err(());
        }
    }
    Ok(())
}

#[cfg(any(test, all(target_os = "macos", target_arch = "aarch64")))]
pub(super) fn absolute_nanos(ticks: u64, numer: u32, denom: u32) -> Result<u64, ()> {
    if numer == 0 || denom == 0 {
        return Err(());
    }
    let nanos = u128::from(ticks).checked_mul(u128::from(numer)).ok_or(())? / u128::from(denom);
    nanos.try_into().map_err(|_| ())
}

#[cfg(any(test, all(target_os = "macos", target_arch = "aarch64")))]
pub(super) fn original_deadline(now: u64, deadline: u64) -> Result<u64, ()> {
    if deadline <= now || deadline - now > 900_000_000_000 {
        Err(())
    } else {
        Ok(deadline)
    }
}

#[cfg(any(test, all(target_os = "macos", target_arch = "aarch64")))]
pub(super) fn frame_deadline(original: u64, first_byte: u64) -> Result<u64, ()> {
    if first_byte >= original {
        return Err(());
    }
    Ok(first_byte
        .checked_add(super::MAX_OPERATION_NS)
        .ok_or(())?
        .min(original))
}

pub(super) fn descriptors(args: &[String], entry: Entry) -> Result<(i32, i32), String> {
    let resource = if entry == Entry::Reader {
        "--directory-fd"
    } else {
        "--leaf-fd"
    };
    if args.len() != 4 || args[0] != resource || args[2] != "--channel-fd" {
        return Err(REFUSAL.into());
    }
    let parse = |value: &str| -> Result<i32, String> {
        if value.is_empty()
            || !value.bytes().all(|byte| byte.is_ascii_digit())
            || (value.len() > 1 && value.starts_with('0'))
        {
            return Err(REFUSAL.into());
        }
        value
            .parse::<i32>()
            .ok()
            .filter(|fd| *fd >= 3)
            .ok_or_else(|| REFUSAL.into())
    };
    let held = parse(&args[1])?;
    let channel = parse(&args[3])?;
    if held == channel {
        return Err(REFUSAL.into());
    }
    Ok((held, channel))
}

pub(super) fn available() -> bool {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        darwin::supported().is_ok()
    }
    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    {
        false
    }
}

pub(super) fn run(args: &[String], entry: Entry) -> Result<i32, String> {
    let recipe = recipe(args, entry)?;
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        match darwin::run(recipe, entry) {
            Ok(code) => Ok(code),
            Err(darwin::RunFailure::Startup(stage)) => Ok(stage.exit_code()),
            Err(darwin::RunFailure::Generic) => Err(REFUSAL.into()),
        }
    }
    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    {
        let _ = (recipe, entry);
        Err(REFUSAL.into())
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod darwin {
    use std::ffi::{c_char, c_int, c_void, CStr};
    use std::fs::File;
    use std::io::{Read, Write};
    use std::mem::{offset_of, size_of, ManuallyDrop};
    use std::os::fd::{FromRawFd, IntoRawFd};
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::net::UnixStream;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use super::super::{
        Backend, Clock, Credentials, Directory, Entry, Facts, OpenFailure, Session, LEAF,
        MAX_MESSAGE, MAX_REQUESTS,
    };

    #[derive(Debug)]
    pub(super) enum RunFailure {
        Startup(super::StartupFailureStage),
        Generic,
    }

    // Pinned public headers: apple-oss-distributions/xnu@ac9718fb1af618d5ce8678d0dc6e8a58f252216f
    // bsd/sys/{proc_info,mount,fcntl}.h and osfmk/mach/mach_time.h.
    #[repr(C)]
    struct BsdInfo {
        flags: u32,
        status: u32,
        xstatus: u32,
        pid: u32,
        ppid: u32,
        uid: u32,
        gid: u32,
        ruid: u32,
        rgid: u32,
        svuid: u32,
        svgid: u32,
        reserved: u32,
        comm: [c_char; 16],
        name: [c_char; 32],
        nfiles: u32,
        pgid: u32,
        jobc: u32,
        tdev: u32,
        tpgid: u32,
        nice: i32,
        start_sec: u64,
        start_usec: u64,
    }

    #[repr(C)]
    struct Timebase {
        numer: u32,
        denom: u32,
    }

    #[repr(C)]
    struct FdInfo {
        fd: i32,
        kind: u32,
    }

    #[link(name = "proc")]
    unsafe extern "C" {
        fn proc_pidinfo(
            pid: c_int,
            flavor: c_int,
            arg: u64,
            buffer: *mut c_void,
            size: c_int,
        ) -> c_int;
    }
    unsafe extern "C" {
        fn mach_absolute_time() -> u64;
        fn mach_timebase_info(info: *mut Timebase) -> c_int;
        // Libc@4e34d0559e3a1b081afeb8604d9e204a1f31321d include/sys/acl.h.
        fn acl_get_fd_np(fd: c_int, kind: c_int) -> *mut c_void;
        fn acl_get_entry(acl: *mut c_void, entry: c_int, result: *mut *mut c_void) -> c_int;
        fn acl_free(object: *mut c_void) -> c_int;
    }

    pub(super) fn supported() -> Result<(), ()> {
        if size_of::<BsdInfo>() != 136
            || offset_of!(BsdInfo, start_sec) != 120
            || offset_of!(BsdInfo, start_usec) != 128
            || size_of::<Timebase>() != 8
            || size_of::<FdInfo>() != 8
            || offset_of!(FdInfo, kind) != 4
            || size_of::<libc::statfs>() != 2168
            || offset_of!(libc::statfs, f_flags) != 64
            || offset_of!(libc::statfs, f_fstypename) != 72
            || libc::O_NOFOLLOW != 0x100
            || libc::O_CLOEXEC != 0x01000000
            || libc::O_DIRECTORY != 0x00100000
            || libc::MNT_LOCAL != 0x1000
            || libc::MNT_IGNORE_OWNERSHIP != 0x00200000
        {
            return Err(());
        }
        let mut name = unsafe { std::mem::zeroed::<libc::utsname>() };
        if unsafe { libc::uname(&mut name) } != 0 {
            return Err(());
        }
        let system = unsafe { CStr::from_ptr(name.sysname.as_ptr()) }.to_bytes();
        let machine = unsafe { CStr::from_ptr(name.machine.as_ptr()) }.to_bytes();
        let release = unsafe { CStr::from_ptr(name.release.as_ptr()) }.to_bytes();
        if system != b"Darwin" || machine != b"arm64" || !release.starts_with(b"25.") {
            return Err(());
        }
        clock().map(|_| ())
    }

    fn clock() -> Result<Clock, ()> {
        let wall = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ())?
            .as_millis();
        let mut info = Timebase { numer: 0, denom: 0 };
        if unsafe { mach_timebase_info(&mut info) } != 0 || info.numer == 0 || info.denom == 0 {
            return Err(());
        }
        // Same epoch and floor conversion as CPython's Darwin mach_absolute_time clock.
        let ticks = unsafe { mach_absolute_time() };
        let nanos = super::absolute_nanos(ticks, info.numer, info.denom)?;
        Ok(Clock {
            wall_ms: wall.try_into().map_err(|_| ())?,
            monotonic_ns: nanos,
        })
    }

    fn observed_principal() -> Result<Credentials, ()> {
        let mut info = unsafe { std::mem::zeroed::<BsdInfo>() };
        let pid = unsafe { libc::getpid() };
        if unsafe { proc_pidinfo(pid, 3, 0, (&mut info as *mut BsdInfo).cast(), 136) } != 136
            || info.pid != pid as u32
            || info.uid != unsafe { libc::geteuid() }
            || info.ruid != unsafe { libc::getuid() }
            || info.gid != unsafe { libc::getegid() }
            || info.rgid != unsafe { libc::getgid() }
        {
            return Err(());
        }
        let count = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
        if !(0..=64).contains(&count) {
            return Err(());
        }
        let mut groups = vec![0u32; count as usize];
        if unsafe { libc::getgroups(count, groups.as_mut_ptr()) } != count {
            return Err(());
        }
        // POSIX permits the effective group to be absent from supplementary groups.
        groups.push(info.gid);
        groups.sort_unstable();
        groups.dedup();
        Ok(Credentials {
            real_uid: info.ruid,
            effective_uid: info.uid,
            saved_uid: info.svuid,
            real_gid: info.rgid,
            effective_gid: info.gid,
            saved_gid: info.svgid,
            groups,
        })
    }

    fn principal() -> Result<Credentials, ()> {
        let result = observed_principal()?;
        result.validate().map_err(|_| ())?;
        Ok(result)
    }

    struct DropCredentials;

    impl super::CredentialDrop for DropCredentials {
        fn observe(&mut self) -> Result<Credentials, ()> {
            observed_principal()
        }
        fn set_groups(&mut self, groups: &[u32]) -> Result<(), ()> {
            if unsafe { libc::setgroups(groups.len() as i32, groups.as_ptr()) } == 0 {
                Ok(())
            } else {
                Err(())
            }
        }
        fn set_gid(&mut self, gid: u32) -> Result<(), ()> {
            if unsafe { libc::setgid(gid) } == 0 {
                Ok(())
            } else {
                Err(())
            }
        }
        fn set_uid(&mut self, uid: u32) -> Result<(), ()> {
            if unsafe { libc::setuid(uid) } == 0 {
                Ok(())
            } else {
                Err(())
            }
        }
    }

    fn empty_acl(fd: i32) -> Result<(), ()> {
        unsafe {
            *libc::__error() = 0;
        }
        let acl = unsafe { acl_get_fd_np(fd, 0x100) };
        if acl.is_null() {
            return if unsafe { *libc::__error() } == libc::ENOENT {
                Ok(())
            } else {
                Err(())
            };
        }
        let mut entry = std::ptr::null_mut();
        unsafe {
            *libc::__error() = 0;
        }
        let status = unsafe { acl_get_entry(acl, 0, &mut entry) };
        let empty = status == -1 && unsafe { *libc::__error() } == libc::EINVAL && entry.is_null();
        let freed = unsafe { acl_free(acl) } == 0;
        if empty && freed {
            Ok(())
        } else {
            Err(())
        }
    }

    fn apfs(fd: i32) -> Result<(), ()> {
        let mut filesystem = unsafe { std::mem::zeroed::<libc::statfs>() };
        if unsafe { libc::fstatfs(fd, &mut filesystem) } != 0 {
            return Err(());
        }
        let kind = filesystem
            .f_fstypename
            .iter()
            .map(|byte| *byte as u8)
            .collect::<Vec<_>>();
        if kind != [b'a', b'p', b'f', b's', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
            || filesystem.f_flags & libc::MNT_LOCAL as u32 == 0
            || filesystem.f_flags & libc::MNT_IGNORE_OWNERSHIP as u32 != 0
        {
            return Err(());
        }
        Ok(())
    }

    fn metadata(fd: i32) -> Result<std::fs::Metadata, ()> {
        if fd < 0 {
            return Err(());
        }
        let file = ManuallyDrop::new(unsafe { File::from_raw_fd(fd) });
        file.metadata().map_err(|_| ())
    }

    fn readonly(fd: i32) -> Result<(), ()> {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0
            || flags & libc::O_ACCMODE != libc::O_RDONLY
            || flags & !(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) != 0
        {
            return Err(());
        }
        if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
            return Err(());
        }
        Ok(())
    }

    fn descriptor_inventory(held: i32, channel: i32, read: Option<i32>) -> Result<(), ()> {
        let mut rows = unsafe { std::mem::zeroed::<[FdInfo; 16]>() };
        let bytes = unsafe {
            proc_pidinfo(
                libc::getpid(),
                1,
                0,
                rows.as_mut_ptr().cast(),
                size_of::<[FdInfo; 16]>() as i32,
            )
        };
        if bytes <= 0
            || bytes as usize >= size_of::<[FdInfo; 16]>()
            || !(bytes as usize).is_multiple_of(size_of::<FdInfo>())
        {
            return Err(());
        }
        let rows = &rows[..bytes as usize / size_of::<FdInfo>()];
        super::inventory(
            &rows
                .iter()
                .map(|row| (row.fd, row.kind))
                .collect::<Vec<_>>(),
            held,
            channel,
            read,
        )?;
        let mut null = unsafe { std::mem::zeroed::<libc::stat>() };
        if unsafe { libc::lstat(c"/dev/null".as_ptr(), &mut null) } != 0
            || null.st_mode & libc::S_IFMT != libc::S_IFCHR
        {
            return Err(());
        }
        for fd in 0..=2 {
            let meta = metadata(fd)?;
            let kind = meta.mode() & libc::S_IFMT as u32;
            if kind != libc::S_IFIFO as u32
                && (kind != libc::S_IFCHR as u32 || meta.rdev() != null.st_rdev as u64)
            {
                return Err(());
            }
        }
        Ok(())
    }

    struct Native {
        held: Option<i32>,
        channel: i32,
        read_fd: Option<i32>,
        entry: Entry,
        cleanup_unknown: bool,
    }

    impl Native {
        fn held(&self) -> Result<i32, ()> {
            self.held.ok_or(())
        }
        fn inventory(&self) -> Result<(), ()> {
            descriptor_inventory(self.held()?, self.channel, self.read_fd)
        }
    }

    impl Backend for Native {
        fn clock(&mut self) -> Result<Clock, ()> {
            clock()
        }
        fn principal(&mut self) -> Result<Credentials, ()> {
            self.inventory()?;
            principal()
        }
        fn directory(&mut self) -> Result<Directory, ()> {
            if self.entry != Entry::Reader {
                return Err(());
            }
            self.inventory()?;
            let fd = self.held()?;
            let before = metadata(fd)?;
            if !before.is_dir() || before.uid() != 0 || before.mode() & 0o7777 != 0o550 {
                return Err(());
            }
            empty_acl(fd)?;
            apfs(fd)?;
            let after = metadata(fd)?;
            if before.dev() != after.dev()
                || before.ino() != after.ino()
                || before.mode() != after.mode()
                || before.uid() != after.uid()
                || before.gid() != after.gid()
                || before.ctime() != after.ctime()
                || before.ctime_nsec() != after.ctime_nsec()
            {
                return Err(());
            }
            Ok(Directory {
                device: after.dev(),
                inode: after.ino(),
                owner_uid: after.uid(),
                group_gid: after.gid(),
                mode: "0550".into(),
            })
        }
        fn open_leaf(&mut self) -> Result<i32, OpenFailure> {
            if self.entry != Entry::Reader {
                return Err(OpenFailure::Unknown);
            }
            let directory = self.held().map_err(|_| OpenFailure::Unknown)?;
            let leaf = std::ffi::CString::new(LEAF).map_err(|_| OpenFailure::Unknown)?;
            let fd = unsafe {
                libc::openat(
                    directory,
                    leaf.as_ptr(),
                    libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd >= 3 {
                self.read_fd = Some(fd);
                return Ok(fd);
            }
            if fd >= 0 {
                let _ = unsafe { libc::close(fd) };
                return Err(OpenFailure::Unknown);
            }
            match std::io::Error::last_os_error().raw_os_error() {
                Some(libc::EACCES | libc::EPERM) => Err(OpenFailure::Denied),
                _ => Err(OpenFailure::Unknown),
            }
        }
        fn facts(&mut self, handle: i32) -> Result<Facts, ()> {
            self.inventory()?;
            let before = metadata(handle)?;
            if !before.is_file() || before.nlink() != 1 || before.mode() & 0o7000 != 0 {
                return Err(());
            }
            empty_acl(handle)?;
            apfs(handle)?;
            let after = metadata(handle)?;
            let facts = |meta: &std::fs::Metadata| Facts {
                device: meta.dev(),
                inode: meta.ino(),
                owner_uid: meta.uid(),
                group_gid: meta.gid(),
                mode: format!("{:04o}", meta.mode() & 0o7777),
                size: meta.size(),
                links: meta.nlink(),
                modified_ns: i128::from(meta.mtime()) * 1_000_000_000
                    + i128::from(meta.mtime_nsec()),
                changed_ns: i128::from(meta.ctime()) * 1_000_000_000
                    + i128::from(meta.ctime_nsec()),
            };
            let original = facts(&before);
            if original != facts(&after) {
                return Err(());
            }
            Ok(original)
        }
        fn read(&mut self, handle: i32, maximum: usize, deadline_ns: u64) -> Result<Vec<u8>, ()> {
            let mut bytes = Vec::new();
            let mut chunk = [0u8; 8192];
            while bytes.len() < maximum {
                if clock()?.monotonic_ns >= deadline_ns {
                    return Err(());
                }
                let capacity = chunk.len().min(maximum - bytes.len());
                let count = unsafe {
                    libc::pread(
                        handle,
                        chunk.as_mut_ptr().cast(),
                        capacity,
                        bytes.len() as libc::off_t,
                    )
                };
                if count < 0 {
                    return Err(());
                }
                if count == 0 {
                    return Ok(bytes);
                }
                bytes.extend_from_slice(&chunk[..count as usize]);
            }
            Ok(bytes)
        }
        fn close_read(&mut self, handle: i32) -> Result<(), ()> {
            if self.read_fd.take() != Some(handle) {
                self.cleanup_unknown = true;
                return Err(());
            }
            if unsafe { libc::close(handle) } == 0 {
                Ok(())
            } else {
                self.cleanup_unknown = true;
                Err(())
            }
        }
        fn held_leaf(&mut self) -> Result<i32, ()> {
            if self.entry != Entry::OwnerControl {
                return Err(());
            }
            self.held()
        }
        fn set_mode(&mut self, handle: i32, mode: &str) -> Result<(), ()> {
            if self.entry != Entry::OwnerControl || self.held()? != handle {
                return Err(());
            }
            let target = match mode {
                "0600" => 0o600,
                "0640" => 0o640,
                _ => return Err(()),
            };
            if unsafe { libc::fchmod(handle, target) } == 0 {
                Ok(())
            } else {
                Err(())
            }
        }
        fn close_held(&mut self) -> Result<(), ()> {
            if let Some(fd) = self.held.take() {
                if unsafe { libc::close(fd) } != 0 {
                    self.cleanup_unknown = true;
                }
            }
            if self.cleanup_unknown {
                Err(())
            } else {
                Ok(())
            }
        }
    }

    impl Drop for Native {
        fn drop(&mut self) {
            let _ = self.close_held();
        }
    }

    fn channel(fd: i32) -> Result<UnixStream, ()> {
        let meta = metadata(fd)?;
        if meta.mode() & libc::S_IFMT as u32 != libc::S_IFSOCK as u32 {
            return Err(());
        }
        let mut kind = 0i32;
        let mut length = size_of::<i32>() as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_TYPE,
                (&mut kind as *mut i32).cast(),
                &mut length,
            )
        } != 0
            || length != size_of::<i32>() as libc::socklen_t
            || kind != libc::SOCK_STREAM
        {
            return Err(());
        }
        let mut peer = unsafe { std::mem::zeroed::<libc::sockaddr_un>() };
        let mut size = size_of::<libc::sockaddr_un>() as libc::socklen_t;
        if unsafe { libc::getpeername(fd, (&mut peer as *mut libc::sockaddr_un).cast(), &mut size) }
            != 0
            || peer.sun_family as i32 != libc::AF_UNIX
            || size < 2
            || size > size_of::<libc::sockaddr_un>() as libc::socklen_t
        {
            return Err(());
        }
        if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
            return Err(());
        }
        Ok(unsafe { UnixStream::from_raw_fd(fd) })
    }

    fn remaining(deadline: u64) -> Result<Duration, ()> {
        let nanos = deadline
            .checked_sub(clock()?.monotonic_ns)
            .filter(|n| *n > 0)
            .ok_or(())?;
        Ok(Duration::from_nanos(nanos))
    }

    fn read_exact(stream: &mut UnixStream, mut bytes: &mut [u8], deadline: u64) -> Result<(), ()> {
        while !bytes.is_empty() {
            stream
                .set_read_timeout(Some(remaining(deadline)?))
                .map_err(|_| ())?;
            let count = stream.read(bytes).map_err(|_| ())?;
            if count == 0 {
                return Err(());
            }
            bytes = &mut bytes[count..];
        }
        remaining(deadline).map(|_| ())
    }

    fn write_all(stream: &mut UnixStream, mut bytes: &[u8], deadline: u64) -> Result<(), ()> {
        while !bytes.is_empty() {
            stream
                .set_write_timeout(Some(remaining(deadline)?))
                .map_err(|_| ())?;
            let count = stream.write(bytes).map_err(|_| ())?;
            if count == 0 {
                return Err(());
            }
            bytes = &bytes[count..];
        }
        remaining(deadline).map(|_| ())
    }

    pub(super) fn run(recipe: super::Recipe, entry: Entry) -> Result<i32, RunFailure> {
        super::startup_step(
            super::StartupFailureStage::RuntimeSupportedCheck,
            supported(),
        )
        .map_err(RunFailure::Startup)?;
        let held = recipe.held;
        let channel_fd = recipe.channel;
        let now = super::startup_step(
            super::StartupFailureStage::InitialClockOrDeadline,
            clock().map(|value| value.monotonic_ns),
        )
        .map_err(RunFailure::Startup)?;
        super::startup_step(
            super::StartupFailureStage::InitialClockOrDeadline,
            super::original_deadline(now, recipe.original_deadline_ns),
        )
        .map_err(RunFailure::Startup)?;
        let mut backend = Native {
            held: Some(held),
            channel: channel_fd,
            read_fd: None,
            entry,
            cleanup_unknown: false,
        };
        let startup = (|| -> Result<(), super::StartupFailureStage> {
            super::startup_step(
                super::StartupFailureStage::InitialDescriptorInventory,
                backend.inventory(),
            )?;
            super::startup_step(
                super::StartupFailureStage::ReadonlyDescriptor,
                readonly(held),
            )?;
            super::startup_step(
                super::StartupFailureStage::CredentialSelection,
                super::select_principal(&mut DropCredentials, &recipe),
            )?;
            super::startup_step(
                super::StartupFailureStage::PostDropDescriptorInventory,
                backend.inventory(),
            )?;
            super::startup_step(
                super::StartupFailureStage::InitialResourceValidation,
                if entry == Entry::Reader {
                    backend.directory().map(|_| ())
                } else {
                    (|| {
                        let facts = backend.facts(held)?;
                        if facts.owner_uid != principal()?.effective_uid {
                            return Err(());
                        }
                        Ok(())
                    })()
                },
            )?;
            Ok(())
        })();
        if let Err(stage) = startup {
            return Err(RunFailure::Startup(stage));
        }
        let mut stream = match channel(channel_fd) {
            Ok(stream) => stream,
            Err(()) => {
                return Err(RunFailure::Startup(
                    super::StartupFailureStage::ChannelInitialization,
                ));
            }
        };
        let result = (|| {
            let mut session = Session::new();
            for _ in 0..MAX_REQUESTS {
                let mut length = [0u8; 4];
                // Idle wait never creates a new enrollment interval.
                read_exact(&mut stream, &mut length[..1], recipe.original_deadline_ns)?;
                let frame_deadline =
                    super::frame_deadline(recipe.original_deadline_ns, clock()?.monotonic_ns)?;
                read_exact(&mut stream, &mut length[1..], frame_deadline)?;
                let size = u32::from_le_bytes(length) as usize;
                if size == 0 || size > MAX_MESSAGE {
                    return Err(());
                }
                let mut raw = vec![0u8; size];
                read_exact(&mut stream, &mut raw, frame_deadline)?;
                let request = super::super::decode_request(&raw).map_err(|_| ())?;
                if request.binding.original_deadline_ns != recipe.original_deadline_ns {
                    return Err(());
                }
                let observation = session.execute(&mut backend, entry, &request);
                let output = serde_json::to_vec(&observation).map_err(|_| ())?;
                if output.len() > MAX_MESSAGE {
                    return Err(());
                }
                let reply_deadline = request.deadline_ns.min(frame_deadline);
                write_all(
                    &mut stream,
                    &(output.len() as u32).to_le_bytes(),
                    reply_deadline,
                )?;
                write_all(&mut stream, &output, reply_deadline)?;
                if session.closed {
                    return Ok(0);
                }
                if session.poisoned {
                    return Err(());
                }
            }
            Err(())
        })();
        let held_closed = backend.close_held().is_ok();
        let fd = stream.into_raw_fd();
        let channel_closed = unsafe { libc::close(fd) } == 0;
        if !held_closed || !channel_closed {
            return Err(RunFailure::Generic);
        }
        result.map_err(|_| RunFailure::Generic)
    }
}
