//! Linux-only fixed client launch. No caller argv, environment, shell or config.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::process::CommandExt;
use std::process::{Child, ChildStderr, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use super::{Cleanup, Issue, Retrieval, VerifiedSftpAdmission, CLEANUP_RESERVE, MAX_DIAGNOSTIC};
use crate::native_tool_inspection::{inspect_protected_record, InspectedNativeTool};

const POLL: Duration = Duration::from_millis(2);

pub(super) enum Chunk {
    Bytes(usize),
    Pending,
    Eof,
}

// Private deterministic lifecycle test seam, not a general process adapter.
pub(super) trait Driver {
    fn now(&self) -> Instant;
    fn pause(&mut self, duration: Duration);
    fn read(&mut self, stderr: bool) -> Result<Chunk, Issue>;
    fn exited(&mut self) -> Result<bool, Issue>;
    fn terminate(&mut self) -> bool;
    fn reap(&mut self) -> Result<Option<Option<i32>>, Issue>;
    fn group_absent(&mut self) -> bool;
}

pub(super) struct Capture {
    pub issue: Option<Issue>,
    pub cleanup: Cleanup,
    pub exit_code: Option<i32>,
    pub diagnostics_bytes: usize,
}

fn drain(
    driver: &mut impl Driver,
    capture: &mut Capture,
    ended: &mut [bool; 2],
) -> Result<(), Issue> {
    for (index, stderr) in [false, true].into_iter().enumerate() {
        if ended[index] {
            continue;
        }
        match driver.read(stderr)? {
            Chunk::Eof => ended[index] = true,
            Chunk::Pending => {}
            Chunk::Bytes(count) => {
                capture.diagnostics_bytes = capture.diagnostics_bytes.saturating_add(count);
                if capture.diagnostics_bytes > MAX_DIAGNOSTIC {
                    return Err(Issue::OutputLimit);
                }
            }
        }
    }
    Ok(())
}

pub(super) fn supervise(
    driver: &mut impl Driver,
    deadline: Instant,
    cancelled: &AtomicBool,
) -> Capture {
    let mut capture = Capture {
        issue: None,
        cleanup: Cleanup::Unknown,
        exit_code: None,
        diagnostics_bytes: 0,
    };
    let mut ended = [false; 2];
    let query_end = deadline.checked_sub(CLEANUP_RESERVE).unwrap_or(deadline);
    loop {
        let issue = if cancelled.load(Ordering::Acquire) {
            Some(Issue::Cancelled)
        } else if driver.now() >= query_end {
            Some(Issue::Deadline)
        } else {
            drain(driver, &mut capture, &mut ended).err()
        };
        if let Some(issue) = issue {
            capture.issue = Some(issue);
            break;
        }
        match driver.exited() {
            Ok(true) => break,
            Ok(false) => driver.pause(POLL.min(query_end.saturating_duration_since(driver.now()))),
            Err(issue) => {
                capture.issue = Some(issue);
                break;
            }
        }
    }
    // Match the existing query process safety: signal before reaping releases
    // the child PID which pins the owned process-group identifier.
    let signalled = driver.terminate();
    let mut reaped = false;
    while driver.now() < deadline {
        if let Err(issue) = drain(driver, &mut capture, &mut ended) {
            capture.issue.get_or_insert(issue);
        }
        if !reaped {
            match driver.reap() {
                Ok(Some(code)) => {
                    capture.exit_code = code;
                    reaped = true;
                }
                Ok(None) => {}
                Err(issue) => {
                    capture.issue.get_or_insert(issue);
                }
            }
        }
        if signalled && reaped && ended == [true, true] && driver.group_absent() {
            capture.cleanup = Cleanup::ReapedClientGroupAbsent;
            break;
        }
        driver.pause(POLL.min(deadline.saturating_duration_since(driver.now())));
    }
    if capture.cleanup == Cleanup::Unknown {
        capture.issue.get_or_insert(Issue::CleanupUnknown);
    }
    if capture.issue.is_none() && capture.exit_code != Some(0) {
        capture.issue = Some(Issue::ProtocolFailure);
    }
    capture
}

// memfd keeps partial or cancelled transfers anonymous: only verified bytes are
// subsequently passed to SafeRoot's pre-effect receipt/publication protocol.
fn memory_file(bytes: &[u8], sealed: bool) -> Result<File, Issue> {
    // SAFETY: fixed NUL-terminated label and flags; returned descriptor becomes
    // owned immediately. No path can be supplied to this private allocator.
    let fd = unsafe {
        libc::memfd_create(
            c"bluefire-sftp".as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        )
    };
    if fd < 0 {
        return Err(Issue::Io);
    }
    // SAFETY: fd is the newly created, exclusively owned memfd.
    let mut file = unsafe { File::from_raw_fd(fd) };
    // SAFETY: fixed mode on the held anonymous inode.
    if unsafe { libc::fchmod(fd, 0o600) } != 0 {
        return Err(Issue::Io);
    }
    file.write_all(bytes).map_err(|_| Issue::Io)?;
    file.seek(SeekFrom::Start(0)).map_err(|_| Issue::Io)?;
    if sealed {
        // SAFETY: fixed sealing commands prevent replacement/change of fixture
        // identity, host-key data and the single generated batch.
        let seals =
            libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
        if unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, seals) } < 0 {
            return Err(Issue::Io);
        }
    }
    Ok(file)
}

fn arguments(
    admission: &VerifiedSftpAdmission,
    transport: i32,
    identity: i32,
    hosts: i32,
) -> Vec<String> {
    // ssh.c closes its inherited descriptors. Its key/known-host inputs refer
    // to pinned parent-owned memfds instead; those handles remain alive until
    // the transport has ended. Inaccessible procfs fails authentication closed.
    let parent = std::process::id();
    let mut args: Vec<String> = [
        "-4",
        "-q",
        "-b",
        "-",
        "-F",
        "/dev/null",
        "-R",
        "1",
        "-B",
        "32768",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    args.extend([
        "-S".to_owned(),
        format!("/proc/self/fd/{transport}"),
        "-P".to_owned(),
        admission.port.to_string(),
    ]);
    for option in [
        "BatchMode=yes",
        "IdentitiesOnly=yes",
        "IdentityAgent=none",
        "CertificateFile=none",
        "StrictHostKeyChecking=yes",
        "GlobalKnownHostsFile=/dev/null",
        "CheckHostIP=yes",
        "VerifyHostKeyDNS=no",
        "UpdateHostKeys=no",
        "HostKeyAlgorithms=ssh-ed25519",
        "PubkeyAcceptedAlgorithms=ssh-ed25519",
        "PKCS11Provider=none",
        "SecurityKeyProvider=none",
        "PreferredAuthentications=publickey",
        "PasswordAuthentication=no",
        "KbdInteractiveAuthentication=no",
        "GSSAPIAuthentication=no",
        "HostbasedAuthentication=no",
        "NumberOfPasswordPrompts=0",
        "ProxyCommand=none",
        "ProxyJump=none",
        "PermitLocalCommand=no",
        "RemoteCommand=none",
        "ClearAllForwardings=yes",
        "ForwardAgent=no",
        "ForwardX11=no",
        "RequestTTY=no",
        "ControlMaster=no",
        "ControlPath=none",
        "ControlPersist=no",
        "ForkAfterAuthentication=no",
        "ConnectionAttempts=1",
        "ConnectTimeout=5",
        "LogLevel=ERROR",
        "Compression=no",
    ] {
        args.extend(["-o".to_owned(), option.to_owned()]);
    }
    args.extend([
        "-o".to_owned(),
        format!("IdentityFile=/proc/{parent}/fd/{identity}"),
    ]);
    args.extend([
        "-o".to_owned(),
        format!("UserKnownHostsFile=/proc/{parent}/fd/{hosts}"),
    ]);
    args.push(format!("{}@127.0.0.1", admission.reader));
    args
}

struct LinuxChild {
    child: Child,
    stdout: ChildStdout,
    stderr: ChildStderr,
    start_ticks: Option<u64>,
    signalled: bool,
    reaped: bool,
    output_ready: bool,
}

impl LinuxChild {
    fn spawn(
        admission: &VerifiedSftpAdmission,
        client: &InspectedNativeTool,
        transport: &InspectedNativeTool,
        batch: &File,
        output: &File,
        identity: &File,
        hosts: &File,
    ) -> Result<Self, Issue> {
        let mut command = Command::new(format!("/proc/self/fd/{}", client.fd()));
        command
            .arg0(&admission.installations[0].installation_location)
            .args(arguments(
                admission,
                transport.fd(),
                identity.as_raw_fd(),
                hosts.as_raw_fd(),
            ))
            .env_clear()
            .env("LC_ALL", "C")
            .current_dir("/")
            .stdin(Stdio::from(batch.try_clone().map_err(|_| Issue::Io)?))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let expected_parent = std::process::id() as i32;
        let inherited = [transport.fd(), output.as_raw_fd()];
        let size = admission.expected_size;
        // SAFETY: this closure contains only fixed async-signal-safe syscalls;
        // descriptor values and bounds are already validated before fork.
        unsafe {
            command.pre_exec(move || {
                if libc::getppid() != expected_parent
                    || libc::setpgid(0, 0) != 0
                    || libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0
                    || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
                    || libc::getppid() != expected_parent
                {
                    return Err(io::Error::from_raw_os_error(libc::ESRCH));
                }
                let limit = libc::rlimit {
                    rlim_cur: size,
                    rlim_max: size,
                };
                let zero = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                if libc::setrlimit(libc::RLIMIT_FSIZE, &limit) != 0
                    || libc::setrlimit(libc::RLIMIT_CORE, &zero) != 0
                {
                    return Err(io::Error::last_os_error());
                }
                for fd in inherited {
                    let flags = libc::fcntl(fd, libc::F_GETFD);
                    if flags < 0 || libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                        return Err(io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
        if Instant::now() >= admission.deadline {
            return Err(Issue::Deadline);
        }
        let mut child = command.spawn().map_err(|_| Issue::Spawn)?;
        let stdout = child.stdout.take().expect("piped stdout");
        let stderr = child.stderr.take().expect("piped stderr");
        let mut owned = Self {
            child,
            stdout,
            stderr,
            start_ticks: None,
            signalled: false,
            reaped: false,
            output_ready: true,
        };
        for fd in [owned.stdout.as_raw_fd(), owned.stderr.as_raw_fd()] {
            // SAFETY: fixed nonblocking flags on owned diagnostic pipes.
            let ready = unsafe {
                let flags = libc::fcntl(fd, libc::F_GETFL);
                flags >= 0 && libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) >= 0
            };
            if !ready {
                owned.output_ready = false;
            }
        }
        Ok(owned)
    }
}

impl Driver for LinuxChild {
    fn now(&self) -> Instant {
        Instant::now()
    }
    fn pause(&mut self, duration: Duration) {
        std::thread::sleep(duration);
    }
    fn read(&mut self, stderr: bool) -> Result<Chunk, Issue> {
        if !self.output_ready {
            return Err(Issue::Io);
        }
        let mut buffer = [0_u8; 4096];
        let result = if stderr {
            self.stderr.read(&mut buffer)
        } else {
            self.stdout.read(&mut buffer)
        };
        match result {
            Ok(0) => Ok(Chunk::Eof),
            Ok(count) => Ok(Chunk::Bytes(count)),
            Err(issue)
                if matches!(
                    issue.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                Ok(Chunk::Pending)
            }
            Err(_) => Err(Issue::Io),
        }
    }
    fn exited(&mut self) -> Result<bool, Issue> {
        let mut bytes = Vec::new();
        File::open(format!("/proc/{}/stat", self.child.id()))
            .and_then(|file| file.take(4097).read_to_end(&mut bytes))
            .map_err(|_| Issue::ProcessIdentity)?;
        let (exited, ticks) =
            crate::owned_child_identity::parse(&bytes, self.child.id(), std::process::id())
                .map_err(|_| Issue::ProcessIdentity)?;
        if self.start_ticks.is_some_and(|before| before != ticks) {
            return Err(Issue::ProcessIdentity);
        }
        self.start_ticks = Some(ticks);
        Ok(exited)
    }
    fn terminate(&mut self) -> bool {
        if self.signalled || self.reaped {
            return false;
        }
        self.signalled = true;
        // SAFETY: only the process group established by the owned unreaped child
        // is signalled; no caller PID, group, shell or daemon is accepted.
        let killed = unsafe { libc::kill(-(self.child.id() as i32), libc::SIGKILL) };
        let group = killed == 0 || io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH);
        let direct = match self.child.kill() {
            Ok(()) => true,
            Err(issue) => issue.raw_os_error() == Some(libc::ESRCH),
        };
        group && direct
    }
    fn reap(&mut self) -> Result<Option<Option<i32>>, Issue> {
        match self.child.try_wait().map_err(|_| Issue::CleanupUnknown)? {
            Some(status) => {
                self.reaped = true;
                Ok(Some(status.code()))
            }
            None => Ok(None),
        }
    }
    fn group_absent(&mut self) -> bool {
        // SAFETY: signal zero is read-only; reuse can only cause uncertainty.
        (unsafe { libc::kill(-(self.child.id() as i32), 0) }) != 0
            && io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
    }
}

impl Drop for LinuxChild {
    fn drop(&mut self) {
        if !self.reaped {
            if !self.signalled {
                self.terminate();
            }
            let _ = self.child.try_wait();
        }
    }
}

pub(super) fn retrieve(
    admission: &VerifiedSftpAdmission,
    cancelled: &AtomicBool,
) -> Result<Retrieval, Issue> {
    let client = inspect_protected_record(&admission.installations[0], admission.deadline)
        .map_err(|_| Issue::Installation)?;
    let transport = inspect_protected_record(&admission.installations[1], admission.deadline)
        .map_err(|_| Issue::Installation)?;
    let mut output = memory_file(&[], false)?;
    let batch = memory_file(
        format!(
            "get {} /proc/self/fd/{}\nbye\n",
            admission.remote_path,
            output.as_raw_fd()
        )
        .as_bytes(),
        true,
    )?;
    let identity = memory_file(&admission.fixture_private_key, true)?;
    let hosts = memory_file(&super::known_host(admission), true)?;
    if cancelled.load(Ordering::Acquire) {
        return Err(Issue::Cancelled);
    }
    client
        .recheck()
        .and_then(|_| transport.recheck())
        .map_err(|_| Issue::Installation)?;
    let mut child = LinuxChild::spawn(
        admission, &client, &transport, &batch, &output, &identity, &hosts,
    )?;
    let capture = supervise(&mut child, admission.deadline, cancelled);
    let mut result = Retrieval {
        bytes: Vec::new(),
        issue: capture.issue,
        cleanup: capture.cleanup,
        executed: true,
        exit_code: capture.exit_code,
        diagnostics_bytes: capture.diagnostics_bytes,
    };
    if result.issue.is_none() {
        if cancelled.load(Ordering::Acquire) {
            result.issue = Some(Issue::Cancelled);
        } else if Instant::now() >= admission.deadline {
            result.issue = Some(Issue::Deadline);
        } else if client.recheck().and_then(|_| transport.recheck()).is_err() {
            result.issue = Some(Issue::Installation);
        } else {
            let mut bytes = Vec::new();
            let read = output.seek(SeekFrom::Start(0)).and_then(|_| {
                (&mut output)
                    .take(admission.expected_size + 1)
                    .read_to_end(&mut bytes)
            });
            if read.is_err() {
                result.issue = Some(Issue::Io);
            } else if let Err(issue) = super::verify_bytes(admission, &bytes) {
                result.issue = Some(issue);
            } else {
                result.bytes = bytes;
            }
        }
    }
    // All anonymous handles stay owned until the client and fixed non-daemonized
    // SSH transport's group/pipe cleanup has been assessed. No key/partial bytes
    // or protocol diagnostics are persisted. This is not escaped-tree proof.
    Ok(result)
}

#[cfg(test)]
#[path = "owned_sftp_process_tests.rs"]
mod tests;
