//! Fixed GNU chmod invocation on one held receipt-owned input.

use std::time::Duration;

use crate::native_tool_installations::NativeToolInstallation;
use crate::safety::{OwnedReceiptInput, SafeRoot};

#[derive(Debug)]
pub(crate) struct ChmodError {
    pub code: &'static str,
    pub message: &'static str,
    pub executed: bool,
}

#[derive(Debug)]
pub(crate) struct ChmodOutput {
    pub before_mode: u32,
    pub after_mode: u32,
    pub exit_code: Option<i32>,
    pub installation_digest: String,
    pub stdout_bytes: usize,
    pub stderr_bytes: usize,
}

pub(crate) fn change_mode(
    installation: &NativeToolInstallation,
    input: &OwnedReceiptInput,
    root: &SafeRoot,
    mode: &str,
    timeout: Duration,
    output_limits: (usize, usize),
) -> Result<ChmodOutput, ChmodError> {
    if !matches!(mode, "0600" | "0640" | "0660" | "0666") {
        return Err(error(
            "invalid_mode",
            "The requested permission mode is not reviewed.",
            false,
        ));
    }
    #[cfg(target_os = "linux")]
    {
        change_linux(installation, input, root, mode, timeout, output_limits)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (installation, input, root, timeout, output_limits);
        Err(error(
            "unsupported_platform",
            "GNU chmod requires a supported Linux host.",
            false,
        ))
    }
}

fn error(code: &'static str, message: &'static str, executed: bool) -> ChmodError {
    ChmodError {
        code,
        message,
        executed,
    }
}

#[cfg(target_os = "linux")]
fn change_linux(
    installation: &NativeToolInstallation,
    input: &OwnedReceiptInput,
    root: &SafeRoot,
    mode: &str,
    timeout: Duration,
    output_limits: (usize, usize),
) -> Result<ChmodOutput, ChmodError> {
    use std::io::Read;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::process::CommandExt;
    use std::process::{Child, Command, Stdio};
    use std::thread;
    use std::time::Instant;

    let started = Instant::now();
    let timeout = timeout.min(Duration::from_secs(5));
    let deadline = started.checked_add(timeout).unwrap_or(started);
    let inspected = crate::native_tool_inspection::inspect(installation, timeout)
        .map_err(|issue| error(issue.code, issue.message, false))?;
    input
        .recheck_attachment_until(root, deadline)
        .map_err(|_| {
            if Instant::now() >= deadline {
                return error(
                    "timed_out",
                    "The input verification deadline elapsed before execution.",
                    false,
                );
            }
            error(
                "input_changed",
                "The receipt-owned input changed before execution.",
                false,
            )
        })?;
    inspected
        .recheck()
        .map_err(|issue| error(issue.code, issue.message, false))?;
    let before_mode = input
        .file()
        .metadata()
        .map_err(|_| {
            error(
                "input_unavailable",
                "The receipt-owned input could not be inspected.",
                false,
            )
        })?
        .mode()
        & 0o7777;
    if started.elapsed() >= timeout {
        return Err(error(
            "timed_out",
            "The permission operation deadline elapsed before execution.",
            false,
        ));
    }
    let input_fd = input.file().as_raw_fd();
    let expected_parent = std::process::id() as i32;
    let mut command = Command::new(format!("/proc/self/fd/{}", inspected.fd()));
    command
        .arg0(&installation.installation_location)
        .args([mode, "--", &format!("/proc/self/fd/{input_fd}")])
        .env_clear()
        .env("LC_ALL", "C")
        .current_dir(root.path())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // SAFETY: only fixed async-signal-safe syscalls run between fork and exec.
    // The input is the sole additional inherited fd; executable resolution
    // uses its held fd before the kernel applies close-on-exec.
    unsafe {
        command.pre_exec(move || {
            if getppid() != expected_parent
                || setpgid(0, 0) != 0
                || prctl(1, 9, 0_usize, 0_usize, 0_usize) != 0
                || prctl(38, 1, 0_usize, 0_usize, 0_usize) != 0
                || getppid() != expected_parent
            {
                return Err(std::io::Error::from_raw_os_error(3));
            }
            let flags = fcntl(input_fd, 1);
            if flags < 0 || fcntl(input_fd, 2, flags & !1) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    struct Reap(Child, bool, bool);
    impl Reap {
        fn terminate(&mut self) {
            // SAFETY: this child created its private process group in pre_exec.
            // The unreaped child pins its PID while the group is terminated.
            let killed = unsafe { kill(-(self.0.id() as i32), 9) };
            // ESRCH means the owned group is already absent. Any other error
            // leaves group cleanup unknown even if the direct child is reaped.
            if killed != 0 && std::io::Error::last_os_error().raw_os_error() != Some(3) {
                self.2 = true;
            }
            self.1 = true;
            let _ = self.0.kill();
        }
    }
    impl Drop for Reap {
        fn drop(&mut self) {
            if !self.1 {
                self.terminate();
            }
            let _ = self.0.wait();
        }
    }
    let mut child = Reap(
        command.spawn().map_err(|_| {
            error(
                "spawn_failed",
                "The reviewed GNU chmod process could not start.",
                false,
            )
        })?,
        false,
        false,
    );
    // Retain byte counts only: unexpected human output is not trusted evidence.
    fn drain(stream: &mut impl Read, count: &mut usize, limit: usize) -> std::io::Result<bool> {
        let mut bytes = [0_u8; 4096];
        loop {
            match stream.read(&mut bytes) {
                Ok(0) => return Ok(false),
                Ok(n) => {
                    *count = count.saturating_add(n);
                    if *count > limit {
                        return Ok(true);
                    }
                }
                Err(issue) if issue.kind() == std::io::ErrorKind::WouldBlock => return Ok(false),
                Err(issue) if issue.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(issue) => return Err(issue),
            }
        }
    }
    let mut stdout = child.0.stdout.take().expect("piped stdout");
    let mut stderr = child.0.stderr.take().expect("piped stderr");
    for fd in [stdout.as_raw_fd(), stderr.as_raw_fd()] {
        // SAFETY: these are held pipe descriptors; fixed commands set O_NONBLOCK.
        let configured = unsafe {
            let flags = fcntl(fd, 3);
            flags >= 0 && fcntl(fd, 4, flags | 0x800) >= 0
        };
        if !configured {
            child.terminate();
            return Err(error(
                "output_unavailable",
                "The permission process output could not be bounded.",
                true,
            ));
        }
    }
    let (mut stdout_bytes, mut stderr_bytes) = (0_usize, 0_usize);
    let mut failure = None;
    let status = loop {
        let output =
            drain(&mut stdout, &mut stdout_bytes, output_limits.0.min(8192)).and_then(|over| {
                drain(&mut stderr, &mut stderr_bytes, output_limits.1.min(8192))
                    .map(|more| over || more)
            });
        if output.is_err() {
            failure = Some(error(
                "output_unavailable",
                "The permission process output could not be accounted for.",
                true,
            ));
            child.terminate();
            break child.0.wait();
        }
        if started.elapsed() >= timeout || matches!(output, Ok(true)) {
            failure = Some(if matches!(output, Ok(true)) {
                error(
                    "output_limit",
                    "GNU chmod exceeded its reviewed output limit.",
                    true,
                )
            } else {
                error(
                    "timed_out",
                    "The permission operation exceeded its deadline.",
                    true,
                )
            });
            child.terminate();
            break child.0.wait();
        }
        // Do not reap before terminating the private process group. Keeping
        // our child unreaped pins its PID and prevents signalling a reused ID.
        let exited = (|| -> std::io::Result<bool> {
            let mut state = String::new();
            std::fs::File::open(format!("/proc/{}/stat", child.0.id()))?
                .take(4096)
                .read_to_string(&mut state)?;
            Ok(state
                .rsplit_once(") ")
                .is_some_and(|(_, fields)| fields.starts_with('Z') || fields.starts_with('X')))
        })();
        match exited {
            Ok(true) => {
                child.terminate();
                break child.0.wait();
            }
            Ok(false) => thread::sleep(Duration::from_millis(5)),
            Err(issue) => {
                child.terminate();
                let _ = child.0.wait();
                break Err(issue);
            }
        }
    };
    if child.2 {
        return Err(error(
            "process_cleanup_unknown",
            "The permission process group could not be terminated; cleanup requires reconciliation.",
            true,
        ));
    }
    if let Some(issue) = failure {
        return Err(issue);
    }
    let status = status.map_err(|_| {
        error(
            "process_failed",
            "The permission process could not be reaped normally.",
            true,
        )
    })?;
    let overflow = drain(&mut stdout, &mut stdout_bytes, output_limits.0.min(8192))
        .and_then(|over| {
            drain(&mut stderr, &mut stderr_bytes, output_limits.1.min(8192))
                .map(|more| over || more)
        })
        .map_err(|_| {
            error(
                "output_unavailable",
                "The permission process output could not be accounted for.",
                true,
            )
        })?;
    if overflow {
        return Err(error(
            "output_limit",
            "GNU chmod exceeded its reviewed output limit.",
            true,
        ));
    }
    inspected
        .recheck()
        .map_err(|issue| error(issue.code, issue.message, true))?;
    input
        .recheck_attachment_until(root, deadline)
        .map_err(|_| {
            if Instant::now() >= deadline {
                return error(
                    "timed_out",
                    "The input verification deadline elapsed; effects may remain.",
                    true,
                );
            }
            error(
                "input_changed",
                "The input changed during the permission operation; verify retained effects.",
                true,
            )
        })?;
    let after_mode = input
        .file()
        .metadata()
        .map_err(|_| {
            error(
                "observation_unavailable",
                "The final permission mode is unknown.",
                true,
            )
        })?
        .mode()
        & 0o7777;
    if started.elapsed() >= timeout {
        return Err(error(
            "timed_out",
            "The permission deadline elapsed during verification; effects may remain.",
            true,
        ));
    }
    Ok(ChmodOutput {
        before_mode,
        after_mode,
        exit_code: status.code(),
        installation_digest: inspected.installation_digest,
        stdout_bytes,
        stderr_bytes,
    })
}

#[cfg(target_os = "linux")]
unsafe extern "C" {
    fn getppid() -> i32;
    fn setpgid(pid: i32, pgid: i32) -> i32;
    fn prctl(option: i32, ...) -> i32;
    fn fcntl(fd: i32, cmd: i32, ...) -> i32;
    fn kill(pid: i32, sig: i32) -> i32;
}
