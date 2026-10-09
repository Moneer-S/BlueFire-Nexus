//! Fixed Python worker process, with owned-group lifetime and bounded pipe IO.

use chrono::{DateTime, FixedOffset};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::process::CommandExt;
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, Stdio};
use std::time::{Duration, Instant};

use crate::s3_runtime::S3Runtime;
use crate::s3_worker_protocol::{Chunk, Driver};

pub(crate) struct LinuxWorker {
    child: Child,
    input: ChildStdin,
    output: ChildStdout,
    errors: ChildStderr,
    ticks: Option<u64>,
    reaped: bool,
    signalled: bool,
    io_ready: bool,
}

fn nonblocking(fd: RawFd) -> bool {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    flags >= 0 && unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } >= 0
}

impl LinuxWorker {
    pub(crate) fn spawn(runtime: &S3Runtime, deadline: Instant) -> Result<Self, ()> {
        runtime.python.recheck().map_err(|_| ())?;
        if Instant::now() >= deadline {
            return Err(());
        }
        let mut command = Command::new(format!("/proc/self/fd/{}", runtime.python.fd()));
        command
            .arg0(&runtime.python_path)
            .args(["-I", "-S", "-B"])
            .arg(&runtime.entry)
            .arg("--runtime-root")
            .arg(&runtime.root)
            .arg("--runtime-digest")
            .arg(&runtime.digest)
            .env_clear()
            .env("LC_ALL", "C")
            .current_dir("/")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let parent = std::process::id() as i32;
        // Fixed syscall-only post-fork setup. Resource limits bound this trusted
        // interpreter; they do not claim to isolate arbitrary same-UID code.
        unsafe {
            command.pre_exec(move || {
                let memory = libc::rlimit {
                    rlim_cur: 512 * 1024 * 1024,
                    rlim_max: 512 * 1024 * 1024,
                };
                let cpu = libc::rlimit {
                    rlim_cur: 60,
                    rlim_max: 60,
                };
                let files = libc::rlimit {
                    rlim_cur: 128,
                    rlim_max: 128,
                };
                let zero = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                if libc::getppid() != parent
                    || libc::setpgid(0, 0) != 0
                    || libc::prctl(
                        libc::PR_SET_PDEATHSIG,
                        libc::SIGKILL,
                        0_usize,
                        0_usize,
                        0_usize,
                    ) != 0
                    || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0_usize, 0_usize, 0_usize) != 0
                    || libc::setrlimit(libc::RLIMIT_AS, &memory) != 0
                    || libc::setrlimit(libc::RLIMIT_CPU, &cpu) != 0
                    || libc::setrlimit(libc::RLIMIT_NOFILE, &files) != 0
                    || libc::setrlimit(libc::RLIMIT_CORE, &zero) != 0
                    || libc::setrlimit(libc::RLIMIT_FSIZE, &zero) != 0
                    || libc::getppid() != parent
                {
                    return Err(io::Error::from_raw_os_error(libc::ESRCH));
                }
                Ok(())
            });
        }
        let mut child = command.spawn().map_err(|_| ())?;
        let input = child.stdin.take().expect("piped input");
        let output = child.stdout.take().expect("piped output");
        let errors = child.stderr.take().expect("piped errors");
        let mut owned = Self {
            child,
            input,
            output,
            errors,
            ticks: None,
            reaped: false,
            signalled: false,
            io_ready: true,
        };
        for fd in [
            owned.input.as_raw_fd(),
            owned.output.as_raw_fd(),
            owned.errors.as_raw_fd(),
        ] {
            if !nonblocking(fd) {
                owned.io_ready = false;
            }
        }
        // Ownership is returned even if IO setup failed, so supervision still
        // reaps this actual child and reports post-start failure truthfully.
        Ok(owned)
    }

    fn observed_identity(&mut self) -> Result<(bool, u64), ()> {
        if self.reaped {
            return Err(());
        }
        let mut bytes = Vec::new();
        std::fs::File::open(format!("/proc/{}/stat", self.child.id()))
            .and_then(|file| file.take(4097).read_to_end(&mut bytes))
            .map_err(|_| ())?;
        let result =
            crate::owned_child_identity::parse(&bytes, self.child.id(), std::process::id())?;
        if self.ticks.is_some_and(|expected| expected != result.1) {
            return Err(());
        }
        self.ticks = Some(result.1);
        Ok(result)
    }
}

impl Driver for LinuxWorker {
    fn now(&self) -> Instant {
        Instant::now()
    }
    fn wall(&self) -> DateTime<FixedOffset> {
        crate::contract::utc_now().fixed_offset()
    }
    fn pause(&mut self, duration: Duration) {
        std::thread::sleep(duration);
    }
    fn read(&mut self, stderr: bool) -> Result<Chunk, ()> {
        if !self.io_ready {
            return Err(());
        }
        let mut bytes = [0_u8; 4096];
        let result = if stderr {
            self.errors.read(&mut bytes)
        } else {
            self.output.read(&mut bytes)
        };
        match result {
            Ok(0) => Ok(Chunk::Eof),
            Ok(n) => Ok(Chunk::Bytes(bytes[..n].to_vec())),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                Ok(Chunk::Pending)
            }
            Err(_) => Err(()),
        }
    }
    fn write(&mut self, bytes: &[u8]) -> Result<usize, ()> {
        if !self.io_ready || bytes.len() > 4096 {
            return Err(());
        }
        match self.input.write(bytes) {
            Ok(0) => Err(()),
            Ok(n) => Ok(n),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                Ok(0)
            }
            Err(_) => Err(()),
        }
    }
    fn identity(&mut self) -> Result<(u32, u64), ()> {
        let (exited, ticks) = self.observed_identity()?;
        if exited {
            return Err(());
        }
        Ok((self.child.id(), ticks))
    }
    fn exited(&mut self) -> Result<bool, ()> {
        self.observed_identity().map(|value| value.0)
    }
    fn terminate_group(&mut self) -> bool {
        if self.reaped || self.signalled {
            return false;
        }
        self.signalled = true;
        let status = unsafe { libc::kill(-(self.child.id() as i32), libc::SIGKILL) };
        let group = status == 0 || io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH);
        let child = match self.child.kill() {
            Ok(()) => true,
            Err(error) => error.raw_os_error() == Some(libc::ESRCH),
        };
        group && child
    }
    fn reap(&mut self) -> Result<Option<Option<i32>>, ()> {
        match self.child.try_wait().map_err(|_| ())? {
            Some(status) => {
                self.reaped = true;
                Ok(Some(status.code()))
            }
            None => Ok(None),
        }
    }
    fn group_absent(&mut self) -> bool {
        (unsafe { libc::kill(-(self.child.id() as i32), 0) }) != 0
            && io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
    }
}
impl Drop for LinuxWorker {
    fn drop(&mut self) {
        if !self.reaped {
            if !self.signalled {
                self.terminate_group();
            }
            let _ = self.child.try_wait();
        }
    }
}
