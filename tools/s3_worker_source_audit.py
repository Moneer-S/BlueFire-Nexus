"""Complete reviewed source and fixed-launch checks for the S3 worker."""

from tools.provider_gate_common import _sha256_bytes

_SOURCE_SIZE = 8_021
_SOURCE_SHA256 = "sha256:2d41be1a0ac57fa82ad1bee540e77af113adbdd90cf489c15a1cd424015fef27"


def reviewed_s3_worker_source(source: bytes) -> bool:
    if type(source) is not bytes or len(source) != _SOURCE_SIZE:
        return False
    if _sha256_bytes(source) != _SOURCE_SHA256:
        return False
    try:
        text = source.decode("utf-8")
    except UnicodeError:
        return False
    once = (
        'Command::new(format!("/proc/self/fd/{}", runtime.python.fd()))',
        "runtime.python.recheck().map_err(|_| ())?;",
        ".arg0(&runtime.python_path)",
        '.args(["-I", "-S", "-B"])',
        ".arg(&runtime.entry)",
        '.arg("--runtime-root")',
        ".arg(&runtime.root)",
        '.arg("--runtime-digest")',
        ".arg(&runtime.digest)",
        ".env_clear()",
        '.env("LC_ALL", "C")',
        '.current_dir("/")',
        ".stdin(Stdio::piped())",
        ".stdout(Stdio::piped())",
        ".stderr(Stdio::piped())",
        "command.pre_exec(move ||",
        "libc::setpgid(0, 0)",
        "libc::PR_SET_PDEATHSIG",
        "libc::PR_SET_NO_NEW_PRIVS",
        "libc::RLIMIT_AS",
        "libc::RLIMIT_CPU",
        "libc::RLIMIT_NOFILE",
        "libc::RLIMIT_CORE",
        "libc::RLIMIT_FSIZE",
        "let mut child = command.spawn().map_err(|_| ())?;",
        "crate::owned_child_identity::parse(&bytes, self.child.id(), std::process::id())?",
        "if self.reaped || self.signalled",
        "libc::kill(-(self.child.id() as i32), libc::SIGKILL)",
        "self.child.kill()",
        "self.child.try_wait().map_err(|_| ())?",
        "libc::kill(-(self.child.id() as i32), 0)",
        "let mut bytes = [0_u8; 4096];",
        "bytes.len() > 4096",
    )
    return (
        all(text.count(token) == 1 for token in once)
        and text.count("Command::new(") == 1
        and text.count(".spawn()") == 1
        and text.count("libc::getppid() != parent") == 2
        and text.index("runtime.python.recheck()") < text.index("Command::new(")
        and all(
            token not in text.casefold()
            for token in ("cmd.exe", "powershell", "/bin/sh", "/bin/bash", "sh -c")
        )
    )
