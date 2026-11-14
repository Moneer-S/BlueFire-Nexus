//! Thread-compatible no-new-process/no-exec seccomp policy for Strix.

#![cfg(target_os = "linux")]

use std::mem::size_of;
use std::ptr;

use sha2::{Digest, Sha256};

const REFUSAL: &str = "the fixed Linux Strix worker boundary was refused";

#[derive(Clone, Copy)]
pub(crate) struct Probe {
    pub(crate) clone3_enosys: bool,
    pub(crate) non_thread_clone_refused: bool,
    pub(crate) fork_refused: bool,
    pub(crate) vfork_refused: bool,
    pub(crate) exec_refused: bool,
}

fn require(value: bool) -> Result<(), String> {
    if value {
        Ok(())
    } else {
        Err(REFUSAL.into())
    }
}

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn stmt(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

fn jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH: u32 = 0xc000_003e;
#[cfg(target_arch = "x86_64")]
const X32_SYSCALL_BIT: u32 = 0x4000_0000;
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH: u32 = 0xc000_00b7;

#[cfg(target_arch = "x86_64")]
pub(crate) fn arch() -> &'static str {
    "linux-x86_64"
}

#[cfg(target_arch = "aarch64")]
pub(crate) fn arch() -> &'static str {
    "linux-aarch64"
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub(crate) fn arch() -> &'static str {
    "unsupported-linux-architecture"
}

pub(crate) fn install() -> Result<String, String> {
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    return Err(REFUSAL.into());

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    {
        const LOAD: u16 = (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16;
        const AND: u16 = (libc::BPF_ALU | libc::BPF_AND | libc::BPF_K) as u16;
        const JEQ: u16 = (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16;
        const RET: u16 = (libc::BPF_RET | libc::BPF_K) as u16;
        let required = (libc::CLONE_VM
            | libc::CLONE_FS
            | libc::CLONE_FILES
            | libc::CLONE_SIGHAND
            | libc::CLONE_THREAD
            | libc::CLONE_SYSVSEM) as u32;
        let forbidden = (0x0000_00ff
            | libc::CLONE_VFORK
            | libc::CLONE_PARENT
            | libc::CLONE_PTRACE
            | libc::CLONE_UNTRACED
            | libc::CLONE_PIDFD
            | libc::CLONE_NEWNS
            | libc::CLONE_NEWCGROUP
            | libc::CLONE_NEWUTS
            | libc::CLONE_NEWIPC
            | libc::CLONE_NEWUSER
            | libc::CLONE_NEWPID
            | libc::CLONE_NEWNET) as u32;
        let deny = libc::SECCOMP_RET_ERRNO | libc::EPERM as u32;
        let unsupported = libc::SECCOMP_RET_ERRNO | libc::ENOSYS as u32;
        let mut filter = vec![
            stmt(LOAD, 4),
            jump(JEQ, AUDIT_ARCH, 1, 0),
            stmt(RET, libc::SECCOMP_RET_KILL_PROCESS),
        ];
        #[cfg(target_arch = "x86_64")]
        filter.extend([
            stmt(LOAD, 0),
            stmt(AND, X32_SYSCALL_BIT),
            jump(JEQ, 0, 1, 0),
            stmt(RET, libc::SECCOMP_RET_KILL_PROCESS),
            stmt(LOAD, 0),
        ]);
        #[cfg(target_arch = "aarch64")]
        filter.push(stmt(LOAD, 0));
        filter.extend([
            jump(JEQ, libc::SYS_clone3 as u32, 0, 1),
            stmt(RET, unsupported),
            jump(JEQ, libc::SYS_clone as u32, 0, 10),
            // Reject every high-bit legacy-clone extension.
            stmt(LOAD, 20),
            jump(JEQ, 0, 0, 6),
            stmt(LOAD, 16),
            stmt(AND, required),
            jump(JEQ, required, 0, 3),
            stmt(LOAD, 16),
            stmt(AND, forbidden),
            jump(JEQ, 0, 1, 0),
            stmt(RET, deny),
            stmt(RET, libc::SECCOMP_RET_ALLOW),
            stmt(LOAD, 0),
        ]);
        let mut denied = vec![
            libc::SYS_execve,
            libc::SYS_execveat,
            libc::SYS_bind,
            libc::SYS_listen,
            libc::SYS_accept,
            libc::SYS_accept4,
            libc::SYS_unshare,
            libc::SYS_setns,
            libc::SYS_mount,
            libc::SYS_umount2,
            libc::SYS_pivot_root,
            libc::SYS_ptrace,
            libc::SYS_bpf,
            libc::SYS_perf_event_open,
            libc::SYS_keyctl,
            libc::SYS_add_key,
            libc::SYS_request_key,
            libc::SYS_userfaultfd,
            libc::SYS_pidfd_open,
            libc::SYS_pidfd_getfd,
            libc::SYS_process_vm_readv,
            libc::SYS_process_vm_writev,
            libc::SYS_open_by_handle_at,
            libc::SYS_name_to_handle_at,
            libc::SYS_init_module,
            libc::SYS_finit_module,
            libc::SYS_delete_module,
            libc::SYS_kexec_load,
        ];
        #[cfg(target_arch = "x86_64")]
        denied.extend([libc::SYS_fork, libc::SYS_vfork]);
        for syscall in denied {
            filter.push(jump(JEQ, syscall as u32, 0, 1));
            filter.push(stmt(RET, deny));
        }
        filter.push(stmt(RET, libc::SECCOMP_RET_ALLOW));
        let filter_bytes = unsafe {
            std::slice::from_raw_parts(
                filter.as_ptr().cast::<u8>(),
                filter.len() * size_of::<libc::sock_filter>(),
            )
        };
        let policy_digest = digest(filter_bytes);
        let program = libc::sock_fprog {
            len: filter.len() as u16,
            filter: filter.as_mut_ptr(),
        };
        require(
            unsafe {
                libc::syscall(
                    libc::SYS_seccomp,
                    libc::SECCOMP_SET_MODE_FILTER,
                    libc::SECCOMP_FILTER_FLAG_TSYNC,
                    &program as *const libc::sock_fprog,
                )
            } == 0,
        )?;
        Ok(policy_digest)
    }
}

fn fork_refused() -> bool {
    let result = unsafe { libc::fork() };
    if result == 0 {
        unsafe { libc::_exit(123) }
    }
    if result > 0 {
        unsafe { libc::waitpid(result, ptr::null_mut(), 0) };
        return false;
    }
    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

fn vfork_refused() -> bool {
    let result = unsafe { libc::syscall(libc::SYS_vfork) as libc::pid_t };
    if result == 0 {
        unsafe { libc::_exit(124) }
    }
    if result > 0 {
        unsafe { libc::waitpid(result, ptr::null_mut(), 0) };
        return false;
    }
    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

pub(crate) fn probe() -> Probe {
    let clone3 = unsafe { libc::syscall(libc::SYS_clone3, ptr::null::<libc::c_void>(), 0) };
    let clone3_errno = std::io::Error::last_os_error().raw_os_error();
    let clone = unsafe {
        libc::syscall(
            libc::SYS_clone,
            libc::CLONE_THREAD,
            ptr::null_mut::<libc::c_void>(),
            ptr::null_mut::<libc::c_void>(),
            ptr::null_mut::<libc::c_void>(),
            0,
        )
    };
    let clone_errno = std::io::Error::last_os_error().raw_os_error();
    let path = b"/inputs/objective.json\0";
    let argv = [path.as_ptr().cast::<libc::c_char>(), ptr::null()];
    let envp = [ptr::null()];
    let exec = unsafe { libc::execve(path.as_ptr().cast(), argv.as_ptr(), envp.as_ptr()) };
    let exec_errno = std::io::Error::last_os_error().raw_os_error();
    Probe {
        clone3_enosys: clone3 == -1 && clone3_errno == Some(libc::ENOSYS),
        non_thread_clone_refused: clone == -1 && clone_errno == Some(libc::EPERM),
        fork_refused: fork_refused(),
        vfork_refused: vfork_refused(),
        exec_refused: exec == -1 && exec_errno == Some(libc::EPERM),
    }
}

#[cfg(test)]
mod tests {
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn x32_syscall_alias_is_explicitly_classified() {
        assert_eq!(super::X32_SYSCALL_BIT, 1_u32 << 30);
        assert_eq!(super::AUDIT_ARCH, 0xc000_003e);
    }
}
