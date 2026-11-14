//! Exact cgroup-v2 leaf used by the fixed Linux Strix worker boundary.

#![cfg(target_os = "linux")]

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::mem::zeroed;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

const REFUSAL: &str = "the fixed Linux Strix worker boundary was refused";
const CGROUP2_SUPER_MAGIC: libc::c_long = 0x6367_7270;
pub(crate) const MEMORY_MAX: u64 = 256 * 1024 * 1024;
pub(crate) const MEMORY_SWAP_MAX: u64 = 0;
pub(crate) const MEMORY_OOM_GROUP: u32 = 1;
pub(crate) const CPU_MAX: &str = "100000 100000";
pub(crate) const PIDS_MAX: u32 = 16;

pub(crate) struct CgroupLeaf {
    pub(crate) path: PathBuf,
    pub(crate) inode: u64,
}

impl Drop for CgroupLeaf {
    fn drop(&mut self) {
        if !self.path.as_os_str().is_empty()
            && members(&self.path).is_ok_and(|rows| rows.is_empty())
            && threads(&self.path).is_ok_and(|rows| rows.is_empty())
        {
            let _ = fs::remove_dir(&self.path);
        }
    }
}

/// A failed cgroup acquisition retains custody of any leaf that may already
/// contain the worker. The caller owns the spawn pidfd, so only it can first
/// terminate and reap the exact process and then remove this partial leaf.
pub(crate) struct CgroupPrepareError {
    message: String,
    partial: Option<CgroupLeaf>,
}

impl CgroupPrepareError {
    fn before_leaf(message: String) -> Self {
        Self {
            message,
            partial: None,
        }
    }

    fn with_leaf(message: String, partial: CgroupLeaf) -> Self {
        Self {
            message,
            partial: Some(partial),
        }
    }

    pub(crate) fn into_parts(self) -> (String, Option<CgroupLeaf>) {
        (self.message, self.partial)
    }
}

impl std::fmt::Display for CgroupPrepareError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::fmt::Debug for CgroupPrepareError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CgroupPrepareError")
            .field("message", &self.message)
            .field("partial_leaf_owned", &self.partial.is_some())
            .finish()
    }
}

impl std::error::Error for CgroupPrepareError {}

impl CgroupLeaf {
    pub(crate) fn remove(&mut self) -> Result<bool, String> {
        require(members(&self.path)?.is_empty() && threads(&self.path)?.is_empty())?;
        let path = self.path.clone();
        fs::remove_dir(&path).map_err(|_| REFUSAL)?;
        self.path = PathBuf::new();
        Ok(!path.exists())
    }
}

fn require(value: bool) -> Result<(), String> {
    if value {
        Ok(())
    } else {
        Err(REFUSAL.into())
    }
}

fn current_root() -> Result<PathBuf, String> {
    let value = fs::read_to_string("/proc/self/cgroup").map_err(|_| REFUSAL)?;
    let rows: Vec<_> = value.lines().collect();
    require(rows.len() == 1 && rows[0].starts_with("0::/"))?;
    let relative = rows[0].strip_prefix("0::/").ok_or(REFUSAL)?;
    require(!relative.split('/').any(|part| matches!(part, "." | "..")))?;
    let mut root = PathBuf::from("/sys/fs/cgroup");
    if !relative.is_empty() {
        root.push(relative);
    }
    let root_c = std::ffi::CString::new(root.as_os_str().as_bytes()).map_err(|_| REFUSAL)?;
    let mut facts: libc::statfs = unsafe { zeroed() };
    require(unsafe { libc::statfs(root_c.as_ptr(), &mut facts) } == 0)?;
    require(facts.f_type == CGROUP2_SUPER_MAGIC)?;
    let controllers = fs::read_to_string(root.join("cgroup.controllers")).map_err(|_| REFUSAL)?;
    let delegated = fs::read_to_string(root.join("cgroup.subtree_control")).map_err(|_| REFUSAL)?;
    for controller in ["cpu", "memory", "pids"] {
        require(controllers.split_whitespace().any(|row| row == controller))?;
        require(delegated.split_whitespace().any(|row| row == controller))?;
    }
    Ok(root)
}

fn write_exact(path: &Path, value: &str) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| REFUSAL)?;
    file.write_all(value.as_bytes())
        .map_err(|_| REFUSAL.to_string())
}

pub(crate) fn read_trimmed(path: &Path) -> Result<String, String> {
    Ok(fs::read_to_string(path)
        .map_err(|_| REFUSAL)?
        .trim()
        .to_string())
}

fn numeric_rows(path: &Path) -> Result<Vec<i32>, String> {
    let text = fs::read_to_string(path).map_err(|_| REFUSAL)?;
    let mut rows = Vec::new();
    for row in text.lines() {
        let value: i32 = row.parse().map_err(|_| REFUSAL)?;
        require(value > 0 && value.to_string() == row)?;
        rows.push(value);
    }
    rows.sort_unstable();
    rows.dedup();
    Ok(rows)
}

pub(crate) fn members(path: &Path) -> Result<Vec<i32>, String> {
    numeric_rows(&path.join("cgroup.procs"))
}

pub(crate) fn threads(path: &Path) -> Result<Vec<i32>, String> {
    numeric_rows(&path.join("cgroup.threads"))
}

pub(crate) fn prepare(pid: i32) -> Result<CgroupLeaf, CgroupPrepareError> {
    let root = current_root().map_err(CgroupPrepareError::before_leaf)?;
    let path = root.join(format!("bluefire-strix-worker-selftest-{pid}"));
    fs::create_dir(&path).map_err(|_| CgroupPrepareError::before_leaf(REFUSAL.into()))?;
    let mut leaf = CgroupLeaf { path, inode: 0 };

    // Configure and read back every property that can be validated before the
    // membership transfer. This minimizes the post-move failure surface while
    // preserving the leaf in the typed error if any later check does fail.
    let configured = (|| -> Result<(), String> {
        let path = &leaf.path;
        write_exact(&path.join("pids.max"), &PIDS_MAX.to_string())?;
        write_exact(&path.join("memory.max"), &MEMORY_MAX.to_string())?;
        write_exact(&path.join("memory.swap.max"), &MEMORY_SWAP_MAX.to_string())?;
        write_exact(
            &path.join("memory.oom.group"),
            &MEMORY_OOM_GROUP.to_string(),
        )?;
        write_exact(&path.join("cpu.max"), CPU_MAX)?;
        require(read_trimmed(&path.join("pids.max"))? == PIDS_MAX.to_string())?;
        require(read_trimmed(&path.join("memory.max"))? == MEMORY_MAX.to_string())?;
        require(read_trimmed(&path.join("memory.swap.max"))? == MEMORY_SWAP_MAX.to_string())?;
        require(read_trimmed(&path.join("memory.oom.group"))? == MEMORY_OOM_GROUP.to_string())?;
        require(read_trimmed(&path.join("cpu.max"))? == CPU_MAX)?;
        require(members(path)?.is_empty() && threads(path)?.is_empty())?;
        require(read_trimmed(&path.join("pids.current"))? == "0")?;
        let inode = fs::metadata(path).map_err(|_| REFUSAL)?.ino();
        require(inode > 0)?;
        leaf.inode = inode;
        Ok(())
    })();
    if let Err(message) = configured {
        return Err(CgroupPrepareError::with_leaf(message, leaf));
    }

    let activated = (|| -> Result<(), String> {
        write_exact(&leaf.path.join("cgroup.procs"), &pid.to_string())?;
        require(members(&leaf.path)? == vec![pid])?;
        require(threads(&leaf.path)? == vec![pid])?;
        require(read_trimmed(&leaf.path.join("pids.current"))? == "1")?;
        Ok(())
    })();
    match activated {
        Ok(()) => Ok(leaf),
        Err(message) => Err(CgroupPrepareError::with_leaf(message, leaf)),
    }
}
