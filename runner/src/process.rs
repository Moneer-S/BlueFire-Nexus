use std::collections::BTreeMap;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use crate::contract::{BoundedOutput, ExecutionLimits};
use crate::safety::{normalize_relative, read_file_bounded, SafeRoot};

const PRIVATE_ENV: &str = "BLUEFIRE_RUNNER_PRIVATE_TRANSFORM";
const PRIVATE_ENV_VALUE: &str = "v1";
const PRIVATE_MAX_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixedProcessSpec {
    pub executable: PathBuf,
    pub args: Vec<String>,
    pub cwd: PathBuf,
    pub environment: BTreeMap<String, String>,
}

#[derive(Debug)]
pub struct ProcessOutcome {
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub stdout: BoundedOutput,
    pub stderr: BoundedOutput,
}

pub fn fixed_transform_spec(
    executable: &Path,
    root: &Path,
    input: &str,
    output: &str,
    transform: &str,
) -> FixedProcessSpec {
    let mut environment = BTreeMap::new();
    environment.insert(PRIVATE_ENV.to_string(), PRIVATE_ENV_VALUE.to_string());
    FixedProcessSpec {
        executable: executable.to_path_buf(),
        args: vec![
            "__private-transform".to_string(),
            root.to_string_lossy().into_owned(),
            input.to_string(),
            output.to_string(),
            transform.to_string(),
        ],
        cwd: root.to_path_buf(),
        environment,
    }
}

fn read_bounded<R: Read>(mut reader: R, limit: usize) -> io::Result<BoundedOutput> {
    let mut retained = Vec::with_capacity(limit.min(16 * 1024));
    let mut total = 0_u64;
    let mut buffer = [0_u8; 8 * 1024];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        total = total.saturating_add(count as u64);
        let remaining = limit.saturating_sub(retained.len());
        retained.extend_from_slice(&buffer[..count.min(remaining)]);
    }
    Ok(BoundedOutput {
        text: String::from_utf8_lossy(&retained).into_owned(),
        total_bytes: total,
        truncated: total > retained.len() as u64,
    })
}

pub fn run_fixed_transform(
    executable: &Path,
    root: &Path,
    input: &str,
    output: &str,
    transform: &str,
    limits: &ExecutionLimits,
) -> Result<ProcessOutcome, String> {
    let spec = fixed_transform_spec(executable, root, input, output, transform);
    let mut command = Command::new(&spec.executable);
    command
        .args(&spec.args)
        .current_dir(&spec.cwd)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (name, value) in &spec.environment {
        command.env(name, value);
    }

    let mut child = command
        .spawn()
        .map_err(|error| format!("cannot start the fixed transform helper: {error}"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "fixed helper stdout was not captured".to_string())?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "fixed helper stderr was not captured".to_string())?;
    let stdout_limit = limits.max_stdout_bytes;
    let stderr_limit = limits.max_stderr_bytes;
    let stdout_reader = thread::spawn(move || read_bounded(stdout, stdout_limit));
    let stderr_reader = thread::spawn(move || read_bounded(stderr, stderr_limit));

    let deadline = Duration::from_millis(limits.timeout_ms);
    let started = Instant::now();
    let (status, timed_out) = loop {
        match child.try_wait() {
            Ok(Some(status)) => break (status, false),
            Ok(None) if started.elapsed() < deadline => thread::sleep(Duration::from_millis(2)),
            Ok(None) => {
                let _ = child.kill();
                let status = child
                    .wait()
                    .map_err(|error| format!("cannot reap timed-out fixed helper: {error}"))?;
                break (status, true);
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("cannot inspect fixed helper status: {error}"));
            }
        }
    };

    let stdout = stdout_reader
        .join()
        .map_err(|_| "fixed helper stdout reader panicked".to_string())?
        .map_err(|error| format!("cannot read fixed helper stdout: {error}"))?;
    let stderr = stderr_reader
        .join()
        .map_err(|_| "fixed helper stderr reader panicked".to_string())?
        .map_err(|error| format!("cannot read fixed helper stderr: {error}"))?;
    Ok(ProcessOutcome {
        exit_code: status.code(),
        timed_out,
        stdout,
        stderr,
    })
}

/// Implementation of the deliberately private helper subcommand. It only
/// performs one of the compiled-in transformations and applies the same
/// containment/link checks as the parent runner.
pub fn private_transform(args: &[String]) -> Result<(), String> {
    if std::env::var(PRIVATE_ENV).ok().as_deref() != Some(PRIVATE_ENV_VALUE) {
        return Err("private transform is available only to the runner".to_string());
    }
    if args.len() != 4 {
        return Err("private transform received an invalid fixed argument vector".to_string());
    }
    let root = SafeRoot::open(Path::new(&args[0]))?;
    let input = normalize_relative(&args[1], false)?;
    let output = normalize_relative(&args[2], false)?;
    let transform = args[3].as_str();
    if !matches!(transform, "uppercase-ascii" | "reverse-bytes") {
        return Err("private transform kind is not registered".to_string());
    }
    let input_path = root.resolve_existing(&input)?;
    let mut bytes = read_file_bounded(&input_path, PRIVATE_MAX_BYTES)?;
    match transform {
        "uppercase-ascii" => bytes.make_ascii_uppercase(),
        "reverse-bytes" => bytes.reverse(),
        _ => unreachable!("validated above"),
    }
    let target = root.prepare_new_file(&output)?;
    root.write_new(&target, &bytes)?;
    println!("fixed transform completed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_spec_is_fixed_and_has_an_explicit_environment() {
        let spec = fixed_transform_spec(
            Path::new("runner-bin"),
            Path::new("sandbox"),
            "input.txt",
            "output.txt",
            "uppercase-ascii",
        );
        assert_eq!(spec.executable, PathBuf::from("runner-bin"));
        assert_eq!(spec.args[0], "__private-transform");
        assert_eq!(spec.environment.len(), 1);
        assert_eq!(
            spec.environment.get(PRIVATE_ENV).map(String::as_str),
            Some(PRIVATE_ENV_VALUE)
        );
        assert!(!spec.args.iter().any(|arg| arg == "sh" || arg == "cmd"));
    }

    #[test]
    fn bounded_reader_drains_but_retains_only_the_limit() {
        let output = read_bounded(&b"abcdefgh"[..], 3).unwrap();
        assert_eq!(output.text, "abc");
        assert_eq!(output.total_bytes, 8);
        assert!(output.truncated);
    }
}
