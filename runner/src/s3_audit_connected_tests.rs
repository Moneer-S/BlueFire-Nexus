//! Opt-in application/worker bridge. Not a protected-runtime or TLS acceptance test.

use super::*;
use crate::canonical::sha256_hex;
use crate::s3_worker_protocol::{Chunk, Driver};
use serde_json::json;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

const TEST: &str = "s3_reservation::connected_tests::application_worker_bridge";
const MAX_FILE: usize = 256 * 1024;

fn read(path: &Path, maximum: usize) -> Vec<u8> {
    assert!(path.is_absolute());
    for ancestor in path.ancestors() {
        assert!(!std::fs::symlink_metadata(ancestor)
            .unwrap()
            .file_type()
            .is_symlink());
    }
    let mut bytes = Vec::new();
    File::open(path)
        .unwrap()
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .unwrap();
    assert!(bytes.len() <= maximum);
    bytes
}

fn pinned(row: &Value, maximum: usize) -> PathBuf {
    let path = PathBuf::from(row["path"].as_str().unwrap());
    assert_eq!(
        format!("sha256:{}", sha256_hex(&read(&path, maximum))),
        row["sha256"]
    );
    path
}

fn save(path: &Path, value: &Value) {
    let bytes = canonical_json(value).into_bytes();
    assert!(bytes.len() <= MAX_FILE);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(&bytes).unwrap();
    file.sync_all().unwrap();
    File::open(path.parent().unwrap())
        .unwrap()
        .sync_all()
        .unwrap();
}

struct Process {
    child: Child,
    input: Option<ChildStdin>,
    output: Option<ChildStdout>,
    errors: Option<ChildStderr>,
    issued: DateTime<FixedOffset>,
    ticks: Option<u64>,
    reaped: bool,
    signalled: bool,
    lost_ack: bool,
    lost_ack_seen: bool,
    ledger_root: PathBuf,
    discovery_ack_checked: bool,
}

impl Process {
    fn start(
        tools: &Value,
        tools_path: &Path,
        tools_hash: &str,
        input: &Path,
        now: DateTime<FixedOffset>,
        lost_ack: bool,
    ) -> Self {
        let python = pinned(&tools["python"], 128 * 1024 * 1024);
        let helper = pinned(&tools["helper"], MAX_FILE);
        let native = pinned(&tools["native"], 512 * 1024 * 1024);
        assert_eq!(
            std::fs::canonicalize(native).unwrap(),
            std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap()
        );
        let mut command = Command::new(python);
        command
            .args(["-I", "-B"])
            .arg(helper)
            .arg("--worker")
            .arg(tools_path)
            .arg(tools_hash)
            .arg(input)
            .env_clear()
            .env("LC_ALL", "C")
            .current_dir("/")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let parent = std::process::id() as i32;
        unsafe {
            command.pre_exec(move || {
                let memory = libc::rlimit {
                    rlim_cur: 512 * 1024 * 1024,
                    rlim_max: 512 * 1024 * 1024,
                };
                let cpu = libc::rlimit {
                    rlim_cur: 15,
                    rlim_max: 15,
                };
                let files = libc::rlimit {
                    rlim_cur: 128,
                    rlim_max: 128,
                };
                let size = libc::rlimit {
                    rlim_cur: MAX_FILE as u64,
                    rlim_max: MAX_FILE as u64,
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
                    || libc::setrlimit(libc::RLIMIT_FSIZE, &size) != 0
                    || libc::setrlimit(libc::RLIMIT_CORE, &zero) != 0
                    || libc::getppid() != parent
                {
                    return Err(std::io::Error::from_raw_os_error(libc::ESRCH));
                }
                Ok(())
            });
        }
        let ledger_root = input
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("native-ledger");
        // Own the Child before pipe extraction or any fallible setup can unwind.
        let mut owned = Self {
            child: command.spawn().unwrap(),
            input: None,
            output: None,
            errors: None,
            issued: now,
            ticks: None,
            reaped: false,
            signalled: false,
            lost_ack,
            lost_ack_seen: false,
            ledger_root,
            discovery_ack_checked: false,
        };
        owned.input = Some(owned.child.stdin.take().unwrap());
        owned.output = Some(owned.child.stdout.take().unwrap());
        owned.errors = Some(owned.child.stderr.take().unwrap());
        for fd in [
            owned.input.as_ref().unwrap().as_raw_fd(),
            owned.output.as_ref().unwrap().as_raw_fd(),
            owned.errors.as_ref().unwrap().as_raw_fd(),
        ] {
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
            {
                drop(owned);
                panic!("test pipe setup failed; owned cleanup attempted");
            }
        }
        owned
    }

    fn observed(&mut self) -> std::result::Result<(bool, u64), ()> {
        let mut bytes = Vec::new();
        File::open(format!("/proc/{}/stat", self.child.id()))
            .and_then(|file| file.take(4097).read_to_end(&mut bytes))
            .map_err(|_| ())?;
        let result =
            crate::owned_child_identity::parse(&bytes, self.child.id(), std::process::id())?;
        if self.ticks.is_some_and(|ticks| ticks != result.1) {
            return Err(());
        }
        self.ticks = Some(result.1);
        Ok(result)
    }
}

impl Driver for Process {
    fn now(&self) -> Instant {
        Instant::now()
    }
    fn wall(&self) -> DateTime<FixedOffset> {
        self.issued
    }
    fn pause(&mut self, duration: Duration) {
        std::thread::sleep(duration);
    }
    fn read(&mut self, stderr: bool) -> std::result::Result<Chunk, ()> {
        let mut bytes = [0; 4096];
        let result = if stderr {
            self.errors.as_mut().ok_or(())?.read(&mut bytes)
        } else {
            self.output.as_mut().ok_or(())?.read(&mut bytes)
        };
        match result {
            Ok(0) => Ok(Chunk::Eof),
            Ok(n) => Ok(Chunk::Bytes(bytes[..n].to_vec())),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) =>
            {
                Ok(Chunk::Pending)
            }
            Err(_) => Err(()),
        }
    }
    fn write(&mut self, bytes: &[u8]) -> std::result::Result<usize, ()> {
        assert!(bytes.len() <= 4096);
        if bytes
            .windows(b"\"kind\":\"discovery_committed\"".len())
            .any(|part| part == b"\"kind\":\"discovery_committed\"")
        {
            assert_eq!(bytes.last(), Some(&b'\n'));
            let ack: Value = serde_json::from_slice(bytes).unwrap();
            let journal = read(
                &self.ledger_root.join("reservations.jsonl"),
                4 * 1024 * 1024,
            );
            let last = journal
                .split(|byte| *byte == b'\n')
                .rfind(|line| !line.is_empty())
                .unwrap();
            let retained: Value = serde_json::from_slice(last).unwrap();
            assert_eq!(retained["record"]["kind"], "audit_discovery");
            assert_eq!(
                ack["discovery_digest"],
                canonical_hash(&retained["record"]["discovery"])
            );
            assert_eq!(
                ack["reservation_digest"],
                retained["record"]["reservation_digest"]
            );
            self.discovery_ack_checked = true;
            if self.lost_ack {
                self.lost_ack_seen = true;
                return Err(());
            }
        }
        match self.input.as_mut().ok_or(())?.write(bytes) {
            Ok(0) => Err(()),
            Ok(n) => Ok(n),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) =>
            {
                Ok(0)
            }
            Err(_) => Err(()),
        }
    }
    fn identity(&mut self) -> std::result::Result<(u32, u64), ()> {
        let (exited, ticks) = self.observed()?;
        if exited {
            Err(())
        } else {
            Ok((self.child.id(), ticks))
        }
    }
    fn exited(&mut self) -> std::result::Result<bool, ()> {
        self.observed().map(|row| row.0)
    }
    fn terminate_group(&mut self) -> bool {
        if self.reaped || self.signalled {
            return false;
        }
        self.signalled = true;
        let killed = unsafe { libc::kill(-(self.child.id() as i32), libc::SIGKILL) };
        let group =
            killed == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH);
        let child = match self.child.kill() {
            Ok(()) => true,
            Err(error) => error.raw_os_error() == Some(libc::ESRCH),
        };
        group && child
    }
    fn reap(&mut self) -> std::result::Result<Option<Option<i32>>, ()> {
        Ok(self.child.try_wait().map_err(|_| ())?.map(|status| {
            self.reaped = true;
            status.code()
        }))
    }
    fn group_absent(&mut self) -> bool {
        (unsafe { libc::kill(-(self.child.id() as i32), 0) }) != 0
            && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        if !self.reaped && !self.signalled {
            self.terminate_group();
        }
        let end = Instant::now() + Duration::from_secs(2);
        while Instant::now() < end {
            if !self.reaped {
                let _ = self.reap();
            }
            if self.reaped && self.group_absent() {
                return;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        // Do not signal a numeric group after its leader was reaped. The Python
        // parent retains the native session leader and cleans exact pidfd members.
        eprintln!("connected worker cleanup unknown; parent session reconciliation required");
    }
}

fn audited(admission: &VerifiedS3Admission) -> audit::AuditedReservation {
    let binding = admission.binding();
    audit::AuditedReservation {
        operation: Reserved {
            workflow_id: admission.workflow_id().into(),
            operation_id: admission.operation_id().into(),
            environment_id: admission.environment_id().into(),
            resource_key: binding.resource_key(),
            scope_digest: binding.scope_digest().into(),
            request_digest: binding.digest().into(),
            request_id: binding.request_id().into(),
            launch_id: binding.launch_id().into(),
            approval_digest: admission.approval_digest().into(),
            runtime_digest: binding.runtime_digest().into(),
            worker_generation: binding.worker_generation().into(),
            phase: admission.phase().into(),
            operation: binding.operation().into(),
            revision: admission.revision(),
            max_sends: binding.max_sends(),
            api_limit: binding.api_limit(),
            session_limit: binding.session_limit(),
            business_attempt_limit: binding.business_attempt_limit(),
            fixture_authority_digest: admission.fixture_authority_digest().map(str::to_owned),
            fixture: binding.fixture().cloned(),
        },
        scope: binding.scope().clone(),
        audit_workflow: admission.audit_workflow().unwrap().document().unwrap(),
        profile_digest: admission.profile_digest().into(),
        task: audit::TaskIdentity {
            run_id: admission.manifest().run_id.clone(),
            manifest_digest: admission.manifest_digest().into(),
            deadline: serde_json::from_str::<Value>(binding.canonical_json()).unwrap()["deadline"]
                .as_str()
                .unwrap()
                .into(),
        },
        collection: binding.audit().map(|value| value.context().unwrap()),
    }
}

fn planned_append(ledger: &mut Ledger, record: Record) -> String {
    let (hash, bytes) = encode_entry(Entry {
        schema_version: SCHEMA.into(),
        sequence: ledger.entries + 1,
        previous_hash: ledger.previous_hash.clone(),
        record: record.clone(),
    })
    .unwrap();
    ledger.apply(record, hash.clone()).unwrap();
    ledger.entries += 1;
    ledger.previous_hash = hash.clone();
    ledger.bytes += bytes.len();
    hash
}

#[test]
#[ignore = "explicit pinned test-only Python/application bridge; never part of ordinary tests"]
fn application_worker_bridge() {
    use crate::actions::ActionOutcome;
    use crate::contract::{BoundedOutput, ErrorRecord, TaskStatus};
    let tools_path = PathBuf::from(std::env::var("BLUEFIRE_S3_CONNECTED_TOOLS").expect(TEST));
    let tools_hash = std::env::var("BLUEFIRE_S3_CONNECTED_TOOLS_SHA256").unwrap();
    let bytes = read(&tools_path, MAX_FILE);
    assert_eq!(format!("sha256:{}", sha256_hex(&bytes)), tools_hash);
    let tools: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        tools["schema_version"],
        "bluefire.s3-connected-test-tools.v1"
    );
    let input_path = PathBuf::from(std::env::var("BLUEFIRE_S3_CONNECTED_INPUT").unwrap());
    let input: Value = serde_json::from_slice(&read(&input_path, MAX_FILE)).unwrap();
    assert_eq!(
        input["schema_version"],
        "bluefire.s3-connected-test-input.v1"
    );
    assert_eq!(input.as_object().unwrap().len(), 9);
    assert_eq!(input_path.file_name().unwrap(), "input.json");
    assert_eq!(
        input["manifest"].get("cleanup_action_id"),
        Some(&Value::Null)
    );
    let admission = crate::s3_admission::tests::checked(&input).unwrap();
    assert_eq!(
        serde_json::to_value(admission.manifest()).unwrap(),
        input["manifest"]
    );
    assert_eq!(
        crate::contract::expected_manifest_hash(admission.manifest()),
        input["manifest"]["request_hash"].as_str().unwrap()
    );
    assert_eq!(
        admission.ledger_root(),
        input_path
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("native-ledger")
    );
    let now = crate::s3_access_scope::utc_time(input["now"].as_str().unwrap()).unwrap();
    assert_eq!(admission.owner_uid(), unsafe { libc::getuid() });
    assert_eq!(
        std::fs::metadata(admission.ledger_root()).unwrap().uid(),
        admission.owner_uid()
    );
    let transport_hash =
        canonical_hash(&json!({"manifest":input["manifest"],"profile":input["profile"]}));
    assert_eq!(
        input["task_id"],
        format!(
            "execute-{}",
            transport_hash.strip_prefix("sha256:").unwrap()
        )
    );
    assert_eq!(input["request_hash"], transport_hash);
    let fault = input["fault"].as_str().unwrap();
    assert!(["none", "append_refused", "lost_ack"].contains(&fault));
    assert!(fault == "none" || admission.binding().audit().is_some());
    let secret = crate::s3_worker_secret::WorkerSecret::from_bytes(
        canonical_json(&input["credentials"]).as_bytes(),
        input["admission"]["credential_digest"].as_str().unwrap(),
        now,
        admission.expires_at(),
    )
    .unwrap();
    let end = Instant::now() + Duration::from_secs(20);
    let deadline = end - Duration::from_secs(2);
    let execution;
    let mut process = Process::start(
        &tools,
        &tools_path,
        &tools_hash,
        &input_path,
        now,
        fault == "lost_ack",
    );
    if admission.binding().audit().is_none() {
        let store = S3ReservationStore::open(&admission).unwrap();
        let reservation = store.reserve(&admission, now).unwrap();
        execution = crate::s3_worker_protocol::supervise(
            &mut process,
            reservation,
            secret,
            deadline,
            end,
            &AtomicBool::new(false),
        );
    } else {
        assert!(S3ReservationStore::open(&admission).is_err());
        let raw = audited(&admission);
        raw.checked(admission.binding().scope(), admission.profile_digest())
            .unwrap();
        let storage = Storage::open(
            admission.ledger_root(),
            admission.enrollment_digest(),
            4 * 1024 * 1024,
            JournalKind::S3,
        )
        .unwrap();
        let mut lease = storage.lease().unwrap();
        let history = lease.read().unwrap();
        assert!(
            !history.is_empty(),
            "original business operations must actually execute first"
        );
        let mut ledger = Ledger::load(&history, admission.enrollment_digest()).unwrap();
        ledger.check_audited(&raw).unwrap();
        drop(lease);
        drop(storage);
        let capacity = if fault == "append_refused" {
            let mut planned = ledger.clone();
            let hash = planned_append(
                &mut planned,
                Record::AuditedReservation {
                    reservation: Box::new(raw.clone()),
                },
            );
            let collection = admission.binding().audit().unwrap();
            let count = 3 + collection
                .list_parameters(admission.binding().scope())
                .unwrap()
                .len();
            for sequence in 1..=count {
                let mut frame = json!({"kind":"send","request_digest":admission.binding().digest(),"sequence":sequence,"send":collection.planned_send(admission.binding(), sequence, None).unwrap()});
                frame["send_digest"] = json!(canonical_hash(&frame));
                let framed = canonical_json(&frame) + "\n";
                let preview = crate::s3_access_send::S3SendPreview::from_audit_frame(
                    admission.binding(),
                    framed.as_bytes(),
                    sequence as u64,
                    None,
                )
                .unwrap();
                planned_append(
                    &mut planned,
                    Record::Debit {
                        reservation_digest: hash.clone(),
                        sequence: sequence as u64,
                        preview_digest: preview.digest().into(),
                        is_write: false,
                    },
                );
            }
            let full = std::fs::metadata(admission.ledger_root().join("reservations.jsonl"))
                .unwrap()
                .len() as usize;
            full - history.len() + planned.bytes
        } else {
            4 * 1024 * 1024
        };
        let storage = Storage::open(
            admission.ledger_root(),
            admission.enrollment_digest(),
            capacity,
            JournalKind::S3,
        )
        .unwrap();
        let mut lease = storage.lease().unwrap();
        assert_eq!(lease.read().unwrap(), history);
        let reservation_digest = append(
            &mut lease,
            &mut ledger,
            Record::AuditedReservation {
                reservation: Box::new(raw),
            },
        )
        .unwrap();
        let reservation = S3Reservation {
            lease,
            ledger,
            admission: &admission,
            reservation_digest,
        };
        execution = crate::s3_worker_protocol::supervise(
            &mut process,
            reservation,
            secret,
            deadline,
            end,
            &AtomicBool::new(false),
        );
    }
    assert!(process.reaped && process.signalled && process.group_absent());
    assert_eq!(process.lost_ack_seen, fault == "lost_ack");
    let storage = Storage::open(
        admission.ledger_root(),
        admission.enrollment_digest(),
        4 * 1024 * 1024,
        JournalKind::S3,
    )
    .unwrap();
    let mut lease = storage.lease().unwrap();
    let retained_bytes = lease.read().unwrap();
    let retained = Ledger::load(&retained_bytes, admission.enrollment_digest()).unwrap();
    let row = &retained.requests[admission.binding().digest()];
    assert_eq!(
        row.digest,
        execution["reservation_digest"].as_str().unwrap()
    );
    if admission.binding().audit().is_some() {
        assert_eq!(row.discovery.is_some(), fault != "append_refused");
        assert!(retained.check_audited(&audited(&admission)).is_err());
        if fault != "none" {
            assert!(execution["result"].is_null());
        }
    }
    let success =
        execution["result"]["outcome"] == "observed" && execution["cleanup"] == "verified";
    let task = crate::runner::outcome_result(admission.manifest(), admission.profile(), now.to_utc(), ActionOutcome {
        status: if success { TaskStatus::Success } else { TaskStatus::Failed }, output: json!({"s3_execution":execution}),
        stdout: BoundedOutput::default(), stderr: BoundedOutput::default(), receipt_ids: Vec::new(), cleanup: None,
        error: (!success).then(|| ErrorRecord { code: "s3_operation_incomplete".into(), message: "The fixed S3 operation did not establish a complete clean observation.".into() }),
        limitations: vec!["Test-only native/Python bridge with inert SDK and fixture transport, not protected installation, TLS, AWS, or independent evidence.".into()],
    });
    save(
        &input_path.parent().unwrap().join("result.json"),
        &json!({
            "task_id":input["task_id"],"request_hash":transport_hash,"result":task,
            "native_journal_sha256":format!("sha256:{}",sha256_hex(&retained_bytes)),
            "native_journal_entries":retained.entries,"discovery_committed":row.discovery.is_some(),
            "discovery_ack_checked":process.discovery_ack_checked,
            "lost_ack_observed":process.lost_ack_seen,"child_reaped":process.reaped,"group_absent":process.group_absent()
        }),
    );
}
