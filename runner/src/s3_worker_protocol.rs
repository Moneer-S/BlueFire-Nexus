//! One fixed worker conversation under native deadlines and durable send debits.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use chrono::{DateTime, FixedOffset};
use serde_json::{json, Value};

use crate::canonical::canonical_json;
use crate::s3_reservation::{PolicyPosition, S3Reservation};
use crate::s3_worker_result::WorkerResult;
use crate::s3_worker_secret::WorkerSecret;

const POLL: Duration = Duration::from_millis(2);

pub(crate) enum Chunk {
    Bytes(Vec<u8>),
    Pending,
    Eof,
}

/// Implemented only by the fixed private process driver and deterministic tests.
pub(crate) trait Driver {
    fn now(&self) -> Instant;
    fn wall(&self) -> DateTime<FixedOffset>;
    fn pause(&mut self, duration: Duration);
    fn read(&mut self, stderr: bool) -> Result<Chunk, ()>;
    fn write(&mut self, bytes: &[u8]) -> Result<usize, ()>;
    fn identity(&mut self) -> Result<(u32, u64), ()>;
    fn exited(&mut self) -> Result<bool, ()>;
    fn terminate_group(&mut self) -> bool;
    fn reap(&mut self) -> Result<Option<Option<i32>>, ()>;
    fn group_absent(&mut self) -> bool;
}

#[derive(PartialEq, Eq)]
enum Phase {
    Ready,
    Running,
    Result,
}

struct Conversation<'a> {
    reservation: S3Reservation<'a>,
    secret: Option<WorkerSecret>,
    phase: Phase,
    pending: Vec<u8>,
    written: usize,
    buffer: Vec<u8>,
    input_total: usize,
    output_total: usize,
    stderr_total: usize,
    ended: [bool; 2],
    result: Option<WorkerResult>,
}

impl<'a> Conversation<'a> {
    fn new(reservation: S3Reservation<'a>, secret: WorkerSecret) -> Self {
        let mut pending = reservation.binding().canonical_json().as_bytes().to_vec();
        pending.push(b'\n');
        Self {
            reservation,
            secret: Some(secret),
            phase: Phase::Ready,
            written: 0,
            input_total: pending.len(),
            pending,
            buffer: Vec::new(),
            output_total: 0,
            stderr_total: 0,
            ended: [false; 2],
            result: None,
        }
    }
    fn queue(&mut self, value: &Value) -> Result<(), ()> {
        if self.written != self.pending.len() {
            return Err(());
        }
        self.pending = canonical_json(value).into_bytes();
        self.pending.push(b'\n');
        self.written = 0;
        self.input_total += self.pending.len();
        if self.input_total > 128 * 1024 {
            Err(())
        } else {
            Ok(())
        }
    }
    fn frame(&mut self, bytes: &[u8], driver: &mut impl Driver) -> Result<(), ()> {
        let frame: Value = serde_json::from_slice(bytes).map_err(|_| ())?;
        if canonical_json(&frame).as_bytes() != &bytes[..bytes.len() - 1] {
            return Err(());
        }
        match self.phase {
            Phase::Ready => {
                let (pid, ticks) = driver.identity()?;
                let nonce = frame["nonce"].as_str().ok_or(())?;
                if nonce.len() != 64
                    || !nonce
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                {
                    return Err(());
                }
                if frame
                    != json!({"kind":"ready", "request_digest":self.reservation.binding().digest(),
                    "process_id":pid,"creation_identity":ticks.to_string(),"nonce":nonce})
                {
                    return Err(());
                }
                let mut ack = frame.clone();
                ack["kind"] = json!("contained");
                self.queue(&ack)?;
                let mut secret = self
                    .secret
                    .take()
                    .ok_or(())?
                    .frame(self.reservation.binding().digest(), nonce);
                self.input_total += secret.len();
                if secret.len() > 16 * 1024 || self.input_total > 128 * 1024 {
                    secret.fill(0);
                    return Err(());
                }
                self.pending.extend_from_slice(&secret);
                secret.fill(0);
                self.phase = Phase::Running;
            }
            Phase::Running if frame["kind"] == "send" => {
                // No queue/pipe operation can precede the durable reservation debit.
                let permit = self
                    .reservation
                    .debit(bytes, driver.wall())
                    .map_err(|_| ())?;
                self.queue(&permit)?;
            }
            Phase::Running if frame["kind"] == "result" => {
                self.result = Some(
                    WorkerResult::from_frame(
                        self.reservation.binding(),
                        bytes,
                        self.reservation.send_debits(),
                    )
                    .map_err(|_| ())?,
                );
                self.phase = Phase::Result;
            }
            _ => return Err(()),
        }
        Ok(())
    }
    fn turn(&mut self, driver: &mut impl Driver, accept_frames: bool) -> Result<(), ()> {
        for (index, stderr) in [false, true].into_iter().enumerate() {
            if self.ended[index] {
                continue;
            }
            match driver.read(stderr)? {
                Chunk::Pending => {}
                Chunk::Eof => self.ended[index] = true,
                Chunk::Bytes(bytes) if stderr => {
                    self.stderr_total = self.stderr_total.saturating_add(bytes.len());
                    if self.stderr_total > 4096 {
                        return Err(());
                    }
                }
                Chunk::Bytes(bytes) => {
                    self.output_total = self.output_total.saturating_add(bytes.len());
                    if bytes.len() > 4096 || self.output_total > 64 * 1024 {
                        return Err(());
                    }
                    if accept_frames {
                        self.buffer.extend_from_slice(&bytes);
                    }
                }
            }
        }
        if !accept_frames {
            return Ok(());
        }
        if self.written < self.pending.len() {
            let maximum = (self.pending.len() - self.written).min(4096);
            let count = driver.write(&self.pending[self.written..self.written + maximum])?;
            if count > maximum {
                return Err(());
            }
            // Do not retain credential bytes in already-written queue space.
            self.pending[self.written..self.written + count].fill(0);
            self.written += count;
        }
        if self.written == self.pending.len() {
            if let Some(end) = self.buffer.iter().position(|byte| *byte == b'\n') {
                if end + 1 > 16 * 1024 {
                    return Err(());
                }
                let line: Vec<_> = self.buffer.drain(..=end).collect();
                self.frame(&line, driver)?;
            } else if self.buffer.len() > 16 * 1024 {
                return Err(());
            }
        }
        Ok(())
    }
}

pub(crate) fn supervise(
    driver: &mut impl Driver,
    reservation: S3Reservation<'_>,
    secret: WorkerSecret,
    deadline: Instant,
    cleanup_end: Instant,
    cancelled: &AtomicBool,
) -> Value {
    let mut conversation = Conversation::new(reservation, secret);
    let mut healthy = true;
    loop {
        if cancelled.load(Ordering::Acquire)
            || driver.now() >= deadline
            || !conversation.reservation.current(driver.wall())
            || conversation.turn(driver, true).is_err()
        {
            healthy = false;
            break;
        }
        match driver.exited() {
            Ok(true) if conversation.ended == [true, true] => break,
            Ok(_) => driver.pause(POLL.min(deadline.saturating_duration_since(driver.now()))),
            Err(()) => {
                healthy = false;
                break;
            }
        }
    }
    // Signal the owned unreaped group before releasing its PID pin. No later
    // retry can signal a reused numeric PID or manufacture verified cleanup.
    let signalled = driver.terminate_group();
    let mut reaped = false;
    let mut exit_code = None;
    let mut clean = false;
    while driver.now() < cleanup_end {
        if conversation.turn(driver, false).is_err() {
            healthy = false;
        }
        if !reaped {
            match driver.reap() {
                Ok(Some(code)) => {
                    reaped = true;
                    exit_code = code;
                }
                Ok(None) => {}
                Err(()) => healthy = false,
            }
        }
        if signalled && reaped && conversation.ended == [true, true] && driver.group_absent() {
            clean = true;
            break;
        }
        driver.pause(POLL.min(cleanup_end.saturating_duration_since(driver.now())));
    }
    let complete = healthy
        && exit_code == Some(0)
        && conversation.buffer.is_empty()
        && conversation.phase == Phase::Result
        && conversation.written == conversation.pending.len();
    let result = conversation.result.take().filter(|_| complete);
    let observed = result.as_ref().is_some_and(|result| result.observed);
    let position = result
        .as_ref()
        .map_or(PolicyPosition::Unknown, |result| result.policy_position);
    let request_digest = conversation.reservation.binding().digest().to_string();
    let reservation_digest = conversation.reservation.digest().to_string();
    let debits = conversation.reservation.send_debits();
    let write_debited = conversation.reservation.write_debited();
    let baseline_ok = !conversation.reservation.baseline_phase()
        || result
            .as_ref()
            .is_some_and(|result| result.all_objects_read);
    let document = result.map_or(Value::Null, |result| result.document().clone());
    conversation.pending.fill(0);
    let committed = conversation
        .reservation
        .complete(&document, observed && baseline_ok, position, clean)
        .is_ok();
    let unsettled = write_debited && !(observed && clean && committed);
    json!({
        "schema_version":"bluefire.s3-execution.v1", "request_digest":request_digest,
        "admission":{"accepted":true,"problem":null},
        "dispatch":if unsettled { "unknown" } else if debits > 0 { "permit_issued" } else { "not_started" },
        "send_debits":debits, "result":document,
        "cleanup":if clean && committed { "verified" } else { "unknown" },
        "provenance":"runner_reported", "reservation_digest":reservation_digest,
    })
}

#[cfg(test)]
#[path = "s3_worker_protocol_tests.rs"]
mod tests;
