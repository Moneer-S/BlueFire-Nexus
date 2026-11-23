//! Two fresh reads in one original interval, never two renewed v1 tasks.
use super::*;
use std::collections::BTreeMap;

#[derive(Clone, Copy)]
enum PairMode {
    Baseline,
    Correction,
}
impl PairMode {
    fn state(self) -> ResourceState {
        match self {
            Self::Baseline => ResourceState::Readable,
            Self::Correction => ResourceState::MetadataOnly,
        }
    }
    fn schema(self) -> &'static str {
        match self {
            Self::Baseline => "bluefire.windows-fixed-read-pair.v2",
            Self::Correction => "bluefire.windows-fixed-read-pair-correction.v3",
        }
    }
}

#[derive(Debug, Serialize)]
pub struct OwnerReadProof {
    pub schema_version: &'static str,
    pub outcome: ReadOutcome,
    pub issue: Option<&'static str>,
    pub failed_stage: Option<&'static str>,
    pub data_open_attempted: bool,
    pub bytes_read: usize,
    pub observed_sha256: Option<String>,
    pub original_owner_verified: bool,
    pub no_thread_token_verified: bool,
    pub resource_rechecked: bool,
}

#[derive(Debug, Serialize)]
pub struct PairReadProof {
    pub schema_version: &'static str,
    pub request_id: String,
    pub outcome: ReadOutcome,
    pub issue: Option<&'static str>,
    pub failed_stage: Option<&'static str>,
    pub reader: ReadProof,
    pub owner: OwnerReadProof,
    pub resource_pair_rechecked: bool,
    pub independent_observation: bool,
    pub cleanup: CleanupFacts,
}

#[derive(Clone, Eq, PartialEq)]
struct Snapshot {
    facts: Vec<FileFacts>,
    descriptors: Vec<Vec<u8>>,
}

// Paired modes check BOTH sides of every native callback. A late token observation must
// not permit the following file open/read even when the v1 helper is reused.
struct Guarded<'a, B, C> {
    backend: &'a mut B,
    read: &'a PreparedRead,
    clock: &'a C,
    facts: BTreeMap<usize, FileFacts>,
    descriptors: BTreeMap<usize, Vec<u8>>,
}
impl<B: Backend, C: Clock> Guarded<'_, B, C> {
    fn check(&self) -> Result<(), Failure> {
        current(self.read, self.clock, "pair_boundary")
    }
    fn snapshot(&self) -> Result<Snapshot, Failure> {
        Ok(Snapshot {
            facts: (0..5)
                .map(|i| self.facts.get(&i).cloned())
                .collect::<Option<Vec<_>>>()
                .ok_or_else(|| Failure::new("pair_recheck", "phase_snapshot_missing"))?,
            descriptors: [3, 4]
                .iter()
                .map(|i| self.descriptors.get(i).cloned())
                .collect::<Option<Vec<_>>>()
                .ok_or_else(|| Failure::new("pair_recheck", "phase_snapshot_missing"))?,
        })
    }
}
macro_rules! guarded {
    ($self:ident, $call:expr) => {{
        $self.check()?;
        let result = $call;
        $self.check()?;
        result
    }};
}
impl<B: Backend, C: Clock> Backend for Guarded<'_, B, C> {
    fn caller(&mut self) -> Result<TokenFacts, Failure> {
        guarded!(self, self.backend.caller())
    }
    fn logon(&mut self, credential: &SecretCredential) -> Result<TokenFacts, Failure> {
        guarded!(self, self.backend.logon(credential))
    }
    fn impersonate(&mut self) -> Result<(), Failure> {
        guarded!(self, self.backend.impersonate())
    }
    fn effective(&mut self) -> Result<TokenFacts, Failure> {
        guarded!(self, self.backend.effective())
    }
    fn open(&mut self, path: &str, directory: bool, data: bool) -> Result<usize, Failure> {
        guarded!(self, self.backend.open(path, directory, data))
    }
    fn facts(&mut self, handle: usize) -> Result<FileFacts, Failure> {
        let facts = guarded!(self, self.backend.facts(handle))?;
        self.facts.entry(handle).or_insert_with(|| facts.clone());
        Ok(facts)
    }
    fn descriptor(&mut self, handle: usize) -> Result<Vec<u8>, Failure> {
        let descriptor = guarded!(self, self.backend.descriptor(handle))?;
        self.descriptors
            .entry(handle)
            .or_insert_with(|| descriptor.clone());
        Ok(descriptor)
    }
    fn read(&mut self, handle: usize, output: &mut [u8]) -> Result<usize, Failure> {
        guarded!(self, self.backend.read(handle, output))
    }
    fn cleanup(&mut self) -> CleanupFacts {
        // Cleanup must still run after cancellation or expiry.
        self.backend.cleanup()
    }
    fn enter_owner_phase(&mut self, original: &TokenFacts) -> Result<(), Failure> {
        guarded!(self, self.backend.enter_owner_phase(original))
    }
}

impl PreparedRead {
    pub fn read_pair(
        self,
        credential: SecretCredential,
        cancelled: &dyn Fn() -> bool,
    ) -> PairReadProof {
        self.read_pair_for(credential, cancelled, PairMode::Baseline)
    }

    /// The digest-bound upstream admission remains an external premise. This
    /// entry only observes the metadata-only recipe with the original deadline.
    pub fn read_pair_correction(
        self,
        credential: SecretCredential,
        cancelled: &dyn Fn() -> bool,
    ) -> PairReadProof {
        self.read_pair_for(credential, cancelled, PairMode::Correction)
    }

    fn read_pair_for(
        self,
        credential: SecretCredential,
        cancelled: &dyn Fn() -> bool,
        mode: PairMode,
    ) -> PairReadProof {
        let clock = SystemClock { cancelled };
        #[cfg(target_os = "windows")]
        {
            let mut backend = windows::WindowsBackend::for_pair(self.deadline, cancelled);
            return self.read_pair_with_mode(credential, &mut backend, &clock, mode);
        }
        #[cfg(not(target_os = "windows"))]
        self.read_pair_with_mode(credential, &mut Unsupported, &clock, mode)
    }

    #[cfg(test)]
    pub(super) fn read_pair_with(
        self,
        credential: SecretCredential,
        backend: &mut impl Backend,
        clock: &impl Clock,
    ) -> PairReadProof {
        self.read_pair_with_mode(credential, backend, clock, PairMode::Baseline)
    }

    #[cfg(test)]
    pub(super) fn read_pair_correction_with(
        self,
        credential: SecretCredential,
        backend: &mut impl Backend,
        clock: &impl Clock,
    ) -> PairReadProof {
        self.read_pair_with_mode(credential, backend, clock, PairMode::Correction)
    }

    fn read_pair_with_mode(
        self,
        credential: SecretCredential,
        backend: &mut impl Backend,
        clock: &impl Clock,
        mode: PairMode,
    ) -> PairReadProof {
        let mut proof = PairReadProof {
            schema_version: mode.schema(),
            request_id: self.request_id.clone(),
            outcome: ReadOutcome::Unknown,
            issue: None,
            failed_stage: None,
            reader: ReadProof {
                schema_version: "bluefire.windows-fixed-read.v1",
                request_id: self.request_id.clone(),
                outcome: ReadOutcome::Unknown,
                issue: None,
                failed_stage: None,
                data_open_attempted: false,
                bytes_read: 0,
                observed_sha256: None,
                effective_reader_verified: false,
                resource_rechecked: false,
                independent_observation: false,
                cleanup: CleanupFacts::default(),
            },
            owner: OwnerReadProof {
                schema_version: "bluefire.windows-fixed-owner-read.v2",
                outcome: ReadOutcome::Unknown,
                issue: None,
                failed_stage: None,
                data_open_attempted: false,
                bytes_read: 0,
                observed_sha256: None,
                original_owner_verified: false,
                no_thread_token_verified: false,
                resource_rechecked: false,
            },
            resource_pair_rechecked: false,
            independent_observation: false,
            cleanup: CleanupFacts::default(),
        };
        let mut guarded = Guarded {
            backend,
            read: &self,
            clock,
            facts: BTreeMap::new(),
            descriptors: BTreeMap::new(),
        };
        let reader = (|| {
            guarded.check()?;
            if credential.generation != self.resource.generation
                || self.resource.state != mode.state()
            {
                return Err(Failure::new(
                    "credential",
                    "pair_resource_or_credential_invalid",
                ));
            }
            let original = guarded.caller()?;
            if !original.valid(&self.resource.owner, 1) {
                return Err(Failure::new("caller", "controller_identity_mismatch"));
            }
            read_once(&self, &credential, &mut guarded, clock, &mut proof.reader)?;
            Ok((original, guarded.snapshot()?))
        })();
        drop(credential);
        proof.reader.cleanup = guarded.cleanup();
        let reader = if !proof.reader.cleanup.complete() {
            Err(Failure::new("cleanup", "cleanup_unknown"))
        } else {
            reader.and_then(|value| {
                guarded.check()?;
                Ok(value)
            })
        };
        match reader {
            Err(error) => {
                proof.reader.outcome = ReadOutcome::Unknown;
                proof.reader.issue = Some(error.issue);
                proof.reader.failed_stage = Some(error.stage);
                proof.issue = Some(error.issue);
                proof.failed_stage = Some(error.stage);
            }
            Ok((original, reader_snapshot)) => {
                let owner = (|| {
                    guarded.enter_owner_phase(&original)?;
                    guarded.facts.clear();
                    guarded.descriptors.clear();
                    guarded.check()?;
                    if guarded.caller()? != original || guarded.effective()? != original {
                        return Err(Failure::new("owner_context", "controller_token_drift"));
                    }
                    proof.owner.original_owner_verified = true;
                    proof.owner.no_thread_token_verified = true;
                    owner_once(&self, &mut guarded, clock, &original, &mut proof.owner)?;
                    if guarded.snapshot()? != reader_snapshot {
                        return Err(Failure::new("pair_recheck", "resource_pair_drift"));
                    }
                    guarded.check()?;
                    proof.resource_pair_rechecked = true;
                    Ok(())
                })();
                if let Err(error) = owner {
                    proof.owner.outcome = ReadOutcome::Unknown;
                    proof.owner.issue = Some(error.issue);
                    proof.owner.failed_stage = Some(error.stage);
                    proof.issue = Some(error.issue);
                    proof.failed_stage = Some(error.stage);
                } else {
                    proof.outcome = proof.reader.outcome;
                }
            }
        }
        proof.cleanup = guarded.cleanup();
        if !proof.cleanup.complete() {
            proof.outcome = ReadOutcome::Unknown;
            proof.issue = Some("cleanup_unknown");
            proof.failed_stage = Some("cleanup");
        } else if let Err(error) = guarded.check() {
            proof.outcome = ReadOutcome::Unknown;
            proof.issue = Some(error.issue);
            proof.failed_stage = Some(error.stage);
        }
        proof
    }
}

fn owner_once(
    read: &PreparedRead,
    backend: &mut impl Backend,
    clock: &impl Clock,
    owner: &TokenFacts,
    proof: &mut OwnerReadProof,
) -> Result<(), Failure> {
    let (held, before, descriptors) = inspect(read, backend, clock, owner)?;
    effective(read, backend, clock, owner)?;
    proof.data_open_attempted = true;
    let data = backend.open(&read.resource.paths()[4], false, true)?;
    if backend.facts(data)? != before[4] {
        return Err(Failure::new("owner_metadata", "data_handle_mismatch"));
    }
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 8192];
    while proof.bytes_read < read.resource.size {
        effective(read, backend, clock, owner)?;
        let limit = buffer.len().min(read.resource.size - proof.bytes_read);
        let count = backend.read(data, &mut buffer[..limit])?;
        if count == 0 || count > limit {
            buffer.fill(0);
            return Err(Failure::new("owner_read", "read_length_mismatch"));
        }
        hash.update(&buffer[..count]);
        buffer[..count].fill(0);
        proof.bytes_read += count;
    }
    effective(read, backend, clock, owner)?;
    let trailing = backend.read(data, &mut buffer[..1])?;
    buffer.fill(0);
    if trailing != 0 {
        return Err(Failure::new("owner_read", "read_eof_mismatch"));
    }
    let digest: [u8; 32] = hash.finalize().into();
    proof.observed_sha256 = Some(format!("sha256:{}", hex::encode(digest)));
    if digest != read.resource.digest {
        return Err(Failure::new("owner_read", "read_digest_mismatch"));
    }
    if backend.facts(data)? != before[4] {
        return Err(Failure::new("owner_metadata", "data_metadata_drift"));
    }
    let (_, after, after_descriptors) = inspect(read, backend, clock, owner)?;
    if after != before || after_descriptors != descriptors {
        return Err(Failure::new("owner_recheck", "resource_drift"));
    }
    for index in 0..5 {
        if backend.facts(held[index])? != before[index] {
            return Err(Failure::new("owner_recheck", "held_metadata_drift"));
        }
    }
    for (slot, index) in [(0, 3), (1, 4)] {
        if backend.descriptor(held[index])? != descriptors[slot] {
            return Err(Failure::new("owner_recheck", "held_descriptor_drift"));
        }
    }
    effective(read, backend, clock, owner)?;
    proof.resource_rechecked = true;
    proof.outcome = ReadOutcome::Allowed;
    Ok(())
}
