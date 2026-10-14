//! Fixed local Win32 backend. Microsoft references: LogonUserW,
//! ImpersonateLoggedOnUser, TOKEN_STATISTICS, GetFileInformationByHandleEx,
//! GetVolumeInformationByHandleW and GetSecurityInfo. Network logon returns an
//! impersonation token; effective instance binding occurs after impersonation.
use super::ffi::*;
use super::{
    descriptor, Backend, CleanupFacts, Failure, FileFacts, FileIdentity, SecretCredential,
    TokenFacts,
};
use std::ffi::c_void;
use std::mem::size_of;
use std::ptr::{null, null_mut};

#[derive(Default)]
pub(super) struct WindowsBackend<'a> {
    logon_token: Option<Handle>,
    logon_facts: Option<TokenFacts>,
    controller: Option<TokenFacts>,
    effective_facts: Option<TokenFacts>,
    thread: Option<u32>,
    impersonating: bool,
    files: Vec<Handle>,
    observers: Vec<Handle>,
    allocations: Vec<*mut c_void>,
    cleanup_failed: bool,
    reader_released: bool,
    owner_phase: bool,
    owner_entered: bool,
    pair_deadline: Option<std::time::Instant>,
    pair_cancelled: Option<&'a dyn Fn() -> bool>,
}
fn native(stage: &'static str) -> Failure {
    Failure::native(stage, unsafe { GetLastError() })
}
fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain([0]).collect()
}
fn invalid(stage: &'static str) -> Failure {
    Failure::new(stage, "native_response_invalid")
}
impl<'a> WindowsBackend<'a> {
    pub(super) fn for_pair(deadline: std::time::Instant, cancelled: &'a dyn Fn() -> bool) -> Self {
        Self {
            logon_token: None,
            logon_facts: None,
            controller: None,
            effective_facts: None,
            thread: None,
            impersonating: false,
            files: Vec::new(),
            observers: Vec::new(),
            allocations: Vec::new(),
            cleanup_failed: false,
            reader_released: false,
            owner_phase: false,
            owner_entered: false,
            pair_deadline: Some(deadline),
            pair_cancelled: Some(cancelled),
        }
    }
    fn pair_current(&self) -> Result<(), Failure> {
        if self.pair_cancelled.is_some_and(|cancelled| cancelled()) {
            return Err(Failure::new("pair_boundary", "cancelled"));
        }
        if self
            .pair_deadline
            .is_some_and(|deadline| std::time::Instant::now() >= deadline)
        {
            return Err(Failure::new("pair_boundary", "deadline"));
        }
        Ok(())
    }
    fn thread_current(&self) -> Result<(), Failure> {
        if self.thread != Some(unsafe { GetCurrentThreadId() }) {
            return Err(Failure::new("context", "thread_changed"));
        }
        Ok(())
    }
    fn close_observer(&mut self, handle: Handle) -> Result<(), Failure> {
        if unsafe { CloseHandle(handle) } == 0 {
            self.observers.push(handle);
            self.cleanup_failed = true;
            return Err(native("token_close"));
        }
        Ok(())
    }
    fn process_facts(&mut self) -> Result<TokenFacts, Failure> {
        // GetCurrentProcessToken's documented pseudo-handle observes the actual
        // current primary token even under thread impersonation. A freshly opened
        // TOKEN_QUERY handle can be denied by the owner's token DACL to the reader.
        // The pseudo-handle follows primary-token replacement and is not owned.
        token_facts(CURRENT_PROCESS_TOKEN)
    }
    fn no_thread_token(&mut self) -> Result<(), Failure> {
        let mut token = null_mut();
        if unsafe { OpenThreadToken(GetCurrentThread(), 8, 1, &mut token) } != 0 {
            if token.is_null() || token == INVALID_HANDLE {
                return Err(invalid("caller"));
            }
            self.close_observer(token)?;
            return Err(Failure::new("caller", "preexisting_impersonation_refused"));
        }
        let code = unsafe { GetLastError() };
        if code != 1008 {
            return Err(Failure::native("caller", code));
        }
        Ok(())
    }
    fn observe_effective(&mut self) -> Result<TokenFacts, Failure> {
        self.thread_current()?;
        if !self.impersonating {
            return Err(Failure::new("context", "owned_impersonation_missing"));
        }
        let mut token = null_mut();
        if unsafe { OpenThreadToken(GetCurrentThread(), 8, 1, &mut token) } == 0 {
            return Err(native("context"));
        }
        if token.is_null() || token == INVALID_HANDLE {
            return Err(invalid("context"));
        }
        let facts = token_facts(token);
        self.close_observer(token)?;
        let observed = facts?;
        let logon = self
            .logon_facts
            .as_ref()
            .ok_or_else(|| invalid("context"))?;
        if !observed.valid(&logon.sid, 2) || observed.authentication != logon.authentication {
            return Err(Failure::new("context", "effective_reader_mismatch"));
        }
        if let Some(bound) = &self.effective_facts {
            if observed != *bound {
                return Err(Failure::new("context", "effective_token_drift"));
            }
        } else {
            self.effective_facts = Some(observed.clone());
        }
        let process = self.process_facts()?;
        if self.controller.as_ref() != Some(&process) {
            return Err(Failure::new("context", "controller_token_drift"));
        }
        Ok(observed)
    }
    fn owned_file(&mut self, index: usize) -> Result<Handle, Failure> {
        self.file_context()?;
        self.files
            .get(index)
            .copied()
            .ok_or_else(|| invalid("metadata"))
    }
    fn file_context(&mut self) -> Result<TokenFacts, Failure> {
        self.pair_current()?;
        let result = if self.owner_phase {
            self.caller()
        } else {
            self.observe_effective()
        };
        self.pair_current()?;
        result
    }
    fn free_descriptor(&mut self, allocation: *mut c_void) -> Result<(), Failure> {
        if unsafe { LocalFree(allocation) }.is_null() {
            return Ok(());
        }
        self.allocations.push(allocation);
        self.cleanup_failed = true;
        Err(Failure::new("descriptor", "descriptor_cleanup_unknown"))
    }
}
impl Backend for WindowsBackend<'_> {
    fn caller(&mut self) -> Result<TokenFacts, Failure> {
        if self.thread.is_none() {
            self.thread = Some(unsafe { GetCurrentThreadId() });
        }
        self.thread_current()?;
        self.no_thread_token()?;
        let facts = self.process_facts()?;
        if let Some(bound) = &self.controller {
            if facts != *bound {
                return Err(Failure::new("caller", "controller_token_drift"));
            }
        } else {
            self.controller = Some(facts.clone());
        }
        Ok(facts)
    }
    fn logon(&mut self, credential: &SecretCredential) -> Result<TokenFacts, Failure> {
        self.thread_current()?;
        self.no_thread_token()?;
        self.pair_current()?;
        if self.logon_token.is_some() || self.owner_entered {
            return Err(Failure::new("logon", "duplicate_logon_refused"));
        }
        let mut token = null_mut();
        // Fixed local SAM domain '.', NETWORK(3), DEFAULT(0); never AD type 9.
        let domain = [b'.' as u16, 0];
        if unsafe {
            LogonUserW(
                credential.account.as_ptr(),
                domain.as_ptr(),
                credential.password.as_ptr(),
                3,
                0,
                &mut token,
            )
        } == 0
        {
            return Err(native("logon"));
        }
        if token.is_null() || token == INVALID_HANDLE {
            return Err(invalid("logon"));
        }
        self.logon_token = Some(token);
        self.pair_current()?;
        let facts = token_facts(token)?;
        self.logon_facts = Some(facts.clone());
        Ok(facts)
    }
    fn impersonate(&mut self) -> Result<(), Failure> {
        self.thread_current()?;
        self.no_thread_token()?;
        self.pair_current()?;
        let token = self.logon_token.ok_or_else(|| invalid("impersonate"))?;
        if unsafe { ImpersonateLoggedOnUser(token) } == 0 {
            return Err(native("impersonate"));
        }
        self.impersonating = true;
        self.pair_current()?;
        self.observe_effective()?;
        Ok(())
    }
    fn effective(&mut self) -> Result<TokenFacts, Failure> {
        self.file_context()
    }
    fn open(&mut self, exact_path: &str, directory: bool, data: bool) -> Result<usize, Failure> {
        self.file_context()?;
        if self.files.len() >= 11 || (directory && data) {
            return Err(invalid("metadata_open"));
        }
        let root = wide("C:\\");
        if unsafe { GetDriveTypeW(root.as_ptr()) } != 3 {
            return Err(Failure::new("metadata_open", "fixed_local_drive_required"));
        }
        self.pair_current()?;
        let path = wide(&format!("\\\\?\\{exact_path}"));
        // READ_CONTROL + FILE_READ_ATTRIBUTES (+FILE_READ_DATA only at data stage).
        // FILE_SHARE_READ only, OPEN_EXISTING, OPEN_REPARSE_POINT. Directory flag
        // enables a directory handle; no privilege is enabled or adjusted.
        let handle = unsafe {
            CreateFileW(
                path.as_ptr(),
                0x0002_0080 | u32::from(data),
                1,
                null(),
                3,
                0x0020_0000 | if directory { 0x0200_0000 } else { 0x80 },
                null_mut(),
            )
        };
        if handle == INVALID_HANDLE {
            return Err(native(if data { "data_open" } else { "metadata_open" }));
        }
        if handle.is_null() {
            return Err(invalid("metadata_open"));
        }
        let slot = self.files.len();
        self.files.push(handle);
        Ok(slot)
    }
    fn facts(&mut self, index: usize) -> Result<FileFacts, Failure> {
        let handle = self.owned_file(index)?;
        let mut basic = FileBasicInfo::default();
        let mut standard = FileStandardInfo::default();
        let mut identity = FileIdInfo::default();
        let mut tag = FileTagInfo::default();
        info(handle, 0, &mut basic)?;
        self.pair_current()?;
        info(handle, 1, &mut standard)?;
        self.pair_current()?;
        info(handle, 18, &mut identity)?;
        self.pair_current()?;
        info(handle, 9, &mut tag)?;
        self.pair_current()?;
        if unsafe { GetFileType(handle) } != 1
            || standard.directory > 1
            || standard.delete_pending != 0
            || standard.size < 0
            || (standard.directory == 0 && standard.links != 1)
            || basic.attributes != tag.attributes
            || tag.attributes & (0x400 | 0x1000) != 0
            || tag.tag != 0
            || identity.id == [0; 16]
            || (tag.attributes & 0x10 != 0) != (standard.directory != 0)
        {
            return Err(Failure::new("metadata", "ordinary_object_required"));
        }
        let mut flags = 0;
        let mut filesystem = [0u16; 32];
        if unsafe {
            GetVolumeInformationByHandleW(
                handle,
                null_mut(),
                0,
                null_mut(),
                null_mut(),
                &mut flags,
                filesystem.as_mut_ptr(),
                filesystem.len() as u32,
            )
        } == 0
        {
            return Err(native("volume"));
        }
        let end = filesystem
            .iter()
            .position(|v| *v == 0)
            .ok_or_else(|| invalid("volume"))?;
        if flags & 8 == 0 || String::from_utf16(&filesystem[..end]).ok().as_deref() != Some("NTFS")
        {
            return Err(Failure::new("volume", "acl_capable_ntfs_required"));
        }
        let mut name = [0u16; 512];
        let length =
            unsafe { GetFinalPathNameByHandleW(handle, name.as_mut_ptr(), name.len() as u32, 0) };
        if length == 0 {
            return Err(native("final_path"));
        }
        if length as usize >= name.len() {
            return Err(invalid("final_path"));
        }
        let final_path =
            String::from_utf16(&name[..length as usize]).map_err(|_| invalid("final_path"))?;
        Ok(FileFacts {
            identity: FileIdentity {
                volume_serial: identity.volume,
                file_id: identity.id,
            },
            final_path,
            directory: standard.directory != 0,
            size: standard.size as u64,
            links: standard.links,
            attributes: tag.attributes,
            created: basic.created,
            written: basic.written,
            changed: basic.changed,
        })
    }
    fn descriptor(&mut self, index: usize) -> Result<Vec<u8>, Failure> {
        let handle = self.owned_file(index)?;
        let mut allocation = null_mut();
        let code = unsafe {
            GetSecurityInfo(
                handle,
                1,
                5,
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
                &mut allocation,
            )
        };
        if code != 0 {
            if !allocation.is_null() {
                self.free_descriptor(allocation)?;
            }
            return Err(Failure::native("descriptor", code));
        }
        if allocation.is_null() {
            return Err(invalid("descriptor"));
        }
        let result = (|| {
            if unsafe { IsValidSecurityDescriptor(allocation) } == 0 {
                return Err(invalid("descriptor"));
            }
            let length = unsafe { GetSecurityDescriptorLength(allocation) } as usize;
            if !(20..=65_536).contains(&length) {
                return Err(invalid("descriptor"));
            }
            // GetSecurityInfo returns one LocalAlloc self-relative descriptor.
            Ok(unsafe { std::slice::from_raw_parts(allocation.cast::<u8>(), length) }.to_vec())
        })();
        self.free_descriptor(allocation)?;
        result
    }
    fn read(&mut self, index: usize, output: &mut [u8]) -> Result<usize, Failure> {
        let handle = self.owned_file(index)?;
        if output.is_empty() || output.len() > 8192 {
            return Err(invalid("read"));
        }
        let mut count = 0;
        if unsafe {
            ReadFile(
                handle,
                output.as_mut_ptr(),
                output.len() as u32,
                &mut count,
                null_mut(),
            )
        } == 0
        {
            return Err(native("read"));
        }
        if count as usize > output.len() {
            return Err(invalid("read"));
        }
        Ok(count as usize)
    }
    fn cleanup(&mut self) -> CleanupFacts {
        if self.thread.is_none()
            && self.controller.is_none()
            && self.logon_token.is_none()
            && self.files.is_empty()
            && self.observers.is_empty()
            && self.allocations.is_empty()
        {
            return CleanupFacts {
                handles_released: true,
                impersonation_reverted: true,
                controller_restored: true,
                owned_process_exit_required: false,
            };
        }
        let mut handles_released = !self.cleanup_failed;
        self.files.retain(|handle| {
            let failed = unsafe { CloseHandle(*handle) } == 0;
            handles_released &= !failed;
            failed
        });
        self.allocations.retain(|pointer| {
            let failed = !unsafe { LocalFree(*pointer) }.is_null();
            handles_released &= !failed;
            failed
        });
        if self.impersonating {
            // Microsoft requires process termination after failed reversion. This
            // component can be used only in the externally owned disposable worker.
            if self.thread_current().is_err() || unsafe { RevertToSelf() } == 0 {
                std::process::abort();
            }
            self.impersonating = false;
        }
        let restored = self.no_thread_token().is_ok()
            && match (self.process_facts(), &self.controller) {
                (Ok(current), Some(original)) => current == *original,
                (Ok(_), None) => true,
                _ => false,
            };
        if let Some(token) = self.logon_token {
            if unsafe { CloseHandle(token) } != 0 {
                self.logon_token = None;
            } else {
                handles_released = false;
            }
        }
        self.observers.retain(|handle| {
            let failed = unsafe { CloseHandle(*handle) } == 0;
            handles_released &= !failed;
            failed
        });
        handles_released &= !self.cleanup_failed
            && self.files.is_empty()
            && self.allocations.is_empty()
            && self.observers.is_empty()
            && self.logon_token.is_none();
        let complete = handles_released && restored && !self.impersonating;
        if self.pair_deadline.is_some() && !complete {
            self.cleanup_failed = true;
            self.reader_released = false;
        }
        if !self.owner_entered && self.effective_facts.is_some() && complete {
            self.reader_released = true;
        }
        self.owner_phase = false;
        CleanupFacts {
            handles_released,
            impersonation_reverted: !self.impersonating,
            controller_restored: restored,
            owned_process_exit_required: !handles_released || !restored,
        }
    }
    fn enter_owner_phase(&mut self, original: &TokenFacts) -> Result<(), Failure> {
        if self.owner_entered
            || !self.reader_released
            || self.cleanup_failed
            || self.impersonating
            || self.logon_token.is_some()
            || !self.files.is_empty()
            || !self.observers.is_empty()
            || !self.allocations.is_empty()
            || self.controller.as_ref() != Some(original)
        {
            return Err(Failure::new("owner_context", "owner_phase_not_ready"));
        }
        if self.caller()? != *original {
            return Err(Failure::new("owner_context", "controller_token_drift"));
        }
        self.logon_facts = None;
        self.effective_facts = None;
        self.owner_entered = true;
        self.owner_phase = true;
        Ok(())
    }
}
impl Drop for WindowsBackend<'_> {
    fn drop(&mut self) {
        if self.impersonating {
            std::process::abort();
        }
        for handle in self
            .files
            .iter()
            .chain(self.observers.iter())
            .chain(self.logon_token.iter())
        {
            unsafe {
                CloseHandle(*handle);
            }
        }
        for pointer in &self.allocations {
            unsafe {
                LocalFree(*pointer);
            }
        }
    }
}
fn info<T>(handle: Handle, class: u32, output: &mut T) -> Result<(), Failure> {
    if unsafe {
        GetFileInformationByHandleEx(
            handle,
            class,
            (output as *mut T).cast(),
            size_of::<T>() as u32,
        )
    } == 0
    {
        return Err(native("metadata"));
    }
    Ok(())
}
fn fixed_token<T: Default>(token: Handle, class: u32) -> Result<T, Failure> {
    let mut output = T::default();
    let mut returned = 0;
    if unsafe {
        GetTokenInformation(
            token,
            class,
            (&mut output as *mut T).cast(),
            size_of::<T>() as u32,
            &mut returned,
        )
    } == 0
    {
        return Err(native("token"));
    }
    if returned as usize != size_of::<T>() {
        return Err(invalid("token"));
    }
    Ok(output)
}
fn token_buffer(token: Handle, class: u32, minimum: usize) -> Result<(Vec<usize>, usize), Failure> {
    let mut needed = 0;
    if unsafe { GetTokenInformation(token, class, null_mut(), 0, &mut needed) } != 0
        || unsafe { GetLastError() } != 122
        || !(minimum..=65_536).contains(&(needed as usize))
    {
        return Err(invalid("token"));
    }
    let mut buffer = vec![0usize; (needed as usize).div_ceil(size_of::<usize>())];
    let mut returned = 0;
    if unsafe {
        GetTokenInformation(
            token,
            class,
            buffer.as_mut_ptr().cast(),
            needed,
            &mut returned,
        )
    } == 0
    {
        return Err(native("token"));
    }
    if returned as usize > needed as usize || (returned as usize) < minimum {
        return Err(invalid("token"));
    }
    Ok((buffer, returned as usize))
}
fn token_facts(token: Handle) -> Result<TokenFacts, Failure> {
    // Two-ended statistics bind identity/elevation/privilege reads to one instance.
    let stats: TokenStatistics = fixed_token(token, 10)?;
    let (buffer, returned) = token_buffer(token, 1, size_of::<TokenUser>())?;
    let row = unsafe { &*buffer.as_ptr().cast::<TokenUser>() };
    let offset = (row.sid as usize)
        .checked_sub(buffer.as_ptr() as usize)
        .filter(|offset| *offset >= size_of::<TokenUser>())
        .ok_or_else(|| invalid("token"))?;
    let bytes = unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), returned) };
    let (sid, _) = descriptor::sid(bytes.get(offset..).ok_or_else(|| invalid("token"))?)?;
    let elevated: u32 = fixed_token(token, 20)?;
    if elevated > 1 {
        return Err(invalid("token"));
    }
    let (privileges, length) = token_buffer(token, 3, 4)?;
    let bytes = unsafe { std::slice::from_raw_parts(privileges.as_ptr().cast::<u8>(), length) };
    let count = u32::from_le_bytes(bytes[..4].try_into().map_err(|_| invalid("token"))?) as usize;
    if count > 128 || length != 4 + count * 12 {
        return Err(invalid("token"));
    }
    // Refuse enabled backup, restore, ownership and security privileges; the
    // backend never enables any privileges or requests write rights.
    let mut dangerous_privileges = false;
    let mut forbidden = [0u64; 4];
    for (index, name) in [
        "SeSecurityPrivilege",
        "SeTakeOwnershipPrivilege",
        "SeBackupPrivilege",
        "SeRestorePrivilege",
    ]
    .iter()
    .enumerate()
    {
        let name = wide(name);
        let mut value = Luid::default();
        if unsafe { LookupPrivilegeValueW(null(), name.as_ptr(), &mut value) } == 0 {
            return Err(native("token_privileges"));
        }
        forbidden[index] = value.value();
    }
    for row in bytes[4..].chunks_exact(12) {
        let low = u32::from_le_bytes(row[..4].try_into().map_err(|_| invalid("token"))?);
        let high = u32::from_le_bytes(row[4..8].try_into().map_err(|_| invalid("token"))?);
        let attributes = u32::from_le_bytes(row[8..12].try_into().map_err(|_| invalid("token"))?);
        if attributes & 2 != 0 && forbidden.contains(&(((high as u64) << 32) | low as u64)) {
            dangerous_privileges = true;
        }
    }
    let after: TokenStatistics = fixed_token(token, 10)?;
    if stats.token_id.value() != after.token_id.value()
        || stats.authentication_id.value() != after.authentication_id.value()
        || stats.modified.value() != after.modified.value()
        || stats.token_type != after.token_type
        || (stats.token_type == 2 && stats.level != after.level)
    {
        return Err(Failure::new("token", "token_snapshot_drift"));
    }
    Ok(TokenFacts {
        sid,
        instance: stats.token_id.value(),
        authentication: stats.authentication_id.value(),
        modified: stats.modified.value(),
        kind: stats.token_type,
        level: if stats.token_type == 2 {
            stats.level
        } else {
            0
        },
        elevated: elevated != 0,
        dangerous_privileges,
    })
}
