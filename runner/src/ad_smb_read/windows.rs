//! Fixed client-local Win32 implementation. All SMB calls are synchronous and
//! require the external disposable-process supervisor's original deadline.
//!
//! Sources: Microsoft LogonUserW, TOKEN_STATISTICS, FILE_REMOTE_PROTOCOL_INFO,
//! GetFileInformationByHandleEx and WNetCancelConnection2W documentation; ABI:
//! microsoft/win32metadata generation/WinSDK/RecompiledIdlHeaders/um/WinBase.h.

use super::ffi::*;
use super::{
    Backend, CleanupFacts, Failure, FileFacts, LocalLogon, ProtocolFacts, SecretCredential,
};
use std::mem::{size_of, size_of_val};
use std::ptr::{null, null_mut};

#[derive(Default)]
pub(super) struct WindowsBackend {
    token: Option<Handle>,
    file: Option<Handle>,
    observation_tokens: Vec<Handle>,
    logon: Option<LocalLogon>,
    thread_id: Option<u32>,
    impersonating: bool,
    open_attempted: bool,
}

fn error(stage: &'static str) -> Failure {
    Failure::native(stage, unsafe { GetLastError() })
}
fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain([0]).collect()
}

impl WindowsBackend {
    fn release_observer(&mut self, token: Handle) -> Result<(), Failure> {
        if unsafe { CloseHandle(token) } == 0 {
            self.observation_tokens.push(token);
            return Err(error("token_observation_close"));
        }
        Ok(())
    }

    fn same_context(&mut self) -> Result<(), Failure> {
        if !self.impersonating || self.thread_id != Some(unsafe { GetCurrentThreadId() }) {
            return Err(Failure::new("context", "owned_impersonation_missing"));
        }
        let mut token = null_mut();
        if unsafe { OpenThreadToken(GetCurrentThread(), 0x0008, 1, &mut token) } == 0 {
            return Err(error("context"));
        }
        let facts = token_facts(token);
        self.release_observer(token)?;
        if facts?
            != *self
                .logon
                .as_ref()
                .ok_or(Failure::new("context", "owned_logon_missing"))?
        {
            return Err(Failure::new("context", "owned_logon_changed"));
        }
        Ok(())
    }

    fn handle(&mut self) -> Result<Handle, Failure> {
        self.same_context()?;
        self.file
            .ok_or(Failure::new("metadata", "owned_file_missing"))
    }
}

impl Backend for WindowsBackend {
    fn caller(&mut self) -> Result<LocalLogon, Failure> {
        self.thread_id = Some(unsafe { GetCurrentThreadId() });
        let mut token = null_mut();
        if unsafe { OpenThreadToken(GetCurrentThread(), 0x0008, 1, &mut token) } != 0 {
            self.release_observer(token)?;
            return Err(Failure::new("caller", "preexisting_impersonation_refused"));
        }
        let status = unsafe { GetLastError() };
        if status != 1008 {
            return Err(Failure::native("caller", status));
        }
        if unsafe { OpenProcessToken(GetCurrentProcess(), 0x0008, &mut token) } == 0 {
            return Err(error("caller"));
        }
        let facts = token_facts(token);
        self.release_observer(token)?;
        facts
    }

    fn logon(&mut self, secret: &SecretCredential) -> Result<LocalLogon, Failure> {
        if self.token.is_some() {
            return Err(Failure::new("logon", "duplicate_logon_refused"));
        }
        let mut token = null_mut();
        // A UPN with NULL domain; NEW_CREDENTIALS/WINNT50 only. No ambient fallback.
        if unsafe {
            LogonUserW(
                secret.upn.as_ptr(),
                null(),
                secret.password.as_ptr(),
                9,
                3,
                &mut token,
            )
        } == 0
        {
            return Err(error("logon"));
        }
        self.token = Some(token);
        let facts = token_facts(token)?;
        self.logon = Some(facts.clone());
        Ok(facts)
    }

    fn impersonate(&mut self) -> Result<(), Failure> {
        if self.thread_id != Some(unsafe { GetCurrentThreadId() }) {
            return Err(Failure::new("impersonate", "thread_changed"));
        }
        let token = self
            .token
            .ok_or(Failure::new("impersonate", "owned_token_missing"))?;
        if unsafe { ImpersonateLoggedOnUser(token) } == 0 {
            return Err(error("impersonate"));
        }
        self.impersonating = true;
        self.same_context()
    }

    fn open(&mut self, exact_path: &str) -> Result<(), Failure> {
        self.same_context()?;
        if self.open_attempted {
            return Err(Failure::new("open", "duplicate_open_refused"));
        }
        self.open_attempted = true;
        let path = wide(exact_path);
        let handle = unsafe {
            CreateFileW(
                path.as_ptr(),
                0x8000_0000,
                1,
                null(),
                3,
                0x0020_0080,
                null_mut(),
            )
        };
        if handle == INVALID_HANDLE {
            return Err(error("open"));
        }
        self.file = Some(handle);
        Ok(())
    }

    fn facts(&mut self) -> Result<FileFacts, Failure> {
        let handle = self.handle()?;
        let mut protocol = RemoteProtocolInfo::default();
        let mut standard = FileStandardInfo::default();
        let mut identity = FileIdInfo::default();
        let mut attributes = FileAttributeTagInfo::default();
        info(handle, 13, &mut protocol)?;
        info(handle, 1, &mut standard)?;
        info(handle, 18, &mut identity)?;
        info(handle, 9, &mut attributes)?;
        let mut name = [0u16; 1024];
        let length =
            unsafe { GetFinalPathNameByHandleW(handle, name.as_mut_ptr(), name.len() as u32, 0) };
        if length == 0 {
            return Err(error("final_path"));
        }
        if length as usize >= name.len() {
            return Err(Failure::new("final_path", "final_path_unbounded"));
        }
        let path = String::from_utf16(&name[..length as usize])
            .map_err(|_| Failure::new("final_path", "final_path_invalid"))?;
        let regular = unsafe { GetFileType(handle) } == 1
            && standard.directory == 0
            && standard.delete_pending == 0
            && standard.number_of_links == 1
            && standard.end_of_file >= 0
            && attributes.attributes & (0x10 | 0x400 | 0x1000) == 0
            && attributes.reparse_tag == 0;
        Ok(FileFacts {
            protocol: ProtocolFacts {
                version: protocol.version,
                size: protocol.size,
                protocol: protocol.protocol,
                major: protocol.major,
                flags: protocol.flags,
            },
            file_id: identity.id,
            volume_serial: identity.volume_serial,
            size: standard.end_of_file.max(0) as u64,
            is_regular: regular,
            final_path: path,
        })
    }

    fn read(&mut self, output: &mut [u8]) -> Result<usize, Failure> {
        let handle = self.handle()?;
        if output.is_empty() || output.len() > 8192 {
            return Err(Failure::new("read", "read_buffer_outside_bound"));
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
            return Err(error("read"));
        }
        if count as usize > output.len() {
            return Err(Failure::new("read", "invalid_read_count"));
        }
        Ok(count as usize)
    }

    fn cleanup(&mut self, exact_share: &str) -> CleanupFacts {
        let mut proof = CleanupFacts::default();
        if let Some(handle) = self.file {
            let closed = unsafe { CloseHandle(handle) } != 0;
            proof.file_closed = Some(closed);
            if closed {
                self.file = None;
            }
        }
        if self.impersonating {
            // A backend cannot migrate across threads. Never revert an unrelated thread.
            if self.thread_id != Some(unsafe { GetCurrentThreadId() }) {
                std::process::abort();
            }
            if self.open_attempted && self.same_context().is_ok() {
                let share = wide(exact_share);
                proof.exact_unc_cancel_status =
                    Some(unsafe { WNetCancelConnection2W(share.as_ptr(), 0, 0) });
            }
            let reverted = unsafe { RevertToSelf() } != 0;
            proof.impersonation_reverted = Some(reverted);
            // Microsoft requires terminating the process if reversion fails.
            // The external supervisor must record this as unknown, not successful cleanup.
            if !reverted {
                std::process::abort();
            }
            self.impersonating = false;
        }
        if let Some(token) = self.token {
            let closed = unsafe { CloseHandle(token) } != 0;
            proof.token_closed = Some(closed);
            if closed {
                self.token = None;
            }
        }
        if !self.observation_tokens.is_empty() {
            self.observation_tokens
                .retain(|token| unsafe { CloseHandle(*token) } == 0);
            proof.observation_tokens_closed = Some(self.observation_tokens.is_empty());
        }
        proof.owned_process_exit_required =
            self.file.is_some() || self.token.is_some() || !self.observation_tokens.is_empty();
        proof
    }
}

impl Drop for WindowsBackend {
    fn drop(&mut self) {
        // No implicit network work. A panic while impersonating must not escape
        // into unrelated controller code; only the disposable process can stop.
        if self.impersonating {
            std::process::abort();
        }
        for handle in self
            .file
            .iter()
            .chain(self.token.iter())
            .chain(self.observation_tokens.iter())
        {
            unsafe {
                CloseHandle(*handle);
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
        return Err(error("metadata"));
    }
    Ok(())
}

fn token_facts(token: Handle) -> Result<LocalLogon, Failure> {
    let mut stats = TokenStatistics::default();
    let mut returned = 0;
    if unsafe {
        GetTokenInformation(
            token,
            10,
            (&mut stats as *mut TokenStatistics).cast(),
            size_of_val(&stats) as u32,
            &mut returned,
        )
    } == 0
    {
        return Err(error("token_statistics"));
    }
    if returned as usize != size_of_val(&stats) {
        return Err(Failure::new("token_statistics", "token_statistics_size"));
    }
    let mut needed = 0;
    if unsafe { GetTokenInformation(token, 1, null_mut(), 0, &mut needed) } != 0
        || unsafe { GetLastError() } != 122
        || !(size_of::<TokenUser>() as u32..=4096).contains(&needed)
    {
        return Err(Failure::new("token_user", "token_user_size"));
    }
    let mut storage = vec![0usize; (needed as usize).div_ceil(size_of::<usize>())];
    if unsafe { GetTokenInformation(token, 1, storage.as_mut_ptr().cast(), needed, &mut returned) }
        == 0
    {
        return Err(error("token_user"));
    }
    if returned < size_of::<TokenUser>() as u32 || returned > needed {
        return Err(Failure::new("token_user", "token_user_size"));
    }
    // The embedded SID pointer must designate bytes inside this returned allocation.
    let row = unsafe { &*storage.as_ptr().cast::<TokenUser>() };
    let base = storage.as_ptr() as usize;
    let offset = (row.sid as usize)
        .checked_sub(base)
        .filter(|offset| *offset >= size_of::<TokenUser>())
        .ok_or(Failure::new("token_user", "token_user_pointer"))?;
    let bytes =
        unsafe { std::slice::from_raw_parts(storage.as_ptr().cast::<u8>(), returned as usize) };
    let sid = sid_from_bytes(
        bytes
            .get(offset..)
            .ok_or(Failure::new("token_user", "token_user_pointer"))?,
    )?;
    Ok(LocalLogon {
        authentication_id: ((stats.authentication_id.high as u32 as u64) << 32)
            | stats.authentication_id.low as u64,
        local_token_user_sid: sid,
    })
}

fn sid_from_bytes(bytes: &[u8]) -> Result<String, Failure> {
    if bytes.len() < 8 || bytes[0] != 1 || bytes[1] > 15 || bytes.len() < 8 + bytes[1] as usize * 4
    {
        return Err(Failure::new("token_user", "token_user_sid"));
    }
    let authority = bytes[2..8]
        .iter()
        .fold(0u64, |value, byte| (value << 8) | *byte as u64);
    let mut result = format!("S-1-{authority}");
    for part in bytes[8..8 + bytes[1] as usize * 4].chunks_exact(4) {
        result.push_str(&format!(
            "-{}",
            u32::from_le_bytes(part.try_into().expect("four-byte SID chunk"))
        ));
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn token_sid_projection_is_bounded_numeric_only() {
        assert!(sid_from_bytes(&[]).is_err());
        assert!(sid_from_bytes(&[1, 16, 0, 0, 0, 0, 0, 5]).is_err());
        assert!(sid_from_bytes(&[1, 1, 0, 0, 0, 0, 0, 5]).is_err());
        assert_eq!(
            sid_from_bytes(&[1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0])
                .ok()
                .as_deref(),
            Some("S-1-5-18")
        );
    }
}
