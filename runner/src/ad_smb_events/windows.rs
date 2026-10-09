use super::{Next, Reader, MAX_EVENT_BYTES};
use std::ffi::c_void;
use std::marker::PhantomData;
use std::ptr;
use std::rc::Rc;

type Handle = *mut c_void;

#[link(name = "wevtapi")]
extern "system" {
    fn EvtQuery(session: Handle, path: *const u16, query: *const u16, flags: u32) -> Handle;
    fn EvtNext(
        result: Handle,
        count: u32,
        events: *mut Handle,
        timeout: u32,
        flags: u32,
        returned: *mut u32,
    ) -> i32;
    fn EvtRender(
        context: Handle,
        event: Handle,
        flags: u32,
        size: u32,
        buffer: *mut c_void,
        used: *mut u32,
        properties: *mut u32,
    ) -> i32;
    fn EvtClose(handle: Handle) -> i32;
}

#[link(name = "kernel32")]
extern "system" {
    fn GetLastError() -> u32;
}

pub(super) struct LocalReader {
    query: Handle,
    failed_closes: Vec<Handle>,
    // Event query handles must remain on their creating thread.
    _thread: PhantomData<Rc<()>>,
}

impl LocalReader {
    pub(super) fn open(query: &str) -> Result<Self, &'static str> {
        let channel: Vec<u16> = "Security".encode_utf16().chain(Some(0)).collect();
        let query: Vec<u16> = query.encode_utf16().chain(Some(0)).collect();
        // EvtQueryChannelPath | EvtQueryForwardDirection; no remote session or tolerated errors.
        let handle = unsafe { EvtQuery(ptr::null_mut(), channel.as_ptr(), query.as_ptr(), 0x101) };
        if handle.is_null() {
            return Err("local Security query could not be opened");
        }
        Ok(Self {
            query: handle,
            failed_closes: Vec::new(),
            _thread: PhantomData,
        })
    }

    fn close_event(&mut self, event: Handle) -> bool {
        if unsafe { EvtClose(event) } == 0 {
            self.failed_closes.push(event);
            false
        } else {
            true
        }
    }

    fn render(event: Handle, maximum_bytes: usize) -> Result<String, u32> {
        // Fixed allocation avoids attacker-sized allocation and a size-query race.
        let maximum_bytes = maximum_bytes.min(MAX_EVENT_BYTES);
        let mut buffer = vec![0_u16; maximum_bytes + 1];
        let (mut used, mut properties) = (0_u32, 0_u32);
        let success = unsafe {
            EvtRender(
                ptr::null_mut(),
                event,
                1,
                (buffer.len() * 2) as u32,
                buffer.as_mut_ptr().cast(),
                &mut used,
                &mut properties,
            )
        };
        if success == 0 {
            return Err(unsafe { GetLastError() });
        }
        if properties != 0 || used < 2 || used as usize > buffer.len() * 2 || used % 2 != 0 {
            return Err(13);
        }
        let count = used as usize / 2;
        if buffer[count - 1] != 0 || buffer[..count - 1].contains(&0) {
            return Err(13);
        }
        let xml = String::from_utf16(&buffer[..count - 1]).map_err(|_| 13_u32)?;
        if xml.is_empty() || xml.len() > maximum_bytes {
            return Err(122);
        }
        Ok(xml)
    }
}

impl Reader for LocalReader {
    fn next(&mut self, timeout_ms: u32, maximum_bytes: usize) -> Result<Next, u32> {
        let mut event = ptr::null_mut();
        let mut returned = 0;
        let ok = unsafe { EvtNext(self.query, 1, &mut event, timeout_ms, 0, &mut returned) };
        let error = if ok == 0 {
            unsafe { GetLastError() }
        } else {
            0
        };
        if ok == 0 || returned != 1 || event.is_null() {
            if !event.is_null() && !self.close_event(event) {
                return Err(6);
            }
            return if ok == 0 && error == 259 && returned == 0 {
                Ok(Next::End)
            } else {
                Err(if error == 0 { 13 } else { error })
            };
        }
        let result = Self::render(event, maximum_bytes);
        if !self.close_event(event) {
            return Err(6);
        }
        result.map(Next::Event)
    }

    fn close(&mut self) -> bool {
        let mut success = true;
        if !self.query.is_null() {
            if unsafe { EvtClose(self.query) } == 0 {
                success = false;
            } else {
                self.query = ptr::null_mut();
            }
        }
        self.failed_closes
            .retain(|handle| unsafe { EvtClose(*handle) } == 0);
        success && self.failed_closes.is_empty()
    }
}

impl Drop for LocalReader {
    fn drop(&mut self) {
        let _ = self.close();
    }
}
