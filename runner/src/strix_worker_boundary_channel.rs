//! Closed inherited channel used by the fixed Linux worker boundary.

#![cfg(target_os = "linux")]

use std::mem::{size_of, zeroed};
use std::os::fd::{AsRawFd, RawFd};
use std::ptr;

const REFUSAL: &str = "the fixed Linux Strix worker boundary was refused";
const MAX_PACKET: usize = 32 * 1024;
const MAX_RECEIVED_RIGHTS: usize = 16;

pub(crate) struct OwnedFd(RawFd);

impl OwnedFd {
    pub(crate) fn checked(fd: RawFd) -> Result<Self, String> {
        if fd < 0 {
            Err(format!("{REFUSAL}: {}", std::io::Error::last_os_error()))
        } else {
            Ok(Self(fd))
        }
    }
}

impl AsRawFd for OwnedFd {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

impl Drop for OwnedFd {
    fn drop(&mut self) {
        if self.0 >= 0 {
            unsafe { libc::close(self.0) };
            self.0 = -1;
        }
    }
}

fn require(value: bool) -> Result<(), String> {
    if value {
        Ok(())
    } else {
        Err(REFUSAL.into())
    }
}

pub(crate) fn socket_pair() -> Result<(OwnedFd, OwnedFd), String> {
    let mut descriptors = [-1; 2];
    require(
        unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                0,
                descriptors.as_mut_ptr(),
            )
        } == 0,
    )?;
    Ok((
        OwnedFd::checked(descriptors[0])?,
        OwnedFd::checked(descriptors[1])?,
    ))
}

pub(crate) fn set_timeout(fd: RawFd, seconds: i64) -> Result<(), String> {
    let timeout = libc::timeval {
        tv_sec: seconds,
        tv_usec: 0,
    };
    for option in [libc::SO_RCVTIMEO, libc::SO_SNDTIMEO] {
        require(
            unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    option,
                    (&timeout as *const libc::timeval).cast(),
                    size_of::<libc::timeval>() as libc::socklen_t,
                )
            } == 0,
        )?;
    }
    Ok(())
}

pub(crate) fn send_packet(fd: RawFd, bytes: &[u8]) -> Result<(), String> {
    require(!bytes.is_empty() && bytes.len() <= MAX_PACKET)?;
    let sent = unsafe { libc::send(fd, bytes.as_ptr().cast(), bytes.len(), libc::MSG_NOSIGNAL) };
    require(sent == bytes.len() as isize)
}

pub(crate) fn recv_packet(fd: RawFd) -> Result<Vec<u8>, String> {
    let mut bytes = vec![0_u8; MAX_PACKET + 1];
    let received = unsafe { libc::recv(fd, bytes.as_mut_ptr().cast(), bytes.len(), 0) };
    require(received > 0 && received as usize <= MAX_PACKET)?;
    bytes.truncate(received as usize);
    Ok(bytes)
}

pub(crate) fn send_packet_with_fd(
    fd: RawFd,
    bytes: &[u8],
    descriptor: RawFd,
) -> Result<(), String> {
    require(!bytes.is_empty() && bytes.len() <= MAX_PACKET && descriptor >= 0)?;
    let mut iovec = libc::iovec {
        iov_base: bytes.as_ptr() as *mut _,
        iov_len: bytes.len(),
    };
    let mut control = vec![0_u8; unsafe { libc::CMSG_SPACE(size_of::<RawFd>() as u32) } as usize];
    let mut message: libc::msghdr = unsafe { zeroed() };
    message.msg_iov = &mut iovec;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = control.len();
    unsafe {
        let header = libc::CMSG_FIRSTHDR(&message);
        require(!header.is_null())?;
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(size_of::<RawFd>() as u32) as usize;
        ptr::copy_nonoverlapping(
            (&descriptor as *const RawFd).cast::<u8>(),
            libc::CMSG_DATA(header),
            size_of::<RawFd>(),
        );
    }
    require(unsafe { libc::sendmsg(fd, &message, libc::MSG_NOSIGNAL) } == bytes.len() as isize)
}

pub(crate) fn recv_packet_with_fd(fd: RawFd) -> Result<(Vec<u8>, OwnedFd), String> {
    let mut bytes = vec![0_u8; MAX_PACKET + 1];
    let mut iovec = libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    };
    // Keep enough ancillary space to take ownership of a bounded malformed
    // packet's installed rights. Linux closes rights beyond a truncated
    // control buffer; every right which fits here is wrapped before any
    // validation can reject the packet.
    let mut control = vec![
        0_u8;
        unsafe { libc::CMSG_SPACE((size_of::<RawFd>() * MAX_RECEIVED_RIGHTS) as u32) }
            as usize
    ];
    let mut message: libc::msghdr = unsafe { zeroed() };
    message.msg_iov = &mut iovec;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = control.len();
    let received = unsafe { libc::recvmsg(fd, &mut message, libc::MSG_CMSG_CLOEXEC) };

    let mut installed_rights = Vec::new();
    let mut ancillary_is_canonical = true;
    let mut header_count = 0_usize;
    let control_length = if received >= 0 {
        message.msg_controllen.min(control.len())
    } else {
        0
    };
    let mut parsed_control_length = 0_usize;
    if received >= 0 {
        let header_length = size_of::<libc::cmsghdr>();
        let data_offset = unsafe { libc::CMSG_LEN(0) } as usize;
        let alignment = size_of::<usize>();
        let mut offset = 0_usize;
        while offset
            .checked_add(header_length)
            .is_some_and(|end| end <= control_length)
        {
            header_count += 1;
            let header = unsafe {
                ptr::read_unaligned(control.as_ptr().add(offset).cast::<libc::cmsghdr>())
            };
            let declared_length = header.cmsg_len as usize;
            let remaining = control_length - offset;
            if declared_length < data_offset || declared_length > remaining {
                ancillary_is_canonical = false;
                break;
            }

            let payload_length = declared_length - data_offset;
            if header.cmsg_level == libc::SOL_SOCKET && header.cmsg_type == libc::SCM_RIGHTS {
                if payload_length == 0 || !payload_length.is_multiple_of(size_of::<RawFd>()) {
                    ancillary_is_canonical = false;
                }
                let descriptor_count = payload_length / size_of::<RawFd>();
                if descriptor_count > MAX_RECEIVED_RIGHTS.saturating_sub(installed_rights.len()) {
                    ancillary_is_canonical = false;
                }
                for index in 0..descriptor_count {
                    let descriptor_offset =
                        match offset.checked_add(data_offset).and_then(|start| {
                            index
                                .checked_mul(size_of::<RawFd>())
                                .and_then(|part| start.checked_add(part))
                        }) {
                            Some(value) => value,
                            None => {
                                ancillary_is_canonical = false;
                                break;
                            }
                        };
                    let descriptor = unsafe {
                        ptr::read_unaligned(control.as_ptr().add(descriptor_offset).cast::<RawFd>())
                    };
                    if descriptor < 0 {
                        ancillary_is_canonical = false;
                    } else {
                        installed_rights.push(OwnedFd(descriptor));
                    }
                }
            } else {
                ancillary_is_canonical = false;
            }

            let aligned_length = match declared_length
                .checked_add(alignment - 1)
                .map(|value| value & !(alignment - 1))
            {
                Some(value) if value > 0 => value,
                _ => {
                    ancillary_is_canonical = false;
                    break;
                }
            };
            let next = match offset.checked_add(aligned_length) {
                Some(value) if value <= control_length => value,
                _ => {
                    ancillary_is_canonical = false;
                    break;
                }
            };
            offset = next;
            parsed_control_length = offset;
        }
    }

    require(
        received > 0
            && received as usize <= MAX_PACKET
            && message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) == 0
            && ancillary_is_canonical
            && header_count == 1
            && parsed_control_length == control_length
            && installed_rights.len() == 1,
    )?;
    bytes.truncate(received as usize);
    let descriptor = installed_rights.pop().ok_or_else(|| REFUSAL.to_string())?;
    Ok((bytes, descriptor))
}
