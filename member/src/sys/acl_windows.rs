// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The control sockets' access lists on Windows, as Go's
//! internal/service/control_windows.go. Windows checks a client's right to
//! write the socket file when it connects, and the file takes its access
//! list from its folder, so the folder gets a protected list first: full
//! access for the system, the administrators and the service's own account,
//! read and write for the cbb group and each of its members. The admin
//! socket's folder lets in only the first three, and is made again unless
//! one of them owns it, so that a folder another user made first, whose
//! list that user could change, is never used.

use std::path::Path;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE, LocalFree};
use windows_sys::Win32::NetworkManagement::NetManagement::{NetApiBufferFree, NetLocalGroupGetMembers};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
    SE_FILE_OBJECT, SetNamedSecurityInfoW, SetSecurityInfo,
};
use windows_sys::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, LookupAccountNameW, OWNER_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES, SID_NAME_USE, SidTypeAlias,
};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CreateDirectoryW, CreateFileW, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, GetFileInformationByHandle, OPEN_EXISTING, READ_CONTROL, WRITE_DAC,
};

use super::UnixListener;
use crate::error::{Context, Error, Result};

/// The local group whose members may use the control socket.
pub const GROUP: &str = "cbb";

const SYSTEM: &str = "S-1-5-18";
const ADMINISTRATORS: &str = "S-1-5-32-544";

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn os_error(what: &str) -> Error {
    Error::with(what.to_string(), std::io::Error::last_os_error())
}

/// The SID as a string; None when it does not convert.
///
/// # Safety
/// sid must point to a valid SID.
unsafe fn sid_string(sid: PSID) -> Option<String> {
    let mut p: *mut u16 = std::ptr::null_mut();
    // SAFETY: the caller passes a valid SID; the string is freed after use.
    unsafe {
        if ConvertSidToStringSidW(sid, &mut p) == 0 {
            return None;
        }
        let len = (0..).take_while(|&i| *p.add(i) != 0).count();
        let s = String::from_utf16_lossy(std::slice::from_raw_parts(p, len));
        LocalFree(p.cast());
        Some(s)
    }
}

/// A security descriptor from SDDL, freed when dropped.
struct Descriptor(PSECURITY_DESCRIPTOR);

impl Descriptor {
    fn new(sddl: &str) -> Result<Descriptor> {
        let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        let w = wide(sddl);
        // SAFETY: w is a NUL-ended string, sd valid for the call to write.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                w.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(os_error("the access list of the control socket"));
        }
        Ok(Descriptor(sd))
    }

    fn dacl(&self) -> Result<*mut ACL> {
        let (mut present, mut defaulted, mut dacl) = (0, 0, std::ptr::null_mut());
        // SAFETY: self.0 is a valid descriptor; the out-pointers are valid.
        if unsafe { GetSecurityDescriptorDacl(self.0, &mut present, &mut dacl, &mut defaulted) } == 0 || present == 0 {
            return Err(os_error("the access list of the control socket"));
        }
        Ok(dacl)
    }
}

impl Drop for Descriptor {
    fn drop(&mut self) {
        // SAFETY: the descriptor was allocated by the conversion.
        unsafe { LocalFree(self.0) };
    }
}

/// Listens on the control socket at path, its folder narrowed first.
pub fn listen(path: &Path, admin: bool) -> Result<UnixListener> {
    let dir = path.parent().unwrap_or(Path::new("."));
    let mk = if admin { dir.parent().unwrap_or(dir) } else { dir };
    std::fs::create_dir_all(mk).context(format!("cannot create {}", mk.display()))?;
    let sd = Descriptor::new(&sddl(admin)?)?;
    let dacl = sd.dacl()?;
    let narrow = DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION;
    if admin {
        let h = own_dir(dir, &sd)?;
        // SAFETY: h is the folder's handle, opened with WRITE_DAC; dacl
        // lives as long as sd.
        let r = unsafe {
            SetSecurityInfo(
                h,
                SE_FILE_OBJECT,
                narrow,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                dacl,
                std::ptr::null(),
            )
        };
        // SAFETY: h is a handle own_dir opened.
        unsafe { CloseHandle(h) };
        if r != 0 {
            return Err(Error::with(
                format!("narrowing {}", dir.display()),
                std::io::Error::from_raw_os_error(r as i32),
            ));
        }
    } else {
        let w = wide(&dir.to_string_lossy());
        // SAFETY: w is NUL-ended; dacl lives as long as sd.
        let r = unsafe {
            SetNamedSecurityInfoW(
                w.as_ptr(),
                SE_FILE_OBJECT,
                narrow,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                dacl,
                std::ptr::null(),
            )
        };
        if r != 0 {
            return Err(Error::with(
                format!("narrowing {}", dir.display()),
                std::io::Error::from_raw_os_error(r as i32),
            ));
        }
    }
    // A socket left by a service that did not stop cleanly blocks the name;
    // anything else there, which a member of the group may have made in the
    // control socket's folder, is moved aside rather than entered.
    match std::fs::symlink_metadata(path) {
        Ok(m) if is_socket(&m) => std::fs::remove_file(path).context(format!("cannot remove {}", path.display()))?,
        Ok(_) => move_aside(path)?,
        Err(_) => {}
    }
    UnixListener::bind(path).context(format!("cannot listen at {}", path.display()))
}

/// Whether m is an AF_UNIX socket's file: a reparse point with the tag
/// IO_REPARSE_TAG_AF_UNIX.
fn is_socket(m: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 && !m.is_dir()
}

/// Renames what is at path, without following or entering it, to a name
/// beside it that nothing else uses.
fn move_aside(path: &Path) -> Result<()> {
    let tag = getrandom::u64().map_err(|_| Error::msg("the system has no randomness"))?;
    let to = format!("{}.untrusted-{tag:016x}", path.display());
    std::fs::rename(path, &to).context(format!("cannot move {} aside", path.display()))
}

/// The folder dir, open, made sure to be a folder, not a link, that the
/// system, the administrators or the service's own account owns; anything
/// else there is moved aside. A folder it makes has sd's list from the
/// start.
fn own_dir(dir: &Path, sd: &Descriptor) -> Result<HANDLE> {
    let w = wide(&dir.to_string_lossy());
    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.0,
        bInheritHandle: 0,
    };
    let make = || -> Result<()> {
        // SAFETY: w is NUL-ended, sa a valid SECURITY_ATTRIBUTES.
        if unsafe { CreateDirectoryW(w.as_ptr(), &sa) } == 0 {
            return Err(os_error(&format!("making {}", dir.display())));
        }
        Ok(())
    };
    for _ in 0..2 {
        match open_own_dir(dir) {
            Ok(Some(h)) => return Ok(h),
            Ok(None) => {
                move_aside(dir)?;
                make()?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => make()?,
            Err(e) => return Err(Error::with(format!("the owner of {}", dir.display()), e)),
        }
    }
    match open_own_dir(dir) {
        Ok(Some(h)) => Ok(h),
        _ => Err(Error::msg(format!("{} belongs to another user", dir.display()))),
    }
}

/// Opens what is at path without following a link: its handle when it is
/// a folder, not a reparse point, that a trusted account owns; None for
/// anything else.
fn open_own_dir(path: &Path) -> std::io::Result<Option<HANDLE>> {
    let w = wide(&path.to_string_lossy());
    // SAFETY: w is NUL-ended; the handle is closed on every path that does
    // not return it.
    unsafe {
        let h = CreateFileW(
            w.as_ptr(),
            FILE_READ_ATTRIBUTES | READ_CONTROL | WRITE_DAC,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        );
        if h == INVALID_HANDLE_VALUE {
            return Err(std::io::Error::last_os_error());
        }
        let mut fi: BY_HANDLE_FILE_INFORMATION = std::mem::zeroed();
        if GetFileInformationByHandle(h, &mut fi) == 0 {
            let e = std::io::Error::last_os_error();
            CloseHandle(h);
            return Err(e);
        }
        if fi.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
            || fi.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        {
            CloseHandle(h);
            return Ok(None);
        }
        let (mut owner, mut psd): (PSID, PSECURITY_DESCRIPTOR) = (std::ptr::null_mut(), std::ptr::null_mut());
        let r = GetSecurityInfo(
            h,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut psd,
        );
        if r != 0 {
            CloseHandle(h);
            return Err(std::io::Error::from_raw_os_error(r as i32));
        }
        let owner = sid_string(owner);
        LocalFree(psd);
        let own = crate::peer::own_sid();
        let trusted = owner.is_some_and(|o| o == SYSTEM || o == ADMINISTRATORS || own.as_deref() == Some(o.as_str()));
        if !trusted {
            CloseHandle(h);
            return Ok(None);
        }
        Ok(Some(h))
    }
}

/// The access list of the socket's folder, which its files inherit. A
/// user's sign-in token lists only the groups the user was in at sign-in,
/// so the list also names each member of the cbb group as the service
/// finds it at start. Without the group only the administrators and the
/// service's account may connect.
fn sddl(admin: bool) -> Result<String> {
    let own = crate::peer::own_sid().ok_or_else(|| Error::msg("the service's account cannot be read"))?;
    let mut s = format!("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{own})");
    if admin {
        return Ok(s);
    }
    let Some(group) = group_sid() else { return Ok(s) };
    s += &format!("(A;OICI;GRGW;;;{group})");
    for m in group_members()? {
        s += &format!("(A;OICI;GRGW;;;{m})");
    }
    Ok(s)
}

/// The cbb group's SID, when the group is there.
fn group_sid() -> Option<String> {
    let name = wide(GROUP);
    let mut sid = vec![0u8; 68];
    let mut domain = vec![0u16; 256];
    let (mut n, mut dn, mut use_) = (sid.len() as u32, domain.len() as u32, SID_NAME_USE::default());
    // SAFETY: the buffers are as long as the counts passed.
    let ok = unsafe {
        LookupAccountNameW(
            std::ptr::null(),
            name.as_ptr(),
            sid.as_mut_ptr().cast(),
            &mut n,
            domain.as_mut_ptr(),
            &mut dn,
            &mut use_,
        )
    } != 0;
    if !ok || use_ != SidTypeAlias {
        return None;
    }
    // SAFETY: sid holds the SID LookupAccountNameW wrote.
    unsafe { sid_string(sid.as_mut_ptr().cast()) }
}

/// The SIDs of the cbb group's members.
fn group_members() -> Result<Vec<String>> {
    let name = wide(GROUP);
    let (mut buf, mut read, mut total): (*mut u8, u32, u32) = (std::ptr::null_mut(), 0, 0);
    // SAFETY: level 0 fills LOCALGROUP_MEMBERS_INFO_0, the member's SID
    // alone; the buffer is read within its count and freed.
    unsafe {
        let r = NetLocalGroupGetMembers(
            std::ptr::null(),
            name.as_ptr(),
            0,
            &mut buf,
            u32::MAX,
            &mut read,
            &mut total,
            std::ptr::null_mut(),
        );
        if r != 0 {
            return Err(Error::with(
                format!("the members of the {GROUP} group"),
                std::io::Error::from_raw_os_error(r as i32),
            ));
        }
        let sids = std::slice::from_raw_parts(buf as *const PSID, read as usize);
        let out = sids.iter().filter(|s| !s.is_null()).filter_map(|s| sid_string(*s)).collect();
        NetApiBufferFree(buf.cast());
        Ok(out)
    }
}
