// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The service under Windows' service manager, as install.ps1 creates it
//! (the service `cbb`): it reports itself running, stops on a stop request
//! or at shutdown, and ends with an error of its own when it fails, so the
//! service's recovery actions start it again; as cmd/cbb's
//! platform_windows.go does for the Go service.

use std::sync::Mutex;

use windows_sys::Win32::Foundation::{ERROR_FAILED_SERVICE_CONTROLLER_CONNECT, ERROR_SERVICE_SPECIFIC_ERROR, NO_ERROR};
use windows_sys::Win32::System::Services::{
    RegisterServiceCtrlHandlerExW, SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP, SERVICE_CONTROL_INTERROGATE,
    SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP, SERVICE_RUNNING, SERVICE_START_PENDING, SERVICE_STATUS,
    SERVICE_STATUS_HANDLE, SERVICE_STOP_PENDING, SERVICE_STOPPED, SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS,
    SetServiceStatus, StartServiceCtrlDispatcherW,
};

use crate::error::{Error, Result};

/// The service's name, as install.ps1 creates it.
const NAME: &str = "cbb";

/// The service's work; its argument says whether it runs under the service
/// manager.
pub type Run = Box<dyn FnOnce(bool) -> Result<()> + Send>;

struct Job {
    run: Option<Run>,
    stop: fn(),
    result: Option<Result<()>>,
    handle: SERVICE_STATUS_HANDLE,
}

// SAFETY: the handle is an opaque value the service manager hands out for
// use from any thread.
unsafe impl Send for Job {}

static JOB: Mutex<Option<Job>> = Mutex::new(None);

fn name() -> Vec<u16> {
    NAME.encode_utf16().chain([0]).collect()
}

/// Runs run under the service manager, and stop on a stop request; or
/// gives run back when the process was not started as a service, for the
/// caller to run in the console.
pub fn run(run: Run, stop: fn()) -> std::result::Result<Result<()>, Run> {
    *JOB.lock().unwrap_or_else(|e| e.into_inner()) =
        Some(Job { run: Some(run), stop, result: None, handle: std::ptr::null_mut() });
    let mut n = name();
    let table = [
        SERVICE_TABLE_ENTRYW { lpServiceName: n.as_mut_ptr(), lpServiceProc: Some(service_main) },
        SERVICE_TABLE_ENTRYW { lpServiceName: std::ptr::null_mut(), lpServiceProc: None },
    ];
    // SAFETY: table ends with the null entry, and n outlives the call,
    // which returns only once the service stopped.
    let ok = unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } != 0;
    let mut job = JOB.lock().unwrap_or_else(|e| e.into_inner()).take().expect("the job stays until here");
    if !ok {
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() == Some(ERROR_FAILED_SERVICE_CONTROLLER_CONNECT as i32) {
            return Err(job.run.take().expect("not run without the service manager"));
        }
        return Ok(Err(Error::msg(format!("cannot start as a Windows service: {e}"))));
    }
    Ok(job.result.take().unwrap_or(Ok(())))
}

fn status(handle: SERVICE_STATUS_HANDLE, state: u32, failed: bool) {
    let accepts = if state == SERVICE_RUNNING { SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN } else { 0 };
    let st = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: state,
        dwControlsAccepted: accepts,
        dwWin32ExitCode: if failed { ERROR_SERVICE_SPECIFIC_ERROR } else { NO_ERROR },
        dwServiceSpecificExitCode: if failed { 1 } else { 0 },
        dwCheckPoint: 0,
        dwWaitHint: if state == SERVICE_RUNNING || state == SERVICE_STOPPED { 0 } else { 30_000 },
    };
    // SAFETY: handle came from RegisterServiceCtrlHandlerExW and st is valid.
    unsafe {
        SetServiceStatus(handle, &st);
    }
}

unsafe extern "system" fn handler(
    control: u32,
    _event: u32,
    _data: *mut core::ffi::c_void,
    _context: *mut core::ffi::c_void,
) -> u32 {
    match control {
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
            let job = JOB.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(j) = job.as_ref() {
                status(j.handle, SERVICE_STOP_PENDING, false);
                (j.stop)();
            }
            NO_ERROR
        }
        SERVICE_CONTROL_INTERROGATE => NO_ERROR,
        _ => 120, // ERROR_CALL_NOT_IMPLEMENTED
    }
}

unsafe extern "system" fn service_main(_argc: u32, _argv: *mut windows_sys::core::PWSTR) {
    let n = name();
    // SAFETY: n is a valid string, and handler stays for the process.
    let handle = unsafe { RegisterServiceCtrlHandlerExW(n.as_ptr(), Some(handler), std::ptr::null_mut()) };
    if handle.is_null() {
        return;
    }
    let run = {
        let mut job = JOB.lock().unwrap_or_else(|e| e.into_inner());
        let Some(j) = job.as_mut() else { return };
        j.handle = handle;
        j.run.take()
    };
    status(handle, SERVICE_START_PENDING, false);
    status(handle, SERVICE_RUNNING, false);
    let result = run.map_or(Ok(()), |r| r(true));
    let failed = result.is_err();
    if let Some(j) = JOB.lock().unwrap_or_else(|e| e.into_inner()).as_mut() {
        j.result = Some(result);
    }
    status(handle, SERVICE_STOPPED, failed);
}
