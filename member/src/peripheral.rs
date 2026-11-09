// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The Bluetooth keyboard and the TVs' remotes (docs/roadmap.md, item 25)
//! through cbb-helper, which runs Go's internal/peripheral for the service:
//! cbb keyboard, cbb remote, their status, the remote pastes the user sends
//! there and the quick action keyboard-layout. The helper keeps the
//! keyboard on BlueZ and a TV pairing between requests; this side asks it
//! only once the keyboard or a TV was set up here, so that a member without
//! either never starts it for them.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::control::Header;
use crate::error::{Error, Result};

/// The keyboard's settings and the TVs in the state folder, which the
/// helper keeps (Go's blekeyboard and tvremote).
const KEYBOARD_FILE: &str = "keyboard";
const TVS_FILE: &str = "tvs.json";

/// How long the helper may take: a TV pairing reaches the TV, and typing
/// on the keyboard by hand waits for the whole text.
const WAIT: Duration = Duration::from_secs(60);
const TYPE_WAIT: Duration = Duration::from_secs(600);
/// How long a status may take, which cbb status waits for.
const STATUS_WAIT: Duration = Duration::from_secs(5);

/// A request of the helper's keyboard and remote operations (Go's
/// helper.PeripheralRequest).
#[derive(Serialize, Default)]
struct Request<'a> {
    dir: &'a str,
    name: &'a str,
    os: &'a str,
    header: Header,
    #[serde(skip_serializing_if = "str::is_empty")]
    text: &'a str,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    enter: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    body_enter: bool,
}

/// How the keyboard and the TVs stand (Go's helper.PeripheralStatus).
#[derive(Deserialize, Default, Debug, Clone)]
pub struct Status {
    #[serde(default)]
    pub keyboard: Option<serde_json::Value>,
    #[serde(default)]
    pub tvs: Vec<serde_json::Value>,
    #[serde(default)]
    pub targets: Vec<String>,
    #[serde(default)]
    pub refused: String,
}

/// A paste's result on the keyboard's host or a TV; an empty status when
/// pastes go to the screen.
#[derive(Deserialize, Default, Debug)]
struct Pasted {
    #[serde(default)]
    status: String,
    #[serde(default)]
    reason: String,
}

/// This device as the keyboard and the remote.
#[derive(Clone)]
pub struct Peripherals {
    dir: PathBuf,
    name: String,
}

impl Peripherals {
    pub fn new(dir: &Path, name: &str) -> Peripherals {
        Peripherals { dir: dir.to_path_buf(), name: name.to_string() }
    }

    /// Whether the keyboard or a TV was set up here.
    fn set_up(&self) -> bool {
        self.dir.join(KEYBOARD_FILE).exists() || self.dir.join(TVS_FILE).exists()
    }

    fn call<T: serde::de::DeserializeOwned>(&self, op: &str, r: Request, wait: Duration) -> Result<T> {
        let helper = crate::helper::shared().ok_or_else(|| {
            Error::msg(
                "the Bluetooth keyboard and the TVs' remotes need cbb-helper beside cbb, and it is not installed here",
            )
        })?;
        let dir = self.dir.to_string_lossy();
        let r = Request { dir: &dir, name: &self.name, os: crate::admin::os_name(), ..r };
        let body = serde_json::to_vec(&r).map_err(|e| Error::with("cannot encode the request", e))?;
        let ans = helper.call(Header { op: op.into(), ..Default::default() }, body, wait)?;
        serde_json::from_slice(&ans.payload).map_err(|e| Error::with("cannot read cbb-helper's answer", e))
    }

    /// cbb keyboard (op keyboard) or cbb remote (op remote): the control
    /// request as it came, and how both stand after it.
    pub fn serve(&self, op: &str, h: &Header, payload: &[u8]) -> Result<Status> {
        let text = String::from_utf8_lossy(payload);
        let wait = if h.name == "type" { TYPE_WAIT } else { WAIT };
        let header = Header { op: op.into(), seq: 0, ..h.clone() };
        self.call(op, Request { header, text: &text, ..Default::default() }, wait)
    }

    /// How the keyboard and the TVs stand, None when neither was set up
    /// or the helper does not answer.
    pub fn status(&self) -> Option<Status> {
        if !self.set_up() {
            // A Linux computer with the helper can be the keyboard: its
            // status says the keyboard is off, as Go's KeyboardStatus,
            // without starting the helper for it.
            let can = cfg!(target_os = "linux") && crate::helper::shared().is_some();
            let off = serde_json::json!({ "layout": "us", "rate": 20 });
            return can.then(|| Status { keyboard: Some(off), ..Default::default() });
        }
        self.call("peripheral-status", Request::default(), STATUS_WAIT).ok()
    }

    /// Types a remote paste on the keyboard's host or the TV the user
    /// sends pastes to, as Go's Host.Paste: the status and reason, or None
    /// when pastes go to the screen. enter is whether the user allows
    /// Enter, body_enter whether the command asks for it.
    pub fn paste(&self, text: &str, enter: bool, body_enter: bool) -> Option<(String, String)> {
        if !self.set_up() {
            return None;
        }
        let r = Request { text, enter, body_enter, ..Default::default() };
        match self.call::<Pasted>("peripheral-paste", r, WAIT) {
            Ok(p) if p.status.is_empty() => None,
            Ok(p) => Some((p.status, p.reason)),
            Err(e) => Some(("failed".into(), e.for_log())),
        }
    }

    /// Stops the paste typed after its answer: its command is no longer
    /// taken.
    pub fn stop(&self) {
        let _ = self.call::<Status>("peripheral-stop", Request::default(), STATUS_WAIT);
    }

    /// The quick action keyboard-layout: the keyboard types in the next
    /// layout.
    pub fn next_layout(&self) -> std::result::Result<(), crate::actions::Failure> {
        use crate::actions::Failure;
        if !self.dir.join(KEYBOARD_FILE).exists() {
            return Err(Failure::Refused("the Bluetooth keyboard is off here: sudo cbb keyboard on".into()));
        }
        match self.call::<Status>("keyboard-layout", Request::default(), WAIT) {
            Ok(s) if !s.refused.is_empty() => Err(Failure::Refused(s.refused)),
            Ok(_) => Ok(()),
            Err(e) => Err(Failure::Failed(e)),
        }
    }
}
