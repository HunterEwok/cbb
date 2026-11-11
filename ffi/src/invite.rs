// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! A remote invitation that an admin phone makes (docs/protocol.md,
//! section 12), with the admin key where the app keeps it: the member opens
//! the invitation's guest tunnel on the phone when it is the group's hub,
//! else through a connected hub of the group, and runs its pairing window.
//! The app shows the invitation's text as a QR code (or shares it), waits
//! for its next state off its main thread, and answers whether to admit
//! each device that uses it, by the fingerprint the device shows.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use cbb_core::admit::Admitter;
use cbb_core::certs::{self, Cert, DeviceId};
use cbb_core::error::{Error, Result};
use cbb_member::phone::Member as Node;
use serde::{Deserialize, Serialize};

use crate::join::{AppKey, ErrorAnswer, SignFn, answer};

#[derive(Deserialize)]
struct NewArgs {
    /// The public point of the key the phone issues with, SEC1
    /// uncompressed: its admin key, or the root's key when it holds the
    /// root.
    #[serde(with = "certs::b64")]
    public: Vec<u8>,
    /// The phone's admin CA, DER; absent when it issues with the root.
    #[serde(with = "certs::b64::opt", default)]
    admin_ca: Option<Vec<u8>>,
    /// How long the invitation is valid, in seconds: an hour when 0, a day
    /// at most.
    #[serde(default)]
    expires: u64,
    /// The hub to open the guest tunnel on, a device ID; any connected hub
    /// of the group when empty.
    #[serde(default)]
    hub: String,
}

#[derive(Serialize)]
struct NewAnswer {
    /// The invitation's text, cbb://invite#..., for the QR code.
    invite: String,
    /// How long it is valid, in seconds.
    expires: u64,
    /// The QR code's modules, a row of '1' and '0' each.
    modules: Vec<String>,
}

/// A device that proved the invitation's secret and waits for the admin.
#[derive(Clone, Serialize)]
struct Joining {
    device: String,
    name: String,
    os: String,
    fingerprint: String,
}

#[derive(Clone, Serialize)]
struct StateAnswer {
    /// Grows with each change; next waits for one past the version it is
    /// given.
    version: u64,
    /// open, joining (the app asks the user about joining), done (a device
    /// joined: name) or failed (error).
    state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    joining: Option<Joining>,
    #[serde(skip_serializing_if = "String::is_empty")]
    name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    device: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<ErrorAnswer>,
}

struct Shared {
    st: Mutex<StateAnswer>,
    changed: Condvar,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, StateAnswer> {
        self.st.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn set(&self, f: impl FnOnce(&mut StateAnswer)) {
        let mut st = self.lock();
        f(&mut st);
        st.version = st.version.saturating_add(1);
        self.changed.notify_all();
    }
}

/// An open invitation of an admin phone.
pub struct Invite {
    inv: Arc<cbb_member::phone::Invite>,
    shared: Arc<Shared>,
    answers: mpsc::SyncSender<bool>,
    closed: Arc<AtomicBool>,
    waiter: Option<JoinHandle<()>>,
}

impl Invite {
    /// An invitation from the app's request (NewArgs) and the issuing key's
    /// callback, with its answer.
    pub fn new(node: Arc<Node>, request: &[u8], sign: SignFn, ctx: usize) -> (Option<Invite>, Vec<u8>) {
        match Invite::make(node, request, sign, ctx) {
            Ok((i, ans)) => (Some(i), answer(Ok(ans))),
            Err(e) => (None, answer::<()>(Err(e))),
        }
    }

    fn make(node: Arc<Node>, request: &[u8], sign: SignFn, ctx: usize) -> Result<(Invite, NewAnswer)> {
        let a: NewArgs = serde_json::from_slice(request)
            .map_err(|e| Error::msg(format!("the invite request does not decode: {e}")))?;
        let identity = (*node.identity()).clone();
        let ca = match &a.admin_ca {
            Some(der) => Cert::parse(der)?,
            None => identity.root().clone(),
        };
        if ca.public_key() != a.public.as_slice() {
            return Err(Error::msg("the key does not belong to the CA this phone issues with"));
        }
        let hub = match a.hub.as_str() {
            "" => None,
            h => Some(DeviceId::parse(h).map_err(|_| Error::msg(format!("{h:?} is not a device ID")))?),
        };
        let admitter =
            Admitter { identity, ca, ca_key: Arc::new(AppKey { public: a.public, sign, ctx }), make_admins: false };

        let shared = Arc::new(Shared {
            st: Mutex::new(StateAnswer {
                version: 1,
                state: "open",
                joining: None,
                name: String::new(),
                device: String::new(),
                error: None,
            }),
            changed: Condvar::new(),
        });
        let closed = Arc::new(AtomicBool::new(false));
        let (answers, asked) = mpsc::sync_channel::<bool>(1);
        let confirm: cbb_member::phone::Confirm = {
            let (shared, closed) = (shared.clone(), closed.clone());
            let asked = Mutex::new(asked);
            Box::new(move |req: &cbb_core::admit::Request| {
                let asked = asked.lock().unwrap_or_else(|e| e.into_inner());
                // Drops an answer left from before.
                while asked.try_recv().is_ok() {}
                shared.set(|st| {
                    st.state = "joining";
                    st.joining = Some(Joining {
                        device: req.device.as_str().to_string(),
                        name: req.name.clone(),
                        os: req.os.clone(),
                        fingerprint: req.fingerprint.clone(),
                    });
                });
                let until = Instant::now().checked_add(cbb_member::phone::CONFIRM_WAIT);
                let yes = loop {
                    if closed.load(Ordering::SeqCst) || until.is_none_or(|u| Instant::now() > u) {
                        break false;
                    }
                    match asked.recv_timeout(Duration::from_millis(200)) {
                        Ok(yes) => break yes,
                        Err(mpsc::RecvTimeoutError::Timeout) => {}
                        Err(mpsc::RecvTimeoutError::Disconnected) => break false,
                    }
                };
                shared.set(|st| {
                    st.state = "open";
                    st.joining = None;
                });
                yes
            })
        };
        let lifetime = Duration::from_secs(a.expires);
        let inv = Arc::new(node.invite(admitter, lifetime, hub.as_ref(), confirm)?);
        let ans = NewAnswer {
            invite: inv.text.clone(),
            expires: inv.lifetime.as_secs(),
            modules: crate::join::modules(&inv.text)?,
        };
        let waiter = {
            let (inv, shared, closed) = (inv.clone(), shared.clone(), closed.clone());
            std::thread::spawn(move || {
                let end = inv.wait(&|| closed.load(Ordering::SeqCst));
                shared.set(|st| {
                    st.joining = None;
                    match end {
                        Ok(j) => {
                            st.state = "done";
                            st.name = j.name;
                            st.device = j.device;
                        }
                        Err(why) => {
                            st.state = "failed";
                            st.error = Some(ErrorAnswer::of(&Error::with("the invitation ended", why)));
                        }
                    }
                });
            })
        };
        Ok((Invite { inv, shared, answers, closed, waiter: Some(waiter) }, ans))
    }

    /// Waits up to timeout_ms for a state past version, and answers the
    /// state then, as StateAnswer.
    pub fn next(&self, version: u64, timeout_ms: u64) -> Vec<u8> {
        let mut st = self.shared.lock();
        let until = Instant::now().checked_add(Duration::from_millis(timeout_ms));
        while st.version <= version && !matches!(st.state, "done" | "failed") {
            let left = until.and_then(|u| u.checked_duration_since(Instant::now())).unwrap_or_default();
            if left.is_zero() {
                break;
            }
            st = self.shared.changed.wait_timeout(st, left).map(|(g, _)| g).unwrap_or_else(|e| e.into_inner().0);
        }
        answer(Ok(st.clone()))
    }

    /// The admin's answer about the joining device: yes admits it.
    pub fn answer(&self, yes: bool) {
        let _ = self.answers.try_send(yes);
    }
}

impl Drop for Invite {
    /// Ends the invitation and waits until its window ended, so that its
    /// key's callback is not called after the app lets go of it.
    fn drop(&mut self) {
        self.closed.store(true, Ordering::SeqCst);
        self.inv.close();
        if let Some(w) = self.waiter.take() {
            let _ = w.join();
        }
    }
}
