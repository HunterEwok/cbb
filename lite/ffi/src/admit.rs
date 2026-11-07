// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! An admin phone that admits a device by the device's QR code, with the
//! admin key where the app keeps it (the Aurora app's key in OP-TEE): the
//! app scans the code, dials one of its addresses and passes the
//! connection's bytes through cbb_core::admit, which runs the pairing in
//! the core's TLS, issues the device's certificate through the admin key's
//! callback, and adds the device's record to the group (docs/protocol.md,
//! section 6, "The joiner listens").

use std::sync::Arc;

use cbb_core::admit::{Admission, Admitter, Outcome};
use cbb_core::certs::{self, Cert};
use cbb_core::error::{Error, Result};
use cbb_core::pair;
use cbb_lite::phone::Member as Node;
use serde::{Deserialize, Serialize};

use crate::join::{AppKey, SignFn, answer, clock, wall_ms};

#[derive(Deserialize)]
struct NewArgs {
    /// The text of the device's QR code, a cbb://join link.
    qr: String,
    /// The public point of the key the phone issues with, SEC1
    /// uncompressed: its admin key, or the root's key when it holds the
    /// root.
    #[serde(with = "certs::b64")]
    public: Vec<u8>,
    /// The phone's admin CA, DER; absent when it issues with the group's
    /// root.
    #[serde(with = "certs::b64::opt", default)]
    admin_ca: Option<Vec<u8>>,
    /// The user chose to make the device an admin: only the root does, for
    /// a phone that asks to be one.
    #[serde(default)]
    make_admin: bool,
}

#[derive(Serialize)]
struct NewAnswer {
    /// The addresses to dial, host:port, in the QR code's order.
    addrs: Vec<String>,
}

#[derive(Serialize)]
struct FeedAnswer {
    #[serde(with = "certs::b64")]
    send: Vec<u8>,
    /// pending, admitted, done or failed.
    state: &'static str,
    #[serde(skip_serializing_if = "core::ops::Not::not")]
    wrong_code: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    device: Option<DeviceAnswer>,
    /// With done: whether the device said it stored its identity.
    #[serde(skip_serializing_if = "core::ops::Not::not")]
    confirmed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<crate::join::ErrorAnswer>,
}

#[derive(Serialize)]
struct DeviceAnswer {
    device: String,
    name: String,
    os: String,
    role: &'static str,
    admin: bool,
}

/// One admission of a device whose QR code the app scanned.
pub struct Admit {
    node: Arc<Node>,
    admitter: Admitter,
    qr: pair::JoinLink,
    admission: Option<Admission>,
}

impl Admit {
    /// An admission from the app's request (NewArgs) and the issuing key's
    /// callback, with its answer.
    pub fn new(node: Arc<Node>, request: &[u8], sign: SignFn, ctx: usize) -> (Option<Admit>, Vec<u8>) {
        let made = (|| -> Result<(Admit, NewAnswer)> {
            let a: NewArgs = serde_json::from_slice(request)
                .map_err(|e| Error::msg(format!("the admit request does not decode: {e}")))?;
            let qr = pair::parse_join_qr(&a.qr)?;
            let identity = (*node.identity()).clone();
            let ca = match &a.admin_ca {
                Some(der) => Cert::parse(der)?,
                None => identity.root().clone(),
            };
            if ca.public_key() != a.public.as_slice() {
                return Err(Error::msg("the key does not belong to the CA this phone issues with"));
            }
            let admitter = Admitter {
                identity,
                ca,
                ca_key: Arc::new(AppKey { public: a.public, sign, ctx }),
                make_admins: a.make_admin,
            };
            if admitter.make_admins && !admitter.is_root() {
                return Err(Error::msg("only the group's root makes a device an admin"));
            }
            let ans = NewAnswer { addrs: qr.addrs.clone() };
            Ok((Admit { node, admitter, qr, admission: None }, ans))
        })();
        match made {
            Ok((a, ans)) => (Some(a), answer(Ok(ans))),
            Err(e) => (None, answer::<()>(Err(e))),
        }
    }

    /// Starts on a connection the app is dialing, ending the one before;
    /// the answer's send is the TLS client hello.
    pub fn dial(&mut self) -> Vec<u8> {
        let made = Admission::dial(
            self.admitter.clone(),
            self.node.group_view(),
            &self.qr.code,
            &self.qr.fingerprint,
            &clock(),
        );
        match made {
            Ok(a) => {
                self.admission = Some(a);
                self.feed(&[], 0)
            }
            Err(e) => answer::<()>(Err(e)),
        }
    }

    /// Takes what arrived on the connection.
    pub fn feed(&mut self, data: &[u8], now_ms: i64) -> Vec<u8> {
        let Some(adm) = self.admission.as_mut() else {
            return answer::<()>(Err(Error::msg("no connection to feed: dial one first")));
        };
        let now = if now_ms == 0 { wall_ms() } else { now_ms };
        let step = adm.feed(data, now);
        let mut out = FeedAnswer {
            send: step.send,
            state: "pending",
            wrong_code: false,
            device: None,
            confirmed: false,
            error: None,
        };
        match step.outcome {
            Outcome::Pending => {}
            Outcome::Admitted(a) => {
                out.state = "admitted";
                // The device counts as admitted from here; its record goes
                // to the group now, whatever the device answers.
                if let Err(e) = self.node.record_admitted(&self.admitter, &a) {
                    out.error = Some(crate::join::ErrorAnswer::of(&e.context("the device's record")));
                }
                let role = if a.info.is_phone() {
                    "phone"
                } else if a.info.role == "lite" {
                    "lite"
                } else {
                    "full"
                };
                out.device = Some(DeviceAnswer {
                    device: a.device.to_string(),
                    name: a.info.name.clone(),
                    os: a.info.os.clone(),
                    role,
                    admin: a.admin_ca.is_some(),
                });
            }
            Outcome::Done { confirmed } => {
                out.state = "done";
                out.confirmed = confirmed;
            }
            Outcome::Failed { error, wrong_code } => {
                out.state = "failed";
                out.wrong_code = wrong_code;
                out.error = Some(crate::join::ErrorAnswer::of(&error));
            }
        }
        answer(Ok(out))
    }
}
