// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! A new phone restores a group with its recovery key (cbb_lite::restore),
//! for an app whose member key the core does not hold (the Aurora app's in
//! OP-TEE): it browses for the group by the sheet's tag, takes and checks
//! the records from a member on a connection that carries records only,
//! and answers what the app starts its member with. The app then claims the
//! group with `cbb_member_manage`'s `recover_with_sheet`.

use std::sync::Arc;
use std::time::Duration;

use cbb_core::certs;
use cbb_core::error::{Error, Result};
use serde::{Deserialize, Serialize};

use crate::join::{AppKey, SignFn, answer};

/// How long browsing looks for the group's members by default.
const WAIT: Duration = Duration::from_secs(5);

#[derive(Deserialize)]
struct Args {
    /// The recovery sheet's QR code.
    sheet: String,
    /// This phone's member key point, SEC1 uncompressed.
    #[serde(with = "certs::b64")]
    public: Vec<u8>,
    #[serde(default)]
    name: String,
    #[serde(default)]
    os: String,
    /// The members to ask, "host:port"; browsing finds them when empty.
    #[serde(default)]
    addrs: Vec<String>,
    #[serde(default)]
    wait_ms: u64,
}

#[derive(Serialize)]
struct Answer {
    /// This phone's new device ID.
    device: String,
    /// Its member certificate and the admin CA that issued it, the
    /// recovery key's.
    #[serde(with = "certs::b64")]
    cert: Vec<u8>,
    #[serde(with = "certs::b64")]
    issuer: Vec<u8>,
    /// The group's first root.
    #[serde(with = "certs::b64")]
    group_ca: Vec<u8>,
    /// The roots that took the group over from group_ca, in order.
    #[serde(with = "certs::b64::list")]
    roots: Vec<Vec<u8>>,
    /// The group's records the member sent, checked, as the member's
    /// records.json.
    #[serde(with = "certs::b64")]
    records: Vec<u8>,
    /// The member that answered.
    addr: String,
}

/// Restores the group of the request's sheet (Args), the member key's
/// callback sign with ctx signing this phone's side of each handshake;
/// blocks while it browses and fetches. The answer is Answer.
pub(crate) fn restore(request: &[u8], sign: SignFn, ctx: usize) -> Vec<u8> {
    answer((|| -> Result<Answer> {
        let a: Args = serde_json::from_slice(request)
            .map_err(|e| Error::msg(format!("the restore request does not decode: {e}")))?;
        let key = Arc::new(AppKey { public: a.public, sign, ctx });
        let wait = if a.wait_ms == 0 { WAIT } else { Duration::from_millis(a.wait_ms.min(60_000)) };
        let name = if a.name.trim().is_empty() { "Phone" } else { a.name.trim() };
        let addrs: Vec<std::net::SocketAddr> = a.addrs.iter().filter_map(|s| s.parse().ok()).collect();
        let (r, g, addr) = cbb_lite::restore::restore(&a.sheet, key, name, &a.os, &addrs, wait)?;
        Ok(Answer {
            device: r.device.to_string(),
            cert: r.cert,
            issuer: r.admin_ca.der,
            group_ca: g.group_ca.der,
            roots: g.records.roots().into_iter().map(|c| c.der).collect(),
            records: g.records.to_file()?,
            addr: addr.to_string(),
        })
    })())
}
