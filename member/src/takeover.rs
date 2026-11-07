// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Taking the group over on a running member, the computer's service and
//! the phones' apps alike, around cbb_core::takeover: the claim added and
//! sent, the new root's records and certificate once it took effect, and
//! the admins' CAs renewed under the new root.

use std::collections::HashMap;
use std::sync::Mutex;

use cbb_core::certs::{self, Cert};
use cbb_core::manage::Signer;
use cbb_core::takeover::{self, How, Own};
use cbb_core::wire;

use crate::error::{Error, Result};
use crate::node::Node;
use crate::uptime;

/// Signs the claim that hands the group to new_root (DER), adds it to the
/// records and sends it to the group.
pub fn claim(node: &Node, s: &Signer, how: How, new_root: &[u8]) -> Result<()> {
    let records = node.records();
    let r = takeover::claim(&records.lock().unwrap(), s, how, new_root, uptime::wall_ms())?;
    node.add_own_records(std::slice::from_ref(&r));
    if !records.lock().unwrap().has(&r) {
        return Err(Error::msg("the group's records did not take the claim; the log says why"));
    }
    Ok(())
}

/// What the new root signs once its claim took effect: its member
/// certificate from the new root and its records (takeover::finish), the
/// records not yet added.
pub fn finished(node: &Node, s: &Signer, own: &Own) -> Result<takeover::Finished> {
    let ident = node.identity();
    let point = ident.cert.public_key().to_vec();
    takeover::finish(&node.records().lock().unwrap(), s, &point, own, uptime::wall_ms())
}

/// Makes the member the group's root with what finished gave: its new
/// certificate, the records added and sent, and the connections made again
/// with the new certificate.
pub fn become_root(node: &Node, f: &takeover::Finished) -> Result<()> {
    node.renewed(&f.cert, None)?;
    node.offer_admin_key(None);
    node.add_own_records(&f.records);
    let records = node.records();
    let taken = f.records.iter().filter(|r| records.lock().unwrap().has(r)).count();
    if taken < f.records.len() {
        node.logf(&format!(
            "cbb: the group's records took {taken} of the new root's {} records; the log says why",
            f.records.len()
        ));
    }
    node.reconnect();
    node.logf("cbb: the claim took effect; this device is the group's root now");
    Ok(())
}

/// On the group's current root s, gives each connected admin whose admin
/// CA is from an earlier root, as after a takeover, a new admin CA for the
/// same key from this root, as Go's renewAdminCAs. The key comes from the
/// admin CA in its chain, or from its hello. sent remembers, by device, the
/// root each got one from. It returns how many it gave.
pub fn renew_admin_cas(node: &Node, s: &Signer, sent: &Mutex<HashMap<String, [u8; 32]>>) -> usize {
    let root = s.ca.key_hash();
    let chains: HashMap<String, Vec<Cert>> =
        node.peer_chains().into_iter().map(|(id, c)| (id.to_string(), c)).collect();
    let mut n = 0;
    for p in node.peers() {
        let id = p.id.to_string();
        let Some(key) =
            node.records().lock().unwrap().devices().into_iter().find(|d| d.id == id).and_then(|d| d.admin_key)
        else {
            continue;
        };
        let chain = chains.get(&id).map(Vec::as_slice).unwrap_or_default();
        let point = match chain.get(1).filter(|c| c.is_ca && c.key_hash() == key) {
            Some(c) if c.signed_by(s.ca) => continue, // from this root already
            Some(c) => Some(c.public_key().to_vec()),
            None => p
                .admin_key
                .as_deref()
                .filter(|k| certs::sha256(k) == key)
                .and_then(certs::p256_spki)
                .map(|k| k.to_sec1_point(false).as_bytes().to_vec()),
        };
        let Some(point) = point else { continue };
        if sent.lock().unwrap().get(&id) == Some(&root) {
            continue;
        }
        let renewal = {
            let records = node.records();
            let rs = records.lock().unwrap();
            if rs.revoked(&key) || rs.frozen(&key) {
                continue;
            }
            takeover::renew_admin_ca(&rs, s, &id, &point, uptime::wall_ms())
        };
        let renewal = match renewal {
            Ok(r) => r,
            Err(e) => {
                node.logf(&format!("cbb: a new admin CA for {id}: {}", e.for_log()));
                continue;
            }
        };
        if let Some(r) = &renewal.record {
            node.add_own_records(std::slice::from_ref(r));
            if !node.records().lock().unwrap().has(r) {
                node.logf(&format!("cbb: recording the admin {id} under this root: the records did not take it"));
                continue;
            }
        }
        if node.send_to(&p.id, wire::admin(&renewal.admin_ca)) {
            sent.lock().unwrap().insert(id.clone(), root);
            n += 1;
            node.logf(&format!(
                "cbb: gave the admin {} ({id}) a new admin CA from this root, for the same key",
                p.name
            ));
        }
    }
    n
}
