// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The group's root and its admins on a computer (docs/design.md, "Full
//! members, admins and the operating system"), as Go's service does them:
//! cbb new makes a group with this computer as its root, and the root or an
//! admin removes, renames, freezes and unfreezes devices, voids two
//! histories, makes admins and sets the key level, each a record it signs
//! (docs/protocol.md, section 10). The keys it signs with are the admin's
//! fields of the identity file (identity::ADMIN_FIELDS): the group CA key
//! of the computer that made the group, a root key it took the group over
//! with, or an admin key, in a file or in the hardware, with its admin CA.
//! The rules and the messages are Go's (internal/service), which stays the
//! reference.

use std::collections::HashMap;
use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use cbb_core::admit;
use cbb_core::authority::{self, Body, Hash};
use cbb_core::certs::{Cert, b64};
use cbb_core::identity::{ExternalKey, FileKey, HeldKey};
use serde::{Deserialize, Serialize};

use crate::error::{Context, Error, Result};
use crate::identity::{self, Identity, Stored as _};
use crate::node::Node;
use crate::records::{self, Device, Record, Stored as _};
use crate::{keys, sealkey, service, uptime};

/// The key a member signs records with, and the CA it stands for: the
/// group's root, or its admin CA.
pub struct Signing {
    pub ca: Cert,
    pub key: Arc<dyn ExternalKey>,
    /// It is the group's root, not an admin.
    pub root: bool,
}

impl Signing {
    fn hash(&self) -> Hash {
        Hash(self.ca.key_hash())
    }
}

/// The admin's fields of the identity file, as Go writes them.
#[derive(Deserialize, Serialize, Default)]
struct AdminFile {
    #[serde(with = "b64::opt", default, skip_serializing_if = "Option::is_none")]
    group_ca_key: Option<Vec<u8>>,
    #[serde(with = "b64::opt", default, skip_serializing_if = "Option::is_none")]
    root_key: Option<Vec<u8>>,
    #[serde(with = "b64::opt", default, skip_serializing_if = "Option::is_none")]
    admin_key: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    admin_key_tpm: Option<serde_json::Value>,
    #[serde(with = "b64::opt", default, skip_serializing_if = "Option::is_none")]
    admin_key_se: Option<Vec<u8>>,
    #[serde(with = "b64::opt", default, skip_serializing_if = "Option::is_none")]
    admin_ca: Option<Vec<u8>>,
    #[serde(with = "b64::opt", default, skip_serializing_if = "Option::is_none")]
    claim: Option<Vec<u8>>,
    #[serde(with = "b64::opt", default, skip_serializing_if = "Option::is_none")]
    claim_key: Option<Vec<u8>>,
}

/// The key this member signs records with, from the identity file in dir:
/// the root's, as Go's Identity.Signer, or its admin key under its admin
/// CA; None on a member that is no admin.
pub fn signer(dir: &Path, ident: &Identity) -> Result<Option<Signing>> {
    let f: AdminFile = serde_json::from_value(serde_json::Value::Object(identity::admin_fields(dir)?))
        .context("the identity file's admin keys are damaged")?;
    if let Some(k) = f.group_ca_key {
        return Ok(Some(Signing { ca: ident.group_ca.clone(), key: Arc::new(FileKey::new(&k)?), root: true }));
    }
    if let Some(k) = f.root_key {
        return Ok(Some(Signing { ca: ident.root().clone(), key: Arc::new(FileKey::new(&k)?), root: true }));
    }
    let Some(ca) = f.admin_ca else { return Ok(None) };
    let key: Arc<dyn ExternalKey> = match (f.admin_key, f.admin_key_tpm, f.admin_key_se) {
        (Some(k), None, None) => Arc::new(FileKey::new(&k)?),
        (None, Some(b), None) => keys::open(&HeldKey::Tpm(b))?,
        (None, None, Some(b)) => keys::open(&HeldKey::SecureEnclave(b))?,
        _ => return Err(Error::msg("the identity file keeps no admin key, or keeps it in more than one place")),
    };
    Ok(Some(Signing { ca: Cert::parse(&ca)?, key, root: false }))
}

/// The name of this system in a device record and a hello.
pub fn os_name() -> &'static str {
    match std::env::consts::OS {
        "macos" => "macos",
        "windows" => "windows",
        _ => "linux",
    }
}

/// Makes a group with this computer as its root, as Go's group.Create and
/// createGroup: a root CA whose key stays in the identity file, the
/// device's member key in the TPM or the Secure Enclave where cbb-helper
/// can put it there and in the file otherwise, and the root's record of
/// its own device. A group whose root's member key is in a file starts at
/// the key level files (docs/roadmap.md, "Key levels"). It returns the new
/// identity, which the service starts in, and why the member key is in a
/// file when the hardware could not take it.
pub fn new_group(dir: &Path, name: &str) -> Result<(Identity, String)> {
    if Identity::load(dir)?.is_some() {
        return Err(Error::msg("this device is already in a group; cbb status shows it"));
    }
    let root_pkcs8 = identity::new_key()?;
    let root = FileKey::new(&root_pkcs8)?;
    let (external, why) = keys::new_device_key();
    if !why.is_empty() {
        service::log_line(&format!("cbb: the device key stays in a file: {why}"));
    }
    let key = if external.is_some() { Vec::new() } else { identity::new_key()? };
    let point = match &external {
        Some(k) => k.public(),
        None => identity::public_key(&key)?,
    };
    let store = match (&external, crate::rootless::is()) {
        (Some(_), _) => "hardware",
        (None, true) => "rootless",
        (None, false) => "file",
    };
    let seal = match sealkey::load(dir)
        .and_then(|s| cbb_core::seal::public_key(&s).map_err(|e| e.context("the key for sealed messages")))
    {
        Ok(p) => p,
        Err(e) => {
            service::log_line(&format!("cbb: the key for sealed commands: {}; commands come unsealed", e.for_log()));
            Vec::new()
        }
    };
    let own = admit::OwnDevice { name, os: os_name(), role: "full", member_point: &point, store, seal };
    let now_ms = uptime::wall_ms();
    let mut g = admit::new_group(&root, &own, now_ms)?;
    if store != "hardware" {
        let b = Body {
            v: 2,
            alg: authority::ALG_ES256.into(),
            kind: authority::TYPE_SETTINGS.into(),
            signer: Hash(g.root.key_hash()),
            time_ms: now_ms,
            key_level: "files".into(),
            ..Default::default()
        };
        let body = g.records.next_body(b)?;
        let sig = identity::sign_external(&root, &body)?;
        if !g.records.add(&Record::new(body, sig, None))? {
            return Err(Error::msg("the new group's key level was not taken"));
        }
    }
    let ident =
        Identity { id: g.device, key, external, cert: g.cert, issuer: None, group_ca: g.root, roots: Vec::new() };
    let mut set = records::new(&ident.group_ca);
    let _ = set.add_all(&g.records.all());
    set.save(dir)?;
    let mut fields = serde_json::Map::new();
    fields.insert("group_ca_key".into(), b64_value(&root_pkcs8));
    identity::save_with(&ident, dir, fields)?;
    service::new_device_mode(dir)?;
    Ok((ident, why))
}

fn b64_value(b: &[u8]) -> serde_json::Value {
    #[derive(Serialize)]
    struct V<'a>(#[serde(with = "b64")] &'a [u8]);
    serde_json::to_value(V(b)).unwrap_or_default()
}

/// The admin key this member keeps beside its member key, opened.
fn admin_key(f: &AdminFile) -> Result<Option<Arc<dyn ExternalKey>>> {
    Ok(Some(match (&f.admin_key, &f.admin_key_tpm, &f.admin_key_se) {
        (None, None, None) => return Ok(None),
        (Some(k), None, None) => Arc::new(FileKey::new(k)?),
        (None, Some(b), None) => keys::open(&HeldKey::Tpm(b.clone()))?,
        (None, None, Some(b)) => keys::open(&HeldKey::SecureEnclave(b.clone()))?,
        _ => return Err(Error::msg("the identity file keeps the admin key in more than one place")),
    }))
}

fn admin_file(dir: &Path) -> Result<AdminFile> {
    serde_json::from_value(serde_json::Value::Object(identity::admin_fields(dir)?))
        .context("the identity file's admin keys are damaged")
}

/// Gives a computer that is not the group's root the admin key its hellos
/// offer, so that the root can make it an admin, as Go's withAdminKey: in
/// the hardware through cbb-helper where it can, else in the identity
/// file. It returns the key's SubjectPublicKeyInfo while the member should
/// offer it: it has no admin CA yet, or one from a root before the current
/// one. A rootless install offers none.
pub fn admin_key_offer(dir: &Path, ident: &Identity) -> Result<Option<Vec<u8>>> {
    let f = admin_file(dir)?;
    if f.group_ca_key.is_some() || f.root_key.is_some() {
        return Ok(None);
    }
    let key = match admin_key(&f)? {
        Some(k) => k,
        None if crate::rootless::is() => {
            service::log_line(
                "cbb: this device is installed without root, so it offers no admin key and cannot be made an admin",
            );
            return Ok(None);
        }
        None => {
            let mut fields = serde_json::Map::new();
            let (hw, why) = keys::new_device_key();
            let key: Arc<dyn ExternalKey> = match hw.as_ref().and_then(|k| k.held().map(|h| (k, h))) {
                Some((k, HeldKey::Tpm(b))) => {
                    fields.insert("admin_key_tpm".into(), b);
                    k.clone()
                }
                Some((k, HeldKey::SecureEnclave(b))) => {
                    fields.insert("admin_key_se".into(), b64_value(&b));
                    k.clone()
                }
                None => {
                    if !why.is_empty() {
                        service::log_line(&format!("cbb: the admin key stays in a file: {why}"));
                    }
                    let pkcs8 = identity::new_key()?;
                    fields.insert("admin_key".into(), b64_value(&pkcs8));
                    Arc::new(FileKey::new(&pkcs8)?)
                }
            };
            identity::save_with(ident, dir, fields)?;
            key
        }
    };
    let current = match &f.admin_ca {
        Some(der) => Cert::parse(der).is_ok_and(|c| c.signed_by(ident.root())),
        None => false,
    };
    Ok((!current).then(|| cbb_core::certs::p256_spki_of(&key.public())))
}

/// Keeps the admin CA the group's root sent for this member's admin key,
/// as Go's becomeAdmin: a new member certificate from it, so that a device
/// it admits checks both against the Welcome's one issuer. From then on it
/// admits and removes devices with it.
pub fn become_admin(dir: &Path, node: &Node, der: &[u8]) -> Result<()> {
    let f = admin_file(dir)?;
    if f.admin_ca.as_deref() == Some(der) {
        return Ok(());
    }
    let key = admin_key(&f)?.ok_or_else(|| Error::msg("this device has no admin key to be an admin with"))?;
    let ca = Cert::parse(der).map_err(|e| e.context("the admin CA"))?;
    let ident = node.identity();
    if ca.public_key() != key.public().as_slice() {
        return Err(Error::msg("the admin CA is for another key"));
    }
    if !ca.is_ca || !ca.cert_sign || !ca.signed_by(ident.root()) {
        return Err(Error::msg("the admin CA is not from the group's current root"));
    }
    let renewed = f.admin_ca.is_some();
    let now = uptime::wall_ms() / 1000;
    let cert = cbb_core::issue::member(&ident.id, ident.cert.public_key(), &ca, now, &mut |tbs| {
        identity::sign_external(&*key, tbs)
    })?;
    ident.with_cert_from(&cert, Some(der))?;
    let mut fields = serde_json::Map::new();
    fields.insert("admin_ca".into(), b64_value(der));
    identity::save_with(&ident, dir, fields)?;
    node.renewed(&cert, Some(der))?;
    node.offer_admin_key(None);
    node.logf(if renewed {
        "cbb: the group's root renewed this admin's CA, for the same key"
    } else {
        "cbb: this device is now an admin of the group: it can admit and remove devices"
    });
    Ok(())
}

/// Makes this admin the group's root once the records make the new root of
/// its claim the current one, as Go's finishTakeoverLocked: the claim's key
/// becomes the root key, a member certificate from the new root replaces
/// the admin's, and the records a new root starts with follow
/// (after_takeover). A claim that was cancelled or became void is dropped.
/// It returns whether this device became the root.
pub fn finish_takeover(dir: &Path, node: &Node, name: &str) -> Result<bool> {
    let f = admin_file(dir)?;
    let (Some(claim), Some(claim_key)) = (f.claim.as_deref(), f.claim_key.as_deref()) else { return Ok(false) };
    let claim_cert = Cert::parse(claim)?;
    let ident = node.identity();
    if ident.roots.last().is_some_and(|r| r.der == claim_cert.der) {
        let key = FileKey::new(claim_key)?;
        let n = ident.roots.len();
        let old = if n >= 2 { &ident.roots[n - 2] } else { &ident.group_ca };
        let old_root = Hash(old.key_hash());
        let now = uptime::wall_ms() / 1000;
        let cert = cbb_core::issue::member(&ident.id, ident.cert.public_key(), &claim_cert, now, &mut |tbs| {
            identity::sign_external(&key, tbs)
        })?;
        ident.with_cert_from(&cert, None)?;
        let mut fields = serde_json::Map::new();
        fields.insert("root_key".into(), b64_value(claim_key));
        fields.insert("prev_cert".into(), b64_value(&ident.cert.der));
        fields
            .insert("prev_issuer".into(), ident.issuer.as_ref().map_or(serde_json::Value::Null, |c| b64_value(&c.der)));
        for k in ["admin_key", "admin_key_tpm", "admin_key_se", "admin_ca", "claim", "claim_key"] {
            fields.insert(k.into(), serde_json::Value::Null);
        }
        identity::save_with(&ident, dir, fields)?;
        node.renewed(&cert, None)?;
        node.offer_admin_key(None);
        after_takeover(dir, node, old_root, name);
        node.reconnect();
        return Ok(true);
    }
    let h = claim_cert.key_hash();
    let state = node.records().lock().unwrap().state().claims.iter().find(|c| c.root.0 == h).map(|c| c.state);
    if let Some(state @ ("cancelled" | "void")) = state {
        let mut fields = serde_json::Map::new();
        fields.insert("claim".into(), serde_json::Value::Null);
        fields.insert("claim_key".into(), serde_json::Value::Null);
        identity::save_with(&ident, dir, fields)?;
        node.logf(&format!("cbb: the claim to take the group over is {state}; this device stays an admin"));
    }
    Ok(false)
}

/// Signs, on the admin whose claim made it the group's root, the records a
/// new root starts with, as Go's afterTakeover: its own device that holds
/// the root, the admins it keeps under the new root, a removal of the old
/// root's device, and the old root's settings again.
fn after_takeover(dir: &Path, node: &Node, old_root: Hash, name: &str) {
    let ident = node.identity();
    let Ok(Some(s)) = signer(dir, &ident) else { return };
    if !s.root {
        return;
    }
    let (devs, all) = {
        let records = node.records();
        let rs = records.lock().unwrap();
        (rs.devices(), rs.all())
    };
    let bodies: Vec<Body> = all.iter().filter_map(|r| Body::parse(&r.body).ok()).collect();
    let lost = bodies
        .iter()
        .filter(|b| b.kind == authority::TYPE_DEVICE && b.holds_root && b.signer == old_root)
        .max_by_key(|b| b.seq)
        .map(|b| b.device.clone())
        .unwrap_or_default();
    let me = ident.id.to_string();
    let mut own_name = name.to_string();
    let mut revoke: Vec<Hash> = Vec::new();
    let mut kept = Vec::new();
    for d in &devs {
        if d.id == me {
            own_name = d.name.clone();
        } else if d.id == lost {
            revoke.extend(d.keys.iter().copied().map(Hash));
        } else if let Some(a) = d.admin_key.filter(|_| !d.frozen) {
            kept.push(Body {
                kind: authority::TYPE_DEVICE.into(),
                device: d.id.clone(),
                name: d.name.clone(),
                role: d.role.clone(),
                os: d.os.clone(),
                key: Some(Hash(d.key)),
                admin: Some(Hash(a)),
                powers: d.powers.clone(),
                commands: d.commands.clone(),
                store: d.store.clone(),
                hardware: d.kind.clone(),
                proof: d.proof.clone(),
                seal: d.seal.clone(),
                ..Default::default()
            });
        }
    }
    let store = if ident.external.is_some() { "hardware" } else { "file" };
    let seal = sealkey::load(dir).ok().and_then(|k| cbb_core::seal::public_key(&k).ok()).unwrap_or_default();
    let mut out = vec![Body {
        kind: authority::TYPE_DEVICE.into(),
        device: me.clone(),
        name: own_name,
        role: "full".into(),
        os: os_name().into(),
        key: Some(Hash(ident.cert.key_hash())),
        store: store.into(),
        seal,
        ..Default::default()
    }];
    out.extend(kept);
    if !revoke.is_empty() {
        revoke.sort_by_key(|k| cbb_core::certs::hex(&k.0));
        revoke.dedup();
        out.push(Body { kind: authority::TYPE_REVOKE.into(), keys: revoke, ..Default::default() });
    }
    // The state counts only the current root's settings, so the new root
    // signs the old root's again: the takeover delay and the key level.
    if let Some(b) =
        bodies.iter().filter(|b| b.kind == authority::TYPE_SETTINGS && b.signer == old_root).max_by_key(|b| b.seq)
    {
        out.push(Body {
            kind: authority::TYPE_SETTINGS.into(),
            takeover_delay_ms: b.takeover_delay_ms,
            key_level: b.key_level.clone(),
            ..Default::default()
        });
    }
    let admin = Admin { node, dir };
    for b in out {
        if let Err(e) = admin.sign(&s, b) {
            node.logf(&format!("cbb: a record of the new root: {}", e.for_log()));
        }
    }
    node.logf("cbb: the claim took effect; this device is the group's root now");
}

/// On the group's root, gives each connected admin computer whose admin
/// CA is from an earlier root, as after a takeover, a new admin CA for the
/// same key from this root, as Go's renewAdminCAs: the records name the
/// key, so they stay, and a takeover by that admin later hangs under this
/// root. The key comes from the admin CA in its chain, or from its hello.
/// sent remembers, by device, the root each got one from.
pub fn renew_admin_cas(dir: &Path, node: &Node, sent: &Mutex<HashMap<String, [u8; 32]>>) {
    let ident = node.identity();
    let Ok(Some(s)) = signer(dir, &ident) else { return };
    if !s.root {
        return;
    }
    let root = s.ca.key_hash();
    let chains: HashMap<String, Vec<Cert>> =
        node.peer_chains().into_iter().map(|(id, c)| (id.to_string(), c)).collect();
    let admin = Admin { node, dir };
    for p in node.peers() {
        let id = p.id.to_string();
        let Some(d) = admin_device(node, &id) else { continue };
        let Some(key) = d.admin_key else { continue };
        let chain = chains.get(&id).map(Vec::as_slice).unwrap_or_default();
        let point = match chain.get(1).filter(|c| c.is_ca && c.key_hash() == key) {
            Some(c) if c.signed_by(&s.ca) => continue, // from this root already
            Some(c) => Some(c.public_key().to_vec()),
            None => p
                .admin_key
                .as_deref()
                .filter(|k| cbb_core::certs::sha256(k) == key)
                .and_then(cbb_core::certs::p256_spki)
                .map(|k| k.to_sec1_point(false).as_bytes().to_vec()),
        };
        let gone = {
            let records = node.records();
            let rs = records.lock().unwrap();
            rs.revoked(&key) || rs.frozen(&key)
        };
        let Some(point) = point else { continue };
        if gone || sent.lock().unwrap().get(&id) == Some(&root) {
            continue;
        }
        let Ok(dev) = cbb_core::certs::DeviceId::parse(&id) else { continue };
        let ca = match cbb_core::issue::admin_ca(&dev, &point, &s.ca, uptime::wall_ms() / 1000, &mut |tbs| {
            identity::sign_external(&*s.key, tbs)
        }) {
            Ok(ca) => ca,
            Err(e) => {
                node.logf(&format!("cbb: a new admin CA for {id}: {}", e.for_log()));
                continue;
            }
        };
        // This root's own record of the admin lets it take the group over
        // from this root in turn.
        let listed = {
            let records = node.records();
            let rs = records.lock().unwrap();
            rs.all()
                .iter()
                .filter_map(|r| Body::parse(&r.body).ok())
                .any(|b| b.kind == authority::TYPE_DEVICE && b.signer == Hash(root) && b.admin == Some(Hash(key)))
        };
        if !listed {
            let b = Body {
                kind: authority::TYPE_DEVICE.into(),
                device: d.id.clone(),
                name: d.name.clone(),
                role: "full".into(),
                os: d.os.clone(),
                key: Some(Hash(d.key)),
                admin: Some(Hash(key)),
                powers: d.powers.clone(),
                commands: d.commands.clone(),
                store: d.store.clone(),
                hardware: d.kind.clone(),
                proof: d.proof.clone(),
                seal: d.seal.clone(),
                ..Default::default()
            };
            if let Err(e) = admin.sign(&s, b) {
                node.logf(&format!("cbb: recording the admin {id} under this root: {}", e.for_log()));
                continue;
            }
        }
        if node.send_to(&p.id, cbb_core::wire::admin(&ca)) {
            sent.lock().unwrap().insert(id.clone(), root);
            node.logf(&format!(
                "cbb: gave the admin {} ({id}) a new admin CA from this root, for the same key",
                p.name
            ));
        }
    }
}

/// The records' device dev, if they list it.
fn admin_device(node: &Node, dev: &str) -> Option<Device> {
    node.records().lock().unwrap().devices().into_iter().find(|d| d.id == dev)
}

/// A duration in milliseconds as Go's time.Duration prints it: 72h0m0s,
/// 1m0s, 5s, 0s.
fn go_duration(ms: i64) -> String {
    if ms == 0 {
        return "0s".into();
    }
    let (h, m, sec, rest) = (ms / 3_600_000, ms / 60_000 % 60, ms / 1000 % 60, ms % 1000);
    let secs =
        if rest == 0 { format!("{sec}s") } else { format!("{sec}.{}s", format!("{rest:03}").trim_end_matches('0')) };
    if ms < 1000 {
        return format!("{ms}ms");
    }
    match (h, m) {
        (0, 0) => secs,
        (0, _) => format!("{m}m{secs}"),
        _ => format!("{h}h{m}m{secs}"),
    }
}

/// The device that target names in the group's records, by its device ID
/// or its name, case-insensitive (Go's findDevice).
pub fn find_device(node: &Node, target: &str) -> Result<Device> {
    let devs = node.devices();
    if let Some(d) = devs.iter().find(|d| d.id == target) {
        return Ok(d.clone());
    }
    let mut matched: Vec<Device> = devs.into_iter().filter(|d| d.name.eq_ignore_ascii_case(target)).collect();
    match matched.len() {
        0 => Err(Error::msg(format!("no device {target:?} in the group; cbb status lists them"))),
        1 => Ok(matched.remove(0)),
        _ => Err(Error::msg(format!(
            "several devices are named {target:?}; name one by its ID: {}",
            matched.iter().map(|d| d.id.as_str()).collect::<Vec<_>>().join(", ")
        ))),
    }
}

const NOT_ADMIN: &str =
    "only an admin can change the devices list: the group's root, an admin it made (cbb admin), or an admin phone";
const FROZEN: &str = "another admin froze this computer's admin key: it changes nothing until the group's root or an admin phone unfreezes it";

/// A computer admin's powers: those of Go's computerAdminPowers.
fn computer_admin_powers(computer_root: bool) -> Vec<String> {
    let mut p = vec![
        authority::POWER_ADMIT,
        authority::POWER_FREEZE,
        authority::POWER_HUB,
        authority::POWER_REMOVE,
        authority::POWER_RENEW,
    ];
    if computer_root {
        p.push(authority::POWER_TAKEOVER);
    }
    p.into_iter().map(String::from).collect()
}

/// The admin computers of this group, and its root: an admin's work.
pub struct Admin<'a> {
    pub node: &'a Node,
    pub dir: &'a Path,
}

impl Admin<'_> {
    fn signing(&self) -> Result<Signing> {
        signer(self.dir, &self.node.identity())?.ok_or_else(|| Error::msg(NOT_ADMIN))
    }

    fn me(&self) -> String {
        self.node.identity().id.to_string()
    }

    fn root_device(&self) -> String {
        self.node.records().lock().unwrap().state().root_device
    }

    /// Signs the next record of the signer s with body, as Go's
    /// signRecord: a device record that makes an admin gives it a computer
    /// admin's powers unless body names them, and the root's record of its
    /// own device says it holds the root. The record goes into the set and
    /// to the group.
    fn sign(&self, s: &Signing, mut b: Body) -> Result<Record> {
        let records = self.node.records();
        let r = {
            let rs = records.lock().unwrap();
            if !s.root && rs.frozen(&s.ca.key_hash()) {
                return Err(Error::msg(FROZEN));
            }
            b.v = 2;
            b.alg = authority::ALG_ES256.into();
            b.signer = s.hash();
            b.time_ms = uptime::wall_ms();
            if b.kind == authority::TYPE_DEVICE {
                if b.admin.is_some() && b.powers.is_empty() {
                    b.powers = computer_admin_powers(s.root);
                    b.commands = authority::COMMANDS.iter().map(|c| (*c).into()).collect();
                }
                b.holds_root = s.root && b.device == self.me();
            }
            let body = rs.next_body(b)?;
            let sig = identity::sign_external(&*s.key, &body)?;
            Record::new(body, sig, (!s.root).then(|| s.ca.der.clone()))
        };
        self.node.add_own_records(std::slice::from_ref(&r));
        if !records.lock().unwrap().has(&r) {
            return Err(Error::msg("the group's records did not take the change; the log says why"));
        }
        Ok(r)
    }

    /// Removes the device target names from the group, as Go's revoke:
    /// every key it had goes, its admin key among them. It returns its name.
    pub fn revoke(&self, target: &str) -> Result<String> {
        let d = find_device(self.node, target)?;
        let s = self.signing()?;
        let root = self.root_device();
        if d.id == self.me() {
            return Err(Error::msg("a device cannot remove itself; run cbb remove on another member"));
        }
        if d.id == root && d.role == "phone" {
            return Err(Error::msg(format!(
                "{} holds the group's root; remove it on another admin phone, which takes the group over",
                d.name
            )));
        }
        if d.id == root {
            return Err(Error::msg(format!(
                "{0} holds the group's root; run cbb takeover {0} on an admin, which takes the group over and removes it",
                d.name
            )));
        }
        if d.admin_key.is_some() && !s.root {
            return Err(Error::msg(format!(
                "{} is an admin; only the group's root or an admin phone removes an admin, since this computer's admin key sits in a file",
                d.name
            )));
        }
        let mut keys: Vec<Hash> = d.keys.iter().copied().map(Hash).collect();
        keys.extend(d.admin_key.map(Hash));
        if keys.is_empty() {
            return Err(Error::msg(format!("the key of {} is unknown", d.id)));
        }
        keys.sort_by_key(|k| cbb_core::certs::hex(&k.0));
        keys.dedup();
        self.sign(&s, Body { kind: authority::TYPE_REVOKE.into(), keys, ..Default::default() })?;
        self.node.logf(&format!("cbb: removed {} ({}) from the group", d.name, d.id));
        Ok(d.name)
    }

    /// Gives the device target names the name name, as Go's rename: a
    /// device record like its newest one. It returns the old name.
    pub fn rename(&self, target: &str, name: &str) -> Result<String> {
        let name = name.trim();
        if !authority::valid_name(name) {
            return Err(Error::msg("a device name has 1 to 64 characters and no control characters"));
        }
        let d = find_device(self.node, target)?;
        let s = self.signing()?;
        if d.name == name {
            return Ok(d.name);
        }
        // A device record that names an admin key, or of a watch, counts
        // only from a root's own key, and so does the root's own device's.
        if !s.root && (d.admin_key.is_some() || d.role == "watch" || d.id == self.root_device()) {
            return Err(Error::msg(format!(
                "only the group's root renames {}: it is an admin or a watch, or the root's own device",
                d.name
            )));
        }
        self.sign(
            &s,
            Body {
                kind: authority::TYPE_DEVICE.into(),
                device: d.id.clone(),
                name: name.into(),
                role: d.role.clone(),
                os: d.os.clone(),
                key: Some(Hash(d.key)),
                admin: d.admin_key.map(Hash),
                powers: d.powers.clone(),
                commands: d.commands.clone(),
                store: d.store.clone(),
                hardware: d.kind.clone(),
                proof: d.proof.clone(),
                seal: d.seal.clone(),
                forward_only: d.forward_only,
                ..Default::default()
            },
        )?;
        self.node.logf(&format!("cbb: renamed {} ({}) to {name}", d.name, d.id));
        Ok(d.name)
    }

    /// Freezes (on) or unfreezes the admin computer target names, as Go's
    /// freeze. It returns its name.
    pub fn freeze(&self, target: &str, on: bool) -> Result<String> {
        let d = find_device(self.node, target)?;
        let s = self.signing()?;
        let frozen = d.admin_key.is_some_and(|a| self.node.records().lock().unwrap().frozen(&a));
        if d.id == self.me() {
            return Err(Error::msg("a device cannot freeze or unfreeze itself"));
        }
        if d.id == self.root_device() {
            return Err(Error::msg(format!("{} holds the group's root, which nobody freezes", d.name)));
        }
        let Some(admin) = d.admin_key.filter(|_| d.role != "phone") else {
            return Err(Error::msg(format!(
                "{} is no admin computer; only those are frozen, and an ordinary device is removed with cbb remove",
                d.name
            )));
        };
        if on && frozen {
            return Err(Error::msg(format!("{} is frozen already", d.name)));
        }
        if !on && !frozen {
            return Err(Error::msg(format!("{} is not frozen", d.name)));
        }
        if !on && !s.root {
            return Err(Error::msg(
                "only the group's root or an admin phone unfreezes an admin, since this computer's admin key sits in a file",
            ));
        }
        let body = if on {
            Body { kind: authority::TYPE_FREEZE.into(), keys: vec![Hash(admin)], ..Default::default() }
        } else {
            let records = self.node.records().lock().unwrap().freezes_of(&admin);
            Body { kind: authority::TYPE_THAW.into(), records, ..Default::default() }
        };
        self.sign(&s, body)?;
        self.node.logf(&format!("cbb: {} the admin {} ({})", if on { "froze" } else { "unfroze" }, d.name, d.id));
        Ok(d.name)
    }

    /// Voids, on the group's root, both histories of every key that signed
    /// two, as Go's resolveHistories; it returns whose keys they were.
    pub fn resolve(&self) -> Result<Vec<String>> {
        let s = self.signing()?;
        if !s.root {
            return Err(Error::msg(
                "only the group's root resolves two histories: run cbb resolve on the root computer, or resolve them on the root phone",
            ));
        }
        let (mut ids, who) = {
            let records = self.node.records();
            let rs = records.lock().unwrap();
            let devices = rs.devices();
            let st = rs.state();
            let mut ids = Vec::new();
            let mut who = Vec::new();
            for c in st.conflicts.iter().filter(|c| c.kind == authority::CONFLICT_TWO_HISTORIES) {
                ids.extend(c.records.iter().copied());
                for k in &c.signers {
                    let name = devices
                        .iter()
                        .find(|d| d.admin_key == Some(k.0) || (st.roots.contains(k) && d.id == st.root_device))
                        .map_or_else(|| cbb_core::certs::hex(&k.0[..4]), |d| d.name.clone());
                    who.push(name);
                }
            }
            (ids, who)
        };
        if ids.is_empty() {
            return Err(Error::msg("no key of the group signed two histories"));
        }
        ids.sort_by_key(|k| cbb_core::certs::hex(&k.0));
        ids.dedup();
        self.sign(&s, Body { kind: authority::TYPE_RESOLVE.into(), records: ids, ..Default::default() })?;
        self.node.logf(&format!("cbb: voided both histories of {}", who.join(", ")));
        Ok(who)
    }

    /// Makes the computer target names an admin, on the group's root, as
    /// Go's makeAdmin: the admin CA for the admin key its hello offers, its
    /// device record naming it, and the admin message. A computer whose
    /// keys sit in a file becomes one only with allow_file_key. It returns
    /// its name.
    pub fn make_admin(&self, target: &str, allow_file_key: bool) -> Result<String> {
        let d = find_device(self.node, target)?;
        let s = self.signing()?;
        if !s.root {
            return Err(Error::msg(
                "only the group's root makes admins: run cbb admin on the computer that created the group, or use \"Make it an admin\" on the root phone",
            ));
        }
        if d.id == self.me() {
            return Err(Error::msg("this device is the group's root, which is more than an admin"));
        }
        if d.role != "full" {
            return Err(Error::msg(format!("{} is no computer with the service; only those can be admins", d.name)));
        }
        if d.admin {
            return Err(Error::msg(format!("{} is already an admin", d.name)));
        }
        let Some(peer) = self.node.peers().into_iter().find(|p| p.id.as_str() == d.id) else {
            return Err(Error::msg(format!(
                "{} is not connected; it gets its admin CA over its connection, so start it and try again",
                d.name
            )));
        };
        if peer.key_store == "rootless" || d.store == "rootless" {
            return Err(Error::msg(format!(
                "{} is installed without root, so every program of its user can read its keys; such a device is never an admin (D-79)",
                d.name
            )));
        }
        let Some(admin_key) = peer.admin_key.clone() else {
            return Err(Error::msg(format!(
                "{} offers no admin key: it runs an older CBB, or in a container that may not hold the group's keys (its log says so)",
                d.name
            )));
        };
        let (store, kind, proof) = if d.store == "proven" {
            (d.store.clone(), d.kind.clone(), d.proof.clone())
        } else {
            (cbb_core::command::store_of(&peer.key_store, "full").to_string(), String::new(), String::new())
        };
        level_allows(
            &self.key_level(),
            &store,
            &d.name,
            &format!("run cbb admin -allow-file-key {target}"),
            allow_file_key,
        )?;
        let point = cbb_core::certs::p256_spki(&admin_key)
            .ok_or_else(|| Error::msg(format!("the admin key that {} offers is no ECDSA key", d.name)))?
            .to_sec1_point(false)
            .as_bytes()
            .to_vec();
        let dev = cbb_core::certs::DeviceId::parse(&d.id)?;
        let ca = cbb_core::issue::admin_ca(&dev, &point, &s.ca, uptime::wall_ms() / 1000, &mut |tbs| {
            identity::sign_external(&*s.key, tbs)
        })?;
        let admin = Hash(Cert::parse(&ca)?.key_hash());
        self.sign(
            &s,
            Body {
                kind: authority::TYPE_DEVICE.into(),
                device: d.id.clone(),
                name: d.name.clone(),
                role: "full".into(),
                os: d.os.clone(),
                key: Some(Hash(d.key)),
                admin: Some(admin),
                store,
                hardware: kind,
                proof,
                seal: d.seal.clone(),
                ..Default::default()
            },
        )?;
        if !self.node.send_to(&peer.id, cbb_core::wire::admin(&ca)) {
            return Err(Error::msg(format!(
                "{} left before it got its admin CA; it is listed as an admin, so run cbb admin again when it is back",
                d.name
            )));
        }
        self.node.logf(&format!("cbb: made {} ({}) an admin of the group", d.name, d.id));
        Ok(d.name)
    }

    /// The group's key level, hardware when no record sets it.
    fn key_level(&self) -> String {
        let l = self.node.records().lock().unwrap().state().key_level;
        if l.is_empty() { "hardware".into() } else { l }
    }

    /// Sets the group's key level on its root, as Go's setKeyLevel,
    /// keeping the takeover delay; it returns the admins and hubs below
    /// the new level, which stay until the user removes them.
    pub fn set_key_level(&self, level: &str) -> Result<Vec<String>> {
        if !authority::KEY_LEVELS.contains(&level) {
            return Err(Error::msg("the key level is proven, hardware or files"));
        }
        let s = self.signing()?;
        if !s.root {
            return Err(Error::msg("only the group's root sets the key level"));
        }
        let ident = self.node.identity();
        let own = if ident.external.is_some() {
            "hardware"
        } else if crate::rootless::is() {
            "rootless"
        } else {
            "file"
        };
        level_allows(level, own, "this device, the group's root,", "", true)?;
        let delay = self.current_delay(&s.hash());
        self.sign(
            &s,
            Body {
                kind: authority::TYPE_SETTINGS.into(),
                takeover_delay_ms: delay,
                key_level: level.into(),
                ..Default::default()
            },
        )?;
        self.node.logf(&format!("cbb: the group's key level is {level} now"));
        let records = self.node.records();
        let rs = records.lock().unwrap();
        let hubs = rs.state().hubs;
        let me = self.me();
        Ok(rs
            .devices()
            .into_iter()
            .filter(|d| {
                (d.admin || hubs.contains(&d.id))
                    && d.id != me
                    && level_allows(level, &d.store, &d.name, "", true).is_err()
            })
            .map(|d| d.name)
            .collect())
    }

    /// Sets, on the group's root, how long an admin's claim waits on each
    /// member before it takes effect, as Go's setTakeoverDelay: value is a
    /// duration from 0s to 168h (docs/protocol.md, section 10, "Handing
    /// the group over"). The settings record keeps the key level.
    pub fn set_takeover_delay(&self, value: &str) -> Result<()> {
        let ms = crate::go_duration_ms(value.trim())
            .filter(|ms| (0..=authority::MAX_DELAY).contains(ms))
            .ok_or_else(|| Error::msg("the takeover delay is a duration from 0s to 168h, as 72h"))?;
        let s = self.signing().ok().filter(|s| s.root);
        let s = s.ok_or_else(|| Error::msg("only the group's root sets how long a claim waits"))?;
        let level = self.current_level(&s.hash());
        self.sign(
            &s,
            Body {
                kind: authority::TYPE_SETTINGS.into(),
                takeover_delay_ms: Some(ms),
                key_level: level,
                ..Default::default()
            },
        )?;
        self.node.logf(&format!("cbb: a claim to take the group over now waits {} on each member", go_duration(ms)));
        Ok(())
    }

    /// Sets, on the root or an admin, how long a copy from another device
    /// stays live after it arrives, as Go's setIncoming: a duration from 5s
    /// to 1h (docs/protocol.md, section 10, "The copies setting").
    pub fn set_incoming(&self, value: &str) -> Result<()> {
        let ms = crate::go_duration_ms(value.trim())
            .filter(|ms| (authority::MIN_INCOMING..=authority::MAX_INCOMING).contains(ms))
            .ok_or_else(|| Error::msg("how long an incoming copy stays live is a duration from 5s to 1h, as 1m"))?;
        let s = self
            .signing()
            .map_err(|_| Error::msg("only the group's root or an admin sets how long an incoming copy stays live"))?;
        self.sign(&s, Body { kind: authority::TYPE_COPIES.into(), incoming_ms: Some(ms), ..Default::default() })?;
        self.node
            .logf(&format!("cbb: a copy from another device now stays live for {} after it arrives", go_duration(ms)));
        Ok(())
    }

    /// Hands the group, on the root, to the admin target names, as Go's
    /// handOver: a handover record names its admin key, so that its claim
    /// takes effect at once. It returns the admin's name.
    pub fn hand_over(&self, target: &str) -> Result<String> {
        let d = find_device(self.node, target)?;
        let s = self.signing().ok().filter(|s| s.root);
        let s = s.ok_or_else(|| Error::msg("only the group's root hands the group over"))?;
        if d.id == self.me() {
            return Err(Error::msg("this device is the group's root already"));
        }
        let Some(admin) = d.admin_key.filter(|_| !d.frozen) else {
            return Err(Error::msg(format!(
                "{} is no admin: make it one first (cbb admin), then hand the group over",
                d.name
            )));
        };
        self.sign(&s, Body { kind: authority::TYPE_HANDOVER.into(), admin: Some(Hash(admin)), ..Default::default() })?;
        self.node.logf(&format!("cbb: handed the group over to {} ({}): its claim takes effect at once", d.name, d.id));
        Ok(d.name)
    }

    /// Mutes the device target names for for_ms (0: until an unmute), or
    /// ends its mute, as an admin, with a command it signs (Go's muteOp);
    /// this device's own mute is set where the service asks (it returns
    /// None then).
    pub fn mute(&self, target: &str, on: bool, for_ms: i64) -> Result<Option<String>> {
        let d = find_device(self.node, target)?;
        let s = self.signing().map_err(|_| {
            Error::msg(
                "only an admin mutes a device or ends its mute: the group's root, an admin it made (cbb admin), or an admin phone; cbb mute without -on keeps the group's copies out of this device",
            )
        })?;
        if !s.root && self.node.records().lock().unwrap().frozen(&s.ca.key_hash()) {
            return Err(Error::msg(FROZEN));
        }
        if d.id == self.me() {
            return Ok(None);
        }
        let me = self.me();
        let signer = cbb_core::manage::Signer { ca: &s.ca, key: &*s.key, me: &me };
        let order = if on { cbb_core::manage::Order::Mute(for_ms) } else { cbb_core::manage::Order::Unmute };
        let r =
            cbb_core::manage::order(&self.node.records().lock().unwrap(), &signer, &d.id, &order, uptime::wall_ms())?;
        let res = self.node.command(&r, Duration::from_secs(5)).map_err(|e| e.context(d.name.clone()))?;
        if res.status != "done" {
            return Err(Error::msg(format!("{} {} it: {}", d.name, res.status, res.reason)));
        }
        Ok(Some(d.name))
    }

    /// Sends the device d a hub command with the order hub, signed as an
    /// admin (Go's moveHub, makeHub and stopHub on another device), and
    /// returns its result once it carried the command out.
    #[cfg_attr(not(feature = "tunnel"), allow(dead_code))]
    pub fn hub_command(&self, d: &Device, hub: serde_json::Value) -> Result<crate::wire::CommandResult> {
        self.order_command(
            d,
            cbb_core::manage::Order::Hub(hub),
            "only an admin makes a device a hub, moves the hub or stops one: the group's root, an admin it made (cbb admin), or an admin phone",
        )
    }

    /// Turns sync away from home off on the device target names with an
    /// away-off command (Go's awayOffOn); only its own user turns it on
    /// again (D-45).
    pub fn away_off_on(&self, target: &str) -> Result<()> {
        let d = find_device(self.node, target)?;
        if d.id == self.me() {
            return Err(Error::msg("-on names this device; cbb global off turns it off here"));
        }
        self.order_command(
            &d,
            cbb_core::manage::Order::AwayOff,
            "only an admin turns sync away from home off on another device: the group's root, an admin it made (cbb admin), or an admin phone",
        )
        .map(|_| ())
    }

    /// Signs the device d a record with forward_only unless its newest has
    /// it, as Go's markForwardOnly: d then passes the copies on as a hub
    /// and reads none (docs/protocol.md, section 11, "Two kinds of hub").
    #[cfg_attr(not(feature = "tunnel"), allow(dead_code))]
    pub fn mark_forward_only(&self, d: &Device) -> Result<()> {
        if d.forward_only {
            return Ok(());
        }
        if d.admin_key.is_some() {
            return Err(Error::msg(format!(
                "{} is an admin; only a computer that is no admin only passes copies on",
                d.name
            )));
        }
        if d.role != "full" {
            return Err(Error::msg(format!("{} is no computer; only a computer only passes copies on", d.name)));
        }
        if d.store == "rootless" {
            return Err(Error::msg(format!(
                "{} is installed without root, and such a computer is never a hub (D-79)",
                d.name
            )));
        }
        if d.id == self.root_device() {
            return Err(Error::msg(format!("{} is the root's own computer, a hub that reads the copies", d.name)));
        }
        let s = self.signing()?;
        self.sign(
            &s,
            Body {
                kind: authority::TYPE_DEVICE.into(),
                device: d.id.clone(),
                name: d.name.clone(),
                role: d.role.clone(),
                os: d.os.clone(),
                key: Some(Hash(d.key)),
                store: d.store.clone(),
                hardware: d.kind.clone(),
                proof: d.proof.clone(),
                seal: d.seal.clone(),
                forward_only: true,
                ..Default::default()
            },
        )
        .map_err(|e| {
            Error::msg(format!(
                "the group's records did not take the record that makes it a hub: only the root or an admin with the powers admit and hub signs it ({})",
                e.message()
            ))
        })?;
        self.node.logf(&format!(
            "cbb: {} ({}) only passes the copies on now, and reads none; the next copies are no longer sealed to it",
            d.name, d.id
        ));
        Ok(())
    }

    /// Signs the table of main hubs, the devices targets name in order, as
    /// Go's setHubs: the root, or an admin that may be a hub.
    pub fn set_hubs(&self, targets: &[String]) -> Result<()> {
        if targets.is_empty() || targets.len() > authority::MAX_HUBS {
            return Err(Error::msg(format!("name 1 to {} hubs, in the order they serve", authority::MAX_HUBS)));
        }
        let s = self.signing().ok();
        let may = s.as_ref().is_some_and(|s| s.root || self.node.records().lock().unwrap().may_host(&self.me()));
        let Some(s) = s.filter(|_| may) else {
            return Err(Error::msg("only the group's root or an admin that may be a hub sets the main hubs"));
        };
        let level = self.node.records().lock().unwrap().state().key_level;
        let level = if level.is_empty() { "hardware".to_string() } else { level };
        let mut ids: Vec<String> = Vec::new();
        for t in targets {
            let d = find_device(self.node, t)?;
            if d.role != "full" && d.role != "phone" {
                return Err(Error::msg(format!("{} cannot be a hub: only a computer or a phone can", d.name)));
            }
            // Naming it in the table is the user's consent to a key in a
            // file, where the level allows one.
            level_allows(&level, &d.store, &d.name, "", true)?;
            if ids.contains(&d.id) {
                return Err(Error::msg(format!("{} is named twice", d.name)));
            }
            ids.push(d.id);
        }
        self.sign(&s, Body { kind: authority::TYPE_HUBS.into(), hubs: ids, ..Default::default() })?;
        self.node.logf(&format!("cbb: the group's main hubs are now {}", targets.join(", ")));
        Ok(())
    }

    /// Sends the device d a command with the order o, signed as an admin,
    /// and returns its result once it carried the command out; not_admin
    /// says why a device that is no admin cannot.
    fn order_command(
        &self,
        d: &Device,
        o: cbb_core::manage::Order,
        not_admin: &str,
    ) -> Result<crate::wire::CommandResult> {
        let s = self.signing().map_err(|_| Error::msg(not_admin))?;
        if !s.root && self.node.records().lock().unwrap().frozen(&s.ca.key_hash()) {
            return Err(Error::msg(FROZEN));
        }
        let me = self.me();
        let signer = cbb_core::manage::Signer { ca: &s.ca, key: &*s.key, me: &me };
        let r = cbb_core::manage::order(&self.node.records().lock().unwrap(), &signer, &d.id, &o, uptime::wall_ms())?;
        let res = self
            .node
            .command(&r, Duration::from_secs(20))
            .map_err(|e| Error::msg(format!("{}: {}", d.name, e.message())))?;
        if res.status != "done" {
            return Err(Error::msg(format!("{} {} it: {}", d.name, res.status, res.reason)));
        }
        Ok(res)
    }

    /// Takes the group over from its lost root, on an admin of a group
    /// whose root is a computer, as Go's takeOver (docs/protocol.md,
    /// section 10): it makes a new root, keeps its key in the identity file
    /// first, and claims the group for it in a record its admin key signs.
    /// The claim takes effect after the group's delay unless the root
    /// cancels it (finish_takeover). It returns the root's name.
    pub fn take_over(&self, target: &str) -> Result<String> {
        if crate::rootless::is() {
            return Err(Error::msg(
                "this device is installed without root, so every program of its user can read its keys; such a device never holds the group's keys (D-79)",
            ));
        }
        let d = find_device(self.node, target)?;
        let ident = self.node.identity();
        let f = admin_file(self.dir)?;
        let root = self.root_device();
        let rooted_by_computer = self.node.devices().iter().any(|dev| dev.id == root && dev.role != "phone");
        let s = self.signing().ok();
        if s.as_ref().is_some_and(|s| s.root) {
            return Err(Error::msg("this device is the group's root already"));
        }
        let Some(s) = s else {
            return Err(Error::msg("only an admin takes the group over; this device is none"));
        };
        if !rooted_by_computer {
            return Err(Error::msg(
                "the group's root is a phone: an admin phone takes the group over, never a computer",
            ));
        }
        if d.id != root {
            return Err(Error::msg(format!("{} is not the group's root; cbb status shows which device is", d.name)));
        }
        if f.claim.is_some() {
            return Err(Error::msg(
                "this admin's claim to take the group over is waiting already; cbb status shows the time left",
            ));
        }
        if !s.ca.signed_by(ident.root()) {
            return Err(Error::msg(
                "this admin's CA is from a root before the current one, so a new root from it would split the group; the current root renews it when they next meet, so take the group over on an admin that met it since",
            ));
        }
        let me = self.me();
        let may = self
            .node
            .devices()
            .iter()
            .any(|dev| dev.id == me && dev.powers.iter().any(|p| p == authority::POWER_TAKEOVER));
        if !may {
            return Err(Error::msg(
                "the root did not give this admin the power to take the group over; take it over on another admin",
            ));
        }
        self.claim_with(s, &format!("from its root {} ({})", d.name, d.id))?;
        Ok(d.name)
    }

    /// Claims the group with its recovery key, on a computer of the group
    /// whose root is lost, as Go's recoverGroup: text is what the user
    /// typed or scanned from the sheet. The claim takes effect after the
    /// group's wait unless the root cancels it, and this computer is the
    /// root then (finish_takeover). The recovery key is not kept.
    pub fn recover(&self, text: &str) -> Result<()> {
        self.can_recover()?;
        let sheet = cbb_core::recovery::read(text).map_err(|r| Error::msg(r.message()))?;
        let (pkcs8, admin) =
            sheet.pkcs8().zip(sheet.admin()).ok_or_else(|| Error::msg("the recovery key cannot be encoded"))?;
        if sheet.group.as_deref().is_some_and(|g| g != self.node.identity().tag()) {
            return Err(Error::msg("this recovery key is of another group"));
        }
        let key: Arc<dyn ExternalKey> = Arc::new(FileKey::new(&pkcs8)?);
        let ca = self.recovery_ca(admin, sheet.cert.as_deref())?;
        if ca.public_key() != key.public().as_slice() {
            return Err(Error::msg("the recovery key's admin CA is for another key"));
        }
        self.claim_with(Signing { ca, key, root: false }, "with its recovery key")
    }

    /// Claims the group as recover does, with the recovery key on a
    /// YubiKey, which signs the claim through cbb-helper after pin and, as
    /// the root phone set it, a touch: the key never leaves the card.
    pub fn recover_with_card(&self, pin: &str) -> Result<()> {
        self.can_recover()?;
        let named = self.node.records().lock().unwrap().state().recovery.ok_or_else(|| Error::msg(NO_RECOVERY_KEY))?;
        let ca = self.recovery_ca(named.0, None)?;
        let key: Arc<dyn ExternalKey> = Arc::new(keys::CardKey::new(named.0, pin, ca.public_key().to_vec())?);
        self.claim_with(Signing { ca, key, root: false }, "with its recovery key on a YubiKey")
    }

    /// Why this device cannot claim the group with its recovery key, if it
    /// cannot.
    fn can_recover(&self) -> Result<()> {
        if crate::rootless::is() {
            return Err(Error::msg(
                "this device is installed without root, so every program of its user can read its keys; such a device never holds the group's keys (D-79)",
            ));
        }
        if self.signing().is_ok_and(|s| s.root) {
            return Err(Error::msg("this device is the group's root already"));
        }
        if admin_file(self.dir)?.claim.is_some() {
            return Err(Error::msg(
                "this device's claim to take the group over is waiting already; cbb status shows the time left",
            ));
        }
        Ok(())
    }

    /// The admin CA of the group's recovery key, whose key hash is admin:
    /// the sheet's when a root of the group issued it, else the newest a
    /// recovery record carries under such a root, else the sheet's.
    fn recovery_ca(&self, admin: [u8; 32], sheet: Option<&[u8]>) -> Result<Cert> {
        let records = self.node.records();
        let rs = records.lock().unwrap();
        match rs.state().recovery {
            None => return Err(Error::msg(NO_RECOVERY_KEY)),
            Some(h) if h.0 != admin => {
                return Err(Error::msg(
                    "this is not the group's recovery key: the root phone made a new one since, which replaced it",
                ));
            }
            Some(_) => {}
        }
        let roots = rs.roots();
        let under = |der: &[u8]| {
            Cert::parse(der).ok().filter(|c| c.key_hash() == admin && roots.iter().any(|r| c.signed_by(r)))
        };
        if let Some(c) = sheet.and_then(under) {
            return Ok(c);
        }
        let kept = rs
            .all()
            .iter()
            .filter_map(|r| Body::parse(&r.body).ok())
            .filter(|b| b.kind == authority::TYPE_RECOVERY && b.admin == Some(Hash(admin)))
            .filter_map(|b| under(&b.cert).map(|c| (b.time_ms, c)))
            .max_by_key(|(t, _)| *t)
            .map(|(_, c)| c);
        // Else the sheet's, as Go's: the members check the claim's chain.
        match (kept, sheet) {
            (Some(c), _) => Ok(c),
            (None, Some(der)) => Ok(Cert::parse(der)?),
            (None, None) => {
                Err(Error::msg("the group's records carry no admin CA for the recovery key from a root of the group"))
            }
        }
    }

    /// Makes a new root, keeps its key in the identity file first, and
    /// claims the group for it with s; how says how, for the log.
    fn claim_with(&self, s: Signing, how: &str) -> Result<()> {
        let ident = self.node.identity();
        let pkcs8 = identity::new_key()?;
        let key = FileKey::new(&pkcs8)?;
        let now = uptime::wall_ms() / 1000;
        let new_root = cbb_core::issue::root_ca(&key.public(), now, &mut |tbs| identity::sign_external(&key, tbs))?;
        // The identity file keeps the new root's key before the claim goes
        // out, so that the claim never takes effect for a key this device
        // lost.
        let mut fields = serde_json::Map::new();
        fields.insert("claim".into(), b64_value(&new_root));
        fields.insert("claim_key".into(), b64_value(&pkcs8));
        identity::save_with(&ident, self.dir, fields)?;
        let claimed = self.sign(&s, Body { kind: authority::TYPE_CLAIM.into(), root: new_root, ..Default::default() });
        if let Err(e) = claimed {
            let mut fields = serde_json::Map::new();
            fields.insert("claim".into(), serde_json::Value::Null);
            fields.insert("claim_key".into(), serde_json::Value::Null);
            let _ = identity::save_with(&ident, self.dir, fields);
            return Err(e);
        }
        self.node.logf(&format!(
            "cbb: claimed the group {how}; this device becomes the root when the waiting time ends, unless the root cancels the claim"
        ));
        Ok(())
    }

    /// The key level of the newest settings record of the root whose key
    /// hash is root, which a new one keeps.
    fn current_level(&self, root: &Hash) -> String {
        let all = self.node.records().lock().unwrap().all();
        all.iter()
            .filter_map(|r| Body::parse(&r.body).ok())
            .filter(|b| b.kind == authority::TYPE_SETTINGS && b.signer == *root)
            .max_by_key(|b| b.seq)
            .map(|b| b.key_level)
            .unwrap_or_default()
    }

    /// The takeover delay of the newest settings record of the root whose
    /// key hash is root, which a new one keeps.
    fn current_delay(&self, root: &Hash) -> Option<i64> {
        let all = self.node.records().lock().unwrap().all();
        all.iter()
            .filter_map(|r| Body::parse(&r.body).ok())
            .filter(|b| b.kind == authority::TYPE_SETTINGS && b.signer == *root)
            .max_by_key(|b| b.seq)
            .and_then(|b| b.takeover_delay_ms)
    }
}

/// How long the QR code's pairing may take, as Go's pair.Lifetime.
const PAIR_LIFETIME: Duration = Duration::from_secs(300);

impl Admin<'_> {
    /// This member as the admitting side of a pairing: the group's root,
    /// or an admin that is not frozen. With admins, on the root only, it
    /// makes a phone that offers an admin key an admin.
    pub fn admitter(&self, admins: bool) -> Result<admit::Admitter> {
        let s = self.signing().map_err(|_| Error::msg(NOT_ADMITTER))?;
        if admins && !s.root {
            return Err(Error::msg("only the group's root lets a phone join as an admin"));
        }
        if !s.root && self.node.records().lock().unwrap().frozen(&s.ca.key_hash()) {
            return Err(Error::msg(FROZEN));
        }
        Ok(admit::Admitter {
            identity: (*self.node.identity()).clone(),
            ca: s.ca.clone(),
            ca_key: s.key.clone(),
            make_admins: admins,
        })
    }

    /// Admits a device that shows a QR code and waits (docs/protocol.md,
    /// section 6, "The joiner listens"), as Go's pairDial: it dials the
    /// code's addresses on the home network in turn, runs the pairing in
    /// the core (cbb_core::admit), and records the device once its Welcome
    /// is out. With admins, on the root only, a phone that offers an admin
    /// key becomes an admin. It returns the device's name.
    pub fn admit_by_qr(&self, code: &str, addrs: &[String], fingerprint: &str, admins: bool) -> Result<String> {
        let code = cbb_core::pair::normalize_code(code)?;
        if fingerprint.is_empty() {
            return Err(Error::msg("the QR code names no certificate fingerprint"));
        }
        let admitter = self.admitter(admins)?;
        let end = Instant::now() + PAIR_LIFETIME;
        let mut tried = Vec::new();
        for addr in addrs {
            match self.admit_at(&admitter, &code, addr, fingerprint, end) {
                Ok(name) => return Ok(name),
                Err(e) => tried.push(format!("{addr}: {}", e.for_log())),
            }
        }
        Err(Error::msg(format!("could not admit the device that shows the QR code: {}", tried.join("; "))))
    }

    fn admit_at(
        &self,
        admitter: &admit::Admitter,
        code: &str,
        addr: &str,
        fingerprint: &str,
        end: Instant,
    ) -> Result<String> {
        let to: SocketAddr = addr.parse().map_err(|_| Error::msg("not an address and port"))?;
        if !crate::pair::home_address(to.ip()) {
            return Err(Error::msg("not on the home network"));
        }
        let mut sock = TcpStream::connect_timeout(&to, Duration::from_secs(10)).context("cannot connect")?;
        let view = admit::GroupView::of(&self.node.records().lock().unwrap());
        let mut adm = admit::Admission::dial(admitter.clone(), view, code, fingerprint, &crate::tls::clock())?;
        let mut name = String::new();
        let mut input: Vec<u8> = Vec::new();
        let mut buf = vec![0u8; 16 << 10];
        loop {
            let step = adm.feed(&input, uptime::wall_ms());
            if !step.send.is_empty() {
                sock.write_all(&step.send).context("cannot send to the device")?;
            }
            match step.outcome {
                admit::Outcome::Pending => {}
                admit::Outcome::Admitted(a) => {
                    // The device counts as admitted from here; its record
                    // goes to the group whatever it answers.
                    record_admitted(self.node, admitter, &a, "by its QR code")?;
                    name = a.info.name.clone();
                }
                admit::Outcome::Done { confirmed } => {
                    if !confirmed {
                        return Err(Error::msg(format!(
                            "{name} got its certificate but did not confirm that it stored it; check it with cbb status there, and pair it again if needed"
                        )));
                    }
                    return Ok(name);
                }
                admit::Outcome::Failed { error, wrong_code } => {
                    return Err(if wrong_code {
                        Error::with("the pairing failed", cbb_core::pair::Refusal::WrongCode)
                    } else {
                        error
                    });
                }
            }
            let left = end.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(Error::msg("the device did not finish pairing in time"));
            }
            sock.set_read_timeout(Some(left.min(Duration::from_secs(60)))).context("cannot read from the device")?;
            let n = sock.read(&mut buf).context("cannot read from the device")?;
            if n == 0 {
                return Err(Error::msg("the device closed the connection"));
            }
            input = buf[..n].to_vec();
        }
    }
}

/// Adds the device record of a device this member admitted, and sends it
/// to the group; how says how it joined, for the log.
pub fn record_admitted(node: &Node, admitter: &admit::Admitter, a: &admit::Admitted, how: &str) -> Result<()> {
    let r = admit::device_record(&node.records().lock().unwrap(), admitter, a, uptime::wall_ms())?;
    node.add_own_records(&[r]);
    if a.admin_ca.is_some() {
        node.logf(&format!("cbb: {} ({}) joined the group {how} as an admin phone", a.info.name, a.device));
    } else {
        node.logf(&format!("cbb: {} ({}) joined the group {how}", a.info.name, a.device));
    }
    Ok(())
}

/// Why this device may not be one of the group's hubs, if it may not, as
/// Go's away does: only the root or an admin, whose key the group's key
/// level still lets be a hub (it had the user's consent when it was made
/// one).
pub fn may_be_hub(dir: &Path, node: &Node) -> Result<()> {
    let ident = node.identity();
    if signer(dir, &ident)?.is_none() {
        return Err(Error::msg(
            "only the group's root or an admin can be its hub, since the members take the hub's offer from them only; make this device an admin first (cbb admin on the root)",
        ));
    }
    let store = if crate::rootless::is() {
        "rootless"
    } else if ident.external.is_some() {
        "hardware"
    } else {
        "file"
    };
    let level = node.records().lock().unwrap().state().key_level;
    level_allows(if level.is_empty() { "hardware" } else { &level }, store, "this device", "", true)
}

const NO_RECOVERY_KEY: &str = "the group has no recovery key: the root phone has not made one, or removed it";

const NOT_ADMITTER: &str = "this device is in a group already (cbb status lists it); only the group's root or an admin adds devices, and this device is neither";

/// Whether the group's key level lets a device whose key is in store be
/// its root, an admin or a hub, as Go's levelAllows; at the level files a
/// key in a file needs consent, which hint says how to give.
fn level_allows(level: &str, store: &str, name: &str, hint: &str, consent: bool) -> Result<()> {
    let msg = match () {
        _ if store == "rootless" => format!(
            "{name} is installed without root, so every program of its user can read its keys; such a device is never the group's root, an admin or a hub (D-79)"
        ),
        _ if level == "proven" && store != "proven" => format!(
            "attestation does not prove that {name} keeps its key in hardware, and the group's key level lets only such keys be its root, an admin or a hub; on the root, cbb keys hardware lets keys in hardware by the device's own word too"
        ),
        _ if store != "file" => return Ok(()),
        _ if level != "files" => format!(
            "{name} keeps its keys in a file, and the group's key level lets only keys in hardware be its root, an admin or a hub; on the root, cbb keys files lets keys in files too, each time after a warning"
        ),
        _ if !consent => format!(
            "{name} keeps its keys in a file, which a thief with it can copy and then act for it until another admin removes it; to allow it anyway, {hint}"
        ),
        _ => return Ok(()),
    };
    Err(Error::msg(msg))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn levels_as_go() {
        assert!(level_allows("hardware", "hardware", "a", "", false).is_ok());
        assert!(level_allows("hardware", "file", "a", "", true).is_err());
        assert!(level_allows("files", "file", "a", "h", false).unwrap_err().to_string().contains("h"));
        assert!(level_allows("files", "file", "a", "", true).is_ok());
        assert!(level_allows("proven", "hardware", "a", "", true).is_err());
        assert!(level_allows("files", "rootless", "a", "", true).is_err());
    }

    #[test]
    fn durations_as_go_prints_them() {
        for (ms, want) in
            [(0, "0s"), (500, "500ms"), (5000, "5s"), (1500, "1.5s"), (60_000, "1m0s"), (72 * 3_600_000, "72h0m0s")]
        {
            assert_eq!(go_duration(ms), want);
        }
    }

    #[test]
    fn a_group_made_here_keeps_its_root_key() {
        let dir = std::env::temp_dir().join(format!("cbb-admin-new-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (ident, _) = new_group(&dir, "desk").unwrap();
        let again = Identity::load(&dir).unwrap().unwrap();
        assert_eq!(again.id, ident.id);
        let s = signer(&dir, &again).unwrap().expect("the root's key");
        assert!(s.root);
        assert_eq!(s.ca, again.group_ca);
        assert_eq!(s.key.public(), again.group_ca.public_key());
        // Saving the identity again, as a renewal does, keeps the root key.
        again.save(&dir).unwrap();
        assert!(signer(&dir, &again).unwrap().is_some());
        let rs = records::Records::load(&dir, &again.group_ca).unwrap();
        let st = rs.state();
        assert_eq!(st.root_device, ident.id.as_str());
        assert_eq!(st.key_level, "files");
        let me = rs.devices().into_iter().find(|d| d.id == ident.id.as_str()).unwrap();
        assert_eq!((me.role.as_str(), me.name.as_str(), me.store.as_str()), ("full", "desk", "file"));
        assert!(new_group(&dir, "desk").err().expect("a second group").to_string().contains("already in a group"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
