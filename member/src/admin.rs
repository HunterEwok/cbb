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

use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::sync::Arc;
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
        let s = self.signing().map_err(|_| Error::msg(NOT_ADMITTER))?;
        if admins && !s.root {
            return Err(Error::msg("only the group's root lets a phone join as an admin"));
        }
        if !s.root && self.node.records().lock().unwrap().frozen(&s.ca.key_hash()) {
            return Err(Error::msg(FROZEN));
        }
        let admitter = admit::Admitter {
            identity: (*self.node.identity()).clone(),
            ca: s.ca.clone(),
            ca_key: s.key.clone(),
            make_admins: admins,
        };
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
                    let r =
                        admit::device_record(&self.node.records().lock().unwrap(), admitter, &a, uptime::wall_ms())?;
                    self.node.add_own_records(&[r]);
                    name = a.info.name.clone();
                    self.node.logf(&format!("cbb: admitted {} ({}) by its QR code", a.info.name, a.device));
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
