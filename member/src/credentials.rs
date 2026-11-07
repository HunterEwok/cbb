// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The group's server credentials on the service (docs/protocol.md, section
//! 18), as Go's service keeps them: the member keeps the group's
//! credentials (cbb_core::credential::Store) in credentials.json, takes
//! those its peers send and passes the new ones on, and brings them up to
//! date as far as it can: on the root a new period when the one kept is due
//! or a member that sent its server key left the group, on every member its
//! server key for the period, on the root the hubs' and the members'
//! credentials when they list other keys than the records say, and on an
//! admin that the hubs' credential lists, the members' credential. Its keys
//! for the servers, a server key for the period and on the root the period
//! key, are in server-keys.json, in the TPM or the Secure Enclave where
//! cbb-helper can put them there, as Go's ServerKeys.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use cbb_core::certs::{Cert, KeyHash};
use cbb_core::credential::{self, Credential, Store};
use serde::{Deserialize, Serialize};

use crate::certs::{self, b64};
use crate::error::{Context, Error, Result};
use crate::identity::{ExternalKey, FileKey, HeldKey};
use crate::node::Node;
use crate::{files, uptime, wire};

/// The files next to the identity, as Go's.
pub const FILE: &str = "credentials.json";
pub const KEYS_FILE: &str = "server-keys.json";

/// The kinds of keys for the servers: the device's for a period, and the
/// period key on the root that started the period.
const SERVER_KEY: &str = "server";
const PERIOD_KEY: &str = "period";

/// A key for the servers as the file keeps it: PKCS #8, or the hardware's
/// blob.
#[derive(Serialize, Deserialize, Clone, Default)]
struct SavedKey {
    #[serde(with = "b64::opt", default, skip_serializing_if = "Option::is_none")]
    key: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tpm: Option<serde_json::Value>,
    #[serde(with = "b64::opt", default, skip_serializing_if = "Option::is_none")]
    se: Option<Vec<u8>>,
}

impl SavedKey {
    fn open(&self) -> Result<Arc<dyn ExternalKey>> {
        match (&self.key, &self.tpm, &self.se) {
            (Some(k), None, None) => Ok(Arc::new(FileKey::new(k)?)),
            (None, Some(b), None) => crate::keys::open(&HeldKey::Tpm(b.clone())),
            (None, None, Some(b)) => crate::keys::open(&HeldKey::SecureEnclave(b.clone())),
            _ => Err(Error::msg("a key for the servers is kept in no place, or in more than one")),
        }
    }
}

/// The device's keys for the servers, by kind and period tag.
struct ServerKeys {
    file: PathBuf,
    keys: BTreeMap<String, (Arc<dyn ExternalKey>, SavedKey)>,
}

impl ServerKeys {
    fn load(dir: &Path) -> Result<ServerKeys> {
        let file = dir.join(KEYS_FILE);
        let mut keys = BTreeMap::new();
        match std::fs::read(&file) {
            Ok(data) => {
                let saved: BTreeMap<String, SavedKey> =
                    serde_json::from_slice(&data).context(format!("{} does not decode", file.display()))?;
                for (name, s) in saved {
                    let k = s.open().map_err(|e| e.context(format!("{}", file.display())))?;
                    keys.insert(name, (k, s));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(Error::with(format!("cannot read {}", file.display()), e)),
        }
        Ok(ServerKeys { file, keys })
    }

    fn has(&self, kind: &str, tag: &str) -> bool {
        self.keys.contains_key(&format!("{kind} {tag}"))
    }

    /// The key of kind for the period of tag, made and saved when there is
    /// none.
    fn get(&mut self, kind: &str, tag: &str) -> Result<Arc<dyn ExternalKey>> {
        let name = format!("{kind} {tag}");
        if let Some((k, _)) = self.keys.get(&name) {
            return Ok(k.clone());
        }
        let (k, saved) = match crate::keys::new_device_key() {
            (Some(k), _) => {
                let saved = match k.held() {
                    Some(HeldKey::Tpm(b)) => SavedKey { tpm: Some(b), ..SavedKey::default() },
                    Some(HeldKey::SecureEnclave(b)) => SavedKey { se: Some(b), ..SavedKey::default() },
                    None => return Err(Error::msg("the hardware gave a key it does not keep")),
                };
                (k, saved)
            }
            (None, _) => {
                let pkcs8 = crate::identity::new_key()?;
                let k: Arc<dyn ExternalKey> = Arc::new(FileKey::new(&pkcs8)?);
                (k, SavedKey { key: Some(pkcs8), ..SavedKey::default() })
            }
        };
        self.keys.insert(name.clone(), (k.clone(), saved));
        if let Err(e) = self.save() {
            self.keys.remove(&name);
            return Err(e);
        }
        Ok(k)
    }

    /// Drops the keys of every period but tag's.
    fn keep(&mut self, tag: &str) -> Result<()> {
        let n = self.keys.len();
        self.keys.retain(|name, _| *name == format!("{SERVER_KEY} {tag}") || *name == format!("{PERIOD_KEY} {tag}"));
        if self.keys.len() == n { Ok(()) } else { self.save() }
    }

    fn save(&self) -> Result<()> {
        let saved: BTreeMap<&String, &SavedKey> = self.keys.iter().map(|(n, (_, s))| (n, s)).collect();
        let mut data = serde_json::to_vec_pretty(&saved).context("cannot encode the keys for the servers")?;
        data.push(b'\n');
        files::write_atomic(&self.file, &data, 0o600)
    }
}

/// The SubjectPublicKeyInfo of a key.
fn spki(k: &dyn ExternalKey) -> Vec<u8> {
    certs::p256_spki_of(&k.public())
}

/// Signs data with k, as the credentials need.
fn signer(k: &Arc<dyn ExternalKey>) -> impl FnMut(&[u8]) -> Result<Vec<u8>> + '_ {
    move |data| crate::identity::sign_external(&**k, data)
}

/// The group's credentials on this member.
pub struct Credentials {
    dir: PathBuf,
    group_ca: Cert,
    store: Mutex<Store>,
    keys: Mutex<ServerKeys>,
    /// Held while the credentials are brought up to date.
    refreshing: Mutex<()>,
    /// Counts the changes, so that a relay link registers again.
    changes: AtomicU64,
    log: Arc<dyn Fn(&str) + Send + Sync>,
}

/// The current root's SubjectPublicKeyInfo: the last of the records'
/// roots, else the group CA's.
fn root_of(node: &Node, group_ca: &Cert) -> Vec<u8> {
    node.records().lock().unwrap().roots().last().map_or_else(|| group_ca.spki.clone(), |c| c.spki.clone())
}

/// Whether k is the member key of a device in the group that is not
/// frozen, as Go's Records.IsMember.
fn member_test(node: &Node) -> impl Fn(&KeyHash) -> bool {
    let devs = node.records().lock().unwrap().devices();
    move |k| devs.iter().any(|d| !d.frozen && d.keys.contains(k))
}

impl Credentials {
    /// Reads the credentials and the keys for the servers kept in dir; a
    /// credentials file that cannot be read leaves the set empty, since the
    /// peers give them again, and a keys file that cannot be read gives new
    /// keys, which only means new pseudonyms at the servers.
    pub fn load(dir: &Path, node: &Node, log: Arc<dyn Fn(&str) + Send + Sync>) -> Arc<Credentials> {
        let group_ca = node.identity().group_ca.clone();
        let mut store = Store::new(&certs::tag(&group_ca));
        match std::fs::read(dir.join(FILE)) {
            Ok(data) => match serde_json::from_slice::<Vec<Credential>>(&data) {
                Ok(all) => {
                    store.add(&root_of(node, &group_ca), &member_test(node), &all);
                }
                Err(e) => log(&format!("cbb: reading the server credentials: {FILE}: {e}")),
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => log(&format!("cbb: reading the server credentials: {e}")),
        }
        let keys = ServerKeys::load(dir).unwrap_or_else(|e| {
            log(&format!("cbb: reading the keys for the servers: {}; making new ones", e.for_log()));
            ServerKeys { file: dir.join(KEYS_FILE), keys: BTreeMap::new() }
        });
        Arc::new(Credentials {
            dir: dir.to_path_buf(),
            group_ca,
            store: Mutex::new(store),
            keys: Mutex::new(keys),
            refreshing: Mutex::new(()),
            changes: AtomicU64::new(0),
            log,
        })
    }

    /// The credentials message a peer gets after its hello; None while
    /// there are none.
    pub fn message(&self) -> Option<wire::Message> {
        let all = self.store.lock().unwrap().all();
        if all.is_empty() {
            return None;
        }
        serde_json::to_value(all).ok().map(|v| wire::credentials(&v))
    }

    /// How many times the credentials changed.
    pub fn changes(&self) -> u64 {
        self.changes.load(Ordering::SeqCst)
    }

    /// Takes the valid credentials among those a peer sent (from, empty for
    /// this member's own), saves them, and returns those that were new.
    pub fn add(&self, node: &Node, from: &str, cs: &[Credential]) -> Vec<Credential> {
        if cs.is_empty() || cs.len() > credential::MAX_CREDENTIALS {
            return Vec::new();
        }
        let (root, member) = (root_of(node, &self.group_ca), member_test(node));
        let mut store = self.store.lock().unwrap();
        let (fresh, errs) = store.add(&root, &member, cs);
        let from = if from.is_empty() { "this device" } else { from };
        for e in errs {
            (self.log)(&format!("cbb: dropped a server credential from {from}: {}", e.for_log()));
        }
        if !fresh.is_empty() {
            if let Err(e) = self.save(&store) {
                (self.log)(&format!("cbb: saving the server credentials: {}", e.for_log()));
            }
            self.changes.fetch_add(1, Ordering::SeqCst);
        }
        fresh
    }

    fn save(&self, store: &Store) -> Result<()> {
        let mut data = serde_json::to_vec_pretty(&store.all()).context("cannot encode the server credentials")?;
        data.push(b'\n');
        files::write_atomic(&self.dir.join(FILE), &data, 0o600)
    }

    /// Takes the credentials message a peer sent and passes the new ones
    /// on to the other peers; new ones may want this member's server key or
    /// new lists, so it brings them up to date.
    pub fn received(&self, node: &Node, from: &crate::certs::DeviceId, v: &serde_json::Value) {
        let Ok(cs) = serde_json::from_value::<Vec<Credential>>(v.clone()) else { return };
        let fresh = self.add(node, from.as_str(), &cs);
        if fresh.is_empty() {
            return;
        }
        if let Ok(v) = serde_json::to_value(&fresh) {
            node.broadcast(&wire::credentials(&v), |p| p.id != *from);
        }
        self.refresh(node);
    }

    /// Brings the credentials up to date as far as this member can, as
    /// Go's refreshCredential (the module's comment), and sends what it
    /// signed to the peers.
    pub fn refresh(&self, node: &Node) {
        let _busy = self.refreshing.lock().unwrap();
        let mut signed = Vec::new();
        if let Err(e) = self.refresh_with(node, &mut signed) {
            (self.log)(&format!("cbb: the server credentials: {}", e.for_log()));
        }
        if !signed.is_empty()
            && let Ok(v) = serde_json::to_value(&signed)
        {
            node.broadcast(&wire::credentials(&v), |_| true);
        }
    }

    fn refresh_with(&self, node: &Node, signed: &mut Vec<Credential>) -> Result<()> {
        let mut add = |c: Credential| signed.extend(self.add(node, "", &[c]));
        let now = uptime::wall_ms();
        let ident = node.identity();
        let root = root_of(node, &self.group_ca);
        let member = member_test(node);

        // The period, on the root.
        let root_key = crate::admin::signer(&self.dir, &ident)?.filter(|s| s.root && s.ca.spki == root).map(|s| s.key);
        if let Some(rk) = &root_key
            && self.store.lock().unwrap().period_stale(&root, &member, now)
        {
            let tag = credential::new_period_tag()?;
            let pk = self.keys.lock().unwrap().get(PERIOD_KEY, &tag).map_err(|e| e.context("making the period key"))?;
            let prev = self.store.lock().unwrap().period(&root).map_or(0, |(_, p)| p.version);
            let body = credential::period_body(
                &certs::tag(&self.group_ca),
                &tag,
                &spki(&*pk),
                credential::next_version(prev, now),
                now,
            );
            add(credential::sign(body, &root, &mut signer(rk)).map_err(|e| e.context("signing the period"))?);
        }
        let Some((_, p)) = self.store.lock().unwrap().period(&root) else { return Ok(()) };
        self.keys.lock().unwrap().keep(&p.tag).map_err(|e| e.context("dropping the keys of the period before"))?;

        // This device's server key for the period.
        let sk = self
            .keys
            .lock()
            .unwrap()
            .get(SERVER_KEY, &p.tag)
            .map_err(|e| e.context("making the key for the servers"))?;
        let mine = certs::sha256(&spki(&*sk));
        if self.store.lock().unwrap().server(&ident.cert.key_hash()) != Some(mine) {
            let mk: Arc<dyn ExternalKey> = match &ident.external {
                Some(k) => k.clone(),
                None => Arc::new(FileKey::new(&ident.key)?),
            };
            let body = credential::server_body(&p, &spki(&*sk), credential::next_version(0, now));
            add(credential::sign(body, &ident.cert.spki, &mut signer(&mk))
                .map_err(|e| e.context("signing the server key"))?);
        }

        let l = credential::lists(&node.records().lock().unwrap());
        let (hubs, admins, members) = {
            let st = self.store.lock().unwrap();
            (st.server_keys(&l.hubs), st.server_keys(&l.admins), st.server_keys(&l.members))
        };
        let listed = self.store.lock().unwrap().hubs();
        let period_key = root_key.is_some() && self.keys.lock().unwrap().has(PERIOD_KEY, &p.tag);
        let signing = if period_key {
            let pk = self.keys.lock().unwrap().get(PERIOD_KEY, &p.tag)?;
            let stale = listed.as_ref().is_none_or(|(_, hb)| {
                let st = self.store.lock().unwrap();
                st.list_stale(&hb.hubs, &hubs, true) || st.list_stale(&hb.admins, &admins, false)
            });
            if stale {
                let prev = listed.as_ref().map_or(0, |(_, hb)| hb.version);
                let body = credential::hubs_body(&p, &hubs, &admins, credential::next_version(prev, now))?;
                add(credential::sign(body, &spki(&*pk), &mut signer(&pk))
                    .map_err(|e| e.context("signing the hubs' credential"))?);
            }
            pk
        } else if listed.as_ref().is_some_and(|(_, hb)| hb.admins.contains(&mine)) {
            sk
        } else {
            return Ok(());
        };
        let cur = self.store.lock().unwrap().members();
        if cur.as_ref().is_none_or(|(_, mb)| self.store.lock().unwrap().list_stale(&mb.members, &members, false)) {
            let prev = cur.as_ref().map_or(0, |(_, mb)| mb.version);
            let body = credential::members_body(&p, &members, credential::next_version(prev, now))?;
            add(credential::sign(body, &spki(&*signing), &mut signer(&signing))
                .map_err(|e| e.context("signing the members' credential"))?);
        }
        Ok(())
    }

    #[cfg(feature = "tunnel")]
    /// What this device registers with on its relay when the period's
    /// members' credential lists its server key (docs/protocol.md, section
    /// 18), as Go's relayCredentials; None otherwise, and it registers with
    /// its member certificate and the records.
    pub fn relay(&self, node: &Node) -> Option<crate::relay::Credentialed> {
        let now = uptime::wall_ms();
        let root = root_of(node, &self.group_ca);
        let st = self.store.lock().unwrap().clone();
        let (pc, p) = st.period(&root)?;
        if now >= p.expires_ms || !self.keys.lock().unwrap().has(SERVER_KEY, &p.tag) {
            return None;
        }
        let sk = self.keys.lock().unwrap().get(SERVER_KEY, &p.tag).ok()?;
        let (hc, _) = st.hubs()?;
        let (mc, mb) = st.members()?;
        if !mb.members.contains(&certs::sha256(&spki(&*sk))) {
            return None;
        }
        let rs = node.records();
        let rs = rs.lock().unwrap();
        let mut roots = vec![self.group_ca.der.clone()];
        roots.extend(rs.roots().into_iter().map(|c| c.der));
        let devs = rs.devices();
        drop(rs);
        let me = node.identity().id.clone();
        let names: std::collections::HashMap<String, String> = st
            .servers()
            .into_iter()
            .filter_map(|(m, k)| {
                let d = devs.iter().find(|d| !d.frozen && d.keys.contains(&m))?;
                (d.id != me.as_str()).then(|| (credential::pseudonym(&k), d.id.clone()))
            })
            .collect();
        match crate::relay::Credentialed::new(sk, vec![hc, mc, pc], roots, names, now) {
            Ok(c) => Some(c),
            Err(e) => {
                (self.log)(&format!("cbb: the credentials for the relay: {}", e.for_log()));
                None
            }
        }
    }
}
