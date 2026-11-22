// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The forwarders of the group's hubs, as the root knows them: those its
//! hub commands named (field 11, each address with the pin the root signs)
//! and its own hub's. Each gets a face of its own (A-55), as the group's
//! relays do, so that a hub registers with a forwarder of its own under the
//! hubs' credential of that face (D-121). They are kept in
//! `hub-forwarders.json` beside the set; a hub that the records no longer
//! allow goes with its forwarders.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use base64::Engine as _;
use cbb_core::records::eval::State;
use cbb_core::records::key::DeviceId;

use super::Server;
use crate::error::Result;

/// The file beside the set.
pub const FILE: &str = "hub-forwarders.json";
/// The most forwarders one hub has (as a hub command names, format 6).
const MAX_EACH: usize = 8;

/// The forwarders of the hubs, by hub.
pub struct HubForwarders {
    path: PathBuf,
    by_hub: Mutex<BTreeMap<DeviceId, Vec<Server>>>,
}

impl HubForwarders {
    /// Opens the forwarders kept in dir; none when the file is missing or
    /// damaged (the root names them again with its next hub command).
    pub fn open(dir: &Path) -> HubForwarders {
        let path = dir.join(FILE);
        let by_hub = std::fs::read(&path).ok().and_then(|b| read(&b)).unwrap_or_default();
        HubForwarders { path, by_hub: Mutex::new(by_hub) }
    }

    /// Notes the forwarders of hub, in place of those it had; none forgets
    /// it. True when that changed them.
    pub fn set(&self, hub: DeviceId, servers: Vec<Server>) -> Result<bool> {
        let mut by_hub = self.by_hub.lock().unwrap();
        let servers: Vec<Server> = servers.into_iter().take(MAX_EACH).collect();
        let changed = if servers.is_empty() {
            by_hub.remove(&hub).is_some()
        } else {
            by_hub.insert(hub, servers.clone()) != Some(servers)
        };
        if changed {
            crate::files::write_atomic(&self.path, &write(&by_hub), 0o600)?;
        }
        Ok(changed)
    }

    /// The forwarders of the hubs that the records allow, each once.
    pub fn servers(&self, state: &State) -> Vec<Server> {
        let mut out: Vec<Server> = Vec::new();
        for (hub, servers) in self.by_hub.lock().unwrap().iter() {
            if !state.may_be_hub(hub) {
                continue;
            }
            for s in servers {
                if !out.contains(s) {
                    out.push(s.clone());
                }
            }
        }
        out
    }
}

fn write(by_hub: &BTreeMap<DeviceId, Vec<Server>>) -> Vec<u8> {
    let b64 = base64::engine::general_purpose::STANDARD;
    let v: serde_json::Map<String, serde_json::Value> = by_hub
        .iter()
        .map(|(hub, servers)| {
            let list = servers.iter().map(|s| serde_json::json!([s.address, b64.encode(s.pin)])).collect();
            (cbb_core::certs::hex(&hub.0), serde_json::Value::Array(list))
        })
        .collect();
    serde_json::to_vec_pretty(&v).unwrap_or_default()
}

fn read(b: &[u8]) -> Option<BTreeMap<DeviceId, Vec<Server>>> {
    let b64 = base64::engine::general_purpose::STANDARD;
    let v: serde_json::Map<String, serde_json::Value> = serde_json::from_slice(b).ok()?;
    let mut out = BTreeMap::new();
    for (hub, list) in v {
        let id = crate::live::id_of_hex(&hub)?;
        let mut servers = Vec::new();
        for s in list.as_array()?.iter().take(MAX_EACH) {
            let address = s.get(0)?.as_str()?.to_string();
            let pin: [u8; 32] = b64.decode(s.get(1)?.as_str()?).ok()?.try_into().ok()?;
            servers.push(Server { pin, address });
        }
        out.insert(id, servers);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_hubs_forwarders_are_kept_and_read_back() {
        let dir = std::env::temp_dir().join(format!("cbb-hubfwd-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let f = HubForwarders::open(&dir);
        let hub = DeviceId([7; 16]);
        let s = Server { pin: [1; 32], address: "192.0.2.1:8764".into() };
        assert!(f.set(hub, vec![s.clone()]).unwrap());
        assert!(!f.set(hub, vec![s.clone()]).unwrap(), "the same again changes nothing");
        let again = HubForwarders::open(&dir);
        assert_eq!(again.by_hub.lock().unwrap().get(&hub), Some(&vec![s]));
        assert!(again.set(hub, Vec::new()).unwrap());
        assert!(HubForwarders::open(&dir).by_hub.lock().unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
