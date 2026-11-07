// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The member as a phone's app runs it in its own process (the Aurora app,
//! through lite/ffi): the same node as the service, with the device key
//! where the app keeps it, no control socket and no listening port. A
//! phone dials the members it finds (docs/protocol.md, section 3).

use std::path::PathBuf;
use std::sync::Arc;

use cbb_core::clip::{Engine, Kind, Via};
use cbb_core::identity::Identity;
use cbb_core::wire::DeviceInfo;

use crate::error::Result;
use crate::node::{KeepIdentity, Node, Peer, Presence, WriteReq};
use crate::records::{Records, Stored as _};
use crate::{discovery, service, uptime};

/// What the phone's member starts from.
pub struct Config {
    /// The app's identity in the group, its key external.
    pub identity: Identity,
    /// The name the other members show.
    pub name: String,
    /// The phone's system (`aurora`, `sailfish`), its version and the app's.
    pub os: String,
    pub os_version: String,
    pub version: String,
    /// Where the phone's key lives, as its hello says: `hardware` (a TEE)
    /// or `file`.
    pub key_store: String,
    /// Where the records, the clock's mark and the entries are kept.
    pub state_dir: PathBuf,
    /// Members to dial at these addresses besides those mDNS finds.
    pub peers: Vec<std::net::SocketAddr>,
    /// Whether to find the members by mDNS.
    pub mdns: bool,
    /// The secret for sealed messages (docs/protocol.md, section 4).
    pub seal_secret: Vec<u8>,
    /// Gets each text to put into the phone's clipboard.
    pub on_write: Box<dyn Fn(WriteReq) + Send + Sync>,
    /// Keeps the identity when it changes: a certificate an admin renewed,
    /// the root a takeover made. The app keeps it in its own file.
    pub keep_identity: KeepIdentity,
    pub log: Arc<dyn Fn(&str) + Send + Sync>,
}

/// A running member of a phone's app.
pub struct Member {
    node: Arc<Node>,
}

impl Member {
    /// Starts the member: it loads the records and dials the members at the
    /// given addresses and those mDNS finds.
    pub fn start(cfg: Config) -> Result<Member> {
        let log = cfg.log;
        crate::sealkey::set(cfg.seal_secret)?;
        let records = Records::load(&cfg.state_dir, &cfg.identity.group_ca)?;
        // The roots the records lead to, as the service takes them; the app
        // keeps its identity itself.
        let mut ident = cfg.identity;
        if !records.is_empty() {
            ident.roots = records.roots();
        }
        log(&format!("cbb: device {} in group {}", ident.id, ident.tag()));
        let engine = Arc::new(Engine::new(
            ident.id.as_str(),
            service::clock(&cfg.state_dir),
            Box::new(uptime::wall_ms),
            Box::new(uptime::now),
        ));
        let tag = ident.tag();
        let device =
            DeviceInfo { form: "phone".into(), os_version: cfg.os_version, version: cfg.version, mac: String::new() }
                .cleaned();
        let node = Node::new(ident, &cfg.name, engine.clone(), records, cfg.state_dir, cfg.on_write, log.clone())
            .presenting(Presence { role: "phone".into(), name: cfg.name, os: cfg.os, key_store: cfg.key_store, device })
            .keeping_identity(cfg.keep_identity);
        let node = Arc::new(node);
        engine.set_seal(node.sealer());
        discovery::start(node.clone(), tag.clone(), cfg.peers, false, None, log.clone());
        if cfg.mdns {
            discovery::start_as_phone(node.clone(), tag, log);
        }
        Ok(Member { node })
    }

    /// Sends a text the user copied on the phone and handed to the app.
    pub fn copy(&self, text: &str, secret: bool) -> Result<()> {
        self.node.send(text, if secret { Kind::Secret } else { Kind::Text }, Via::Phone)
    }

    /// The members connected now.
    pub fn peers(&self) -> Vec<Peer> {
        self.node.peers()
    }

    /// Stops the member and closes its connections.
    pub fn stop(&self) {
        self.node.close();
    }
}

impl Drop for Member {
    fn drop(&mut self) {
        self.node.close();
    }
}
