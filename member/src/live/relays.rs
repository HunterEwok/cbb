// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The group's relays, which the root names in the group's settings
//! (docs/protocol.md, section 14): the same in a build without the
//! tunnel, which writes the setting but meets at no relay itself.

use std::net::SocketAddr;

use cbb_core::records::body::SERVER_RELAY;

use super::Live;

impl Live {
    /// The root sets the group's relays (`cbb global relay`, and an app on
    /// a root phone): given is each relay's address and its key's pin in
    /// base64, or the one pair (`default`) for the project's relay by
    /// name; none meets at no relay. signer is the root key outside the
    /// member (a phone's), or None for the member's own. Gives the relays
    /// written into the group's settings.
    pub fn set_relays(
        &self,
        signer: Option<&dyn cbb_core::identity::ExternalKey>,
        given: &[(String, String)],
    ) -> crate::error::Result<Vec<cbb_core::records::body::Server>> {
        use crate::error::Error;
        use cbb_core::records::body::Server;
        let st = self.mesh.state();
        let root_key = match signer {
            Some(k) => Some(k.public()),
            None => self.mesh.own().root.as_ref().map(|k| k.public()),
        };
        let root = root_key.is_some_and(|k| st.roots.last() == Some(&cbb_core::records::Key::es256(k).hash()));
        // An admin too: on 0.6 only the root sets it (the owner,
        // 2026-11-21); an admin asking the root comes with a command of
        // its own in 0.7.
        if !root {
            return Err(Error::msg("only the group's root sets the group's relay: run cbb global relay on the root"));
        }
        let mut relays: Vec<Server> = Vec::new();
        for (addr, key) in given {
            if key == "default" {
                if given.len() > 1 {
                    return Err(Error::msg("the project's relay goes alone: cbb global relay default"));
                }
                // The project's relay, by name, with the pin of its key the
                // newest keys.json gives (else the one built in): the
                // root's consent is in the group's settings.
                let now = crate::uptime::wall_ms();
                let pin = crate::faces::project_servers(self.mesh.entries().as_deref(), now)
                    .into_iter()
                    .find(|s| s.address == crate::faces::PROJECT_RELAY)
                    .map(|s| s.pin)
                    .ok_or_else(|| Error::msg("this build knows no key of the project's relay"))?;
                relays.push(Server { kind: SERVER_RELAY, endpoint: crate::faces::PROJECT_RELAY.to_string(), pin });
                break;
            }
            let endpoint = match addr.parse::<SocketAddr>() {
                Ok(ep) if ep.port() != 0 => ep.to_string(),
                _ => {
                    return Err(Error::msg(format!(
                        "{addr:?} is not the relay's address with a port, such as 203.0.113.9:8764"
                    )));
                }
            };
            let pin = cbb_core::certs::b64::decode_str(key)
                .filter(|b| cbb_core::certs::b64::encode(b) == *key)
                .and_then(|b| <[u8; 32]>::try_from(b).ok())
                .ok_or_else(|| {
                    Error::msg(format!("{key:?} is not a relay's key; cbb relay prints it, 44 characters of base64"))
                })?;
            if relays.iter().any(|r| r.endpoint == endpoint) {
                return Err(Error::msg(format!("the relay {endpoint} is given twice")));
            }
            relays.push(Server { kind: SERVER_RELAY, endpoint, pin });
        }
        let others = st.settings.servers.iter().filter(|v| v.kind != SERVER_RELAY).count();
        if relays.len() + others > cbb_core::records::body::MAX_SERVERS {
            return Err(Error::msg(format!(
                "a group names at most {} servers in its settings",
                cbb_core::records::body::MAX_SERVERS
            )));
        }
        let now = crate::uptime::wall_ms().max(0) as u64;
        let write = |set: &mut cbb_core::records::RecordSet, k: &dyn cbb_core::identity::ExternalKey| {
            crate::writers::set_settings(
                set,
                k,
                |s| {
                    s.servers.retain(|v| v.kind != SERVER_RELAY);
                    s.servers.extend(relays.iter().cloned());
                },
                now,
            )
        };
        match signer {
            Some(k) => self.mesh.write_by(k, write)?,
            None => self.mesh.write(write)?,
        };
        Ok(relays)
    }
}
