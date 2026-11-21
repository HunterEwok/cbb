// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The hub order (docs/protocol.md, section 11, "Several hubs"): the
//! root's hubs record first, in its order, then the computers with an admin
//! key, then the phones, the root's own device first in each part, then by
//! device ID; frozen devices and devices that may not be hubs left out.

use crate::format::{DeviceId, KeyHash};
use crate::records::body::{ROLE_MEMBER, ROLE_PHONE};
use crate::records::eval::{DeviceState, State};

fn device(n: u8, role: u64, admin: bool) -> DeviceState {
    let k = crate::records::Key::es256(vec![n; 65]);
    DeviceState {
        id: DeviceId([n; 16]),
        key: k,
        name: format!("d{n}"),
        role,
        rights: 3,
        skip: 0,
        caps: 0,
        os: 1,
        store: 1,
        proof: 0,
        admin: admin.then_some(KeyHash([n; 32])),
        powers: 0,
        commands: 0,
        frozen: false,
        replaces: None,
        guarded: false,
        by_root: true,
    }
}

#[test]
fn the_hub_order() {
    let id = |n: u8| DeviceId([n; 16]);
    let mut st = State {
        devices: vec![
            device(1, ROLE_PHONE, true),
            device(2, ROLE_MEMBER, true),
            device(3, ROLE_MEMBER, false),
            device(4, ROLE_MEMBER, true),
            device(5, ROLE_PHONE, true),
            device(6, ROLE_MEMBER, false),
            device(7, ROLE_MEMBER, true),
            device(8, ROLE_PHONE, false),
        ],
        root_device: Some(id(5)),
        ..State::default()
    };
    // No hubs record: the admin computers, then the admin phones, the
    // root's device first in its part; devices without an admin key are
    // no hubs.
    assert_eq!(st.hub_order(), vec![id(2), id(4), id(7), id(5), id(1)]);
    // The hubs record comes first, in its order, a computer without an
    // admin key among them; a device it names that is not in the group is
    // left out, and nobody comes twice.
    st.hubs = vec![id(6), id(7), id(9)];
    assert_eq!(st.hub_order(), vec![id(6), id(7), id(2), id(4), id(5), id(1)]);
    assert!(st.may_be_hub(&id(6)) && !st.may_be_hub(&id(3)) && !st.may_be_hub(&id(9)));
    // A frozen device is no hub, wherever it was.
    st.devices[5].frozen = true;
    st.devices[3].frozen = true;
    assert_eq!(st.hub_order(), vec![id(7), id(2), id(5), id(1)]);
    assert!(!st.may_be_hub(&id(6)));
}
