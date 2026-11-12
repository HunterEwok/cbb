// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

use super::*;

fn ex(n: u64) -> Psk {
    let mut b = [0u8; 32];
    b[..8].copy_from_slice(&n.to_be_bytes());
    psk(&b, true).unwrap()
}

/// The device tries its keys in order against what the hub accepts; the
/// first that fits is the handshake.
fn handshake(d: &mut DeviceSide, h: &mut HubSide) -> Option<[u8; 32]> {
    let ok = d.to_try().into_iter().find(|k| h.accepts().contains(k))?;
    h.handshake(&ok);
    d.handshake(&ok);
    Some(ok)
}

/// One direct connection: the device sends `tunnel`, the hub confirms.
fn connect(d: &mut DeviceSide, h: &mut HubSide, n: u64) {
    let p = ex(n);
    let tag = d.connected(p);
    let back = h.tunnel(p, &tag).expect("the hub takes its own connection's tag");
    assert!(d.confirmed(&back));
}

#[test]
fn one_key_per_hub() {
    let secret = [7u8; 32];
    let (a, b) = (DeviceId([1; 16]), DeviceId([2; 16]));
    assert_eq!(key_for(&secret, &a), key_for(&secret, &a), "stable for a hub");
    assert_ne!(key_for(&secret, &a).1, key_for(&secret, &b).1, "another for another hub");
    assert_ne!(key_for(&secret, &a).1, key_for(&[8; 32], &a).1, "another device, another key");
    let (k, c) = (key_for(&secret, &a).1, ex(1).confirm);
    assert_eq!(read(&message(&k, &c)), Ok((k, c)));
    assert!(read(&message(&[0; 32], &c)).is_err());
    assert_ne!(ex(1).key, ex(1).confirm, "the tag does not give the key away");
    // The hub's own key toward forwarders: one per face.
    let f = hub_key_for_face(&secret, &[1; 16]);
    assert_eq!(f, hub_key_for_face(&secret, &[1; 16]));
    assert_ne!(f.1, hub_key_for_face(&secret, &[2; 16]).1);
    assert_ne!(f.1, key_for(&secret, &DeviceId([1; 16])).1);
}

#[test]
fn a_switch_needs_both_ends() {
    let (mut d, mut h) = (DeviceSide::default(), HubSide::default());
    connect(&mut d, &mut h, 1);
    assert_eq!(handshake(&mut d, &mut h), Some(ex(1).key));

    // The next connection breaks after the device sent `tunnel` and before
    // the hub's confirmation came back: the confirmed key still fits.
    let tag = d.connected(ex(2));
    assert!(h.tunnel(ex(2), &tag).is_some());
    assert_eq!(handshake(&mut d, &mut h), Some(ex(1).key));
    // A tag of another connection confirms nothing.
    assert!(!d.confirmed(&ex(9).confirm));
    assert!(h.tunnel(ex(3), &ex(9).confirm).is_none());

    // The next connection completes the switch; the hub keeps the keys of
    // connections before it.
    connect(&mut d, &mut h, 3);
    assert_eq!(handshake(&mut d, &mut h), Some(ex(3).key));
    assert_eq!(h.accepts().first(), Some(&ex(3).key));
    assert!(h.accepts().contains(&ex(1).key));

    // Only a connection with the hybrid key exchange gives a key.
    assert_eq!(psk(&[1; 32], false), None);
    #[cfg(feature = "tls")]
    {
        assert!(hybrid(Some(rustls::NamedGroup::X25519MLKEM768)));
        assert!(!hybrid(Some(rustls::NamedGroup::X25519)));
        assert!(!hybrid(None));
    }
}

#[test]
fn a_device_back_from_an_older_state_still_gets_in() {
    let (mut d, mut h) = (DeviceSide::default(), HubSide::default());
    connect(&mut d, &mut h, 1);
    assert!(handshake(&mut d, &mut h).is_some());
    // Last night's backup; then a connection at home and a trip.
    let backup = d.clone();
    connect(&mut d, &mut h, 2);
    assert_eq!(handshake(&mut d, &mut h), Some(ex(2).key));
    let mut d = backup;
    assert_eq!(handshake(&mut d, &mut h), Some(ex(1).key), "the restored device still gets in");

    // A device that never made a handshake: four confirmations lost, then
    // four `tunnel` messages lost.
    let (mut d, mut h) = (DeviceSide::default(), HubSide::default());
    for n in 1..=4 {
        let p = ex(n);
        let tag = d.connected(p);
        assert!(h.tunnel(p, &tag).is_some());
    }
    for n in 5..=8 {
        d.connected(ex(n));
    }
    assert!(handshake(&mut d, &mut h).is_some());
}

#[test]
fn several_connections_at_home_then_a_lost_confirmation() {
    let (mut d, mut h) = (DeviceSide::default(), HubSide::default());
    connect(&mut d, &mut h, 1);
    assert!(handshake(&mut d, &mut h).is_some());
    // At home the tunnel is not used: two connections, both confirmed.
    connect(&mut d, &mut h, 2);
    connect(&mut d, &mut h, 3);
    // The last one at home: the hub takes `tunnel`, the confirmation is lost.
    let tag = d.connected(ex(4));
    assert!(h.tunnel(ex(4), &tag).is_some());
    // Away from home a key fits.
    assert!(handshake(&mut d, &mut h).is_some());
}

#[test]
fn a_hub_restarted_from_an_older_state_still_lets_the_device_in() {
    let (mut d, mut h) = (DeviceSide::default(), HubSide::default());
    connect(&mut d, &mut h, 1);
    assert!(handshake(&mut d, &mut h).is_some());
    let saved = h.clone();
    connect(&mut d, &mut h, 2);
    assert!(handshake(&mut d, &mut h).is_some());
    // The hub comes back from the state it saved before the switch.
    let mut h = saved;
    assert!(handshake(&mut d, &mut h).is_some(), "the device falls back");
    connect(&mut d, &mut h, 3);
    assert_eq!(handshake(&mut d, &mut h), Some(ex(3).key));

    // A hub that lost everything: away from home the device is out until a
    // direct connection, which repairs it.
    let mut h = HubSide::default();
    assert_eq!(handshake(&mut d, &mut h), None);
    connect(&mut d, &mut h, 4);
    assert_eq!(handshake(&mut d, &mut h), Some(ex(4).key));
}

/// A long random life: connections at home (with `tunnel` or the
/// confirmation lost), trips away (with the handshake's answer lost now and
/// then), restarts of either end, which lose what it had not saved, and a
/// hub restored from a backup a connection or two old. Each end saves its
/// keys before it sends `tunnel` or the confirmation. On every trip the two
/// ends share a key.
#[test]
fn the_two_ends_always_share_a_key() {
    for seed in 1..=500u64 {
        let mut x = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
        let mut next = move |n: u64| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x % n
        };
        let (mut d, mut h) = (DeviceSide::default(), HubSide::default());
        let mut n = 1u64;
        // The limit the module states: the hub holds a key of one of the
        // device's last KEEP connections. Losses beyond it are not drawn.
        let within = |d: &DeviceSide, h: &HubSide| h.received.iter().any(|k| d.sent.iter().any(|p| &p.key == k));
        // The first connection at home, whole and saved.
        connect(&mut d, &mut h, n);
        let (mut d_saved, mut h_saved) = (d.clone(), h.clone());
        let mut backups = vec![h.clone()];
        for step in 0..600 {
            match next(12) {
                // A connection at home.
                0..=4 => {
                    n += 1;
                    let p = ex(n);
                    let tag = d.connected(p);
                    d_saved = d.clone();
                    let fate = next(4);
                    if fate == 0 && within(&d, &h) {
                        continue;
                    }
                    let back = h.tunnel(p, &tag).unwrap();
                    h_saved = h.clone();
                    backups.push(h.clone());
                    if fate != 1 {
                        assert!(d.confirmed(&back));
                    }
                }
                // A trip away.
                5..=7 => {
                    let Some(k) = d.to_try().into_iter().find(|k| h.accepts().contains(k)) else {
                        panic!("seed {seed} step {step}: no common key\n{d:?}\n{h:?}");
                    };
                    h.handshake(&k);
                    if next(4) != 0 {
                        d.handshake(&k);
                    }
                    if next(2) == 0 {
                        d_saved = d.clone();
                        h_saved = h.clone();
                    }
                }
                // The device restarts.
                8 => d = d_saved.clone(),
                // The hub restarts.
                9 | 10 => h = h_saved.clone(),
                // The hub comes back from a backup one or two connections old.
                _ => {
                    let back = usize::try_from(next(2)).unwrap_or(0) + 1;
                    if let Some(b) = backups.len().checked_sub(back + 1).and_then(|i| backups.get(i))
                        && within(&d, b)
                    {
                        h = b.clone();
                        h_saved = h.clone();
                    }
                }
            }
        }
    }
}
