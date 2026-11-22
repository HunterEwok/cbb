// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The recovery secret on a fake YubiKey 5: sealed into the first empty
//! retired slot from 95 down and opened by the group's tag, with each kind
//! of management key, and every stop before the card is written.

use std::collections::HashMap;

use p256::elliptic_curve::sec1::ToSec1Point as _;

use super::*;

/// A wrong management key: the factory key with one byte changed.
fn wrong_key(n: u8) -> Vec<u8> {
    let mut k = super::super::factory_management_key().to_vec();
    k[0] ^= n;
    k
}

const PIN: &str = "123456";
const GENERATE: u8 = 0x47;
const PUT_DATA: u8 = 0xdb;
const TAG: &str = "0123456789abcdef";
const TAG_B: &str = "fedcba9876543210";

fn ok(mut data: Vec<u8>) -> Vec<u8> {
    data.extend_from_slice(&[0x90, 0x00]);
    data
}

fn sw(w: u16) -> Vec<u8> {
    w.to_be_bytes().to_vec()
}

fn cert_object(slot: u8) -> [u8; 3] {
    super::super::cert_object(slot)
}

/// A YubiKey 5 as far as cbb talks to it: GET VERSION, GET METADATA of
/// the retired slots and 9B (an empty slot answers 6A88, as firmware 5.x
/// does), the PIN, GET DATA (PRINTED needs the PIN, the certificate
/// objects do not) and PUT DATA, chained commands (CLA 10), the management
/// key's challenge and response, GENERATE in a retired slot and ECDH with
/// its key after a touch. writes lists the INS of every command that
/// changed the card.
pub(crate) struct Yubi {
    version: Option<[u8; 3]>,
    slots: HashMap<u8, Slot>,
    objects: HashMap<[u8; 3], Vec<u8>>,
    mgmt: (u8, Vec<u8>, bool),
    /// GENERATE takes these policies whatever it is asked (a card that
    /// ignores them); None follows the command.
    forced_policy: Option<(u8, u8)>,
    /// The status word of an empty slot's metadata.
    empty_sw: u16,
    verified: bool,
    authed: bool,
    witness: Option<Vec<u8>>,
    writes: Vec<u8>,
    /// The objects PUT DATA wrote, in order.
    put: Vec<[u8; 3]>,
    /// The slots GENERATE made a key in, in order.
    generated: Vec<u8>,
    /// The data of a chain so far.
    chain: Vec<u8>,
    /// PUT DATA fails without effect, as a card pulled out mid-way.
    fail_put: bool,
    touches: u32,
    made: u8,
}

#[derive(Clone)]
struct Slot {
    key: p256::SecretKey,
    policy: (u8, u8),
    origin: u8,
}

fn scalar(n: u8) -> p256::SecretKey {
    let mut b = [0x42u8; 32];
    b[31] = n;
    p256::SecretKey::from_bytes(&b.into()).unwrap()
}

fn point(k: &p256::SecretKey) -> Vec<u8> {
    k.public_key().to_sec1_point(false).as_bytes().to_vec()
}

impl Yubi {
    pub(crate) fn new(version: [u8; 3]) -> Yubi {
        let alg = if version >= [5, 7, 0] { ALG_AES192 } else { ALG_3DES };
        Yubi {
            version: Some(version),
            slots: HashMap::new(),
            objects: HashMap::new(),
            mgmt: (alg, super::super::factory_management_key().to_vec(), true),
            forced_policy: None,
            empty_sw: 0x6a88,
            verified: false,
            authed: false,
            witness: None,
            writes: Vec::new(),
            put: Vec::new(),
            generated: Vec::new(),
            chain: Vec::new(),
            fail_put: false,
            touches: 0,
            made: 1,
        }
    }

    /// Another tool's key in slot, with or without a certificate.
    fn foreign(&mut self, slot: u8, cert: bool) {
        self.slots.insert(slot, Slot { key: scalar(200 - slot), policy: (1, 1), origin: 2 });
        if cert {
            self.objects.insert(cert_object(slot), tlv(0x70, &[0x30, 3, 1, 2, 3]));
        }
    }

    fn slot_metadata(&self, slot: u8) -> Vec<u8> {
        let Some(s) = self.slots.get(&slot) else { return sw(self.empty_sw) };
        let p = point(&s.key);
        ok([
            tlv(0x01, &[ALG_P256]),
            tlv(0x02, &[s.policy.0, s.policy.1]),
            tlv(0x03, &[s.origin]),
            tlv(0x04, &tlv(0x86, &p)),
        ]
        .concat())
    }

    pub(crate) fn handle(&mut self, apdu: &[u8]) -> Vec<u8> {
        let (cla, ins, p1, p2) = (apdu[0], apdu[1], apdu[2], apdu[3]);
        let part = if apdu.len() > 5 { &apdu[5..5 + usize::from(apdu[4])] } else { &[][..] };
        if cla == 0x10 {
            self.chain.extend_from_slice(part);
            return ok(vec![]);
        }
        let mut data = std::mem::take(&mut self.chain);
        data.extend_from_slice(part);
        let data = data.as_slice();
        match ins {
            0xa4 => ok(vec![]),
            0xfd => match self.version {
                Some(v) => ok(v.to_vec()),
                None => sw(0x6d00),
            },
            0xf7 => match p2 {
                0x82..=0x95 => self.slot_metadata(p2),
                SLOT_MGMT => ok([tlv(0x01, &[self.mgmt.0]), tlv(0x05, &[u8::from(self.mgmt.2)])].concat()),
                _ => sw(0x6a82),
            },
            0x20 => {
                if data == b"123456\xff\xff" {
                    self.verified = true;
                    ok(vec![])
                } else {
                    sw(0x63c2)
                }
            }
            0xcb => {
                let tag: [u8; 3] = data[2..5].try_into().unwrap();
                if tag == PRINTED && !self.verified {
                    return sw(0x6982);
                }
                match self.objects.get(&tag) {
                    Some(v) => ok(tlv(0x53, v)),
                    None => sw(0x6a82),
                }
            }
            0x87 if p2 == SLOT_MGMT => self.challenge(p1, data),
            0x87 if p1 == ALG_P256 => {
                let Some(s) = self.slots.get(&p2) else { return sw(0x6a82) };
                if !self.verified {
                    return sw(0x6982);
                }
                self.touches += 1;
                let (outer, _) = read_tlv(data, 0x7c).unwrap();
                let (_, rest) = read_tlv(outer, 0x82).unwrap();
                let (e, _) = read_tlv(rest, 0x85).unwrap();
                let z = yk::ecdh(&s.key, e).unwrap();
                ok(tlv(0x7c, &tlv(0x82, z.as_ref())))
            }
            GENERATE => {
                if !self.authed {
                    return sw(0x6982);
                }
                assert!((0x82..=0x95).contains(&p2), "GENERATE outside the retired slots");
                assert!(!self.slots.contains_key(&p2), "GENERATE over a key in slot {p2:02x}");
                self.writes.push(ins);
                self.generated.push(p2);
                let (spec, _) = read_tlv(data, 0xac).unwrap();
                let asked = (spec[5], spec[8]);
                self.made += 1;
                let key = scalar(self.made);
                let p = point(&key);
                self.slots
                    .insert(p2, Slot { key, policy: self.forced_policy.unwrap_or(asked), origin: ORIGIN_GENERATED });
                let mut out = vec![0x7f];
                out.extend(tlv(0x49, &tlv(0x86, &p)));
                ok(out)
            }
            PUT_DATA => {
                if !self.authed {
                    return sw(0x6982);
                }
                let (tag, rest) = read_tlv(data, 0x5c).unwrap();
                let tag: [u8; 3] = tag.try_into().unwrap();
                assert!(!self.objects.contains_key(&tag), "PUT DATA over {tag:02x?}");
                if self.fail_put {
                    return sw(0x6581);
                }
                self.writes.push(ins);
                self.put.push(tag);
                let (v, _) = read_tlv(rest, 0x53).unwrap();
                self.objects.insert(tag, v.to_vec());
                ok(vec![])
            }
            _ => sw(0x6d00),
        }
    }

    fn challenge(&mut self, alg: u8, data: &[u8]) -> Vec<u8> {
        if alg != self.mgmt.0 {
            return sw(0x6a86);
        }
        let n = block(alg).unwrap();
        let (outer, _) = read_tlv(data, 0x7c).unwrap();
        let (first, rest) = read_tlv(outer, 0x80).unwrap();
        if first.is_empty() {
            let w: Vec<u8> = (0..n as u8).map(|i| i.wrapping_mul(37).wrapping_add(self.made)).collect();
            let enc = cipher(alg, &self.mgmt.1, &w, true).unwrap();
            self.witness = Some(w);
            return ok(tlv(0x7c, &tlv(0x80, &enc)));
        }
        if self.witness.take().as_deref() != Some(first) {
            return sw(0x6982);
        }
        let (chal, _) = read_tlv(rest, 0x81).unwrap();
        self.authed = true;
        ok(tlv(0x7c, &tlv(0x82, &cipher(alg, &self.mgmt.1, chal, true).unwrap())))
    }
}

type Y = std::sync::Arc<std::sync::Mutex<Yubi>>;

struct Shared(Y);

impl Card for Shared {
    fn transmit(&mut self, apdu: &[u8]) -> crate::error::Result<Vec<u8>> {
        Ok(self.0.lock().unwrap().handle(apdu))
    }
}

fn card(y: Yubi) -> (Shared, Y) {
    let a = std::sync::Arc::new(std::sync::Mutex::new(y));
    (Shared(a.clone()), a)
}

fn secret() -> [u8; 32] {
    core::array::from_fn(|i| i as u8 ^ 0xa5)
}

fn secret_b() -> [u8; 32] {
    core::array::from_fn(|i| i as u8 ^ 0x5a)
}

fn never(_: u8) -> Option<Zeroizing<Vec<u8>>> {
    panic!("the default or protected key needs nobody to type it")
}

/// A new connection, as a later signing has.
fn fresh(y: &Y) {
    let mut g = y.lock().unwrap();
    (g.verified, g.authed) = (false, false);
}

/// Opens with a new connection, as a later signing does.
fn reopen(y: &Y) -> Result<Zeroizing<[u8; 32]>> {
    reopen_for(y, Some(TAG))
}

fn reopen_for(y: &Y, tag: Option<&str>) -> Result<Zeroizing<[u8; 32]>> {
    fresh(y);
    open(&mut Shared(y.clone()), PIN, tag)
}

fn seal_on(y: &Y, s: &[u8; 32], tag: &str) -> Result<Sealed> {
    fresh(y);
    seal(&mut Shared(y.clone()), PIN, s, tag, &mut never)
}

#[test]
fn seals_and_opens_with_the_default_key() {
    for v in [[5, 4, 3], [5, 7, 2]] {
        let (mut c, y) = card(Yubi::new(v));
        assert_eq!(seal(&mut c, PIN, &secret(), TAG, &mut never).unwrap(), Sealed { slot: 0x95, default_key: true });
        {
            let g = y.lock().unwrap();
            assert_eq!(g.writes, vec![GENERATE, PUT_DATA], "{v:?}");
            assert_eq!(g.put, vec![cert_object(0x95)], "{v:?}");
            assert_eq!(g.mgmt, (g.mgmt.0, super::super::factory_management_key().to_vec(), true), "the key changed");
            let (der, _) = read_tlv(&g.objects[&cert_object(0x95)], 0x70).unwrap();
            let c = yk::read_container(der).unwrap();
            assert_eq!((c.tag.as_str(), c.object.len()), (TAG, yk::LEN));
        }
        assert_eq!(*reopen(&y).unwrap(), secret(), "{v:?}");
        assert_eq!(y.lock().unwrap().touches, 1);
    }
}

#[test]
fn seals_with_a_pin_protected_key() {
    let key: Vec<u8> = (1..=24).collect();
    let mut y = Yubi::new([5, 7, 2]);
    y.mgmt = (ALG_AES192, key.clone(), false);
    y.objects.insert(ADMIN_DATA, tlv(0x80, &tlv(0x81, &[0x02])));
    y.objects.insert(PRINTED, tlv(0x88, &tlv(0x89, &key)));
    let (mut c, y) = card(y);
    assert_eq!(seal(&mut c, PIN, &secret(), TAG, &mut never).unwrap(), Sealed { slot: 0x95, default_key: false });
    assert_eq!(*reopen(&y).unwrap(), secret());
}

#[test]
fn asks_for_a_changed_key_three_times_at_most() {
    let key: Vec<u8> = (9..33).collect();
    let mut y = Yubi::new([5, 4, 3]);
    y.mgmt = (ALG_3DES, key.clone(), false);
    let (mut c, y) = card(y);
    let mut asked = Vec::new();
    let mut ask = |n: u8| {
        asked.push(n);
        Some(Zeroizing::new(if n == 3 { key.clone() } else { wrong_key(7) }))
    };
    assert_eq!(seal(&mut c, PIN, &secret(), TAG, &mut ask).unwrap(), Sealed { slot: 0x95, default_key: false });
    assert_eq!(asked, vec![1, 2, 3]);
    assert_eq!(*reopen(&y).unwrap(), secret());
}

/// The owner's card: release keys in slots 82 and 83, with their
/// certificates. cbb takes 95 and leaves both as they were.
#[test]
fn slots_in_use_are_never_touched() {
    let mut y = Yubi::new([5, 7, 2]);
    y.foreign(0x82, true);
    y.foreign(0x83, true);
    let before = (y.objects.clone(), point(&y.slots[&0x82].key), point(&y.slots[&0x83].key));
    let (_, y) = card(y);
    assert_eq!(seal_on(&y, &secret(), TAG).unwrap().slot, 0x95);
    let g = y.lock().unwrap();
    assert_eq!(g.objects[&cert_object(0x82)], before.0[&cert_object(0x82)]);
    assert_eq!(g.objects[&cert_object(0x83)], before.0[&cert_object(0x83)]);
    assert_eq!((point(&g.slots[&0x82].key), point(&g.slots[&0x83].key)), (before.1, before.2));
    drop(g);
    // From 95 down: a key without a certificate (95), a certificate
    // without a key (94) and both (93) keep their slots; 92 is the first
    // empty one.
    let mut y = Yubi::new([5, 7, 2]);
    y.foreign(0x95, false);
    y.objects.insert(cert_object(0x94), tlv(0x70, &[0x30, 0]));
    y.foreign(0x93, true);
    let (_, y) = card(y);
    assert_eq!(seal_on(&y, &secret(), TAG).unwrap().slot, 0x92);
    assert_eq!(y.lock().unwrap().generated, vec![0x92]);
    assert_eq!(*reopen(&y).unwrap(), secret());
}

/// GET METADATA of an empty slot: 6A88 on the real firmware, 6A82 on some
/// cards; both mean empty.
#[test]
fn an_empty_slot_is_6a88_or_6a82() {
    for empty in [0x6a88, 0x6a82] {
        let mut y = Yubi::new([5, 7, 2]);
        y.empty_sw = empty;
        let (_, y) = card(y);
        assert_eq!(seal_on(&y, &secret(), TAG).unwrap().slot, 0x95, "{empty:04x}");
        assert_eq!(*reopen(&y).unwrap(), secret(), "{empty:04x}");
    }
}

#[test]
fn two_groups_share_a_card_in_two_slots() {
    let (_, y) = card(Yubi::new([5, 7, 2]));
    assert_eq!(seal_on(&y, &secret(), TAG).unwrap().slot, 0x95);
    assert_eq!(seal_on(&y, &secret_b(), TAG_B).unwrap().slot, 0x94);
    assert_eq!(*reopen_for(&y, Some(TAG)).unwrap(), secret());
    assert_eq!(*reopen_for(&y, Some(TAG_B)).unwrap(), secret_b());
    // Without the group, cbb does not choose.
    assert_eq!(reopen_for(&y, None).unwrap_err().to_string(), GROUPS);
    // A group that is not there.
    assert_eq!(reopen_for(&y, Some("00000000000000aa")).unwrap_err().to_string(), NONE);
}

#[test]
fn two_slots_for_one_group_open_neither() {
    let (_, y) = card(Yubi::new([5, 7, 2]));
    seal_on(&y, &secret(), TAG).unwrap();
    {
        let mut g = y.lock().unwrap();
        let (s, o) = (g.slots[&0x95].clone(), g.objects[&cert_object(0x95)].clone());
        g.slots.insert(0x90, s);
        g.objects.insert(cert_object(0x90), o);
    }
    assert_eq!(reopen(&y).unwrap_err().to_string(), TWO_SLOTS);
    // Without the group named too: both name the same group.
    assert_eq!(reopen_for(&y, None).unwrap_err().to_string(), TWO_SLOTS);
    assert_eq!(y.lock().unwrap().touches, 0);
    assert!(!y.lock().unwrap().verified, "asked for the PIN");
}

/// A seal that stops between GENERATE and the container (the card refuses
/// PUT DATA) leaves a key without cbb's certificate: that slot is taken
/// for good, nothing opens there, and the next seal goes one slot down.
#[test]
fn a_seal_that_stops_before_the_certificate_leaves_its_slot_taken() {
    let mut y = Yubi::new([5, 7, 2]);
    y.fail_put = true;
    let (_, y) = card(y);
    assert!(seal_on(&y, &secret(), TAG).is_err());
    {
        let g = y.lock().unwrap();
        assert!(g.slots.contains_key(&0x95), "no key made");
        assert!(!g.objects.contains_key(&cert_object(0x95)), "a certificate written");
    }
    assert_eq!(reopen(&y).unwrap_err().to_string(), NONE);
    y.lock().unwrap().fail_put = false;
    assert_eq!(seal_on(&y, &secret(), TAG).unwrap().slot, 0x94);
    assert_eq!(y.lock().unwrap().generated, vec![0x95, 0x94]);
    assert_eq!(*reopen(&y).unwrap(), secret());
}

/// Every stop of sealing comes before the first write: each card would let
/// the default management key write, so a path that wrote first and checked
/// after would show here.
#[test]
fn every_stop_comes_before_any_write() {
    let sealed_one = {
        let (_, y) = card(Yubi::new([5, 4, 3]));
        seal_on(&y, &secret(), TAG).unwrap();
        let g = y.lock().unwrap();
        (g.objects[&cert_object(0x95)].clone(), g.slots[&0x95].clone())
    };
    type Setup = Box<dyn Fn(&mut Yubi)>;
    let cases: Vec<(&str, Setup, &str)> = vec![
        (
            "a card that holds this group's recovery key",
            Box::new({
                let (o, s) = sealed_one.clone();
                move |y| {
                    y.objects.insert(cert_object(0x91), o.clone());
                    y.slots.insert(0x91, s.clone());
                }
            }),
            HOLDS_ONE,
        ),
        (
            "every retired slot in use",
            Box::new(|y| {
                for slot in 0x82..=0x95 {
                    y.foreign(slot, slot % 2 == 0);
                }
            }),
            super::super::NO_FREE_SLOT,
        ),
        ("firmware 5.2.7", Box::new(|y| y.version = Some([5, 2, 7])), FIRMWARE),
        ("firmware 4.3.7", Box::new(|y| y.version = Some([4, 3, 7])), FIRMWARE),
        ("another PIV card, without GET VERSION", Box::new(|y| y.version = None), FIRMWARE),
        (
            "a PIN-derived management key",
            Box::new(|y| {
                y.mgmt = (ALG_3DES, wrong_key(5), false);
                y.objects.insert(ADMIN_DATA, tlv(0x80, &[tlv(0x81, &[0x00]), tlv(0x82, &[9; 16])].concat()));
            }),
            PIN_DERIVED,
        ),
        ("three wrong management keys", Box::new(|y| y.mgmt = (ALG_3DES, wrong_key(5), false)), KEY_TRIES),
    ];
    for (name, setup, want) in cases {
        let mut y = Yubi::new([5, 4, 3]);
        setup(&mut y);
        let before = (y.slots.keys().copied().collect::<std::collections::BTreeSet<_>>(), y.objects.clone());
        let (mut c, y) = card(y);
        let mut wrong = |_: u8| Some(Zeroizing::new(wrong_key(6)));
        let err = seal(&mut c, PIN, &secret(), TAG, &mut wrong).unwrap_err().to_string();
        assert_eq!(err, want, "{name}");
        let g = y.lock().unwrap();
        assert!(g.writes.is_empty(), "{name}: {:?}", g.writes);
        assert_eq!((g.slots.keys().copied().collect(), g.objects.clone()), before, "{name}");
    }
    // A wrong PIN and a tag that is not one stop too.
    let (mut c, y) = card(Yubi::new([5, 4, 3]));
    assert!(seal(&mut c, "654321", &secret(), TAG, &mut never).is_err());
    assert!(seal(&mut c, PIN, &secret(), "0123", &mut never).is_err());
    assert!(y.lock().unwrap().writes.is_empty());
}

#[test]
fn a_key_made_without_the_policies_is_not_written_to() {
    let mut y = Yubi::new([5, 4, 3]);
    y.forced_policy = Some((2, 1));
    let (mut c, y) = card(y);
    assert_eq!(seal(&mut c, PIN, &secret(), TAG, &mut never).unwrap_err().to_string(), NOT_AS_ASKED);
    // GENERATE wrote the key; nothing came after it.
    assert_eq!(y.lock().unwrap().writes, vec![GENERATE]);
    assert!(!y.lock().unwrap().objects.contains_key(&cert_object(0x95)));
    // The key without cbb's certificate keeps the slot taken: a second try
    // goes to 94.
    y.lock().unwrap().forced_policy = None;
    assert_eq!(seal_on(&y, &secret(), TAG).unwrap().slot, 0x94);
}

/// A container whose object is changed by f, put back in slot 95.
fn with_object(y: &Y, f: impl Fn(&mut [u8; yk::LEN])) {
    let mut g = y.lock().unwrap();
    let (der, _) = read_tlv(&g.objects[&cert_object(0x95)], 0x70).unwrap();
    let c = yk::read_container(der).unwrap();
    let mut o: [u8; yk::LEN] = c.object.try_into().unwrap();
    f(&mut o);
    let cert = yk::container(&c.tag, &c.point, &o).unwrap();
    g.objects.insert(cert_object(0x95), tlv(0x70, &cert));
}

#[test]
fn opening_refuses_what_is_not_ours_before_the_touch() {
    let sealed_by = |made: u8| {
        let mut y = Yubi::new([5, 4, 3]);
        y.made = made;
        let (_, y) = card(y);
        seal_on(&y, &secret(), TAG).unwrap();
        y
    };
    let sealed = || sealed_by(1);
    // Nothing there; another tool's certificate is not cbb's.
    let mut empty = Yubi::new([5, 4, 3]);
    empty.foreign(0x95, true);
    let (_, y) = card(empty);
    assert_eq!(reopen(&y).unwrap_err().to_string(), NONE);
    // A later version: nothing else is read and the card is not touched.
    let y = sealed();
    with_object(&y, |o| o[4] = 2);
    assert_eq!(reopen(&y).unwrap_err().to_string(), "this YubiKey needs a newer cbb");
    assert_eq!(y.lock().unwrap().touches, 0);
    // A key in the slot that cbb did not ask for.
    let y = sealed();
    y.lock().unwrap().slots.get_mut(&0x95).unwrap().policy = (1, 1);
    assert_eq!(reopen(&y).unwrap_err().to_string(), NOT_AS_ASKED);
    assert_eq!(y.lock().unwrap().touches, 0);
    // A container that names another key than the slot's.
    let y = sealed();
    y.lock().unwrap().slots.get_mut(&0x95).unwrap().key = scalar(99);
    assert_eq!(reopen(&y).unwrap_err().to_string(), NOT_AS_ASKED);
    // An object sealed to another card's key.
    let y = sealed();
    let other = sealed_by(50);
    let o = other.lock().unwrap().objects[&cert_object(0x95)].clone();
    let (der, _) = read_tlv(&o, 0x70).unwrap();
    let theirs: [u8; yk::LEN] = yk::read_container(der).unwrap().object.try_into().unwrap();
    with_object(&y, |o| *o = theirs);
    assert_eq!(reopen(&y).unwrap_err().to_string(), "this YubiKey holds another recovery key");
    // Old firmware.
    let y = sealed();
    y.lock().unwrap().version = Some([5, 2, 7]);
    assert_eq!(reopen(&y).unwrap_err().to_string(), FIRMWARE);
}

#[test]
fn the_management_key_ciphers_are_the_standard_ones() {
    // FIPS 46-3 (Triple DES with three equal keys is single DES) and
    // FIPS 197 (AES-192), appendix C.2.
    let des = cipher(
        ALG_3DES,
        &[[0x13, 0x34, 0x57, 0x79, 0x9b, 0xbc, 0xdf, 0xf1]; 3].concat(),
        &[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef],
        true,
    );
    assert_eq!(des.unwrap(), [0x85, 0xe8, 0x13, 0x54, 0x0f, 0x0a, 0xb4, 0x05]);
    let key: Vec<u8> = (0..24).collect();
    let plain: Vec<u8> = (0..16).map(|i| i * 0x11).collect();
    let aes = cipher(ALG_AES192, &key, &plain, true).unwrap();
    assert_eq!(aes, [0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91]);
    assert_eq!(cipher(ALG_AES192, &key, &aes, false).unwrap(), plain);
    assert!(cipher(ALG_3DES, &key[..16], &plain[..8], true).is_none());
}

#[test]
fn the_texts_for_the_caller_name_what_they_warn_of() {
    assert!(DUPLICATES.contains("YubiKey") && DUPLICATES.contains("sheet"));
    assert!(TWO_SLOTS.contains("two") && GROUPS.contains("group"));
    assert!(super::super::NO_FREE_SLOT.contains("slot"));
}

#[test]
fn the_factory_management_key_is_yubicos() {
    let hex: String = super::super::factory_management_key().iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(hex, "0102030405060708".repeat(3));
}

#[test]
fn the_recovery_opens_the_one_card_with_a_key_in_slot_95() {
    let sealed = |tag: &str| {
        let (_, y) = card(Yubi::new([5, 4, 3]));
        seal_on(&y, &secret(), tag).unwrap();
        let mut g = y.lock().unwrap();
        (g.verified, g.authed, g.touches) = (false, false, 0);
        drop(g);
        y
    };
    let boxed = |y: &Y| -> Box<dyn Card> { Box::new(Shared(y.clone())) };
    // Another card beside it is not asked for the PIN.
    let (other, empty) = (sealed(TAG), card(Yubi::new([5, 7, 2])).1);
    let got = open_among(vec![boxed(&empty), boxed(&other)], PIN, None).unwrap();
    assert_eq!(*got, secret());
    assert!(!empty.lock().unwrap().verified, "the card without cbb's key was asked for the PIN");
    assert_eq!(other.lock().unwrap().touches, 1);
    // Two cards with a key there: neither is opened.
    let (a, b) = (sealed(TAG), sealed(TAG));
    assert_eq!(open_among(vec![boxed(&a), boxed(&b)], PIN, None).unwrap_err().to_string(), super::super::TWO_CARDS);
    assert!(!a.lock().unwrap().verified && !b.lock().unwrap().verified);
    // With the group named, the other group's card is passed over.
    let (a, b) = (sealed(TAG), sealed(TAG_B));
    assert_eq!(*open_among(vec![boxed(&a), boxed(&b)], PIN, Some(TAG_B)).unwrap(), secret());
    assert!(!a.lock().unwrap().verified, "the other group's card was asked for the PIN");
    // A card without it, and no card at all.
    assert_eq!(open_among(vec![boxed(&empty)], PIN, None).unwrap_err().to_string(), NONE);
    assert_eq!(open_among(Vec::new(), PIN, None).unwrap_err().to_string(), super::super::NO_CARD);
}
