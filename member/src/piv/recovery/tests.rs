// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The recovery secret on a fake YubiKey 5: sealed and opened with each kind
//! of management key, and every stop before the card is written.

use std::collections::HashMap;

use p256::elliptic_curve::sec1::ToSec1Point as _;

use super::*;

const PIN: &str = "123456";
const GENERATE: u8 = 0x47;
const PUT_DATA: u8 = 0xdb;

fn ok(mut data: Vec<u8>) -> Vec<u8> {
    data.extend_from_slice(&[0x90, 0x00]);
    data
}

fn sw(w: u16) -> Vec<u8> {
    w.to_be_bytes().to_vec()
}

/// A YubiKey 5 as far as cbb talks to it: GET VERSION, GET METADATA of
/// slots 95 and 9B, the PIN, GET DATA and PUT DATA (5FC121 and 5FC109 need
/// the PIN), the management key's challenge and response, GENERATE in slot
/// 95 and ECDH with its key after a touch. writes lists the INS of every
/// command that changed the card.
struct Yubi {
    version: Option<[u8; 3]>,
    slot: Option<Slot>,
    objects: HashMap<[u8; 3], Vec<u8>>,
    mgmt: (u8, Vec<u8>, bool),
    /// GENERATE takes these policies whatever it is asked (a card that
    /// ignores them); None follows the command.
    forced_policy: Option<(u8, u8)>,
    verified: bool,
    authed: bool,
    witness: Option<Vec<u8>>,
    writes: Vec<u8>,
    touches: u32,
    made: u8,
}

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
    fn new(version: [u8; 3]) -> Yubi {
        let alg = if version >= [5, 7, 0] { ALG_AES192 } else { ALG_3DES };
        Yubi {
            version: Some(version),
            slot: None,
            objects: HashMap::new(),
            mgmt: (alg, DEFAULT_KEY.to_vec(), true),
            forced_policy: None,
            verified: false,
            authed: false,
            witness: None,
            writes: Vec::new(),
            touches: 0,
            made: 1,
        }
    }

    fn slot_metadata(&self) -> Vec<u8> {
        let Some(s) = &self.slot else { return sw(0x6a82) };
        let p = point(&s.key);
        ok([
            tlv(0x01, &[ALG_P256]),
            tlv(0x02, &[s.policy.0, s.policy.1]),
            tlv(0x03, &[s.origin]),
            tlv(0x04, &tlv(0x86, &p)),
        ]
        .concat())
    }

    fn handle(&mut self, apdu: &[u8]) -> Vec<u8> {
        let (ins, p1, p2) = (apdu[1], apdu[2], apdu[3]);
        let data = if apdu.len() > 5 { &apdu[5..5 + usize::from(apdu[4])] } else { &[][..] };
        match ins {
            0xa4 => ok(vec![]),
            0xfd => match self.version {
                Some(v) => ok(v.to_vec()),
                None => sw(0x6d00),
            },
            0xf7 => match p2 {
                yk::SLOT => self.slot_metadata(),
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
                if (tag == yk::OBJECT || tag == PRINTED) && !self.verified {
                    return sw(0x6982);
                }
                match self.objects.get(&tag) {
                    Some(v) => ok(tlv(0x53, v)),
                    None => sw(0x6a82),
                }
            }
            0x87 if p2 == SLOT_MGMT => self.challenge(p1, data),
            0x87 if p2 == yk::SLOT && p1 == ALG_P256 => {
                let Some(s) = &self.slot else { return sw(0x6a82) };
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
                self.writes.push(ins);
                let (spec, _) = read_tlv(data, 0xac).unwrap();
                let asked = (spec[5], spec[8]);
                self.made += 1;
                let key = scalar(self.made);
                let p = point(&key);
                self.slot = Some(Slot { key, policy: self.forced_policy.unwrap_or(asked), origin: ORIGIN_GENERATED });
                let mut out = vec![0x7f];
                out.extend(tlv(0x49, &tlv(0x86, &p)));
                ok(out)
            }
            PUT_DATA => {
                if !self.authed {
                    return sw(0x6982);
                }
                self.writes.push(ins);
                let (tag, rest) = read_tlv(data, 0x5c).unwrap();
                let (v, _) = read_tlv(rest, 0x53).unwrap();
                self.objects.insert(tag.try_into().unwrap(), v.to_vec());
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

struct Shared(std::sync::Arc<std::sync::Mutex<Yubi>>);

impl Card for Shared {
    fn transmit(&mut self, apdu: &[u8]) -> crate::error::Result<Vec<u8>> {
        Ok(self.0.lock().unwrap().handle(apdu))
    }
}

fn card(y: Yubi) -> (Shared, std::sync::Arc<std::sync::Mutex<Yubi>>) {
    let a = std::sync::Arc::new(std::sync::Mutex::new(y));
    (Shared(a.clone()), a)
}

fn secret() -> [u8; 32] {
    core::array::from_fn(|i| i as u8 ^ 0xa5)
}

fn never(_: u8) -> Option<Zeroizing<Vec<u8>>> {
    panic!("the default or protected key needs nobody to type it")
}

/// Opens with a new connection, as a later signing does.
fn reopen(y: &std::sync::Arc<std::sync::Mutex<Yubi>>) -> Result<Zeroizing<[u8; 32]>> {
    {
        let mut g = y.lock().unwrap();
        g.verified = false;
        g.authed = false;
    }
    open(&mut Shared(y.clone()), PIN)
}

#[test]
fn seals_and_opens_with_the_default_key() {
    for v in [[5, 4, 3], [5, 7, 2]] {
        let (mut c, y) = card(Yubi::new(v));
        assert_eq!(seal(&mut c, PIN, &secret(), &mut never).unwrap(), Sealed { default_key: true });
        assert_eq!(y.lock().unwrap().writes, vec![GENERATE, PUT_DATA], "{v:?}");
        assert_eq!(y.lock().unwrap().objects[&yk::OBJECT].len(), yk::LEN);
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
    assert_eq!(seal(&mut c, PIN, &secret(), &mut never).unwrap(), Sealed { default_key: false });
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
        Some(Zeroizing::new(if n == 3 { key.clone() } else { vec![7u8; 24] }))
    };
    assert_eq!(seal(&mut c, PIN, &secret(), &mut ask).unwrap(), Sealed { default_key: false });
    assert_eq!(asked, vec![1, 2, 3]);
    assert_eq!(*reopen(&y).unwrap(), secret());
}

/// Every stop of sealing comes before the first write: each card would let
/// the default management key write, so a path that wrote first and checked
/// after would show here.
#[test]
fn every_stop_comes_before_any_write() {
    let foreign = || Slot { key: scalar(200), policy: (1, 1), origin: 2 };
    let sealed_one = {
        let (mut c, y) = card(Yubi::new([5, 4, 3]));
        seal(&mut c, PIN, &secret(), &mut never).unwrap();
        let g = y.lock().unwrap();
        (g.objects[&yk::OBJECT].clone(), Slot { key: g.slot.as_ref().unwrap().key.clone(), policy: (3, 2), origin: 1 })
    };
    type Setup = Box<dyn Fn(&mut Yubi)>;
    let cases: Vec<(&str, Setup, &str)> = vec![
        ("a key in slot 95", Box::new(move |y| y.slot = Some(foreign())), TAKEN),
        (
            "another program's 5FC121",
            Box::new(|y| {
                y.objects.insert(yk::OBJECT, vec![0x30, 3, 1, 2, 3]);
            }),
            TAKEN,
        ),
        (
            "cbb's object without its key",
            Box::new({
                let o = sealed_one.0.clone();
                move |y| {
                    y.objects.insert(yk::OBJECT, o.clone());
                }
            }),
            TAKEN,
        ),
        (
            "a card that holds a recovery key",
            Box::new({
                let o = sealed_one.0.clone();
                let k = sealed_one.1.key.clone();
                move |y| {
                    y.objects.insert(yk::OBJECT, o.clone());
                    y.slot = Some(Slot { key: k.clone(), policy: (3, 2), origin: 1 });
                }
            }),
            HOLDS_ONE,
        ),
        ("firmware 5.2.7", Box::new(|y| y.version = Some([5, 2, 7])), FIRMWARE),
        ("firmware 4.3.7", Box::new(|y| y.version = Some([4, 3, 7])), FIRMWARE),
        ("another PIV card, without GET VERSION", Box::new(|y| y.version = None), FIRMWARE),
        (
            "a PIN-derived management key",
            Box::new(|y| {
                y.mgmt = (ALG_3DES, vec![5; 24], false);
                y.objects.insert(ADMIN_DATA, tlv(0x80, &[tlv(0x81, &[0x00]), tlv(0x82, &[9; 16])].concat()));
            }),
            PIN_DERIVED,
        ),
        ("three wrong management keys", Box::new(|y| y.mgmt = (ALG_3DES, vec![5; 24], false)), KEY_TRIES),
    ];
    for (name, setup, want) in cases {
        let mut y = Yubi::new([5, 4, 3]);
        setup(&mut y);
        let before = (y.slot.as_ref().map(|s| point(&s.key)), y.objects.clone());
        let (mut c, y) = card(y);
        let mut wrong = |_: u8| Some(Zeroizing::new(vec![6u8; 24]));
        let err = seal(&mut c, PIN, &secret(), &mut wrong).unwrap_err().to_string();
        assert_eq!(err, want, "{name}");
        let g = y.lock().unwrap();
        assert!(g.writes.is_empty(), "{name}: {:?}", g.writes);
        assert_eq!((g.slot.as_ref().map(|s| point(&s.key)), g.objects.clone()), before, "{name}");
    }
    // A wrong PIN stops too, before anything is written.
    let (mut c, y) = card(Yubi::new([5, 4, 3]));
    assert!(seal(&mut c, "654321", &secret(), &mut never).is_err());
    assert!(y.lock().unwrap().writes.is_empty());
}

#[test]
fn a_key_made_without_the_policies_is_not_written_to() {
    let mut y = Yubi::new([5, 4, 3]);
    y.forced_policy = Some((2, 1));
    let (mut c, y) = card(y);
    assert_eq!(seal(&mut c, PIN, &secret(), &mut never).unwrap_err().to_string(), NOT_AS_ASKED);
    // GENERATE wrote the key; nothing came after it.
    assert_eq!(y.lock().unwrap().writes, vec![GENERATE]);
    assert!(!y.lock().unwrap().objects.contains_key(&yk::OBJECT));
}

#[test]
fn opening_refuses_what_is_not_ours_before_the_touch() {
    let sealed_by = |made: u8| {
        let mut y = Yubi::new([5, 4, 3]);
        y.made = made;
        let (mut c, y) = card(y);
        seal(&mut c, PIN, &secret(), &mut never).unwrap();
        y
    };
    let sealed = || sealed_by(1);
    // Nothing there.
    let (_, y) = card(Yubi::new([5, 4, 3]));
    assert_eq!(reopen(&y).unwrap_err().to_string(), NONE);
    // A later version: nothing else is read and the card is not touched.
    let y = sealed();
    y.lock().unwrap().objects.get_mut(&yk::OBJECT).unwrap()[4] = 2;
    assert_eq!(reopen(&y).unwrap_err().to_string(), "this YubiKey needs a newer cbb");
    assert_eq!(y.lock().unwrap().touches, 0);
    // Another program's object beside a key.
    let y = sealed();
    y.lock().unwrap().objects.insert(yk::OBJECT, vec![1, 2, 3]);
    assert_eq!(reopen(&y).unwrap_err().to_string(), TAKEN);
    // A key in slot 95 that cbb did not ask for.
    let y = sealed();
    y.lock().unwrap().slot.as_mut().unwrap().policy = (1, 1);
    assert_eq!(reopen(&y).unwrap_err().to_string(), TAKEN);
    assert_eq!(y.lock().unwrap().touches, 0);
    // An object sealed to another card's key.
    let y = sealed();
    let other = sealed_by(50);
    let o = other.lock().unwrap().objects[&yk::OBJECT].clone();
    y.lock().unwrap().objects.insert(yk::OBJECT, o);
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
