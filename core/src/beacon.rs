// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The freshness beacon (A-18, format section 9.4, label `cbb beacon v1`):
//! an admin's device says "I saw this set of records at this time", signed
//! with its member key. It is not a record, and no rule of the records reads
//! it; a device uses it to tell how fresh its own view of the records is.
//! When its set digest is one an admin saw at time t, its records were
//! current at t; when an admin saw more records than it holds, it is behind
//! (a removal may be on its way) and asks for them.
//!
//! The signer must be the member key of a device whose record makes it an
//! admin, while that admin key may command ([`State::may_command`]): a
//! removed, frozen or forked admin is no witness.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::error::Error;
use crate::format::cbor::{self, Value};
use crate::format::envelope::{self, Envelope};
use crate::format::{Rule, frame, sig};
use crate::identity::ExternalKey;
use crate::records::eval::State;
use crate::records::key::{self as rkey, DeviceId, GroupId, Key, KeyHash};

/// The message type of a beacon.
pub const T_BEACON: u64 = crate::msg::wave4::T_BEACON;
/// A beacon body's ceiling.
pub const MAX_BEACON: usize = 512;
/// The most records a set holds, so the most a beacon counts.
pub const MAX_COUNT: u64 = crate::records::MAX_RECORDS as u64;

pub const RULE_TYPE: Rule = Rule::field("beacons/type");
pub const RULE_GROUP: Rule = Rule::field("beacons/group");
pub const RULE_SIGNER: Rule = Rule::field("beacons/signer");
pub const RULE_N: Rule = Rule::field("beacons/n");
pub const RULE_TIME: Rule = Rule::field("beacons/time");
pub const RULE_DIGEST: Rule = Rule::field("beacons/digest");
pub const RULE_COUNT: Rule = Rule::field("beacons/count");

const FIELDS: [u16; 7] = [1, 2, 3, 4, 6, 10, 11];

/// A beacon read and checked.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Beacon {
    pub group: GroupId,
    /// The key hash of the admin device's member key.
    pub signer: KeyHash,
    pub n: u64,
    pub time_ms: u64,
    /// The set digest it saw (`records::digest`).
    pub digest: [u8; 32],
    /// How many records that set held.
    pub count: u64,
}

/// Signs a beacon with an admin device's member key.
pub fn sign(
    member: &dyn ExternalKey,
    group: &GroupId,
    n: u64,
    time_ms: u64,
    digest: &[u8; 32],
    count: u64,
) -> Result<Vec<u8>, Error> {
    let signer = Key::es256(member.public()).hash();
    let m: Vec<(u16, Value<'_>)> = alloc::vec![
        (1, Value::Uint(1)),
        (2, Value::Bytes(&group.0)),
        (3, Value::Bytes(&signer.0)),
        (4, Value::Uint(n)),
        (6, Value::Uint(time_ms)),
        (10, Value::Bytes(digest)),
        (11, Value::Uint(count)),
    ];
    let body = Value::Map(m).encode();
    let s = rkey::sign_es256(member, sig::LABEL_BEACON, &body)?;
    Ok(envelope::write(&body, &s, None))
}

fn fixed<const N: usize>(v: Option<&Value<'_>>, rule: Rule) -> Result<[u8; N], Rule> {
    v.and_then(Value::as_bytes).and_then(|b| b.try_into().ok()).ok_or(rule)
}

/// Reads a beacon's form: at most 512 bytes of body, no critical field 0.6
/// does not define (a beacon is never held), each field's row.
pub fn read(b: &[u8]) -> Result<(Beacon, Envelope<'_>), Rule> {
    let e = Envelope::parse_limited(b, MAX_BEACON)?;
    let m = &e.map;
    if m.as_map().unwrap_or(&[]).iter().any(|(k, _)| *k < 256 && !FIELDS.contains(k)) {
        return Err(Rule::FORM_CRITICAL);
    }
    sig::check_form(e.sig)?;
    if m.get(1).and_then(Value::as_uint) != Some(1) {
        return Err(RULE_TYPE);
    }
    let group = DeviceId(fixed(m.get(2), RULE_GROUP)?);
    let signer = KeyHash(fixed(m.get(3), RULE_SIGNER)?);
    let n = m.get(4).and_then(Value::as_uint).filter(|n| *n >= 1).ok_or(RULE_N)?;
    let time_ms = m.get(6).and_then(Value::as_uint).filter(|t| *t >= 1).ok_or(RULE_TIME)?;
    let digest = fixed(m.get(10), RULE_DIGEST)?;
    let count = m.get(11).and_then(Value::as_uint).filter(|c| (1..=MAX_COUNT).contains(c)).ok_or(RULE_COUNT)?;
    Ok((Beacon { group, signer, n, time_ms, digest, count }, e))
}

/// Reads a beacon and checks it against the state: of this group, signed
/// by the member key of a device whose admin key may command.
pub fn check(b: &[u8], state: &State) -> Result<Beacon, Rule> {
    let (beacon, e) = read(b)?;
    if beacon.group != state.group {
        return Err(RULE_GROUP);
    }
    let d = state.device_by_key(&beacon.signer).ok_or(RULE_SIGNER)?;
    let admin = d.admin.as_ref().ok_or(RULE_SIGNER)?;
    if d.frozen || !state.may_command(admin) || state.two_histories(&beacon.signer) {
        return Err(RULE_SIGNER);
    }
    e.verify(&d.key.public, sig::LABEL_BEACON)?;
    Ok(beacon)
}

/// Message `beacon` (t 22).
pub fn message(envelope: &[u8]) -> Result<Vec<u8>, Rule> {
    let v = cbor::decode(envelope)?;
    Ok(frame::write(&Value::Map(alloc::vec![(frame::FIELD_T, Value::Uint(T_BEACON)), (2, v)])))
}

/// The newest beacon of each admin a device took.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Beacons(pub BTreeMap<KeyHash, Beacon>);

/// What a device can tell of its records from the beacons it holds.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Freshness {
    /// The latest time an admin saw exactly the set this device holds.
    pub current_at_ms: Option<u64>,
    /// An admin saw more records, at a later time than that, than this
    /// device holds: it asks for them.
    pub behind: bool,
}

impl Beacons {
    /// Keeps a checked beacon when its `n` is above the signer's last one;
    /// reports whether it kept it.
    pub fn take(&mut self, b: Beacon) -> bool {
        if self.0.get(&b.signer).is_some_and(|old| b.n <= old.n) {
            return false;
        }
        self.0.insert(b.signer, b);
        true
    }

    /// Forgets the beacons of signers that are no longer witnesses.
    pub fn retain(&mut self, state: &State) {
        self.0
            .retain(|k, _| state.device_by_key(k).and_then(|d| d.admin.as_ref()).is_some_and(|a| state.may_command(a)));
    }

    /// How fresh a set with this digest and count is, by the beacons held.
    pub fn freshness(&self, digest: &[u8; 32], count: u64) -> Freshness {
        let current_at_ms = self.0.values().filter(|b| &b.digest == digest).map(|b| b.time_ms).max();
        let behind = self
            .0
            .values()
            .any(|b| &b.digest != digest && b.count > count && current_at_ms.is_none_or(|t| b.time_ms > t));
        Freshness { current_at_ms, behind }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::records::body::{AdminKind, RIGHT_READ, ROLE_MEMBER};
    use crate::testkit::{G, T0, k};

    #[test]
    fn an_admin_device_says_which_set_it_saw_and_when() {
        let mut g = G::new();
        g.device("laptop", ROLE_MEMBER, RIGHT_READ, |_| {});
        g.admin("phone", "phone admin", AdminKind::Phone);
        let state = g.state();
        let digest = g.set.digest();
        let count = g.set.len() as u64;
        let b = sign(&k("phone"), &g.gid, 1, T0, &digest, count).unwrap();
        let got = check(&b, &state).unwrap();
        assert_eq!((got.digest, got.count, got.time_ms), (digest, count, T0));
        assert!(message(&b).unwrap().len() <= 1024);
        // Not an admin's device, not a device, the admin key itself, another
        // group.
        for who in ["laptop", "stranger", "phone admin", "root"] {
            let b = sign(&k(who), &g.gid, 1, T0, &digest, count).unwrap();
            assert_eq!(check(&b, &state), Err(RULE_SIGNER), "{who}");
        }
        let other = sign(&k("phone"), &k("x").key.device_id(), 1, T0, &digest, count).unwrap();
        assert_eq!(check(&other, &state), Err(RULE_GROUP));
        // A frozen admin is no witness.
        let mut g2 = G::new();
        g2.admin("phone", "phone admin", AdminKind::Phone);
        g2.freeze(&[k("phone").hash]);
        let b = sign(&k("phone"), &g2.gid, 1, T0, &digest, count).unwrap();
        assert_eq!(check(&b, &g2.state()), Err(RULE_SIGNER));
    }

    #[test]
    fn beacon_rows() {
        let body =
            |f: Vec<(u16, Value<'_>)>| envelope::sign(&k("phone").sk, sig::LABEL_BEACON, &Value::Map(f).encode());
        let (g, s, d) = ([1u8; 16], k("phone").hash.0, [2u8; 32]);
        let base = |extra: Vec<(u16, Value<'static>)>| {
            let mut f = extra;
            f.extend([(1, Value::Uint(1)), (4, Value::Uint(1)), (6, Value::Uint(T0)), (11, Value::Uint(3))]);
            f
        };
        let full = |extra: Vec<(u16, Value<'static>)>| {
            let mut f = base(extra);
            f.push((2, Value::Bytes(&g)));
            f.push((3, Value::Bytes(&s)));
            f.push((10, Value::Bytes(&d)));
            f.sort_by_key(|(n, _)| *n);
            f.dedup_by_key(|(n, _)| *n);
            body(f)
        };
        assert!(read(&full(vec![])).is_ok());
        let pad: &'static [u8] = &[0; 600];
        for (name, extra, rule) in [
            ("type 2", vec![(1, Value::Uint(2))], RULE_TYPE),
            ("time 0", vec![(6, Value::Uint(0))], RULE_TIME),
            ("count 0", vec![(11, Value::Uint(0))], RULE_COUNT),
            ("count over a set", vec![(11, Value::Uint(MAX_COUNT + 1))], RULE_COUNT),
            ("n 0", vec![(4, Value::Uint(0))], RULE_N),
            ("digest of 31 bytes", vec![(10, Value::Bytes(&[0; 31]))], RULE_DIGEST),
            ("a later critical field", vec![(12, Value::Uint(1))], Rule::FORM_CRITICAL),
            ("over 512 bytes", vec![(300, Value::Bytes(pad))], Rule::ENV_SIZE),
        ] {
            assert_eq!(read(&full(extra)).err().map(|e| e.name()), Some(rule.name()), "{name}");
        }
    }

    #[test]
    fn beacons_tell_how_fresh_a_set_is() {
        let mut bs = Beacons::default();
        let b = |who: &str, n, t, d: u8, count| Beacon {
            group: k("root").key.device_id(),
            signer: k(who).hash,
            n,
            time_ms: t,
            digest: [d; 32],
            count,
        };
        assert!(bs.take(b("phone", 2, T0, 1, 10)));
        assert!(!bs.take(b("phone", 2, T0 + 5, 9, 10)), "n must rise");
        assert_eq!(bs.freshness(&[1; 32], 10), Freshness { current_at_ms: Some(T0), behind: false });
        // Another admin saw more records later.
        assert!(bs.take(b("desk", 1, T0 + 1000, 2, 11)));
        assert_eq!(bs.freshness(&[1; 32], 10), Freshness { current_at_ms: Some(T0), behind: true });
        assert_eq!(bs.freshness(&[3; 32], 12), Freshness { current_at_ms: None, behind: false });
        // A signer no longer a witness is forgotten.
        let mut g = G::new();
        g.admin("phone", "phone admin", AdminKind::Phone);
        bs.retain(&g.state());
        assert_eq!(bs.0.len(), 1);
    }
}
