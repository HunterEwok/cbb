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
    e.verify(d.key.public(), sig::LABEL_BEACON)?;
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

/// How far ahead of the receiver's clock a beacon's time may be.
pub const ALLOWANCE_MS: u64 = crate::copies::fresh::ALLOWANCE_MS;

/// How old a beacon may be, on the receiver's clock, and still say that
/// the receiver is behind: as old as a statement may be.
pub const MAX_AGE_MS: u64 = crate::copies::STATEMENT_MAX_AGE_MS;

/// What a device can tell of its records from the beacons it holds.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Freshness {
    /// The latest time an admin saw exactly the set this device holds.
    pub current_at_ms: Option<u64>,
    /// Some admin's newest beacon names another, larger set than this
    /// device holds: it asks for the records. Judged for each admin by its
    /// own beacon, so one admin's time never hides another's. A beacon
    /// dated at or before the newest checkpoint this device holds (unless
    /// that checkpoint is dated more than [`ALLOWANCE_MS`] ahead of its
    /// clock), or older than [`MAX_AGE_MS`] on its clock, does not count: a set before a
    /// checkpoint was larger, and a silent admin's old view says nothing of
    /// today's.
    pub behind: bool,
}

impl Beacons {
    /// Keeps a checked beacon when its `n` is above the signer's last one
    /// and, on a receiver with a clock, its time is not more than
    /// [`ALLOWANCE_MS`] ahead of it; reports whether it kept it.
    pub fn take(&mut self, b: Beacon, now_ms: Option<u64>) -> bool {
        if now_ms.is_some_and(|now| b.time_ms > now.saturating_add(ALLOWANCE_MS)) {
            return false;
        }
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

    /// How fresh a set with this digest and count is, by the beacons held,
    /// on the device's clock (None without one) and the time of the newest
    /// checkpoint it holds ([`checkpoint_ms`], 0 without one).
    pub fn freshness(&self, digest: &[u8; 32], count: u64, now_ms: Option<u64>, checkpoint_ms: u64) -> Freshness {
        let current_at_ms = self.0.values().filter(|b| &b.digest == digest).map(|b| b.time_ms).max();
        // A checkpoint dated more than the allowance ahead of the clock is
        // not used, as a beacon so dated is not taken.
        let checkpoint_ms = match now_ms {
            Some(now) if checkpoint_ms > now.saturating_add(ALLOWANCE_MS) => 0,
            _ => checkpoint_ms,
        };
        let recent = |b: &Beacon| {
            b.time_ms > checkpoint_ms && now_ms.is_none_or(|now| now.saturating_sub(b.time_ms) <= MAX_AGE_MS)
        };
        let behind = self.0.values().any(|b| &b.digest != digest && b.count > count && recent(b));
        Freshness { current_at_ms, behind }
    }
}

/// The time of the checkpoint that counts in these records, 0 without one.
pub fn checkpoint_ms(state: &State, set: &crate::records::set::RecordSet) -> u64 {
    state.checkpoint.as_ref().and_then(|id| set.get(id)).map_or(0, |r| r.body().time_ms)
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
        assert!(bs.take(b("phone", 2, T0, 1, 10), Some(T0)));
        assert!(!bs.take(b("phone", 2, T0 + 5, 9, 10), Some(T0)), "n must rise");
        assert_eq!(bs.freshness(&[1; 32], 10, Some(T0), 0), Freshness { current_at_ms: Some(T0), behind: false });
        // Another admin saw more records later.
        assert!(bs.take(b("desk", 1, T0 + 1000, 2, 11), Some(T0)));
        assert_eq!(bs.freshness(&[1; 32], 10, Some(T0), 0), Freshness { current_at_ms: Some(T0), behind: true });
        assert_eq!(bs.freshness(&[3; 32], 12, Some(T0), 0), Freshness { current_at_ms: None, behind: false });
        // A signer no longer a witness is forgotten.
        let mut g = G::new();
        g.admin("phone", "phone admin", AdminKind::Phone);
        bs.retain(&g.state());
        assert_eq!(bs.0.len(), 1);
    }

    /// A beacon dated ahead of the receiver's clock is not used, and each
    /// admin's evidence counts by itself, whatever the times of others.
    #[test]
    fn one_admins_time_never_hides_anothers_evidence() {
        let b = |who: &str, t, d: u8, count| Beacon {
            group: k("root").key.device_id(),
            signer: k(who).hash,
            n: 1,
            time_ms: t,
            digest: [d; 32],
            count,
        };
        let mut bs = Beacons::default();
        assert!(bs.take(b("phone", T0, 2, 11), Some(T0)));
        assert!(bs.freshness(&[1; 32], 10, Some(T0), 0).behind);
        // Far ahead of the clock: not taken.
        assert!(!bs.take(b("desk", T0 + ALLOWANCE_MS + 1, 1, 10), Some(T0)));
        assert!(bs.take(b("desk", T0 + ALLOWANCE_MS, 1, 10), Some(T0)));
        // A later beacon that saw this set does not hide the larger one.
        let f = bs.freshness(&[1; 32], 10, Some(T0), 0);
        assert_eq!(f, Freshness { current_at_ms: Some(T0 + ALLOWANCE_MS), behind: true });
        // Without a clock the time is not judged; the evidence still holds.
        let mut nc = Beacons::default();
        assert!(nc.take(b("desk", u64::MAX / 2, 1, 10), None));
        assert!(nc.take(b("phone", T0, 2, 11), None));
        assert!(nc.freshness(&[1; 32], 10, None, 0).behind);
    }

    /// An admin's beacon of a larger set stops counting once it is older
    /// than the checkpoint this device holds, or than the age of a set.
    #[test]
    fn behind_follows_the_newest_checkpoint_and_the_age_of_a_beacon() {
        let b = |who: &str, t, d: u8, count| Beacon {
            group: k("root").key.device_id(),
            signer: k(who).hash,
            n: 1,
            time_ms: t,
            digest: [d; 32],
            count,
        };
        let now = T0 + 90 * 86_400_000;
        let mut bs = Beacons::default();
        assert!(bs.take(b("watch", T0, 2, 50), Some(now)));
        // Ninety days old: says nothing of today's set, with a clock.
        assert!(!bs.freshness(&[1; 32], 10, Some(now), 0).behind);
        assert!(bs.freshness(&[1; 32], 10, Some(T0 + MAX_AGE_MS), 0).behind);
        // Without a clock, the checkpoint the device holds decides.
        assert!(bs.freshness(&[1; 32], 10, None, 0).behind);
        assert!(!bs.freshness(&[1; 32], 10, None, T0).behind);
        assert!(bs.freshness(&[1; 32], 10, None, T0 - 1).behind);
        // A checkpoint dated ahead of the clock beyond the allowance is not
        // used; within it, it is.
        let soon = T0 + 1000;
        assert!(bs.freshness(&[1; 32], 10, Some(soon), soon + 365 * 86_400_000).behind);
        assert!(!bs.freshness(&[1; 32], 10, Some(soon), soon + ALLOWANCE_MS).behind);
        // A newer beacon from the same admin counts again.
        assert!(bs.take(Beacon { n: 2, ..b("watch", T0 + 10, 3, 11) }, None));
        assert!(bs.freshness(&[1; 32], 10, None, T0).behind);
    }

    #[test]
    fn the_checkpoint_time_comes_from_the_records() {
        let mut g = G::new();
        assert_eq!(checkpoint_ms(&g.state(), &g.set), 0);
        g.device("laptop", ROLE_MEMBER, RIGHT_READ, |_| {});
        let cp = g.checkpoint(T0);
        let state = g.state();
        assert_eq!(state.checkpoint, Some(cp.id()));
        assert_eq!(checkpoint_ms(&state, &g.set), T0);
    }
}
