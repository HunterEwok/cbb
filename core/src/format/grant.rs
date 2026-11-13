// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! A leaf's grant (format section 7): one signed envelope `[body, sig]`,
//! label `cbb grant v1`, like every other signed thing.
//!
//! Every grant lists the leaf's `commanders`, and a leaf of either kind
//! obeys exactly those keys: an ordinary leaf's are admin keys, a guarded
//! leaf's the devices the root named. The root signs any grant; for an
//! ordinary leaf a key among the commanders of the leaf's current grant
//! signs one too, and the first grant comes from the admitter with the
//! root's record of that admin key. A guarded leaf takes grants from the
//! root only. The leaf keeps two counters, the root's and the admins', so a
//! root grant replaces an admin grant whatever the admin counter is, and an
//! old root grant is never taken again. An admin grant names the root
//! counter it was made under (field 17) and counts its own from 1 again
//! after each root grant, so one made before a root grant never beats it.
//! A later admin grant also names the grant it replaces (field 18, the
//! SHA-256 of the kept grant's body), so an older one held back is never
//! taken after a newer one.
//!
//! Every grant names the recovery seq it was made under (field 19): the
//! seq of the newest recovery head (records rule 33) its signer held,
//! absent before any change of root. A leaf takes a grant only of the
//! recovery seq it knows as the newest, and never goes back to a lower one;
//! a change starts its counters and commanders afresh.
//!
//! A guarded leaf that takes a change of root obeys nobody until it is
//! bound again in person, by code, by the new root ([`Kept::changed`],
//! [`read_bound`]): [`read`] takes no grant for it, the new root's
//! included, and a kept grant made under a lower recovery seq than the one
//! the leaf knows means the same, whatever the leaf remembers: it takes
//! no command either (`commands::accept_leaf` asks [`Kept::needs_rebind`]
//! of the recovery seq the leaf knows). An ordinary leaf follows a change
//! of root: it takes the new root's grant.
//!
//! A leaf stores the newest recovery head it verified apart from its kept
//! state, so a power cut between the two writes can leave a head newer than
//! the kept state. At every start, before it reads a grant or a command,
//! it calls [`Kept::start`] with that head; and since a leaf that skips it
//! must still neither obey nor be stuck, the commands ask the recovery seq
//! itself, and a binding ([`Binding`]) and [`read_bound`] apply the head
//! themselves.
//!
//! Two different records signed by the root the leaf keeps at one seq are
//! a fork of that root (records rule 9): the leaf takes the pair from
//! anyone ([`fork`]), stops obeying that root ([`Kept::fork`]) and takes no
//! grant again until one made under a higher recovery seq.

use alloc::vec::Vec;

use super::cbor::{self, Value, is_set};
use super::envelope::Envelope;
use super::key::{Alg, DeviceId, GroupId, Key, KeyHash};
use super::{Rule, sha256, sig};

/// The largest grant body: 4 KiB, room for 16 commanders and 16 readers
/// and a later second key's fields, inside the leaf's 16 KiB frame.
pub const MAX_GRANT: usize = 4096;

/// Message `grant`'s field of the grant envelope.
pub const FIELD_GRANT: u16 = 2;
/// Message `grant`'s field of the root's record of the admin that signed
/// the leaf's first grant.
pub const FIELD_ADMIN: u16 = 3;

/// The grant's field of its counter.
pub const FIELD_COUNTER: u16 = 4;
/// The grant's field of its lifetime (a guarded leaf's only).
pub const FIELD_LIFE: u16 = 11;
/// The grant's field of the keys the leaf obeys.
pub const FIELD_COMMANDERS: u16 = 12;
/// The grant's field of its readers.
pub const FIELD_READERS: u16 = 13;
/// The grant's flag of a guarded leaf.
pub const FIELD_GUARDED: u16 = 15;
/// An admin grant's field of the root counter it was made under (absent:
/// 0, before any root grant); a root grant has none.
pub const FIELD_ROOT_COUNTER: u16 = 17;
/// An admin grant's field of the grant it replaces: the SHA-256 of the
/// body of the leaf's kept grant (every admin grant but the first).
pub const FIELD_REPLACES: u16 = 18;
/// The grant's field of the recovery seq it was made under (absent: 0,
/// before any change of root).
pub const FIELD_RECOVERY: u16 = 19;
/// The highest recovery seq: the records' one constant (records rule 33).
pub const MAX_RECOVERY: u64 = crate::records::body::MAX_RECOVERY;
/// The grant's field of its type (1).
pub const FIELD_TYPE: u16 = 1;
/// The grant's field of its group.
pub const FIELD_GROUP: u16 = 2;
/// The grant's field of its leaf's device ID.
pub const FIELD_LEAF: u16 = 10;
/// The fields of a grant below the optional zone (256): any other is a
/// critical field this version does not know, and `signer2` (8) is one.
pub const FIELDS: [u16; 15] = [1, 2, 3, 4, 6, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19];
/// The longest lifetime of a guarded grant: 40 days.
pub const MAX_LIFE_MS: u64 = 3_456_000_000;
/// The most readers of a leaf (format 20.6).
pub const MAX_READERS: usize = 16;
/// The most commanders of a leaf (format 20.6).
pub const MAX_COMMANDERS: usize = 16;
/// The grant's field of the only peers the leaf connects with.
pub const FIELD_NEIGHBORS: u16 = 14;
/// The most neighbours of a leaf.
pub const MAX_NEIGHBORS: usize = 8;
/// Neighbours that are not a list of at most eight key hashes (bytes 32)
/// in a set.
pub const RULE_NEIGHBORS: Rule = Rule::field("grants/neighbors");

/// A guarded leaf's grant that a root did not sign, or a grant without
/// `guarded` for a leaf that is guarded.
pub const RULE_GUARDED: Rule = Rule::field("grants/guarded");
/// More than eight commanders, one that is not an ES256 Key, or commanders
/// out of order.
pub const RULE_COMMANDERS: Rule = Rule::field("grants/commanders");
/// A lifetime in an ordinary leaf's grant, or a guarded grant's lifetime
/// that is not an integer from 1 to 40 days.
pub const RULE_LIFE: Rule = Rule::field("grants/life");
/// Readers that are not a list of at most four `[device ID, ES256 Key]` in
/// a set.
pub const RULE_READERS: Rule = Rule::field("grants/readers");
/// An admin's first grant without the root's record of that admin key, or
/// with one that does not make it an admin that admits.
pub const RULE_ADMIN: Rule = Rule::field("grants/admin");
/// A later grant signed by a key that is neither the root nor among the
/// commanders of the leaf's current grant.
pub const RULE_SIGNER: Rule = Rule::field("grants/signer");
/// A counter not above the leaf's last of its signer's side (the root's or
/// the admins'), an admin grant made under another root counter than the
/// leaf's, or a root grant that names one.
pub const RULE_COUNTER: Rule = Rule::field("grants/counter");

/// An admin grant after the first that does not name the leaf's kept grant
/// as the one it replaces, or a root grant or a first grant that names one.
pub const RULE_REPLACES: Rule = Rule::field("grants/replaces");

/// A grant made under another recovery seq than the newest the leaf knows,
/// one above MAX_RECOVERY, or a leaf asked to read grants under a recovery seq below
/// the one it kept.
pub const RULE_RECOVERY: Rule = Rule::field("grants/recovery");

/// Two records that are not a fork of the leaf's root: not two different
/// records of this group, both signed by that root at one seq.
pub const RULE_FORK: Rule = Rule::field("grants/fork");

/// A grant to a leaf that holds a fork of its root, made under the
/// recovery seq it kept.
pub const RULE_FORKED: Rule = Rule::field("grants/forked");

/// A grant to a guarded leaf by any way but a binding in person by code
/// after it took a change of root, or a binding that does not commit to
/// this root, this leaf and this recovery seq.
pub const RULE_REBIND: Rule = Rule::field("grants/rebind");

/// A commander: its key hash and its uncompressed point.
pub type Commander = (KeyHash, [u8; 65]);

/// What a leaf keeps of the grants it took.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Kept {
    /// Whether the leaf is guarded; once it is, it stays so.
    pub guarded: bool,
    /// The counter of the last root grant, 0 before the first.
    pub root_counter: u64,
    /// The counter of the last admin grant since the last root grant, 0
    /// before the first.
    pub admin_counter: u64,
    /// The commanders of the current grant, sorted by key hash.
    pub commanders: Vec<Commander>,
    /// The SHA-256 of the current grant's body.
    pub grant_hash: [u8; 32],
    /// The recovery seq the current grant was made under.
    pub recovery: u64,
    /// Whether the leaf holds a fork of the root under that recovery seq:
    /// it then obeys nobody and takes no grant of that seq.
    pub forked: bool,
    /// Whether the leaf, guarded, took a change of root, and the new
    /// root's key hash and recovery seq from the head it verified: it obeys
    /// nobody and takes a grant only by a binding in person by code
    /// ([`read_bound`]).
    pub rebind: Option<(KeyHash, u64)>,
}

impl Kept {
    /// The leaf's state once it verified a fork of its root ([`fork`]),
    /// the root it knows under recovery seq `recovery` (the newest it
    /// knows, whatever seq its kept grant was made under): its grant is
    /// over, as at a change of root; guarded stays, and only a grant made
    /// under a higher recovery seq is taken again.
    pub fn fork(&self, recovery: u64) -> Kept {
        Kept {
            guarded: self.guarded,
            recovery: recovery.max(self.recovery),
            forked: true,
            rebind: self.rebind,
            ..Kept::default()
        }
    }

    /// The leaf's state once it verified a change of root to the root
    /// with key hash `root` under recovery seq `recovery`: a guarded leaf's
    /// grant is over, it obeys nobody and waits to be bound again in person
    /// by that root ([`read_bound`]); an ordinary leaf keeps what it has
    /// until the new root's grant comes, as its kept grant of a lower
    /// recovery seq counts as none.
    pub fn changed(&self, root: KeyHash, recovery: u64) -> Kept {
        let newer = recovery > self.rebind.map_or(self.recovery, |(_, seq)| seq.max(self.recovery));
        if !self.guarded || !newer {
            return self.clone();
        }
        Kept { guarded: true, recovery: self.recovery, rebind: Some((root, recovery)), ..Kept::default() }
    }

    /// The leaf's state at a start, from what it stored: its kept state and
    /// the newest recovery head it verified, the head's new root key hash
    /// and recovery seq (none before any change of root). It is
    /// [`Kept::changed`] by that head, so a head stored without the kept
    /// state that should have followed it counts all the same. A leaf calls
    /// it at every start, before it reads anything.
    pub fn start(&self, head: Option<(KeyHash, u64)>) -> Kept {
        head.map_or_else(|| self.clone(), |(root, recovery)| self.changed(root, recovery))
    }

    /// Whether the leaf, knowing `recovery` as the newest recovery seq,
    /// waits to be bound again in person: it is guarded and took a change
    /// of root, or keeps a grant made under a lower seq. The second needs
    /// nothing remembered, so a leaf that lost the flag still waits.
    pub fn needs_rebind(&self, recovery: u64) -> bool {
        self.guarded && (self.rebind.is_some() || self.recovery < recovery)
    }

    /// The point of the commander with this key hash: the keys the leaf
    /// obeys, and for an ordinary leaf the keys that may sign its next
    /// grant.
    pub fn commander(&self, hash: &KeyHash) -> Option<&[u8; 65]> {
        self.commanders.iter().find(|(h, _)| h == hash).map(|(_, p)| p)
    }
}

/// A malformed stored leaf state ([`Stored::decode`]): not a map of the
/// fields below in their one spelling, another version, or a critical
/// field this version does not know.
pub const RULE_STATE: Rule = Rule::field("grants/state");

/// A stored leaf state of a later version, or with a recovery seq above
/// this version's [`MAX_RECOVERY`]: the firmware needs an update.
pub const RULE_STATE_NEWER: Rule = Rule::field("grants/state-newer");

/// The version of the stored leaf state's encoding.
pub const STATE_VERSION: u64 = 1;

/// What a leaf stores across restarts, in one write: its kept state and the
/// newest recovery head it verified (the head's new root key hash and
/// recovery seq). Its one reader is [`Stored::start`], which applies the
/// head ([`Kept::start`]), so a leaf cannot take the kept state without it.
///
/// The bytes ([`Stored::encode`]) are a canonical CBOR map, every field in
/// its one spelling (a default is left out): 1 the version (1), 2 guarded
/// (flag), 3 the root counter, 4 the admin counter, 5 the commanders
/// (`[key hash, point]` sorted by key hash, at most eight), 6 the grant's
/// hash (bytes 32), 7 the recovery seq of the grant, 8 forked (flag), 9 the
/// wait to be bound again (`[root key hash, recovery seq]`), 10 the newest
/// head (`[root key hash, recovery seq]`). Fields from 256 on are a later
/// version's: kept as they are and written back; another field below 256
/// is refused. Recovery seqs are 1 to [`MAX_RECOVERY`].
///
/// The reader takes only what a writer makes: the wait (9) only on a
/// guarded leaf, the wait and the fork (8) only without a grant (no
/// commanders, counters or grant hash), commanders and counters only with
/// a grant hash, and the head (10) at or above every other seq.
///
/// A leaf loads its state with [`Stored::load`] and never treats bytes
/// that are there and do not read as no state: they give
/// [`Stored::unreadable`], which obeys nobody and takes no grant until the
/// leaf is set up again in person. A state of a later version, or with a
/// recovery seq above this version's [`MAX_RECOVERY`], is the same, with
/// [`Stored::update_needed`]. The bytes go in the store's frames
/// (`crate::store`), which are required, not a convenience: two slots keep
/// the last whole copy while the next is written, and the SHA-256 of each
/// frame catches a torn write or a flipped bit, so a cut write gives the
/// older state and never a freed lock.
///
/// The named limit: the state is not signed or authenticated at rest.
/// Whoever can write the leaf's flash owns the leaf: the bytes of before a
/// change of root, put back whole, read, and the leaf obeys the old
/// commanders again, which a MAC would not stop (they carry a right one
/// too). Only the chip guards against it: flash encryption, secure boot
/// and a counter in hardware are the firmware's.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Stored {
    kept: Kept,
    head: Option<(KeyHash, u64)>,
    later: Vec<(u16, Vec<u8>)>,
    update: bool,
}

impl Stored {
    /// What the leaf stores once it took `kept`, knowing `head` as the
    /// newest recovery head; a later version's fields of `before` stay.
    pub fn new(kept: Kept, head: Option<(KeyHash, u64)>, before: Option<&Stored>) -> Stored {
        Stored { kept, head, later: before.map(|b| b.later.clone()).unwrap_or_default(), update: false }
    }

    /// The state of a leaf whose store holds bytes that do not read: guarded
    /// and forked under the highest recovery seq, so it obeys nobody, takes
    /// no grant by [`read`] or [`read_bound`] and can be bound by no root,
    /// until it is set up again in person. Never written.
    pub fn unreadable(update: bool) -> Stored {
        let kept = Kept { guarded: true, forked: true, recovery: MAX_RECOVERY, ..Kept::default() };
        Stored { kept, head: None, later: Vec::new(), update }
    }

    /// The leaf's state from its store: `None` when the store holds no state
    /// at all (a leaf never set up, or erased on purpose), the bytes of the
    /// newest whole frame otherwise. Bytes that do not read are never no
    /// state ([`Stored::unreadable`]).
    pub fn load(bytes: Option<&[u8]>) -> Stored {
        match bytes {
            None => Stored::default(),
            Some(b) => Stored::decode(b).unwrap_or_else(|r| Stored::unreadable(r == RULE_STATE_NEWER)),
        }
    }

    /// Whether the state is of a later version than this firmware reads:
    /// the leaf obeys nobody until it is updated.
    pub fn update_needed(&self) -> bool {
        self.update
    }

    /// The leaf's kept state at a start ([`Kept::start`] by the stored head)
    /// and the newest recovery seq it knows, for `commands::Leaf` and the
    /// grant readers.
    pub fn start(&self) -> (Kept, u64) {
        let recovery = self.head.map_or(self.kept.recovery, |(_, seq)| seq.max(self.kept.recovery));
        (self.kept.start(self.head), recovery)
    }

    /// The newest recovery head the leaf stored.
    pub fn head(&self) -> Option<(KeyHash, u64)> {
        self.head
    }

    pub fn encode(&self) -> Vec<u8> {
        let k = &self.kept;
        fn pair((h, seq): &(KeyHash, u64)) -> Value<'_> {
            Value::Array(alloc::vec![Value::Bytes(&h.0), Value::Uint(*seq)])
        }
        let later: Vec<(u16, Value<'_>)> =
            self.later.iter().filter_map(|(n, b)| cbor::decode(b).ok().map(|v| (*n, v))).collect();
        let mut m = alloc::vec![(1u16, Value::Uint(STATE_VERSION))];
        if k.guarded {
            m.push((2, Value::Uint(1)));
        }
        for (n, v) in [(3u16, k.root_counter), (4, k.admin_counter)] {
            if v > 0 {
                m.push((n, Value::Uint(v)));
            }
        }
        if !k.commanders.is_empty() {
            let cs = k.commanders.iter().map(|(h, p)| Value::Array(alloc::vec![Value::Bytes(&h.0), Value::Bytes(p)]));
            m.push((5, Value::Array(cs.collect())));
        }
        if k.grant_hash != [0; 32] {
            m.push((6, Value::Bytes(&k.grant_hash)));
        }
        if k.recovery > 0 {
            m.push((7, Value::Uint(k.recovery)));
        }
        if k.forked {
            m.push((8, Value::Uint(1)));
        }
        if let Some(r) = &k.rebind {
            m.push((9, pair(r)));
        }
        if let Some(h) = &self.head {
            m.push((10, pair(h)));
        }
        m.extend(later);
        Value::Map(m).encode()
    }

    pub fn decode(b: &[u8]) -> Result<Stored, Rule> {
        let v = cbor::decode(b).map_err(|_| RULE_STATE)?;
        let map = v.as_map().ok_or(RULE_STATE)?;
        match v.get(1).and_then(Value::as_uint) {
            Some(STATE_VERSION) => {}
            Some(n) if n > STATE_VERSION => return Err(RULE_STATE_NEWER),
            _ => return Err(RULE_STATE),
        }
        if map.iter().any(|(n, _)| *n < 256 && *n > 10) {
            return Err(Rule::FORM_CRITICAL);
        }
        let flag = |n| match v.get(n) {
            None => Ok(false),
            Some(Value::Uint(1)) => Ok(true),
            Some(_) => Err(RULE_STATE),
        };
        let count = |n| match v.get(n) {
            None => Ok(0),
            Some(Value::Uint(0)) => Err(Rule::FORM_DEFAULT),
            Some(x) => x.as_uint().ok_or(RULE_STATE),
        };
        let hash = |x: &Value<'_>| x.as_bytes().and_then(KeyHash::from_slice).ok_or(RULE_STATE);
        let pair = |n| -> Result<Option<(KeyHash, u64)>, Rule> {
            let Some(x) = v.get(n) else { return Ok(None) };
            match x.as_array() {
                Some([h, Value::Uint(seq)]) if (1..=MAX_RECOVERY).contains(seq) => Ok(Some((hash(h)?, *seq))),
                Some([_, Value::Uint(seq)]) if *seq > MAX_RECOVERY => Err(RULE_STATE_NEWER),
                _ => Err(RULE_STATE),
            }
        };
        let mut commanders: Vec<Commander> = Vec::new();
        if let Some(cs) = v.get(5) {
            let cs = cs.as_array().filter(|cs| !cs.is_empty() && cs.len() <= MAX_COMMANDERS).ok_or(RULE_STATE)?;
            for c in cs {
                let Some([h, p]) = c.as_array() else { return Err(RULE_STATE) };
                let point: [u8; 65] = p.as_bytes().and_then(|p| p.try_into().ok()).ok_or(RULE_STATE)?;
                let h = hash(h)?;
                if Key::new(Alg::Es256, &point).hash() != h || commanders.last().is_some_and(|(last, _)| *last >= h) {
                    return Err(RULE_STATE);
                }
                commanders.push((h, point));
            }
        }
        let grant_hash = match v.get(6) {
            None => [0; 32],
            Some(x) => {
                x.as_bytes().and_then(|b| <[u8; 32]>::try_from(b).ok()).filter(|h| *h != [0; 32]).ok_or(RULE_STATE)?
            }
        };
        let recovery = count(7)?;
        if recovery > MAX_RECOVERY {
            return Err(RULE_STATE_NEWER);
        }
        let kept = Kept {
            guarded: flag(2)?,
            root_counter: count(3)?,
            admin_counter: count(4)?,
            commanders,
            grant_hash,
            recovery,
            forked: flag(8)?,
            rebind: pair(9)?,
        };
        let head = pair(10)?;
        // Only what a writer makes: the wait on a guarded leaf, the wait and
        // the fork without a grant, a grant's parts with its hash, the head
        // at or above every other seq.
        let k = &kept;
        let has_grant = k.grant_hash != [0; 32];
        let grant_parts = !k.commanders.is_empty() || k.root_counter > 0 || k.admin_counter > 0;
        let seqs_ok = head.is_none_or(|(_, h)| h >= k.recovery && k.rebind.is_none_or(|(_, r)| h >= r));
        if (k.rebind.is_some() && !k.guarded)
            || ((k.rebind.is_some() || k.forked) && (has_grant || grant_parts))
            || (grant_parts && !has_grant)
            || !seqs_ok
        {
            return Err(RULE_STATE);
        }
        let later = map.iter().filter(|(n, _)| *n >= 256).map(|(n, x)| (*n, x.encode())).collect();
        let stored = Stored { kept, head, later, update: false };
        // One spelling: the bytes are the ones this state writes.
        if stored.encode() != b {
            return Err(RULE_STATE);
        }
        Ok(stored)
    }
}

/// A grant as message `grant` carries it, checked to its signature, its
/// kind and the leaf's kept state.
#[derive(Clone, Debug)]
pub struct Granted<'a> {
    /// The grant envelope; its body is the grant.
    pub grant: Envelope<'a>,
    /// The root's record of the admin that signed the leaf's first grant.
    pub admin: Option<Envelope<'a>>,
    /// Whether the root signed it.
    pub by_root: bool,
    /// Whether the grant is a guarded leaf's.
    pub guarded: bool,
    /// Its counter.
    pub counter: u64,
    /// Its commanders.
    pub commanders: Vec<Commander>,
    /// The recovery seq it was made under.
    pub recovery: u64,
}

impl Granted<'_> {
    /// The leaf's state once it takes this grant.
    pub fn keep(&self, before: Option<&Kept>) -> Kept {
        // A change of root starts the counters afresh; guarded stays.
        let b = before.filter(|k| k.recovery == self.recovery).cloned().unwrap_or_default();
        let guarded = before.is_some_and(|k| k.guarded);
        Kept {
            guarded: guarded || self.guarded,
            root_counter: if self.by_root { self.counter } else { b.root_counter },
            admin_counter: if self.by_root { 0 } else { self.counter },
            commanders: self.commanders.clone(),
            grant_hash: sha256(&[self.grant.body]),
            recovery: self.recovery,
            forked: false,
            rebind: None,
        }
    }
}

/// A binding in person by code: made only by the leaf's own pairing
/// session once the person said its code matches
/// (`crate::join::invitation::Matched::binding`), for that session alone; no
/// message carries it, it is never built from values a caller passes, and
/// it is not kept past the session or a restart. It holds what the leaf
/// knows by itself: the new root's key hash and the recovery seq from the
/// head it verified ([`Kept::rebind`]) and its own device ID, the one of
/// its TLS key in that session.
#[derive(Debug, PartialEq, Eq)]
pub struct Binding {
    root: KeyHash,
    leaf: DeviceId,
    recovery: u64,
    session: [u8; 32],
}

/// The mark of a pairing session: the hash of its TLS exporter, which is
/// local to the session's two ends and new for each session.
pub fn session_mark(exporter: &[u8]) -> [u8; 32] {
    sha256(&[b"cbb pairing session mark v1\0", exporter])
}

impl Binding {
    /// The binding a session of the leaf `leaf` makes once the person said
    /// the codes match, from the leaf's stored state ([`Kept::start`]):
    /// none unless it waits to be bound again.
    pub(crate) fn matched(
        kept: &Kept,
        head: Option<(KeyHash, u64)>,
        leaf: DeviceId,
        session: [u8; 32],
    ) -> Option<Binding> {
        kept.start(head).rebind.map(|(root, recovery)| Binding { root, leaf, recovery, session })
    }
}

/// Reads a grant as [`read`] does, for a leaf bound in person by code:
/// the binding must commit to this root, this leaf and `recovery`, and to
/// the wait the kept state holds (with the head `root` under `recovery`
/// applied, [`Kept::start`]), so a binding made before a later change of
/// root clears nothing. It is the only way a guarded leaf that took a
/// change of root takes a grant again; the grant must be the root's,
/// guarded, under `recovery`, and it starts the counters afresh. The
/// binding is taken by value: one binding reads one grant, and only one
/// that came over the very pairing session whose code the person
/// confirmed: `exporter` is the TLS exporter of the session the grant
/// arrived on, and a grant by sync or by another session is refused.
#[allow(clippy::too_many_arguments, reason = "the grant, the leaf's state and the session it came on")]
pub fn read_bound<'a>(
    msg: &Value<'a>,
    root: &[u8],
    leaf: &DeviceId,
    group: &GroupId,
    kept: Option<&Kept>,
    recovery: u64,
    binding: Binding,
    exporter: &[u8],
) -> Result<Granted<'a>, Rule> {
    let root_hash = Key::new(Alg::Es256, root).hash();
    if binding.root != root_hash
        || binding.leaf != *leaf
        || binding.recovery != recovery
        || !crate::secret::ct_eq(&binding.session, &session_mark(exporter))
    {
        return Err(RULE_REBIND);
    }
    let kept = kept.map(|k| k.start(Some((root_hash, recovery))));
    if kept.as_ref().and_then(|k| k.rebind) != Some((binding.root, binding.recovery)) {
        return Err(RULE_REBIND);
    }
    let got = read_any(msg, root, leaf, group, kept.as_ref(), recovery, true)?;
    if !(got.by_root && got.guarded) {
        return Err(RULE_REBIND);
    }
    Ok(got)
}

/// The admin key of the root's record in field 3, if it makes that key an
/// admin with `admit`: a `device` record (type 1) the root signed, with its
/// `admin` Key (20) and the admit bit in its `powers` (21).
fn admin_key(record: &Envelope<'_>, root: &[u8], group: &GroupId) -> Result<[u8; 65], Rule> {
    use crate::records::{Body, Kind, key::ALG_ES256};
    record.verify(root, sig::LABEL_RECORD).map_err(|_| RULE_ADMIN)?;
    // Read by the record reader itself (section 4.1): a device record of
    // this group that a reader would apply, not hold.
    if record.sig2.is_some() || record.body.len() > crate::records::MAX_BODY {
        return Err(RULE_ADMIN);
    }
    let body = Body::from_value(&record.map).map_err(|_| RULE_ADMIN)?;
    if body.check().map_err(|_| RULE_ADMIN)? || body.held {
        return Err(RULE_ADMIN);
    }
    let Kind::Device(d) = &body.kind else { return Err(RULE_ADMIN) };
    let by_root = body.signer == Key::new(Alg::Es256, root).hash();
    let admits = d.powers & crate::records::body::POWER_ADMIT != 0;
    let admin = d.admin.as_ref().ok_or(RULE_ADMIN)?;
    let points =
        [&d.key, admin].iter().all(|k| k.alg() == ALG_ES256 && Key::new(Alg::Es256, k.public()).check().is_ok());
    if !(body.group == *group && by_root && admits && points) {
        return Err(RULE_ADMIN);
    }
    admin.public().to_vec().try_into().map_err(|_| RULE_ADMIN)
}

/// The commanders of a grant body: at most eight ES256 Keys, sorted by key
/// hash, each once.
fn commanders(map: &Value<'_>) -> Result<Vec<Commander>, Rule> {
    let list = match map.get(FIELD_COMMANDERS) {
        None => return Ok(Vec::new()),
        Some(v) => v.as_array().ok_or(RULE_COMMANDERS)?,
    };
    if list.len() > MAX_COMMANDERS {
        return Err(RULE_COMMANDERS);
    }
    let mut out: Vec<Commander> = Vec::with_capacity(list.len());
    for x in list {
        let k = Key::from_value(x).map_err(|_| RULE_COMMANDERS)?;
        if k.alg != Alg::Es256 || k.check().is_err() {
            return Err(RULE_COMMANDERS);
        }
        let h = k.hash();
        if out.last().is_some_and(|(prev, _)| prev.0 >= h.0) {
            return Err(RULE_COMMANDERS);
        }
        out.push((h, k.public.try_into().map_err(|_| RULE_COMMANDERS)?));
    }
    Ok(out)
}

/// Reads a grant from the map of message `grant` (or the Welcome's `grant`)
/// for the leaf `leaf` of group `group` that keeps `kept` (None before its
/// first grant) and knows `recovery` as the newest recovery seq (0 before
/// any change of root), whose root `root` is then: field 2 the grant
/// envelope, 3 the root's record of the admin that signed a first grant.
///
/// The grant must name `recovery` (field 19), and `recovery` must not be
/// below the kept grant's. A kept grant of a lower recovery seq counts as
/// none, but a guarded leaf stays guarded.
///
/// The grant must be of type 1, for this group and this leaf, with no
/// critical field this version does not know (`signer2` among them). A root
/// grant is checked with the root's uncompressed point and must be above
/// the kept root counter. Any other grant is an ordinary leaf's: the first
/// one signed by an admin key that the record in field 3 makes an admin
/// with `admit`; a later one by a commander of the kept grant, made under
/// the kept root counter, above the kept admin counter, naming the kept
/// grant as the one it replaces. Then the rules of the two kinds of leaf
/// (design-small-device section 15): a lifetime only in a guarded grant and
/// within 40 days; at most eight commanders, four readers
/// `[device ID, Key]` and eight neighbours, each list a set.
///
/// A guarded leaf that waits to be bound again ([`Kept::needs_rebind`])
/// takes no grant here ([`RULE_REBIND`]): only [`read_bound`].
pub fn read<'a>(
    msg: &Value<'a>,
    root: &[u8],
    leaf: &DeviceId,
    group: &GroupId,
    kept: Option<&Kept>,
    recovery: u64,
) -> Result<Granted<'a>, Rule> {
    read_any(msg, root, leaf, group, kept, recovery, false)
}

fn read_any<'a>(
    msg: &Value<'a>,
    root: &[u8],
    leaf: &DeviceId,
    group: &GroupId,
    kept: Option<&Kept>,
    recovery: u64,
    bound: bool,
) -> Result<Granted<'a>, Rule> {
    let grant = Envelope::from_value(msg.get(FIELD_GRANT).ok_or(Rule::GRANTS_SHAPE)?)?;
    if grant.body.len() > MAX_GRANT {
        return Err(Rule::ENV_SIZE);
    }
    let map = &grant.map;
    if map
        .as_map()
        .unwrap_or(&[])
        .iter()
        .any(|(k, _)| *k < 256 && *k != crate::format::envelope::FIELD_SIGNER2 && !FIELDS.contains(k))
    {
        return Err(Rule::FORM_CRITICAL);
    }
    // A second signature is taken on the first alone, which covers it.
    crate::format::envelope::signer2(map, Rule::field("grants/signer2"))?;
    let bytes_of = |field| map.get(field).and_then(Value::as_bytes);
    if map.get(FIELD_TYPE).and_then(Value::as_uint) != Some(1)
        || bytes_of(FIELD_GROUP) != Some(group.0.as_slice())
        || bytes_of(FIELD_LEAF) != Some(leaf.0.as_slice())
    {
        return Err(Rule::GRANTS_SHAPE);
    }
    let made_after = match map.get(FIELD_RECOVERY) {
        None => 0,
        Some(Value::Uint(0)) => return Err(Rule::FORM_DEFAULT),
        Some(v) => v.as_uint().ok_or(Rule::GRANTS_SHAPE)?,
    };
    if made_after != recovery || recovery > MAX_RECOVERY || kept.is_some_and(|k| k.recovery > recovery) {
        return Err(RULE_RECOVERY);
    }
    if kept.is_some_and(|k| k.forked && k.recovery == recovery) {
        return Err(RULE_FORKED);
    }
    if !bound && kept.is_some_and(|k| k.needs_rebind(recovery)) {
        return Err(RULE_REBIND);
    }
    let was_guarded = kept.is_some_and(|k| k.guarded);
    let kept = kept.filter(|k| k.recovery == recovery);
    let signer = grant.signer().and_then(Value::as_bytes).and_then(KeyHash::from_slice).ok_or(Rule::GRANTS_SHAPE)?;
    let counter = map.get(FIELD_COUNTER).and_then(Value::as_uint).ok_or(Rule::GRANTS_SHAPE)?;
    let guarded = match map.get(FIELD_GUARDED) {
        None => false,
        Some(Value::Uint(1)) => true,
        Some(_) => return Err(Rule::field("grants/guarded-value")),
    };
    let by_root = signer == Key::new(Alg::Es256, root).hash();
    let made_under = match map.get(FIELD_ROOT_COUNTER) {
        None => 0,
        Some(Value::Uint(0)) => return Err(Rule::FORM_DEFAULT),
        Some(v) => v.as_uint().ok_or(Rule::GRANTS_SHAPE)?,
    };
    let replaces = match map.get(FIELD_REPLACES) {
        None => None,
        Some(v) => Some(v.as_bytes().filter(|b| b.len() == 32).ok_or(RULE_REPLACES)?),
    };
    let mut admin = None;
    if by_root {
        grant.verify(root, sig::LABEL_GRANT)?;
        if map.get(FIELD_ROOT_COUNTER).is_some() || kept.is_some_and(|k| counter <= k.root_counter) {
            return Err(RULE_COUNTER);
        }
        if replaces.is_some() {
            return Err(RULE_REPLACES);
        }
    } else {
        if guarded || was_guarded {
            return Err(RULE_GUARDED);
        }
        if made_under != kept.map_or(0, |k| k.root_counter) {
            return Err(RULE_COUNTER);
        }
        match kept {
            None => {
                let record = Envelope::from_value(msg.get(FIELD_ADMIN).ok_or(RULE_ADMIN)?)?;
                let key = admin_key(&record, root, group)?;
                if Key::new(Alg::Es256, &key).hash() != signer {
                    return Err(RULE_ADMIN);
                }
                grant.verify(&key, sig::LABEL_GRANT)?;
                if replaces.is_some() {
                    return Err(RULE_REPLACES);
                }
                admin = Some(record);
            }
            Some(k) => {
                let point = k.commander(&signer).ok_or(RULE_SIGNER)?;
                grant.verify(point, sig::LABEL_GRANT)?;
                if counter <= k.admin_counter {
                    return Err(RULE_COUNTER);
                }
                if replaces != Some(k.grant_hash.as_slice()) {
                    return Err(RULE_REPLACES);
                }
            }
        }
    }
    if was_guarded && !guarded {
        return Err(RULE_GUARDED);
    }
    match (guarded, map.get(FIELD_LIFE)) {
        (_, None) => {}
        (true, Some(Value::Uint(n))) if (1..=MAX_LIFE_MS).contains(n) => {}
        _ => return Err(RULE_LIFE),
    }
    let commanders = commanders(map)?;
    let list = |field, rule| match map.get(field) {
        None => Ok(&[][..]),
        Some(v) => v.as_array().ok_or(rule),
    };
    let readers = list(FIELD_READERS, RULE_READERS)?;
    let reader_ok = |r: &Value<'_>| match r.as_array() {
        Some([Value::Bytes(id), k]) => Key::from_value(k)
            .is_ok_and(|k| k.alg == Alg::Es256 && k.check().is_ok() && k.device_id().0.as_slice() == *id),
        _ => false,
    };
    if readers.len() > MAX_READERS || !is_set(readers) || !readers.iter().all(reader_ok) {
        return Err(RULE_READERS);
    }
    let neighbors = list(FIELD_NEIGHBORS, RULE_NEIGHBORS)?;
    let neighbor_ok = |n: &Value<'_>| n.as_bytes().is_some_and(|b| b.len() == 32);
    if neighbors.len() > MAX_NEIGHBORS || !is_set(neighbors) || !neighbors.iter().all(neighbor_ok) {
        return Err(RULE_NEIGHBORS);
    }
    Ok(Granted { grant, admin, by_root, guarded, counter, commanders, recovery })
}

/// Checks the proof of a fork of the root `root` (its uncompressed point)
/// that a leaf of group `group` is handed: two record envelopes `a` and `b`
/// of this group, both signed by that root at one seq, with different
/// bodies (two record IDs; one body under another signature is the same
/// record). It gives that seq. A leaf takes it from anyone, before any
/// check of who speaks, rate limited like a recovery head, and then keeps
/// [`Kept::fork`] with the recovery seq it knows its root under.
pub fn fork(a: &[u8], b: &[u8], root: &[u8], group: &GroupId) -> Result<u64, Rule> {
    use crate::records::{Key as RecordKey, Record};
    let key = RecordKey::es256(root.to_vec());
    let signer = Key::new(Alg::Es256, root).hash();
    let read = |env: &[u8]| -> Result<Record, Rule> {
        let r = Record::decode(env).map_err(|_| RULE_FORK)?;
        if r.body().group != *group || r.body().signer != signer {
            return Err(RULE_FORK);
        }
        Ok(r)
    };
    let (a, b) = (read(a)?, read(b)?);
    if a.body().seq != b.body().seq || a.id() == b.id() {
        return Err(RULE_FORK);
    }
    // The signatures last: what is no pair costs no verification.
    for r in [&a, &b] {
        r.verify(&key).map_err(|_| RULE_FORK)?;
    }
    Ok(a.body().seq)
}

/// A copy to a leaf from a device its grant does not let send it copies.
pub const RULE_COPY_SENDER: Rule = Rule::field("copy/leaf-sender");

/// Whether a leaf takes a copy whose header names origin, by the grant it
/// keeps (owner, 2026-11-11): an ordinary leaf takes copies from its readers
/// (field 13, `[device ID, Key]`), the same devices it seals to; a guarded
/// leaf only from its commanders (field 12, Keys), whose device IDs are
/// their keys' IDs.
pub fn copy_sender(grant: &Value<'_>, origin: &DeviceId) -> Result<(), Rule> {
    let list = |field| grant.get(field).and_then(Value::as_array).unwrap_or(&[]);
    let named = if grant.get(FIELD_GUARDED).is_some() {
        list(FIELD_COMMANDERS).iter().any(|k| Key::from_value(k).is_ok_and(|k| k.device_id() == *origin))
    } else {
        list(FIELD_READERS)
            .iter()
            .any(|r| r.as_array().and_then(|a| a.first()).and_then(Value::as_bytes) == Some(origin.0.as_slice()))
    };
    if named { Ok(()) } else { Err(RULE_COPY_SENDER) }
}
