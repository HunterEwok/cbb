// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! A leaf's grants over time (format section 7): the input picks a sequence
//! of signed grants (by the root the leaf knows, an older or newer root, a
//! commander, a stranger), changes of root, forks, a lost flag and bindings
//! in person by code, and feeds them to `grant::read` and
//! `grant::read_bound` as one leaf would. After every step the leaf's kept
//! state must hold what the module promises: a guarded leaf that waits to
//! be bound again takes nothing by `read`; a grant is taken only under the
//! recovery seq the leaf knows; the recovery seq never goes back; guarded
//! stays; a forked leaf takes nothing of that seq; a guarded leaf takes
//! grants from the root only; an old root grant is never taken again; a
//! binding takes only the new root's guarded grant, for this leaf.

#![no_main]

use cbb_core::format::envelope;
use cbb_core::format::grant::{self, Kept};
use cbb_core::format::sig;
use cbb_core::format::{Alg, DeviceId, Encoder, Key, KeyHash, Value, decode};
use cbb_core::join::invitation::JoinerAttempts;

use p256::ecdsa::SigningKey;
use std::sync::OnceLock;

struct K {
    sk: SigningKey,
    public: Vec<u8>,
}

impl K {
    fn key(&self) -> Key<'_> {
        Key { alg: Alg::Es256, public: &self.public }
    }
    fn hash(&self) -> KeyHash {
        self.key().hash()
    }
}

fn k(name: &str) -> K {
    let sk = SigningKey::from_slice(&cbb_core::certs::sha256(name.as_bytes())).unwrap();
    let public = sk.verifying_key().to_sec1_point(false).as_bytes().to_vec();
    K { sk, public }
}

// 0..=3: the roots under recovery seq 0..=3; 4: a commander (an admin);
// 5: another commander; 6: a stranger.
const ROOTS: usize = 4;
const ADMIN: usize = 4;
const PHONE: usize = 5;
const STRANGER: usize = 6;

fn keys() -> &'static Vec<K> {
    static KS: OnceLock<Vec<K>> = OnceLock::new();
    KS.get_or_init(|| {
        ["root", "new root 1", "new root 2", "new root 3", "admin", "phone", "stranger"].iter().map(|n| k(n)).collect()
    })
}

const GROUP: DeviceId = DeviceId([7; 16]);

fn leaf() -> DeviceId {
    k("lock").key().device_id()
}

struct Bytes<'a>(&'a [u8]);
impl Bytes<'_> {
    fn next(&mut self) -> Option<u8> {
        let (b, rest) = self.0.split_first()?;
        self.0 = rest;
        Some(*b)
    }
    fn byte(&mut self) -> u8 {
        self.next().unwrap_or(0)
    }
}

/// What a grant says, before it is signed.
struct Spec {
    by: usize,
    counter: u64,
    recovery: u64,
    guarded: bool,
    commanders: u8,
    life: Option<u64>,
    root_counter: Option<u64>,
    replaces: Option<[u8; 32]>,
    other_leaf: bool,
    other_group: bool,
}

fn message(s: &Spec) -> Vec<u8> {
    let ks = keys();
    let by = ks[s.by].hash();
    let lf = if s.other_leaf { DeviceId([9; 16]) } else { leaf() };
    let grp = if s.other_group { DeviceId([8; 16]) } else { GROUP };
    let mut cmd: Vec<Key<'_>> = Vec::new();
    for (bit, i) in [(1u8, ADMIN), (2, PHONE), (4, STRANGER)] {
        if s.commanders & bit != 0 {
            cmd.push(ks[i].key());
        }
    }
    cmd.sort_by_key(|k| k.hash().0);
    let mut m = vec![
        (1u16, Value::Uint(1)),
        (2, Value::Bytes(&grp.0)),
        (3, Value::Bytes(&by.0)),
        (4, Value::Uint(s.counter)),
        (10, Value::Bytes(&lf.0)),
    ];
    if let Some(l) = s.life {
        m.push((11, Value::Uint(l)));
    }
    m.push((12, Value::Array(cmd.iter().map(Key::to_value).collect())));
    if s.guarded {
        m.push((15, Value::Uint(1)));
    }
    if let Some(r) = s.root_counter {
        m.push((17, Value::Uint(r)));
    }
    let rep;
    if let Some(h) = s.replaces {
        rep = h;
        m.push((18, Value::Bytes(&rep)));
    }
    if s.recovery > 0 {
        m.push((19, Value::Uint(s.recovery)));
    }
    let env = envelope::sign(&ks[s.by].sk, sig::LABEL_GRANT, &Value::Map(m).encode());
    let mut e = Encoder::new();
    e.map(1).uint(2).raw(&env);
    e.finish()
}

/// The leaf: what it keeps and the newest recovery seq it knows.
struct Leaf {
    kept: Option<Kept>,
    rec: u64,
    ever_guarded: bool,
    max_rec: u64,
}

impl Leaf {
    fn root(&self) -> &'static K {
        &keys()[self.rec as usize]
    }

    /// The invariants after a step.
    fn check(&mut self) {
        if let Some(k) = &self.kept {
            if self.ever_guarded {
                assert!(k.guarded, "guarded did not stay");
            }
            self.ever_guarded |= k.guarded;
            assert!(k.recovery >= self.max_rec, "the kept recovery seq went back");
            self.max_rec = k.recovery;
        }
    }

    /// Takes a grant by `read`, checking what may be taken.
    fn read(&mut self, msg: &[u8], spec: Option<&Spec>) {
        let Ok(v) = decode(msg) else { return };
        let before = self.kept.clone();
        let root = self.root();
        let Ok(got) = grant::read(&v, &root.public, &leaf(), &GROUP, before.as_ref(), self.rec) else { return };
        if let Some(b) = &before {
            assert!(!b.needs_rebind(self.rec), "read took a grant for a leaf that waits to be bound again");
            assert!(!(b.forked && b.recovery == self.rec), "a forked leaf took a grant of its seq");
            if b.guarded {
                assert!(got.by_root, "a guarded leaf took a grant not by the root");
            }
            if got.by_root && b.recovery == got.recovery && b.root_counter > 0 {
                assert!(got.counter > b.root_counter, "an old root grant was taken again");
            }
            if !got.by_root && b.recovery == got.recovery {
                if let Some(h) = spec.map(|s| keys()[s.by].hash()) {
                    assert!(b.commander(&h).is_some(), "an admin grant by a key that is not a commander was taken");
                }
            }
        } else if !got.by_root {
            assert!(got.admin.is_some(), "a first grant by an admin without the root's record of it");
        }
        assert_eq!(got.recovery, self.rec, "a grant of another recovery seq was taken");
        if let Some(s) = spec {
            assert_eq!(got.by_root, s.by == self.rec as usize, "by_root names the wrong signer");
            assert!(!s.other_leaf && !s.other_group, "a grant for another leaf or group was taken");
        }
        if std::env::var_os("FZ_TRACE").is_some() {
            eprintln!("read took: by_root={} counter={} rec={}", got.by_root, got.counter, got.recovery);
        }
        self.kept = Some(got.keep(before.as_ref()));
    }

    /// The newest recovery head the leaf verified: the root it knows under
    /// its seq, none before any change.
    fn head(&self) -> Option<(KeyHash, u64)> {
        (self.rec > 0).then(|| (self.root().hash(), self.rec))
    }

    /// A binding in person by code: the pairing session's code step, the
    /// person's answer, the binding made from the leaf's stored state, and
    /// the grant read over a session (`how`: bit 0 the person said they do
    /// not match, bit 1 the binding asked with another session's exporter,
    /// bit 2 the grant came over another session, bit 3 the session's key
    /// is another device's).
    fn bound(&mut self, msg: &[u8], spec: &Spec, how: u8) {
        let Some(before) = self.kept.clone() else { return };
        let (ex, other_ex) = ([0x11u8; 32], [0x22u8; 32]);
        let mut tries = JoinerAttempts::default();
        let Ok((code, _)) = tries.start() else { return };
        let local = if how & 8 != 0 { DeviceId([9; 16]) } else { leaf() };
        let member: [u8; 65] = keys()[PHONE].public.as_slice().try_into().unwrap();
        let Ok((_, _, shown)) = tries.open(code, &ex, &[0; 32], None, local, &member) else { return };
        let Some(matched) = tries.answered(shown, how & 1 == 0) else {
            assert!(how & 1 != 0, "no answer for codes that match");
            return;
        };
        let head = self.head();
        let Some(binding) = matched.binding(&before, head, if how & 2 != 0 { &other_ex } else { &ex }) else {
            assert!(how & 2 != 0 || before.start(head).rebind.is_none(), "no binding for a leaf that waits");
            return;
        };
        assert!(how & 3 == 0, "a binding from an answer of no match or of another session");
        let Ok(v) = decode(msg) else { return };
        let root = self.root();
        let grant_ex = if how & 4 != 0 { &other_ex } else { &ex };
        let Ok(got) =
            grant::read_bound(&v, &root.public, &leaf(), &GROUP, Some(&before), self.rec, binding, grant_ex)
        else {
            return;
        };
        let (want_root, want_rec) = before.start(head).rebind.unwrap();
        assert_eq!(want_root, root.hash(), "a binding took a grant for a root other than the one the leaf waits for");
        assert_eq!(want_rec, self.rec, "a binding took a grant under another recovery seq");
        assert!(how & 8 == 0, "a binding made for another device was taken");
        assert!(how & 4 == 0, "a bound grant that came over another session was taken");
        assert!(got.by_root && got.guarded && got.recovery == self.rec, "a binding took a grant that is not the new root's guarded one");
        assert_eq!(spec.by, self.rec as usize, "a binding took a grant by another key");
        if std::env::var_os("FZ_TRACE").is_some() {
            eprintln!("binding took: counter={} rec={}", got.counter, got.recovery);
        }
        let kept = got.keep(Some(&before.start(head)));
        assert!(!kept.needs_rebind(self.rec), "the leaf still waits after its binding");
        self.kept = Some(kept);
    }

    /// A restart: the leaf writes its state with the newest head and reads
    /// it back; what it starts with is what it would have had.
    fn restart(&mut self) {
        let Some(k) = self.kept.clone() else { return };
        let head = self.head();
        let st = grant::Stored::new(k.clone(), head, None);
        let bytes = st.encode();
        let back = grant::Stored::load(Some(&bytes));
        assert!(!back.update_needed(), "a state this version wrote reads as a later one");
        let (kept, rec) = back.start();
        let want = k.start(head);
        if grant::Stored::decode(&bytes).is_err() {
            // The reader takes only what a writer makes; a state the leaf
            // reached by the readers must be one of them.
            panic!("a state the leaf reached does not read back: {k:?} head {head:?}");
        }
        assert_eq!(kept, want, "a restart changed the kept state");
        assert_eq!(rec, self.rec.max(k.recovery), "a restart changed the recovery seq the leaf knows");
        self.kept = Some(kept);
    }
}

fn spec(b: &mut Bytes<'_>, l: &Leaf) -> Spec {
    let x = b.byte();
    let y = b.byte();
    let by = match x & 7 {
        0..=2 => l.rec as usize,
        3 => (l.rec as usize + 1).min(ROOTS - 1),
        4 => (l.rec as usize).saturating_sub(1),
        5 => ADMIN,
        6 => PHONE,
        _ => STRANGER,
    };
    let rec = match (x >> 3) & 3 {
        0 | 1 => l.rec,
        2 => l.rec + 1,
        _ => l.rec.saturating_sub(1),
    };
    let kept = l.kept.as_ref();
    let rc = kept.map_or(0, |k| k.root_counter);
    Spec {
        by,
        counter: match y & 3 {
            0 => rc + 1,
            1 => kept.map_or(1, |k| k.admin_counter + 1),
            2 => rc,
            _ => u64::from(b.byte()),
        },
        recovery: rec,
        guarded: x & 0x20 != 0,
        commanders: (y >> 2) & 7,
        life: if y & 0x20 != 0 { Some(u64::from(b.byte()) * 86_400 / 4) } else { None },
        root_counter: if y & 0x40 != 0 { Some(rc) } else { None },
        replaces: if y & 0x80 != 0 { Some(kept.map_or([0; 32], |k| k.grant_hash)) } else { None },
        other_leaf: x & 0x40 != 0 && x & 0x80 != 0,
        other_group: x & 0x80 != 0 && x & 0x40 == 0 && y & 1 == 1,
    }
}

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let mut b = Bytes(data);
    let mut l = Leaf { kept: None, rec: 0, ever_guarded: false, max_rec: 0 };
    let mut steps = 0;
    let mut last: Vec<u8> = Vec::new();
    while let Some(op) = b.next() {
        steps += 1;
        if steps > 24 {
            break;
        }
        match op % 8 {
            0..=2 => {
                let s = spec(&mut b, &l);
                let m = message(&s);
                l.read(&m, Some(&s));
                last = m;
            }
            3 => {
                // A change of root the leaf verified.
                if (l.rec as usize) < ROOTS - 1 {
                    l.rec += 1;
                    let h = l.root().hash();
                    l.kept = l.kept.as_ref().map(|k| k.changed(h, l.rec));
                }
            }
            4 => {
                // A fork of the root the leaf keeps.
                l.kept = l.kept.as_ref().map(|k| k.fork(l.rec));
            }
            5 => {
                let s = spec(&mut b, &l);
                let m = message(&s);
                let how = b.byte() & 0x0f;
                l.bound(&m, &s, if op & 0x80 == 0 { 0 } else { how });
                last = m;
            }
            6 => {
                if op & 0x80 != 0 {
                    l.restart();
                } else if let Some(k) = &mut l.kept {
                    // The leaf lost its waiting flag (a restart that kept less).
                    k.rebind = None;
                }
            }
            _ => {
                // A grant changed in flight: never taken whatever it says.
                if !last.is_empty() {
                    let i = usize::from(b.byte()) % last.len();
                    last[i] ^= 1 << (b.byte() & 7);
                    let before = l.kept.clone();
                    if let Ok(v) = decode(&last) {
                        let root = l.root();
                        if let Ok(got) = grant::read(&v, &root.public, &leaf(), &GROUP, before.as_ref(), l.rec) {
                            // A flip in the signature or the signed body must
                            // not verify; a flip outside the envelope may.
                            assert_eq!(got.recovery, l.rec, "a changed grant of another seq was taken");
                        }
                    }
                }
            }
        }
        l.check();
    }
});
