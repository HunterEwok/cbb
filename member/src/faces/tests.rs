// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

use cbb_core::records::body::{self, Device};
use cbb_core::records::{Kind, RecordSet, Recovery, key::ALG_SLH_DSA, pq};
use p256::ecdsa::signature::hazmat::PrehashSigner as _;

use super::*;

struct K(SigningKey);

impl ExternalKey for K {
    fn public(&self) -> Vec<u8> {
        self.0.verifying_key().to_sec1_point(false).as_bytes().to_vec()
    }
    fn sign_digest(&self, digest: &[u8; 32]) -> cbb_core::error::Result<Vec<u8>> {
        let sig: p256::ecdsa::Signature = self.0.sign_prehash(digest).unwrap();
        Ok(sig.to_der().as_bytes().to_vec())
    }
}

fn k(b: u8) -> K {
    K(SigningKey::from_slice(&[b; 32]).unwrap())
}

fn temp(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("cbb-faces-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn quiet() -> Arc<dyn Fn(&str) + Send + Sync> {
    Arc::new(|_| {})
}

/// A group of root key 1 with devices a (key 2) and b (key 3), and the
/// state once b is removed.
fn group() -> (State, State) {
    let root = k(1);
    let (k1, k2) = pq::recovery_keys(&[1; 32]).unwrap();
    let k1 = SigningKey::from(&k1).verifying_key().to_sec1_point(false).as_bytes().to_vec();
    let mut set = RecordSet::new(
        Key::es256(root.public()),
        Recovery::new(Key::es256(k1), Key::new(ALG_SLH_DSA, k2.public())).unwrap(),
    );
    let now = crate::uptime::wall_ms() as u64;
    for (key, name) in [(k(2), "a"), (k(3), "b")] {
        let d = Device::new(Key::es256(key.public()), name, body::ROLE_MEMBER);
        let st = set.state();
        set.write_record(&st, &root, Kind::device(d), now - 1000).unwrap();
    }
    let both = set.state();
    let st = set.state();
    set.write_removal(&st, &root, &[hash_of(&k(3).public())], now - 500).unwrap();
    (both, set.state())
}

#[test]
fn the_root_starts_a_period_and_members_add_their_keys() {
    let (state, without_b) = group();
    let (root, a, b) = (k(1), k(2), k(3));
    let ra = Faces::open(&temp("root"), &state, quiet()).unwrap();
    let signed = ra.refresh(&state, &Signers { member: &a, root: Some(&root), secret: ra.secret() }).unwrap();
    assert_eq!(signed.len(), 4, "the period, a's server key, the hubs' and the members' credentials");
    assert!(ra.refresh(&state, &Signers { member: &a, root: Some(&root), secret: ra.secret() }).unwrap().is_empty());

    // b takes them all, then adds its own server key; it signs nothing else.
    let fb = Faces::open(&temp("b"), &state, quiet()).unwrap();
    assert_eq!(fb.add(&state, "a", &signed).len(), 4);
    let mine = fb.refresh(&state, &Signers { member: &b, root: None, secret: fb.secret() }).unwrap();
    assert_eq!(mine.len(), 1);
    assert_eq!(Credential::read(&mine[0]).unwrap().kind, TYPE_SERVER);

    // The root lists b in a new members' credential.
    assert_eq!(ra.add(&state, "b", &mine).len(), 1);
    let more = ra.refresh(&state, &Signers { member: &a, root: Some(&root), secret: ra.secret() }).unwrap();
    assert_eq!(more.len(), 1);
    let m = Credential::read(&more[0]).unwrap();
    assert_eq!(m.kind, TYPE_MEMBERS);
    assert_eq!(m.members.len(), 4, "padded");
    let kept = ra.kept();
    assert!(kept.server_of(&hash_of(&b.public())).is_some_and(|h| m.members.contains(&h)));
    assert_eq!(fb.add(&state, "a", &more).len(), 1);

    // The servers' keys differ by device and by period.
    let (pa, pb) = (kept.server_of(&hash_of(&a.public())).unwrap(), kept.server_of(&hash_of(&b.public())).unwrap());
    assert_ne!(pa, pb);

    // b leaves: its key goes, and the root starts a new period at once.
    assert!(!kept.period_due(&state, crate::uptime::wall_ms() as u64));
    assert!(kept.period_due(&without_b, crate::uptime::wall_ms() as u64));
    let old_tag = kept.tag();
    let next = ra.refresh(&without_b, &Signers { member: &a, root: Some(&root), secret: ra.secret() }).unwrap();
    assert_eq!(next.len(), 4);
    let kept = ra.kept();
    assert_ne!(kept.tag(), old_tag);
    assert_ne!(kept.server_of(&hash_of(&a.public())), Some(pa), "a new server key with the new tag");
    assert!(kept.server_of(&hash_of(&b.public())).is_none());
}

#[test]
fn what_is_not_the_groups_is_refused() {
    let (state, without_b) = group();
    let (root, a, b) = (k(1), k(2), k(3));
    let ra = Faces::open(&temp("refuse-root"), &state, quiet()).unwrap();
    let signed = ra.refresh(&state, &Signers { member: &a, root: Some(&root), secret: ra.secret() }).unwrap();

    // A period signed by a member is no period of the group.
    let fake = Faces::open(&temp("refuse-fake"), &state, quiet()).unwrap();
    let not_root = fake.refresh(&state, &Signers { member: &b, root: Some(&b), secret: fake.secret() }).unwrap();
    assert!(not_root.is_empty(), "the period does not count, so nothing follows it");
    let fresh = Faces::open(&temp("refuse-fresh"), &state, quiet()).unwrap();
    assert!(fresh.add(&state, "b", &not_root).is_empty());

    // A server key of a device removed is refused.
    let fb = Faces::open(&temp("refuse-b"), &state, quiet()).unwrap();
    fb.add(&state, "a", &signed);
    let mine = fb.refresh(&state, &Signers { member: &b, root: None, secret: fb.secret() }).unwrap();
    assert!(ra.add(&without_b, "b", &mine).is_empty());

    // The members' credential signed by a server key the hubs' credential
    // does not list among its admins is refused.
    let mut kept = ra.kept();
    let tag = kept.tag().unwrap();
    let (d, _) = alias::server_key(fb.secret(), &tag);
    let c = Credential { members: vec![[9; 32]], version: 1 << 62, ..Credential::read(&signed[3]).unwrap() };
    let env = c.sign(&ServerKey::from_scalar(&d).unwrap()).unwrap();
    assert!(kept.add(&state, &env, crate::uptime::wall_ms() as u64).is_err());

    // An older version of what is kept is not new.
    assert!(!kept.add(&state, &signed[0], crate::uptime::wall_ms() as u64).unwrap());
}

#[test]
fn messages_carry_them_and_the_file_keeps_them() {
    let (state, _) = group();
    let (root, a) = (k(1), k(2));
    let dir = temp("file");
    let ra = Faces::open(&dir, &state, quiet()).unwrap();
    let signed = ra.refresh(&state, &Signers { member: &a, root: Some(&root), secret: ra.secret() }).unwrap();
    let frames = Faces::messages(&signed);
    assert_eq!(frames.len(), 1);
    let got = Faces::read_message(&frames[0][4..]).unwrap();
    assert_eq!(got, signed);
    // Many server credentials go in several messages, the order kept.
    let many: Vec<Vec<u8>> = (0..MAX_CREDENTIALS + 5).map(|_| signed[1].clone()).collect();
    let frames = Faces::messages(&many);
    assert!(frames.len() > 1);
    let back: Vec<Vec<u8>> = frames.iter().flat_map(|f| Faces::read_message(&f[4..]).unwrap()).collect();
    assert_eq!(back, many);

    // Opened again: the same credentials, the same secret, and the root
    // keeps signing with its period key.
    let secret = *ra.secret();
    drop(ra);
    let again = Faces::open(&dir, &state, quiet()).unwrap();
    assert_eq!(again.kept().envelopes(), signed);
    assert_eq!(again.secret(), &secret);
    let b = k(3);
    let fb = Faces::open(&temp("file-b"), &state, quiet()).unwrap();
    fb.add(&state, "a", &signed);
    let mine = fb.refresh(&state, &Signers { member: &b, root: None, secret: fb.secret() }).unwrap();
    again.add(&state, "b", &mine);
    let more = again.refresh(&state, &Signers { member: &a, root: Some(&root), secret: again.secret() }).unwrap();
    assert_eq!(more.len(), 1, "a new members' credential, no new period");
}
