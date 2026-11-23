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

fn server(n: u8) -> Server {
    Server { pin: [n; 32], address: format!("server{n}.example:8764") }
}

/// Refreshes for the one server S and gives what was signed for it.
fn one(f: &Faces, state: &State, s: &Signers<'_>) -> Vec<Vec<u8>> {
    let got = f.refresh(state, s, &[server(7)]).unwrap();
    assert!(got.iter().all(|(srv, _)| *srv == server(7)), "a face of another server");
    got.into_iter().flat_map(|(_, e)| e).collect()
}

const S: [u8; 32] = [7; 32];

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
    let signed = one(&ra, &state, &Signers { member: &a, root: Some(&root), root_here: true, secret: ra.secret() });
    assert_eq!(signed.len(), 4, "the period, a's server key, the hubs' and the members' credentials");
    assert!(
        one(&ra, &state, &Signers { member: &a, root: Some(&root), root_here: true, secret: ra.secret() }).is_empty()
    );

    // b takes them all, then adds its own server key; it signs nothing else.
    let fb = Faces::open(&temp("b"), &state, quiet()).unwrap();
    assert_eq!(fb.add(&state, "a", &server(7), &signed).len(), 4);
    let mine = one(&fb, &state, &Signers { member: &b, root: None, root_here: false, secret: fb.secret() });
    assert_eq!(mine.len(), 1);
    assert_eq!(Credential::read(&mine[0]).unwrap().kind, TYPE_SERVER);

    // The root lists b in a new members' credential.
    assert_eq!(ra.add(&state, "b", &server(7), &mine).len(), 1);
    let more = one(&ra, &state, &Signers { member: &a, root: Some(&root), root_here: true, secret: ra.secret() });
    assert_eq!(more.len(), 1);
    let m = Credential::read(&more[0]).unwrap();
    assert_eq!(m.kind, TYPE_MEMBERS);
    assert_eq!(m.members.len(), 4, "padded");
    let kept = ra.kept(&S);
    assert!(kept.server_of(&hash_of(&b.public())).is_some_and(|h| m.members.contains(&h)));
    assert_eq!(fb.add(&state, "a", &server(7), &more).len(), 1);

    // The servers' keys differ by device and by period.
    let (pa, pb) = (kept.server_of(&hash_of(&a.public())).unwrap(), kept.server_of(&hash_of(&b.public())).unwrap());
    assert_ne!(pa, pb);

    // b leaves: its key goes, and the root starts a new period at once.
    assert!(!kept.period_due(&state, crate::uptime::wall_ms() as u64));
    assert!(kept.period_due(&without_b, crate::uptime::wall_ms() as u64));
    let old_tag = kept.tag();
    let next = one(&ra, &without_b, &Signers { member: &a, root: Some(&root), root_here: true, secret: ra.secret() });
    assert_eq!(next.len(), 4);
    let kept = ra.kept(&S);
    assert_ne!(kept.tag(), old_tag);
    assert_ne!(kept.server_of(&hash_of(&a.public())), Some(pa), "a new server key with the new tag");
    assert!(kept.server_of(&hash_of(&b.public())).is_none());
}

#[test]
fn what_is_not_the_groups_is_refused() {
    let (state, without_b) = group();
    let (root, a, b) = (k(1), k(2), k(3));
    let ra = Faces::open(&temp("refuse-root"), &state, quiet()).unwrap();
    let signed = one(&ra, &state, &Signers { member: &a, root: Some(&root), root_here: true, secret: ra.secret() });

    // A period signed by a member is no period of the group.
    let fake = Faces::open(&temp("refuse-fake"), &state, quiet()).unwrap();
    let not_root = one(&fake, &state, &Signers { member: &b, root: Some(&b), root_here: true, secret: fake.secret() });
    assert!(not_root.is_empty(), "the period does not count, so nothing follows it");
    let fresh = Faces::open(&temp("refuse-fresh"), &state, quiet()).unwrap();
    assert!(fresh.add(&state, "b", &server(7), &not_root).is_empty());

    // A server key of a device removed is refused.
    let fb = Faces::open(&temp("refuse-b"), &state, quiet()).unwrap();
    fb.add(&state, "a", &server(7), &signed);
    let mine = one(&fb, &state, &Signers { member: &b, root: None, root_here: false, secret: fb.secret() });
    assert!(ra.add(&without_b, "b", &server(7), &mine).is_empty());

    // The members' credential signed by a server key the hubs' credential
    // does not list among its admins is refused.
    let mut kept = ra.kept(&S);
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
    let signed = one(&ra, &state, &Signers { member: &a, root: Some(&root), root_here: true, secret: ra.secret() });
    let frames = Faces::messages(&server(7), &signed);
    assert_eq!(frames.len(), 1);
    let got = Faces::read_message(&frames[0][4..]).unwrap();
    assert_eq!(got, (server(7), signed.clone()));
    // Many server credentials go in several messages, the order kept.
    let many: Vec<Vec<u8>> = (0..MAX_CREDENTIALS + 5).map(|_| signed[1].clone()).collect();
    let frames = Faces::messages(&server(7), &many);
    assert!(frames.len() > 1);
    let back: Vec<Vec<u8>> = frames.iter().flat_map(|f| Faces::read_message(&f[4..]).unwrap().1).collect();
    assert_eq!(back, many);

    // Opened again: the same credentials, the same secret, and the root
    // keeps signing with its period key.
    let secret = *ra.secret();
    drop(ra);
    let again = Faces::open(&dir, &state, quiet()).unwrap();
    assert_eq!(again.kept(&S).envelopes(), signed);
    assert_eq!(again.secret(), &secret);
    let b = k(3);
    let fb = Faces::open(&temp("file-b"), &state, quiet()).unwrap();
    fb.add(&state, "a", &server(7), &signed);
    let mine = one(&fb, &state, &Signers { member: &b, root: None, root_here: false, secret: fb.secret() });
    again.add(&state, "b", &server(7), &mine);
    let more = one(&again, &state, &Signers { member: &a, root: Some(&root), root_here: true, secret: again.secret() });
    assert_eq!(more.len(), 1, "a new members' credential, no new period");
}

/// Each server gets a face of its own: another tag, another period key,
/// another version count and other server keys, so two servers that
/// compare what they saw find nothing in common.
#[test]
fn each_server_sees_another_face() {
    let (state, _) = group();
    let (root, a) = (k(1), k(2));
    let dir = temp("two");
    let ra = Faces::open(&dir, &state, quiet()).unwrap();
    let s = Signers { member: &a, root: Some(&root), root_here: true, secret: ra.secret() };
    let got = ra.refresh(&state, &s, &[server(7), server(8)]).unwrap();
    assert_eq!(
        got.iter().map(|(srv, e)| (srv.clone(), e.len())).collect::<Vec<_>>(),
        vec![(server(7), 4), (server(8), 4)]
    );
    let (x, y) = (ra.kept(&[7; 32]), ra.kept(&[8; 32]));
    assert_ne!(x.tag(), y.tag());
    let (px, py) = (x.period.as_ref().unwrap(), y.period.as_ref().unwrap());
    assert_ne!(px.c.key, py.c.key, "a period key for each face");
    assert_ne!(px.c.version, py.c.version, "versions from a random start for each face");
    let me = hash_of(&a.public());
    assert_ne!(x.server_of(&me), y.server_of(&me), "a server key for each face");
    for (srv, envs) in &got {
        for f in Faces::messages(srv, envs) {
            assert_eq!(Faces::read_message(&f[4..]).unwrap(), (srv.clone(), envs.clone()));
        }
    }
    assert_eq!(ra.servers(), vec![server(7), server(8)]);
    assert_eq!(ra.all_messages().len(), 2);

    // A server the root no longer lists keeps its face until it expires,
    // with no new period; the period keys of both stay on the root.
    assert!(ra.refresh(&state, &s, &[server(7)]).unwrap().is_empty());
    assert_eq!(ra.servers().len(), 2);
    let again = Faces::open(&dir, &state, quiet()).unwrap();
    assert_eq!(again.servers(), vec![server(7), server(8)]);
    assert_eq!(again.kept(&[8; 32]).envelopes(), y.envelopes());
}

/// A message that names no server is refused, and a member keeps at most
/// MAX_FACES faces.
#[test]
fn every_face_names_its_server() {
    let (state, _) = group();
    let (root, a) = (k(1), k(2));
    let ra = Faces::open(&temp("names"), &state, quiet()).unwrap();
    let signed = one(&ra, &state, &Signers { member: &a, root: Some(&root), root_here: true, secret: ra.secret() });
    let f = Faces::messages(&server(7), &signed).remove(0);
    let (_, v, _) = cbb_core::msg::read_noted(&f[4..]).unwrap();
    let without: Vec<(u16, Value<'_>)> = v.as_map().unwrap().iter().filter(|(k, _)| *k != 4).cloned().collect();
    let bare = frame::write(&Value::Map(without));
    let e = Faces::read_message(&bare[4..]).unwrap_err();
    assert!(e.to_string().contains("member-credentials/server"), "{e}");

    let many: Vec<Server> = (0..=MAX_FACES as u8).map(|i| server(100 + i)).collect();
    let rb = Faces::open(&temp("many"), &state, quiet()).unwrap();
    let got = rb
        .refresh(&state, &Signers { member: &a, root: Some(&root), root_here: true, secret: rb.secret() }, &many)
        .unwrap();
    assert_eq!(got.len(), MAX_FACES);
    assert_eq!(rb.servers().len(), MAX_FACES);
    let other = Faces::open(&temp("many-b"), &state, quiet()).unwrap();
    for (srv, envs) in &got {
        assert_eq!(other.add(&state, "a", srv, envs).len(), envs.len());
    }
    assert!(other.add(&state, "a", &server(9), &signed).is_empty(), "past MAX_FACES");
}

/// The hubs' credential lists the hubs in their order, the admins after the
/// root's hubs record, so an admin computer is listed, never a frozen one,
/// and never a phone, admin or not (D-134).
#[test]
fn the_hubs_listed_are_the_hub_order_without_the_frozen() {
    let root = k(1);
    let (k1, k2) = pq::recovery_keys(&[1; 32]).unwrap();
    let k1 = SigningKey::from(&k1).verifying_key().to_sec1_point(false).as_bytes().to_vec();
    let mut set = RecordSet::new(
        Key::es256(root.public()),
        Recovery::new(Key::es256(k1), Key::new(ALG_SLH_DSA, k2.public())).unwrap(),
    );
    let now = crate::uptime::wall_ms() as u64;
    for (key, name, role) in [
        (k(2), "a", body::ROLE_MEMBER),
        (k(3), "b", body::ROLE_MEMBER),
        (k(4), "c", body::ROLE_MEMBER),
        (k(7), "p", body::ROLE_PHONE),
    ] {
        let d = Device::new(Key::es256(key.public()), name, role);
        let st = set.state();
        set.write_record(&st, &root, Kind::device(d), now - 1000).unwrap();
    }
    crate::writers::make_admin(&mut set, &root, "a", &k(5).public(), now - 900).unwrap();
    crate::writers::make_admin(&mut set, &root, "b", &k(6).public(), now - 800).unwrap();
    crate::writers::make_admin(&mut set, &root, "p", &k(8).public(), now - 750).unwrap();
    crate::writers::freeze(&mut set, &root, "b", true, now - 700).unwrap();
    let st = set.state();
    let names: Vec<&str> = hub_devices(&st).iter().map(|d| d.name.as_str()).collect();
    assert_eq!(
        names,
        ["a"],
        "the admin computer, not the frozen admin, the computer that is no admin nor the admin phone"
    );
}
