// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use cbb_core::alpn;
use cbb_core::identity::ExternalKey;
use cbb_core::join::invitation::{Path, PathKind, Profile};
use cbb_core::join::welcome::Welcome;
use cbb_core::records::body::{self, Device};
use cbb_core::records::{Key, Kind, RecordSet, Recovery, key::ALG_SLH_DSA, pq};
use cbb_core::tls::{Session, bykey};
use p256::ecdsa::SigningKey;
use p256::ecdsa::signature::hazmat::PrehashSigner as _;

use super::*;

struct K(SigningKey);

impl K {
    fn new(n: u8) -> K {
        K(SigningKey::from_slice(&[n; 32]).unwrap())
    }
    fn point(&self) -> [u8; 65] {
        self.0.verifying_key().to_sec1_point(false).as_bytes().try_into().unwrap()
    }
    fn key(&self) -> Key {
        Key::es256(self.point().to_vec())
    }
    fn pkcs8(&self) -> Vec<u8> {
        use p256::pkcs8::EncodePrivateKey as _;
        self.0.to_pkcs8_der().unwrap().as_bytes().to_vec()
    }
}

impl ExternalKey for K {
    fn public(&self) -> Vec<u8> {
        self.point().to_vec()
    }
    fn sign_digest(&self, digest: &[u8; 32]) -> cbb_core::error::Result<Vec<u8>> {
        let sig: p256::ecdsa::Signature = self.0.sign_prehash(digest).unwrap();
        Ok(sig.to_der().as_bytes().to_vec())
    }
}

const NOW: u64 = 1_793_000_000_000;

/// A group whose root key the member device "laptop" (key 2) holds.
fn group(root: &K, laptop: &K) -> RecordSet {
    let (k1, k2) = pq::recovery_keys(&[1; 32]).unwrap();
    let k1 = SigningKey::from(&k1).verifying_key().to_sec1_point(false).as_bytes().to_vec();
    let mut set =
        RecordSet::new(root.key(), Recovery::new(Key::es256(k1), Key::new(ALG_SLH_DSA, k2.public())).unwrap());
    let mut d = Device::new(laptop.key(), "laptop", body::ROLE_PHONE);
    d.rights = body::RIGHT_READ | body::RIGHT_SEND | body::RIGHT_SECRETS;
    d.holds_root = true;
    let st = set.state();
    set.write_record(&st, root, Kind::device(d), NOW - 10).unwrap();
    set
}

fn invitation() -> Invitation {
    Invitation::new(
        vec![Path { kind: PathKind::Home, endpoints: vec![], hub_key: None, guest: None, obfuscation: None }],
        Profile {
            role: body::ROLE_MEMBER,
            rights: body::RIGHT_READ | body::RIGHT_SEND,
            home_only: false,
            guarded: false,
        },
    )
}

/// One pairing over TLS of `cbb-pair/3`: the laptop admits tv (key 3)
/// with its root key. Gives the joiner's result, the member's, and the
/// member's set.
#[allow(clippy::type_complexity)]
fn pair(
    joiner_says: bool,
    member_says: bool,
    joiner_invitation: Option<Invitation>,
    open: Option<Open>,
) -> (Result<Box<Admitted>>, Result<Info>, RecordSet, Option<Open>) {
    let (root, laptop, tv) = (Arc::new(K::new(1)), K::new(2), K::new(3));
    let set = Arc::new(Mutex::new(group(&root, &laptop)));
    let clock = crate::tls::clock();
    let (scfg, sx) = bykey::exporting_server(
        bykey::server(&bykey::OwnKey::pkcs8(&laptop.pkcs8()).unwrap(), bykey::any_key(), alpn::PAIR, &clock).unwrap(),
    );
    let (ccfg, cx) = bykey::exporting_client(
        bykey::client(&bykey::OwnKey::pkcs8(&tv.pkcs8()).unwrap(), None, bykey::any_key(), alpn::PAIR, &clock).unwrap(),
    );
    let ln = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = ln.local_addr().unwrap();
    let (laptop_point, laptop_hash) = (laptop.point(), laptop.key().hash());
    let member_set = set.clone();
    let server = std::thread::spawn(move || {
        let (sock, _) = ln.accept().unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut s = Session::server(Arc::new(scfg)).unwrap();
        crate::tls::handshake(&mut s, &sock, "the handshake").unwrap();
        let joiner = bykey::peer_key(s.peer_certificates()).unwrap();
        let exporter = bykey::pairing_exporter(&s, &sx).unwrap();
        let adb = cbb_core::join::session::Adb {
            group: cbb_core::format::DeviceId(member_set.lock().unwrap().state().group.0),
            device: cbb_core::format::Key::new(cbb_core::format::Alg::Es256, &laptop_point).device_id(),
            name: "laptop".into(),
        };
        let ms = MemberSession::new(laptop_point, joiner, adb, exporter);
        let mut stream = crate::tls::Stream::new(s, sock);
        let mut open = open;
        let way = match &mut open {
            Some(o) => Way::Invited { open: o, network: Network::Home },
            None => Way::Home,
        };
        let joiner_key = Key::es256(joiner.to_vec());
        let r = member(&mut stream, ms, way, &mut |_| member_says, &|| NOW, &mut |info, s| {
            let mut set = member_set.lock().unwrap();
            let mut d = Device::new(joiner_key.clone(), &info.name, info.role);
            d.rights = body::RIGHT_READ | body::RIGHT_SEND;
            let st = set.state();
            set.write_record(&st, &*root, Kind::device(d), NOW).map_err(|e| Error::msg(e.to_string()))?;
            let st = set.state();
            let (w, parts) = Welcome::build(&set, &st, &laptop_hash, &joiner_key.hash(), NOW).unwrap();
            s.welcome(&w, &parts).map_err(|e| Error::msg(format!("{e:?}")))
        });
        (r, open)
    });
    let sock = TcpStream::connect(addr).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut s = Session::client(Arc::new(ccfg), bykey::unsent_name()).unwrap();
    crate::tls::handshake(&mut s, &sock, "the handshake").unwrap();
    let member_key = bykey::peer_key(s.peer_certificates()).unwrap();
    let exporter = bykey::pairing_exporter(&s, &cx).unwrap();
    let mut stream = crate::tls::Stream::new(s, sock);
    let mut attempts = JoinerAttempts::default();
    let j = Joiner {
        attempts: &mut attempts,
        info: Info::new("tv", 1, body::ROLE_MEMBER),
        invitation: joiner_invitation,
        joining: Joining::Ordinary,
        own: tv.point(),
        member: member_key,
        exporter,
    };
    let mut stored = false;
    let jr = joiner(&mut stream, j, &mut |_| joiner_says, &|| NOW, &mut |_| {
        stored = true;
        Ok(())
    });
    assert_eq!(stored, jr.is_ok());
    drop(stream);
    let (mr, open) = server.join().unwrap();
    let set = set.lock().unwrap().clone();
    (jr, mr, set, open)
}

fn open(inv: &Invitation) -> Open {
    Open {
        invitation: inv.clone(),
        name: "tv".into(),
        created_ms: NOW - 1000,
        expires_ms: NOW + 600_000,
        used: false,
        failures: 0,
        allowed_key: None,
        attempt: None,
        next_attempt: 0,
    }
}

#[test]
fn a_device_joins_at_home_over_tls() {
    let (j, m, set, _) = pair(true, true, None, None);
    let a = j.unwrap();
    assert_eq!(m.unwrap().name, "tv");
    assert_eq!(a.set.digest(), set.digest());
    assert!(a.state.device_by_key(&K::new(3).key().hash()).is_some());
}

#[test]
fn a_device_joins_by_an_invitation_over_tls() {
    let inv = invitation();
    let (j, m, set, open) = pair(false, false, Some(inv.clone()), Some(open(&inv)));
    // No one is asked: the invitation's secret binds the member.
    assert_eq!(j.unwrap().set.digest(), set.digest());
    assert!(m.is_ok());
    assert!(open.unwrap().used);
}

#[test]
fn a_no_at_either_end_ends_the_pairing() {
    let (j, m, set, _) = pair(false, true, None, None);
    assert!(j.is_err() && m.is_err());
    assert!(set.state().device_by_key(&K::new(3).key().hash()).is_some(), "the member wrote before it sent 67");
    let (j, m, set, _) = pair(true, false, None, None);
    assert!(j.is_err());
    assert!(m.is_err());
    assert!(set.state().device_by_key(&K::new(3).key().hash()).is_none(), "nothing written without a yes");
}

#[test]
fn a_wrong_invitation_lets_nothing_in() {
    let inv = invitation();
    let mut wrong = inv.clone();
    wrong.secret = [7; 32];
    let (j, m, set, open) = pair(true, true, Some(wrong), Some(open(&inv)));
    assert!(j.is_err() && m.is_err());
    assert!(set.state().device_by_key(&K::new(3).key().hash()).is_none());
    assert!(!open.unwrap().used);
}
