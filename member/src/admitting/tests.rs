// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use cbb_core::join::invitation::JoinerAttempts;
use cbb_core::join::welcome::Joining;
use cbb_core::records::body::{self, ROLE_PHONE};
use cbb_core::records::{RecordSet, Recovery, key::ALG_SLH_DSA, pq};
use p256::ecdsa::SigningKey;
use p256::pkcs8::EncodePrivateKey as _;

use super::*;
use crate::join::Joiner;
use crate::own::{Own, Which};

fn temp(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("cbb-admitting-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A group whose root key this computer holds, opened as its mesh.
fn root_mesh(name: &str) -> Arc<Mesh> {
    let dir = temp(name);
    let mut own = Own::load_with(&dir, &|_| Err(Error::msg("no hardware")), &|| None).unwrap();
    let root = own.make(&dir, Which::Root).unwrap();
    let (k1, k2) = pq::recovery_keys(&[1; 32]).unwrap();
    let k1 = SigningKey::from(&k1).verifying_key().to_sec1_point(false).as_bytes().to_vec();
    let mut set = RecordSet::new(
        Key::es256(root.public()),
        Recovery::new(Key::es256(k1), Key::new(ALG_SLH_DSA, k2.public())).unwrap(),
    );
    let mut d = Device::new(own.member_key(), "desk", ROLE_MEMBER);
    d.rights = RIGHT_READ | RIGHT_SEND;
    d.holds_root = true;
    let st = set.state();
    let now = crate::uptime::wall_ms() as u64;
    set.write_record(&st, &*root, Kind::device(d), now - 1000).unwrap();
    let local = crate::set::local_key(&dir).unwrap();
    crate::set::save(&dir, &set, &local).unwrap();
    let mesh = Mesh::open(&dir, own, Arc::new(|_| {})).unwrap();
    mesh.rotate().unwrap();
    mesh
}

#[test]
fn a_phone_pairs_at_home_on_the_member_port() {
    let desk = root_mesh("home");
    let ln = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = ln.local_addr().unwrap();
    let (tx, rx) = mpsc::channel();
    let tx = Mutex::new(tx);
    let d2 = desk.clone();
    desk.on_pair(Some(Box::new(move |sock, s, x| {
        let r = at_home(&d2, sock, s, x, &mut |_| true);
        let _ = tx.lock().unwrap().send(r.map(|i| i.name));
    })));
    let d3 = desk.clone();
    std::thread::spawn(move || {
        let (sock, _) = ln.accept().unwrap();
        let _ = d3.accept_port(sock);
    });
    let phone = SigningKey::from_slice(&[5; 32]).unwrap();
    let point: [u8; 65] = phone.verifying_key().to_sec1_point(false).as_bytes().try_into().unwrap();
    let der = phone.to_pkcs8_der().unwrap().as_bytes().to_vec();
    let (ccfg, cx) = bykey::exporting_client(
        bykey::client(
            &bykey::OwnKey::pkcs8(&der).unwrap(),
            None,
            bykey::any_key(),
            cbb_core::alpn::PAIR,
            &tls::clock(),
        )
        .unwrap(),
    );
    let sock = TcpStream::connect(addr).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let mut s = tls::Session::client(Arc::new(ccfg), bykey::unsent_name()).unwrap();
    tls::handshake(&mut s, &sock, "the handshake").unwrap();
    let member = bykey::peer_key(s.peer_certificates()).unwrap();
    let exporter = bykey::pairing_exporter(&s, &cx).unwrap();
    let mut stream = tls::Stream::new(s, sock);
    let mut attempts = JoinerAttempts::default();
    let j = Joiner {
        attempts: &mut attempts,
        info: Info::new("phone", 5, ROLE_PHONE),
        invitation: None,
        joining: Joining::Ordinary,
        own: point,
        member,
        exporter,
    };
    let now = || crate::uptime::wall_ms() as u64;
    let joined = join::joiner(&mut stream, j, &mut |_| true, &now, &mut |_| Ok(())).unwrap();
    assert_eq!(rx.recv_timeout(Duration::from_secs(10)).unwrap().unwrap(), "phone");
    let st = desk.state();
    let d = st.device_by_key(&Key::es256(point.to_vec()).hash()).expect("the phone is in the group");
    assert_eq!((d.role, d.rights), (ROLE_PHONE, body::RIGHT_READ | body::RIGHT_SEND | body::RIGHT_SECRETS));
    assert_eq!(joined.set.digest(), desk.set().lock().unwrap().digest());
    desk.close();
}
