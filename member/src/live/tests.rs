// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

use std::sync::mpsc;
use std::time::Instant;

use super::*;
use crate::mesh::tests::{own, root, two_dirs, two_dirs_b_hub, two_dirs_both_hubs};

fn until(what: &str, f: impl Fn() -> bool) {
    let end = Instant::now() + Duration::from_secs(10);
    while !f() {
        assert!(Instant::now() < end, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn open(dir: &Path) -> Arc<Live> {
    Live::open(dir, own(dir), Arc::new(|_| {})).unwrap()
}

#[test]
fn device_ids_go_to_discovery_and_back() {
    let id = DeviceId([0xab; 16]);
    let s = shown(&id);
    assert_eq!(s.as_str(), "ab".repeat(16));
    assert_eq!(of(&s), Some(id));
    let st = State { group: DeviceId([1, 2, 3, 4, 5, 6, 7, 8, 9, 9, 9, 9, 9, 9, 9, 9]), ..State::default() };
    assert_eq!(tag(&st), "0102030405060708");
}

/// A pairing window announces the member key's hash as `f`, the key the
/// new device checks the window's TLS by, as the phones' QR code's `fp`.
#[test]
fn a_window_announces_its_member_key_hash() {
    let (a, _) = two_dirs("window-fp");
    let l = open(&a);
    let fp = l.window_fingerprint();
    assert_eq!(fp, certs::hex(&cbb_core::records::Key::es256(l.mesh.own().member.public()).hash().0));
    assert_eq!(fp.len(), 64);
    assert!(fp.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
    // It is the start of the device ID too.
    assert!(fp.starts_with(&id_text(&l.mesh.device())));
    l.close();
}

#[test]
fn a_copy_goes_through_discovery_s_dial_and_listen_to_the_clipboard() {
    let (da, db) = two_dirs("live");
    let (a, b) = (open(&da), open(&db));
    let (tx, rx) = mpsc::channel();
    let tx = Mutex::new(tx);
    a.on_write(Box::new(move |w| {
        let _ = tx.lock().unwrap().send(w);
    }));
    let log: Arc<dyn Fn(&str) + Send + Sync> = Arc::new(|_| {});
    let port = crate::discovery::listen(a.clone(), 0, log.clone()).unwrap();
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    crate::discovery::start(b.clone(), b.tag(), vec![addr], false, None, log);
    until("the connection", || Peers::connected(&*b, &a.me()) && Peers::connected(&*a, &b.me()));
    // a holds a record b lacks (two_dirs' device c), which syncs over the
    // connection after it came up: both then know the same devices.
    until("the records to sync", || a.known() == b.known() && a.known().len() == 3);
    // The statements cross after the hellos.
    let end = Instant::now() + Duration::from_secs(10);
    loop {
        b.copied("hello from b", Kind::Text, Via::Copy).unwrap();
        if let Ok(w) = rx.recv_timeout(Duration::from_millis(200)) {
            assert_eq!((w.text.as_str(), w.kind, w.from), ("hello from b", Kind::Text, b.mesh.device()));
            break;
        }
        assert!(Instant::now() < end, "the copy never came");
        // Copied again, the same text is no change: something else is.
        b.board.clipboard_is("", Kind::Text);
    }
    assert_eq!(a.board.local().map(|(t, ..)| t).as_deref(), Some("hello from b"));
    // A deliberate send while muted is refused, and says why.
    b.board.set_mute(0);
    assert!(b.send("no", Kind::Text, Via::Copy).unwrap_err().message().contains("muted"));
    b.close();
    a.close();
    assert!(Peers::is_closed(&*a));
}

#[test]
fn a_paused_member_neither_dials_nor_takes() {
    let (da, _) = two_dirs("live-pause");
    let a = open(&da);
    a.pause();
    let err = a.dial_ended(SocketAddr::from(([127, 0, 0, 1], 9)), None).unwrap_err();
    assert!(err.message().contains("paused"));
    a.resume();
    assert!(!Peers::is_paused(&*a));
    let far = a.dial_ended(SocketAddr::from(([8, 8, 8, 8], 9)), None).unwrap_err();
    assert!(far.message().contains("home network"));
    // Found at home, and lost.
    let id = shown(&DeviceId([5; 16]));
    a.found(&id, true);
    assert!(a.at_home(&DeviceId([5; 16])));
    a.found(&id, false);
    assert!(!a.at_home(&DeviceId([5; 16])));
}

/// Sync away from home on the records of 0.6, the device's side: once on,
/// a connection with a device the records make a hub carries `tunnel` with
/// this device's key toward it and the connection's tag; the hub's offer
/// in the `result` that answers is kept, its tag confirming the key.
#[test]
fn a_device_sends_its_hub_the_tunnels_key_and_keeps_its_offer() {
    use cbb_core::format::cbor::Value as V;
    use cbb_core::format::frame;
    let (da, db) = two_dirs_b_hub("away-toward");
    let (a, b) = (open(&da), open(&db));
    let me = crate::certs::DeviceId::parse(&id_text(&a.mesh.device())).unwrap();
    let away = Arc::new(crate::away::Away::new(da.clone(), a.tag(), me, Arc::new(|_| {})));
    away.turn_on().unwrap();
    a.with_away(away.clone());
    let (tx, rx) = mpsc::channel();
    let tx = Mutex::new(tx);
    let hub = b.mesh.clone();
    b.mesh.on_other(Box::new(move |from, t, msg| {
        if t != cbb_core::msg::tables::T_TUNNEL {
            return;
        }
        let (key, confirm) = cbb_core::hubkey::read(msg).unwrap();
        let ours = hub.tunnel_psk(from, true).unwrap();
        let _ = tx.lock().unwrap().send((key, confirm == ours.confirm));
        let k = [5u8; 32];
        let offer = V::Map(vec![
            (1, cbb_core::format::Key::new(cbb_core::format::Alg::X25519, &k).to_value()),
            (2, V::Array(vec![V::Text("192.0.2.1:51820")])),
            (8, V::Bytes(&confirm)),
        ]);
        let me = hub.device();
        let id = cbb_core::hubkey::offer_id(&confirm);
        let result = V::Map(vec![
            (frame::FIELD_T, V::Uint(cbb_core::msg::tables::T_RESULT)),
            (2, V::Bytes(&id)),
            (3, V::Bytes(&me.0)),
            (4, V::Uint(1)),
            (6, offer),
        ]);
        hub.send(from, frame::write(&result));
    }));
    let log: Arc<dyn Fn(&str) + Send + Sync> = Arc::new(|_| {});
    let port = crate::discovery::listen(b.clone(), 0, log.clone()).unwrap();
    crate::discovery::start(a.clone(), a.tag(), vec![SocketAddr::from(([127, 0, 0, 1], port))], false, None, log);
    let (key, confirmed) = rx.recv_timeout(Duration::from_secs(10)).unwrap();
    assert!(confirmed, "the tag of the connection's own key");
    let secret = crate::tunnel::State::load(&da).unwrap().unwrap().private_key().unwrap();
    assert_eq!(key, cbb_core::hubkey::key_for(&secret, &cbb_core::format::DeviceId(b.mesh.device().0)).1);
    until("the offer kept", || away.live_status().is_some_and(|s| s.hub_device == id_text(&b.mesh.device())));
    let st = crate::tunnel::State::load(&da).unwrap().unwrap();
    assert_eq!(st.hubs[0].key, vec![5; 32]);
    let toward = &st.toward[&id_text(&b.mesh.device())];
    assert!(!toward.side().to_try().is_empty());
    assert_eq!(away.keys_toward(&b.mesh.device()).first(), toward.side().to_try().first(), "the confirmed key first");
    a.close();
    b.close();
}

/// Sync away from home on the records of 0.6 end to end: at home the hub
/// takes the device's key and answers with its offer; away from home (the
/// device started again with no way to the hub but the tunnel) the device
/// reaches the hub through its tunnel, AmneziaWG on, under a pre-shared key
/// of their connection at home, and the member connection runs through it.
#[test]
fn a_device_reaches_its_hub_of_0_6_through_the_tunnel() {
    let (da, db) = two_dirs_b_hub("away-through");
    let (a, b) = (open(&da), open(&db));
    let away_of = |l: &Arc<Live>, dir: &Path| {
        let me = crate::certs::DeviceId::parse(&id_text(&l.mesh.device())).unwrap();
        Arc::new(crate::away::Away::new(dir.to_path_buf(), l.tag(), me, Arc::new(|_| {})))
    };
    let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = udp.local_addr().unwrap().port();
    drop(udp);
    let hub_away = away_of(&b, &db);
    let h = crate::control::Header {
        addrs: vec![format!("127.0.0.1:{port}")],
        port: i64::from(port),
        consent: true,
        ..Default::default()
    };
    hub_away.make_hub(&h).unwrap();
    b.with_away(hub_away.clone());
    let dev_away = away_of(&a, &da);
    dev_away.turn_on().unwrap();
    a.with_away(dev_away.clone());
    let log: Arc<dyn Fn(&str) + Send + Sync> = Arc::new(|_| {});
    let member_port = crate::discovery::listen(b.clone(), 0, log.clone()).unwrap();
    crate::discovery::start(
        a.clone(),
        a.tag(),
        vec![SocketAddr::from(([127, 0, 0, 1], member_port))],
        false,
        None,
        log,
    );
    until("the hub's offer at home", || {
        dev_away.live_status().is_some_and(|s| s.hub_device == id_text(&b.mesh.device()))
    });
    let kept = crate::tunnel::State::load(&da).unwrap().unwrap().hubs;
    assert_eq!(kept[0].endpoints, vec![SocketAddr::from(([127, 0, 0, 1], port))]);
    assert!(kept[0].obfuscation.is_some(), "the group's AmneziaWG settings");
    assert!(crate::tunnel::State::load(&db).unwrap().unwrap().held.contains_key(&id_text(&a.mesh.device())));
    a.close();
    // Away from home: the device again, with no way to the hub but the
    // tunnel.
    let a = open(&da);
    let dev_away = away_of(&a, &da);
    a.with_away(dev_away.clone());
    let end = Instant::now() + Duration::from_secs(40);
    while !a.mesh.connected().contains(&b.mesh.device()) {
        assert!(Instant::now() < end, "never reached the hub through the tunnel: {:?}", dev_away.live_status());
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(dev_away.live_status().unwrap().through, "through the tunnel");
    // Both ends note the key the handshake took.
    let name = id_text(&b.mesh.device());
    let toward = crate::tunnel::State::load(&da).unwrap().unwrap().toward[&name].side();
    assert!(toward.handshaked.is_some());
    until("the hub notes the handshake", || {
        crate::tunnel::State::load(&db).unwrap().unwrap().held[&id_text(&a.mesh.device())].side().handshaked
            == vec![toward.handshaked.unwrap()]
    });
    // The connection through the tunnel sent its own `tunnel`: the hub
    // holds that key too, and the tunnel it rides stays up.
    until("the hub holds the key of the connection through the tunnel", || {
        crate::tunnel::State::load(&db).unwrap().unwrap().held[&id_text(&a.mesh.device())].side().received.len() == 2
    });
    std::thread::sleep(Duration::from_secs(1));
    assert!(a.mesh.connected().contains(&b.mesh.device()), "the tunnel stays up as the hub's keys change");
    assert!(dev_away.live_status().unwrap().through);
    a.close();
    b.close();
}

/// Of two hubs of 0.6, the one lower in the order stands by while the one
/// above serves and says so (`hubs`, t 16); once the one above stops being
/// a hub and says so, the lower one serves after its wait.
#[test]
fn a_hub_stands_by_while_the_hub_above_serves() {
    let (da, db) = two_dirs_both_hubs("away-ladder");
    let (a, b) = (open(&da), open(&db));
    let hub_of = |l: &Arc<Live>, dir: &Path| {
        let me = crate::certs::DeviceId::parse(&id_text(&l.mesh.device())).unwrap();
        let away = Arc::new(crate::away::Away::new(dir.to_path_buf(), l.tag(), me, Arc::new(|_| {})));
        let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = udp.local_addr().unwrap().port();
        drop(udp);
        let h = crate::control::Header {
            addrs: vec![format!("127.0.0.1:{port}")],
            port: i64::from(port),
            consent: true,
            ..Default::default()
        };
        away.make_hub(&h).unwrap();
        l.with_away(away.clone());
        away
    };
    assert_eq!(a.mesh.hub_order(), vec![b.mesh.device(), a.mesh.device()]);
    let b_away = hub_of(&b, &db);
    until("b serves", || b.hub.lock().unwrap().is_some());
    let _a_away = hub_of(&a, &da);
    let log: Arc<dyn Fn(&str) + Send + Sync> = Arc::new(|_| {});
    let member_port = crate::discovery::listen(b.clone(), 0, log.clone()).unwrap();
    crate::discovery::start(
        a.clone(),
        a.tag(),
        vec![SocketAddr::from(([127, 0, 0, 1], member_port))],
        false,
        None,
        log,
    );
    until("a and b connect", || a.mesh.connected().contains(&b.mesh.device()));
    until("a stands by", || a.hub.lock().unwrap().is_none() && a.stands_by());
    std::thread::sleep(Duration::from_secs(1));
    assert!(a.hub.lock().unwrap().is_none(), "a stays standing by");
    assert!(b.hub.lock().unwrap().is_some(), "b serves");
    b_away.turn_off().unwrap();
    until("b stops", || b.hub.lock().unwrap().is_none());
    until("a serves", || a.hub.lock().unwrap().is_some());
    a.close();
    b.close();
}

/// Once the root chose a relay in the group's settings, two members with
/// sync away from home on and no other way to each other meet there: each
/// registers under the period's credentials of the relay's face, one dials
/// the other through the relay, and the call is served as a member
/// connection; status shows the relay. With the settings naming no relay
/// the link stops.
#[test]
fn members_of_0_6_meet_at_the_groups_relay() {
    use crate::relayd::server;
    let (da, db) = two_dirs("relay-meet");
    let mut oa = own(&da);
    oa.root = Some(Arc::new(root()));
    let log: Arc<dyn Fn(&str) + Send + Sync> = Arc::new(|_| {});
    let a = Live::open(&da, oa, log.clone()).unwrap();
    let b = open(&db);
    let keys = crate::relayd::keys::Keys::new().unwrap();
    let pin = cbb_core::certs::Cert::parse(&keys.cert).unwrap().key_hash();
    let relay = server::Relay::start(server::Config {
        listen: SocketAddr::from(([127, 0, 0, 1], 0)),
        keys,
        groups: Vec::new(),
        open: true,
        limits: crate::relayd::limits::Limits::default(),
        log: Arc::new(|_| {}),
        verbose: false,
        refused: None,
    })
    .unwrap();
    let endpoint = relay.addr().to_string();
    let now = crate::uptime::wall_ms() as u64;
    a.mesh
        .write(|set, k| {
            crate::writers::set_settings(
                set,
                k,
                |s| {
                    s.servers.push(cbb_core::records::body::Server {
                        kind: cbb_core::records::body::SERVER_RELAY,
                        endpoint: endpoint.clone(),
                        pin,
                    });
                },
                now,
            )
        })
        .unwrap();
    // At home first: b takes the settings and the period, and the root
    // lists b's server key on the relay's face.
    let member_port = crate::discovery::listen(b.clone(), 0, log.clone()).unwrap();
    let dialer = a.clone();
    std::thread::spawn(move || dialer.mesh.dial(SocketAddr::from(([127, 0, 0, 1], member_port)), None));
    let has_face = |l: &Arc<Live>| {
        let member = l.mesh.own().member.public();
        l.mesh.relay_credentials(&l.mesh.state(), &member, &[pin], crate::uptime::wall_ms() as u64).is_some()
    };
    until("both hold the relay's credentials", || has_face(&a) && has_face(&b));
    until("b takes the settings", || !b.mesh.state().settings.servers.is_empty());
    b.close();
    // Away from home: b again, with no way to a but the relay.
    let b = open(&db);
    assert!(!a.mesh.connected().contains(&b.mesh.device()));
    let away_of = |l: &Arc<Live>, dir: &Path| {
        let me = crate::certs::DeviceId::parse(&id_text(&l.mesh.device())).unwrap();
        let away = Arc::new(crate::away::Away::new(dir.to_path_buf(), l.tag(), me, Arc::new(|_| {})));
        away.turn_on().unwrap();
        l.with_away(away.clone());
        away
    };
    let a_away = away_of(&a, &da);
    let _b_away = away_of(&b, &db);
    until("a and b meet through the relay", || {
        a.mesh.connected().contains(&b.mesh.device()) && b.mesh.connected().contains(&a.mesh.device())
    });
    let st = a.relay_status().unwrap();
    assert!(st.connected, "{st:?}");
    assert_eq!(st.endpoint, endpoint);
    // Off: the link stops.
    a_away.turn_off().unwrap();
    until("the link stops", || a.relay_status().is_none());
    a.close();
    b.close();
}

/// A hub of 0.6 with a forwarder shows it in its status: where it is and
/// that it has not registered there, while the forwarder does not answer;
/// a hub that stops serving shows none.
#[test]
fn a_hub_of_0_6_shows_its_forwarder() {
    use base64::Engine;
    let (_, db) = two_dirs_b_hub("away-forwarder");
    let b = open(&db);
    let me = crate::certs::DeviceId::parse(&id_text(&b.mesh.device())).unwrap();
    let away = Arc::new(crate::away::Away::new(db.clone(), b.tag(), me, Arc::new(|_| {})));
    let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = udp.local_addr().unwrap().port();
    drop(udp);
    let h = crate::control::Header {
        addrs: vec![format!("127.0.0.1:{port}")],
        port: i64::from(port),
        forwarder: "127.0.0.1:9".into(),
        forwarder_key: base64::engine::general_purpose::STANDARD.encode([7u8; 32]),
        consent: true,
        ..Default::default()
    };
    away.make_hub(&h).unwrap();
    assert!(away.live_forwarder(false).is_some_and(|f| f.endpoint == "127.0.0.1:9" && !f.registered));
    b.with_away(away.clone());
    until("the hub serves", || b.hub.lock().unwrap().is_some());
    let f = away.live_forwarder(false).unwrap();
    assert_eq!(f.endpoint, "127.0.0.1:9");
    assert!(!f.registered, "nothing answers there");
    away.turn_off().unwrap();
    until("the hub stops", || b.hub.lock().unwrap().is_none());
    assert!(away.live_forwarder(false).is_none());
    b.close();
}

/// A hub of 0.6 with a forwarder registers there under the hubs'
/// credential of the forwarder's face, which the root lists it on: its
/// status shows it registered and where the forwarder saw it, it keeps the
/// VLESS settings the forwarder gave, and setting it again keeping its
/// settings keeps the same VLESS user ID. A forwarder that refuses shows
/// why in short.
#[test]
fn a_hub_of_0_6_registers_with_its_forwarder() {
    use crate::nettest::forwarder::{Answer, Forwarder, welcome};
    use base64::Engine;
    let (da, db) = two_dirs_b_hub("away-registers");
    let mut oa = own(&da);
    oa.root = Some(Arc::new(root()));
    let log: Arc<dyn Fn(&str) + Send + Sync> = Arc::new(|_| {});
    let a = Live::open(&da, oa, log.clone()).unwrap();
    let b = open(&db);
    let f = Forwarder::start(welcome(), Some("203.0.113.9:51820"));
    let no = Forwarder::start(Arc::new(|_: &crate::forward::v3::Register| Answer::Refused("full".into())), None);
    // The forwarders as the project's keys.json would name them: the
    // group shows each a face.
    for l in [&a, &b] {
        for fw in [&f, &no] {
            l.mesh.add_test_server(crate::faces::Server { pin: fw.pin, address: fw.addr.to_string() });
        }
    }
    // At home: the root lists b's server key on the forwarder's face.
    let member_port = crate::discovery::listen(b.clone(), 0, log.clone()).unwrap();
    let dialer = a.clone();
    std::thread::spawn(move || dialer.mesh.dial(SocketAddr::from(([127, 0, 0, 1], member_port)), None));
    until("b holds the hubs' credential of the forwarder's face", || b.mesh.hub_credential(&f.pin).is_some());
    let me = crate::certs::DeviceId::parse(&id_text(&b.mesh.device())).unwrap();
    let away = Arc::new(crate::away::Away::new(db.clone(), b.tag(), me, Arc::new(|_| {})));
    let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = udp.local_addr().unwrap().port();
    drop(udp);
    let h = crate::control::Header {
        port: i64::from(port),
        forwarder: f.addr.to_string(),
        forwarder_key: base64::engine::general_purpose::STANDARD.encode(f.pin),
        consent: true,
        ..Default::default()
    };
    away.make_hub(&h).unwrap();
    b.with_away(away.clone());
    let end = Instant::now() + Duration::from_secs(20);
    while !away.live_forwarder(false).is_some_and(|fw| fw.registered && fw.seen == "203.0.113.9:51820") {
        assert!(Instant::now() < end, "never registered: {:?}", away.live_forwarder(false));
        std::thread::sleep(Duration::from_millis(50));
    }
    let claim = f.claims()[0].register.clone();
    assert!(claim.vless.is_some() && claim.obfuscation.is_some(), "VLESS comes with AmneziaWG");
    let user = claim.vless.unwrap();
    let id_of = |s: &str| cbb_core::vless::parse_id(s).unwrap();
    let vless_id =
        || crate::tunnel::State::load(&db).unwrap().unwrap().forwarder.map(|fw| fw.vless_id).unwrap_or_default();
    until("the hub keeps the forwarder's VLESS settings", || {
        crate::tunnel::State::load(&db).unwrap().unwrap().forwarder.is_some_and(|fw| fw.vless.is_some())
    });
    assert_eq!(id_of(&vless_id()), user);
    // Set again keeping its settings: the same VLESS user ID.
    away.make_hub(&crate::control::Header { keep: true, consent: true, ..Default::default() }).unwrap();
    assert_eq!(id_of(&vless_id()), user);
    // A forwarder that refuses.
    let h = crate::control::Header {
        forwarder: no.addr.to_string(),
        forwarder_key: base64::engine::general_purpose::STANDARD.encode(no.pin),
        vless_off: true,
        ..h
    };
    away.make_hub(&h).unwrap();
    let end = Instant::now() + Duration::from_secs(20);
    while !away.live_forwarder(false).is_some_and(|fw| fw.error.contains("refused the registration: full")) {
        assert!(Instant::now() < end, "no refusal shown: {:?}", away.live_forwarder(false));
        std::thread::sleep(Duration::from_millis(50));
    }
    a.close();
    b.close();
}
