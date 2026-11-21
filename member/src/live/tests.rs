// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

use std::sync::mpsc;
use std::time::Instant;

use super::*;
use crate::mesh::tests::{own, two_dirs, two_dirs_b_hub};

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
    assert_eq!(a.known(), b.known());
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
        let result = V::Map(vec![
            (frame::FIELD_T, V::Uint(cbb_core::msg::tables::T_RESULT)),
            (2, V::Bytes(&confirm[..16])),
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
