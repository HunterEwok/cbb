// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

use std::sync::mpsc;
use std::time::Instant;

use super::*;
use crate::mesh::tests::{own, two_dirs};

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
