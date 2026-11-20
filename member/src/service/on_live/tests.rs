// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

use std::net::{Ipv4Addr, SocketAddr};

use super::*;
use crate::live::NotYet;
use crate::mesh::tests::two_dirs;

fn config(dir: &Path, peers: Vec<SocketAddr>) -> Config {
    Config {
        state_dir: dir.to_path_buf(),
        socket: dir.join("cbb.sock"),
        name: "test".into(),
        peers,
        mdns: false,
        port: Some(0),
        tunnel_via: None,
        caps: Vec::new(),
    }
}

fn ask(svc: &Service, op: &str, f: impl FnOnce(&mut Header)) -> Result<Message> {
    let mut h = Header { op: op.into(), ..Default::default() };
    f(&mut h);
    svc.request(&Message { header: h, payload: Vec::new() })
}

fn until(what: &str, f: impl Fn() -> bool) {
    let end = Instant::now() + Duration::from_secs(10);
    while !f() {
        assert!(Instant::now() < end, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn a_group_of_0_6_runs_the_clipboard_status_and_devices() {
    let (da, db) = two_dirs("svc-live");
    assert!(in_group(&da));
    let log: Arc<dyn Fn(&str) + Send + Sync> = Arc::new(|_| {});
    let a = Service::new(&config(&da, Vec::new()), log.clone(), false);
    let la = a.start_live(&config(&da, Vec::new())).unwrap();
    let port = a.port.lock().unwrap().unwrap();
    let b = Service::new(&config(&db, Vec::new()), log.clone(), false);
    let lb = b.start_live(&config(&db, vec![SocketAddr::from((Ipv4Addr::LOCALHOST, port))])).unwrap();
    until("the connection", || la.mesh.connected().contains(&lb.mesh.device()));

    let st = ask(&a, "status", |_| {}).unwrap().header.status.unwrap();
    assert_eq!(st.device, id_text(&la.mesh.device()));
    assert_eq!(st.group, la.tag());
    assert!(!st.removed);
    let devs = ask(&a, "devices", |_| {}).unwrap().header.devices;
    assert_eq!(devs.len(), 3);
    until("b's hello", || {
        ask(&a, "devices", |_| {}).unwrap().header.devices.iter().any(|d| d.online && !d.this)
    });

    // A copy b sends is the clipboard's on a, which paste gives.
    let end = Instant::now() + Duration::from_secs(10);
    while la.board.local().is_none() {
        let m = Message { header: Header { op: "copy".into(), ..Default::default() }, payload: b"over".to_vec() };
        b.request(&m).unwrap();
        assert!(Instant::now() < end, "the copy never came");
        std::thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(ask(&a, "paste", |_| {}).unwrap().payload, b"over");

    // Sync off on this device, and the standing says so.
    let s = ask(&a, "sync", |h| h.on = Some(false)).unwrap().header.standing.unwrap();
    assert!(s.sync_off);
    ask(&a, "sync", |h| h.on = Some(true)).unwrap();

    // This device mutes itself, by its name.
    ask(&a, "mute", |h| h.device = "a".into()).unwrap();
    assert!(ask(&a, "muted", |_| {}).unwrap().header.standing.unwrap().muted);
    ask(&a, "unmute", |h| h.device = "a".into()).unwrap();

    // Neither holds the root key: the records refuse to be written, and say why.
    let e = ask(&a, "rename", |h| (h.device, h.name) = ("b".into(), "bee".into())).unwrap_err();
    assert!(e.message().contains("root key"), "{}", e.message());

    // What has not moved yet answers so, with its cause.
    for op in ["release_held", "away", "resolve"] {
        let e = ask(&a, op, |_| {}).unwrap_err();
        assert!(e.find::<NotYet>().is_some(), "{op}: {}", e.for_log());
    }
    let e = ask(&a, "mute", |h| h.device = "b".into()).unwrap_err();
    assert!(e.find::<NotYet>().is_some());
    // A request that needs no group is answered as ever.
    assert_eq!(ask(&a, "version", |_| {}).unwrap().header.status.unwrap().version, VERSION);
    lb.close();
    la.close();
}
