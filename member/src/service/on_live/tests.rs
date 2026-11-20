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
    until("b's hello", || ask(&a, "devices", |_| {}).unwrap().header.devices.iter().any(|d| d.online && !d.this));

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

    // Neither holds the root key nor an admin key: the devices list is
    // refused, and says why.
    let e = ask(&a, "rename", |h| (h.device, h.name) = ("b".into(), "bee".into())).unwrap_err();
    assert!(e.message().contains("only an admin can change the devices list"), "{}", e.message());

    // What has not moved yet answers so, with its cause.
    for op in ["release_held", "away", "invite"] {
        let e = ask(&a, op, |_| {}).unwrap_err();
        assert!(e.find::<NotYet>().is_some(), "{op}: {}", e.for_log());
    }
    // Muting another device takes an admin.
    let e = ask(&a, "mute", |h| h.device = "b".into()).unwrap_err();
    assert!(e.message().contains("only an admin mutes a device"), "{}", e.message());
    // A request that needs no group is answered as ever.
    assert_eq!(ask(&a, "version", |_| {}).unwrap().header.status.unwrap().version, VERSION);
    lb.close();
    la.close();
}

/// The client's side of a pairing: answers yes to the code it is shown,
/// and gives that code and the final answer.
fn client(conn: UnixStream) -> std::thread::JoinHandle<(String, Message)> {
    std::thread::spawn(move || {
        let mut w = conn.try_clone().unwrap();
        let mut r = control::Reader::new(conn);
        let mut code = String::new();
        loop {
            let m = r.read().unwrap().unwrap();
            assert!(m.header.error.is_empty(), "{}", m.header.error);
            if m.header.done {
                return (code, m);
            }
            if !m.header.code.is_empty() {
                code.clone_from(&m.header.code);
                let yes = Header { op: "answer".into(), consent: true, ..Default::default() };
                control::write(&mut w, &Message::new(yes, Vec::new())).unwrap();
            }
        }
    })
}

#[test]
fn a_computer_pairs_with_the_window_of_a_new_group() {
    let base = std::env::temp_dir().join(format!("cbb-svc-pair-{}", std::process::id()));
    let (da, dc) = (base.join("a"), base.join("c"));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&da).unwrap();
    std::fs::create_dir_all(&dc).unwrap();
    let me = crate::founding::Me { name: "desk", os: 1, caps: cbb_core::records::body::CAP_ADMIN };
    let f = crate::founding::found_with(&da, &me, uptime::wall_ms() as u64, &|| None).unwrap();
    assert!(!f.sheet.is_empty());
    let log: Arc<dyn Fn(&str) + Send + Sync> = Arc::new(|_| {});
    let a = Service::new(&config(&da, Vec::new()), log.clone(), false);
    let la = a.start_live(&config(&da, Vec::new())).unwrap();
    let port = a.port.lock().unwrap().unwrap();

    // The window: opened, then the code, then the device's name.
    let (a_cli, a_srv) = UnixStream::pair().unwrap();
    let opened = {
        let mut r = control::Reader::new(a_cli.try_clone().unwrap());
        let (a2, la2) = (a.clone(), la.clone());
        std::thread::spawn(move || {
            let mut out = a_srv.try_clone().unwrap();
            a2.live_pair_window(&la2, control::Reader::new(a_srv), &mut out).unwrap();
        });
        r.read().unwrap().unwrap()
    };
    assert!(opened.header.code.is_empty() && opened.header.expires > 0);
    until("the window to open", || la.window_open());
    let at_a = client(a_cli);

    let log: Arc<dyn Fn(&str) + Send + Sync> = Arc::new(|l| eprintln!("{l}"));
    let c = Service::new(&config(&dc, Vec::new()), log, false);
    let (c_cli, c_srv) = UnixStream::pair().unwrap();
    let at_c = client(c_cli);
    let join =
        Header { op: "join".into(), address: format!("127.0.0.1:{port}"), name: "laptop".into(), ..Default::default() };
    let mut out = c_srv.try_clone().unwrap();
    c.live_join(&Message::new(join, Vec::new()), control::Reader::new(c_srv), &mut out).unwrap();
    drop(out);

    let (code_c, _) = at_c.join().unwrap();
    let (code_a, done) = at_a.join().unwrap();
    assert_eq!(code_a, code_c);
    assert_eq!(done.header.name, "laptop");
    assert!(in_group(&dc));
    until("the record", || la.mesh.state().devices.iter().any(|d| d.name == "laptop"));
    assert!(!la.window_open());
    // A second window may open now.
    assert!(a.pairing.lock().unwrap().is_none());
    // The new device starts in its group and dials the address it joined at.
    let lc = c.start_live(&config(&dc, Vec::new())).unwrap();
    until("the new device's connection", || {
        la.mesh.connected().contains(&lc.mesh.device()) && lc.mesh.connected().contains(&la.mesh.device())
    });
    lc.close();
    la.close();
}
