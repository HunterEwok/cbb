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

    // Neither invites: an invitation comes from the root or an admin.
    let e = invite_now(&a, &la, |_| {}).unwrap_err();
    assert!(e.message().contains("only the group's root or an admin adds devices"), "{}", e.message());
    // No hub to stop or move here.
    let e = ask(&a, "away", |h| h.name = "hub-off".into()).unwrap_err();
    assert!(e.message().contains("no other hub"), "{}", e.message());
    let e = ask(&a, "away", |h| (h.name, h.force) = ("hub-off".into(), true)).unwrap_err();
    assert!(e.message().contains("no hub of the group"), "{}", e.message());
    let e = ask(&a, "away", |h| h.name = "move".into()).unwrap_err();
    assert!(e.message().contains("names the device"), "{}", e.message());
    // A hub command that names another device's key as the hub is not for
    // this device: refused, whoever signed it.
    let order = crate::orders::Order::Hub(crate::orders::Hub {
        hub: Some(("127.0.0.1:9".into(), [9; 32])),
        forwarders: Vec::new(),
        stop: false,
    });
    let t = crate::commands::Taken {
        kind: order.kind(),
        id: [1; 16],
        signer: cbb_core::records::KeyHash([2; 32]),
        orders: order.orders().unwrap(),
    };
    let e = a.live_command(&la, &t).unwrap_err();
    assert!(e.message().contains("names another device as the hub"), "{}", e.message());
    let stop = crate::orders::Order::Hub(crate::orders::Hub { stop: true, ..Default::default() });
    let t = crate::commands::Taken { kind: stop.kind(), orders: stop.orders().unwrap(), ..t };
    let e = a.live_command(&la, &t).unwrap_err();
    assert!(e.message().contains("no hub of the group"), "{}", e.message());
    // A device the records do not make a hub is refused as one.
    let e = ask(&a, "away", |h| (h.name, h.consent) = ("hub".into(), true)).unwrap_err();
    assert!(e.message().contains("do not make this device a hub"), "{}", e.message());
    // Sync away from home turns on, with consent to keys in files, and
    // off; cbb global shows it.
    assert!(ask(&a, "away", |_| {}).unwrap().header.status.unwrap().away.is_none(), "off");
    let e = ask(&a, "away", |h| h.name = "on".into()).unwrap_err();
    assert!(e.message().contains("needs your consent"), "{}", e.message());
    let on = ask(&a, "away", |h| (h.name, h.consent) = ("on".into(), true)).unwrap();
    assert!(on.header.status.unwrap().away.unwrap().keys_in_file);
    assert!(ask(&a, "away", |_| {}).unwrap().header.status.unwrap().away.is_some(), "on");
    let off = ask(&a, "away", |h| h.name = "off".into()).unwrap();
    assert!(off.header.status.unwrap().away.is_none());
    // The signed release and entry points have moved: none is held yet.
    for (op, says) in [("release_held", "no signed release"), ("entries_get", "no signed entry points")] {
        let e = ask(&a, op, |_| {}).unwrap_err();
        assert!(e.find::<NotYet>().is_none() && e.message().contains(says), "{op}: {}", e.for_log());
    }
    // Muting another device takes an admin.
    let e = ask(&a, "mute", |h| h.device = "b".into()).unwrap_err();
    assert!(e.message().contains("only an admin mutes a device"), "{}", e.message());
    // A request that needs no group is answered as ever.
    assert_eq!(ask(&a, "version", |_| {}).unwrap().header.status.unwrap().version, VERSION);
    lb.close();
    la.close();
}

/// The client's side of a pairing: reads the service's answers to the
/// last, and gives the tries it was told failed and that last answer.
/// cbb invite on svc, answered at once: an error, before anything opens.
fn invite_now(svc: &Service, live: &Arc<Live>, f: impl FnOnce(&mut Header)) -> Result<()> {
    let (_cli, srv) = UnixStream::pair().unwrap();
    let mut h = Header { op: "invite".into(), ..Default::default() };
    f(&mut h);
    let mut out = srv.try_clone().unwrap();
    svc.live_invite(live, &Message::new(h, Vec::new()), control::Reader::new(srv), &mut out)
}

fn client(conn: UnixStream) -> std::thread::JoinHandle<(usize, Message)> {
    std::thread::spawn(move || {
        let mut r = control::Reader::new(conn);
        let mut failed = 0;
        loop {
            let m = r.read().unwrap().unwrap();
            assert!(m.header.error.is_empty(), "{}", m.header.error);
            if m.header.done {
                return (failed, m);
            }
            if m.header.refused {
                failed += 1;
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

    // The window: opened with its six digits, a failed try, then the
    // device's name.
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
    let digits = opened.header.code.clone();
    assert!(cbb_core::join::invitation::home_secret(&digits).is_some(), "six digits");
    assert_eq!(opened.header.kind, crate::admit_cli::HOME_WINDOW);
    assert!(opened.header.expires > 0);
    until("the window to open", || la.window_open());
    // Its mDNS announcement names its ID, and the QR code carries it with
    // the digits and the member key.
    let id = crate::discovery::Peers::window_id(&*la);
    assert_eq!(id.len(), 32);
    if !opened.header.invite.is_empty() {
        let link = cbb_core::join::invitation::WindowLink::parse(&opened.header.invite).unwrap();
        assert_eq!(
            (cbb_core::certs::hex(&link.id), &link.digits, link.fp),
            (id.clone(), &digits, la.mesh.own().hash())
        );
    }
    let at_a = client(a_cli);
    let link = |digits: &str| {
        cbb_core::join::invitation::WindowLink {
            addrs: vec![format!("127.0.0.1:{port}")],
            fp: la.mesh.own().hash(),
            id: cbb_core::join::invitation::hex_bytes(&id).unwrap(),
            digits: digits.to_string(),
        }
        .text()
    };

    let log: Arc<dyn Fn(&str) + Send + Sync> = Arc::new(|l| eprintln!("{l}"));
    let c = Service::new(&config(&dc, Vec::new()), log, false);
    let join = |code: String| {
        let (c_cli, c_srv) = UnixStream::pair().unwrap();
        let h = Header { op: "join".into(), code, name: "laptop".into(), ..Default::default() };
        let mut out = c_srv.try_clone().unwrap();
        let got = c.live_join(&Message::new(h, Vec::new()), control::Reader::new(c_srv), &mut out);
        drop(c_cli);
        got
    };
    // Wrong digits: refused, the window stays open and says so.
    let wrong = if digits == "000000" { "000001" } else { "000000" };
    let e = join(link(wrong)).unwrap_err();
    assert!(e.message().contains("not the window's"), "{}", e.for_log());
    assert!(!in_group(&dc));
    assert!(la.window_open());
    // The window's digits.
    join(link(&digits)).unwrap();

    let (failed, done) = at_a.join().unwrap();
    assert_eq!(failed, 1, "the window told of the wrong try");
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

/// cbb global relay on the group's root signs the relay in the group's
/// settings (D-121), and the group shows it a face; `default` leaves the
/// project's alone. A device that is not the root is refused.
#[test]
fn the_root_sets_the_groups_relay() {
    use cbb_core::records::body::{SERVER_RELAY, Server};
    let base = std::env::temp_dir().join(format!("cbb-svc-relay-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).unwrap();
    let me = crate::founding::Me { name: "desk", os: 1, caps: cbb_core::records::body::CAP_ADMIN };
    crate::founding::found_with(&base, &me, uptime::wall_ms() as u64, &|| None).unwrap();
    let log: Arc<dyn Fn(&str) + Send + Sync> = Arc::new(|_| {});
    let a = Service::new(&config(&base, Vec::new()), log, false);
    let la = a.start_live(&config(&base, Vec::new())).unwrap();
    let pin = [9u8; 32];
    let key = {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(pin)
    };
    let relay = |addr: &str, key: &str, consent: bool| {
        ask(&a, "away", |h| {
            (h.name, h.relay, h.relay_key, h.consent) = ("relay".into(), addr.into(), key.into(), consent);
        })
    };

    let e = relay("203.0.113.9:8764", &key, false).unwrap_err();
    assert!(e.message().contains("a relay learns"), "{}", e.message());
    let e = relay("203.0.113.9:8764", "short", true).unwrap_err();
    assert!(e.message().contains("not a relay's key"), "{}", e.message());
    let e = relay("203.0.113.9", &key, true).unwrap_err();
    assert!(e.message().contains("with a port"), "{}", e.message());
    assert!(la.mesh.state().settings.servers.is_empty());

    let m = relay("203.0.113.9:8764", &key, true).unwrap();
    assert_eq!(m.header.relays, ["203.0.113.9:8764"]);
    let want = vec![Server { kind: SERVER_RELAY, endpoint: "203.0.113.9:8764".into(), pin }];
    assert_eq!(la.mesh.state().settings.servers, want);
    #[cfg(feature = "tunnel")]
    {
        let face = crate::faces::Server { pin, address: "203.0.113.9:8764".into() };
        la.mesh.refresh_faces(&la.mesh.state());
        assert!(la.mesh.faces().servers().contains(&face), "a face for the group's relay");
    }
    // Another relay takes its place.
    relay("198.51.100.7:8764", &key, true).unwrap();
    let st = la.mesh.state();
    assert_eq!(st.settings.servers.len(), 1);
    assert_eq!(st.settings.servers[0].endpoint, "198.51.100.7:8764");
    // Several relays, each once.
    let m = ask(&a, "away", |h| {
        (h.name, h.relay, h.relay_key, h.consent) = ("relay".into(), "203.0.113.9:8764".into(), key.clone(), true);
        h.relays = vec![format!("198.51.100.7:8764 {key}")];
    })
    .unwrap();
    assert_eq!(m.header.relays, ["203.0.113.9:8764", "198.51.100.7:8764"]);
    assert_eq!(la.mesh.state().settings.servers.len(), 2);
    let e = ask(&a, "away", |h| {
        (h.name, h.relay, h.relay_key, h.consent) = ("relay".into(), "203.0.113.9:8764".into(), key.clone(), true);
        h.relays = vec![format!("203.0.113.9:8764 {key}")];
    })
    .unwrap_err();
    assert!(e.message().contains("given twice"), "{}", e.message());
    // The project's relay: the group's own go, and the settings name the
    // project's by name with its key's pin, so the root's consent is
    // recorded; it takes consent as any relay.
    let e = relay("cbb.tools:8765", "default", false).unwrap_err();
    assert!(e.message().contains("a relay learns"), "{}", e.message());
    let m = relay("cbb.tools:8765", "default", true).unwrap();
    assert_eq!(m.header.relays, [crate::away::PROJECT_RELAY]);
    let servers = la.mesh.state().settings.servers;
    assert_eq!(servers.len(), 1);
    assert_eq!((servers[0].kind, servers[0].endpoint.as_str()), (SERVER_RELAY, crate::away::PROJECT_RELAY));
    let built_in = crate::faces::project_servers(None, uptime::wall_ms());
    assert!(built_in.iter().any(|s| s.address == crate::away::PROJECT_RELAY && s.pin == servers[0].pin));
    // Off: no relay, which needs no consent; no entries never mean the
    // project's relay.
    let m = relay("off", "", false).unwrap();
    assert!(m.header.relays.is_empty());
    assert!(la.mesh.state().settings.servers.is_empty());
    la.close();

    // A device that holds neither the root key nor an admin key.
    let (da, _db) = two_dirs("svc-relay");
    let log: Arc<dyn Fn(&str) + Send + Sync> = Arc::new(|_| {});
    let b = Service::new(&config(&da, Vec::new()), log, false);
    let lb = b.start_live(&config(&da, Vec::new())).unwrap();
    let e = ask(&b, "away", |h| {
        (h.name, h.relay, h.relay_key, h.consent) = ("relay".into(), "203.0.113.9:8764".into(), key.clone(), true);
    })
    .unwrap_err();
    assert!(e.message().contains("only the group's root sets the group's relay"), "{}", e.message());
    lb.close();
}

/// A remote invitation of 0.6 end to end (docs/protocol.md, section 12):
/// the root, a hub, invites a computer that shares no network with it. The
/// computer pairs through the invitation's guest tunnel at the hub's guest
/// address; the admin declines its first attempt and admits the second,
/// each after the computer proved the secret, so nothing was written for
/// the first. The new member then reaches the hub through the guest tunnel,
/// hands it its tunnel key, forgets the invitation, and reaches the hub
/// with its own key from then on.
#[test]
fn a_computer_joins_from_afar_with_an_invitation() {
    let base = std::env::temp_dir().join(format!("cbb-svc-invite-{}", std::process::id()));
    let (da, dc) = (base.join("a"), base.join("c"));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&da).unwrap();
    std::fs::create_dir_all(&dc).unwrap();
    let me = crate::founding::Me {
        name: "desk",
        os: 1,
        caps: cbb_core::records::body::CAP_ADMIN | cbb_core::records::body::CAP_HUB,
    };
    crate::founding::found_with(&da, &me, uptime::wall_ms() as u64, &|| None).unwrap();
    let log: Arc<dyn Fn(&str) + Send + Sync> = Arc::new(|l| eprintln!("a: {l}"));
    let a = Service::new(&config(&da, Vec::new()), log, false);
    let la = a.start_live(&config(&da, Vec::new())).unwrap();
    // Not a hub yet: refused, and nothing opens.
    let e = invite_now(&a, &la, |_| {}).unwrap_err();
    assert!(e.message().contains("this device is none"), "{}", e.message());
    // The root is the hub, with an address away from home.
    let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let hub_port = udp.local_addr().unwrap().port();
    drop(udp);
    let h = Header {
        addrs: vec![format!("127.0.0.1:{hub_port}")],
        port: i64::from(hub_port),
        consent: true,
        ..Default::default()
    };
    la.away().unwrap().make_hub(&h).unwrap();
    ask(&a, "hubs", |h| h.hubs = vec!["desk".into()]).unwrap();
    // An invitation through another hub has not moved yet; one for a
    // watch is no invitation.
    let e = invite_now(&a, &la, |h| h.device = "00112233445566778899aabbccddeeff".into()).unwrap_err();
    assert!(e.find::<NotYet>().is_some(), "{}", e.for_log());
    let e = invite_now(&a, &la, |h| h.kind = "watch".into()).unwrap_err();
    assert!(e.message().contains("a computer or a phone"), "{}", e.message());
    assert!(invite_now(&a, &la, |h| h.expires = 25 * 3600).is_err(), "a day at most");

    let (a_cli, a_srv) = UnixStream::pair().unwrap();
    let inviting = {
        let (a2, la2) = (a.clone(), la.clone());
        std::thread::spawn(move || {
            let h = Header { op: "invite".into(), expires: 600, ..Default::default() };
            let mut out = a_srv.try_clone().unwrap();
            a2.live_invite(&la2, &Message::new(h, Vec::new()), control::Reader::new(a_srv), &mut out)
        })
    };
    let mut r = control::Reader::new(a_cli.try_clone().unwrap());
    let opened = r.read().unwrap().unwrap();
    assert!(opened.header.error.is_empty(), "{}", opened.header.error);
    assert_eq!(opened.header.expires, 600);
    let text = opened.header.invite.clone();
    let inv = cbb_core::join::invitation::Invitation::parse(&text).unwrap();
    let path = crate::live::invite::guest_path(&inv).unwrap();
    assert_eq!(path.endpoints, vec![format!("127.0.0.1:{hub_port}")]);
    assert!(path.obfuscation.is_some(), "the group's AmneziaWG settings");
    assert_eq!(inv.profile.role, cbb_core::records::body::ROLE_MEMBER);
    assert!(!inv.profile.home_only);
    // The admin: no to the first device, yes to the second.
    let admin = {
        let mut w = a_cli;
        std::thread::spawn(move || {
            let (mut asked, mut refused, mut prints) = (0, 0, Vec::new());
            loop {
                let m = r.read().unwrap().unwrap();
                assert!(m.header.error.is_empty(), "{}", m.header.error);
                if m.header.done {
                    return (asked, refused, prints, m.header.name);
                }
                if m.header.refused {
                    refused += 1;
                }
                if let Some(j) = m.header.joining {
                    prints.push(j.fingerprint);
                    let yes = asked > 0;
                    asked += 1;
                    let answer = Header { op: "answer".into(), consent: yes, ..Default::default() };
                    control::write(&mut w, &Message::new(answer, Vec::new())).unwrap();
                }
            }
        })
    };

    let log: Arc<dyn Fn(&str) + Send + Sync> = Arc::new(|l| eprintln!("c: {l}"));
    let c = Service::new(&config(&dc, Vec::new()), log, false);
    let join = || {
        let (c_cli, c_srv) = UnixStream::pair().unwrap();
        let h =
            Header { op: "join".into(), invite: text.clone(), consent: true, name: "far".into(), ..Default::default() };
        let mut out = c_srv.try_clone().unwrap();
        let got = c.live_join(&Message::new(h, Vec::new()), control::Reader::new(c_srv), &mut out);
        let shown = control::Reader::new(c_cli).read().unwrap().unwrap().header.fingerprint;
        (got, shown)
    };
    let (got, _) = join();
    let e = got.unwrap_err();
    assert!(e.message().contains("did not admit"), "{}", e.for_log());
    assert!(!in_group(&dc));
    assert!(!la.mesh.state().devices.iter().any(|d| d.name == "far"), "nothing written for a no");
    let (got, shown) = join();
    got.unwrap();
    let (asked, refused, prints, name) = admin.join().unwrap();
    assert_eq!((asked, refused, name.as_str()), (2, 1, "far"));
    assert_eq!(prints[1], shown, "the admin sees the fingerprint the device shows");
    inviting.join().unwrap().unwrap();
    assert!(in_group(&dc));
    assert!(dc.join(crate::live::invite::GUEST_FILE).exists(), "kept until the hub's offer");
    until("the record", || la.mesh.state().devices.iter().any(|d| d.name == "far"));

    // The new member knows no address of the hub's at home: it reaches the
    // hub through the guest tunnel first, then with its own key.
    let lc = c.start_live(&config(&dc, Vec::new())).unwrap();
    let a_id = id_text(&la.mesh.device());
    let away = lc.away().unwrap().clone();
    let end = Instant::now() + Duration::from_secs(60);
    while !away.live_status().is_some_and(|s| s.hub_device == a_id) {
        assert!(Instant::now() < end, "never took the hub's offer: {:?}", away.live_status());
        std::thread::sleep(Duration::from_millis(100));
    }
    let end = Instant::now() + Duration::from_secs(60);
    while dc.join(crate::live::invite::GUEST_FILE).exists()
        || !lc.mesh.connected().contains(&la.mesh.device())
        || !away.live_status().is_some_and(|s| s.through)
    {
        assert!(Instant::now() < end, "never reached the hub with its own key: {:?}", away.live_status());
        std::thread::sleep(Duration::from_millis(100));
    }
    lc.close();
    la.close();
}
