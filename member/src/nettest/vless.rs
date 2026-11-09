// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The way over VLESS with XHTTP against a web server in the same process
//! (nettest::xhttp): the tunnel's packets and a stream's bytes there and
//! back, the requests as XHTTP makes them, and what the way does when the
//! site answers otherwise.

use std::net::{Ipv4Addr, TcpListener, TcpStream, UdpSocket};

use super::*;
use crate::nettest::wait_for;
use crate::nettest::xhttp::{HEADER, Knobs, Site};

const ID: &str = "6f1c2b9e-3d4a-4f5b-8c7d-0e1f2a3b4c5d";

type Logs = Arc<Mutex<Vec<String>>>;

fn logger() -> (Logs, Arc<dyn Fn(&str) + Send + Sync>) {
    let logs: Logs = Arc::new(Mutex::new(Vec::new()));
    let l = logs.clone();
    (logs, Arc::new(move |s: &str| l.lock().unwrap().push(s.to_string())))
}

fn logged(logs: &Logs, s: &str) -> bool {
    logs.lock().unwrap().iter().any(|l| l.contains(s))
}

/// A way over VLESS to the site, as Client::start makes one, with a TLS
/// configuration that takes the site's certificate.
fn udp_way(site: &Site, log: Arc<dyn Fn(&str) + Send + Sync>) -> (Arc<Ctx>, JoinHandle<()>, SocketAddr) {
    let link = Link::from_offer(&site.offer(ID)).unwrap();
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = udp.local_addr().unwrap();
    let header = cv::request_header(&link.id);
    let ctx = Arc::new(Ctx {
        link,
        endpoint: site.addr,
        tls: crate::nettest::xhttp::client_config(),
        header,
        out: Out::Udp { udp, peer: Mutex::new(None) },
        stop: Arc::new(AtomicBool::new(false)),
        log,
    });
    let t = {
        let ctx = ctx.clone();
        std::thread::spawn(move || upload(&ctx))
    };
    (ctx, t, addr)
}

fn stop(ctx: &Ctx, t: JoinHandle<()>) {
    ctx.stop.store(true, Ordering::SeqCst);
    t.join().unwrap();
}

/// The tunnel's packets go up in POSTs, the first with VLESS's request
/// header, and what the site sends back reaches the tunnel's socket.
#[test]
fn packets_there_and_back() {
    let site = Site::start(Knobs::default());
    let (logs, log) = logger();
    let (ctx, t, addr) = udp_way(&site, log);
    let tunnel = UdpSocket::bind("127.0.0.1:0").unwrap();
    tunnel.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let mut got = Vec::new();
    for i in 0..20u8 {
        tunnel.send_to(&[i; 100], addr).unwrap();
        if i % 5 == 0 {
            std::thread::sleep(Duration::from_millis(60));
        }
    }
    let mut buf = [0u8; 2048];
    while got.len() < 20 {
        let (n, _) = tunnel.recv_from(&mut buf).expect("an answer through the way");
        got.push(buf[..n].to_vec());
    }
    for (i, p) in got.iter().enumerate() {
        assert_eq!(p, &vec![i as u8; 100]);
    }
    let posts = site.posts();
    assert!(posts.len() >= 2, "{} uploads", posts.len());
    let first = &posts[0];
    assert_eq!(first.seq, 0);
    assert_eq!(&first.body[..HEADER], &cv::request_header(&cv::parse_id(ID).unwrap())[..]);
    assert!(posts.iter().all(|p| p.session == first.session));
    assert!(posts.windows(2).all(|w| w[1].seq == w[0].seq + 1));
    assert_eq!(site.gets.load(Ordering::SeqCst), 1);
    stop(&ctx, t);
    assert!(logs.lock().unwrap().is_empty(), "{:?}", logs.lock().unwrap());
}

/// Uploads whose answers come in chunks, end the connection, or are ended
/// by closing all still carry the packets.
#[test]
fn answers_of_every_shape() {
    for knobs in [
        Knobs { post_chunked: true, ..Knobs::default() },
        Knobs { post_connection_close: true, ..Knobs::default() },
        Knobs { post_close_delimited: true, ..Knobs::default() },
        Knobs { get_length: Some(1 << 20), ..Knobs::default() },
    ] {
        let site = Site::start(knobs);
        let (_logs, log) = logger();
        let (ctx, t, addr) = udp_way(&site, log);
        let tunnel = UdpSocket::bind("127.0.0.1:0").unwrap();
        tunnel.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let mut buf = [0u8; 2048];
        for i in 0..3u8 {
            tunnel.send_to(&[i; 50], addr).unwrap();
            let (n, _) = tunnel.recv_from(&mut buf).expect("an answer through the way");
            assert_eq!(&buf[..n], &[i; 50]);
        }
        stop(&ctx, t);
    }
}

/// An upload the site refuses ends the session; the way says so once and
/// opens a new session for later packets after its backoff.
#[test]
fn a_refused_upload() {
    let site = Site::start(Knobs { post_status: 403, ..Knobs::default() });
    let (logs, log) = logger();
    let (ctx, t, addr) = udp_way(&site, log);
    let tunnel = UdpSocket::bind("127.0.0.1:0").unwrap();
    tunnel.send_to(b"one", addr).unwrap();
    assert!(wait_for(Duration::from_secs(10), || logged(&logs, "answers an upload with 403")), "{:?}", logs);
    // After the backoff a new session takes the packets that keep coming,
    // as a tunnel's do.
    assert!(wait_for(Duration::from_secs(10), || {
        tunnel.send_to(b"two", addr).unwrap();
        std::thread::sleep(Duration::from_millis(100));
        site.posts().len() >= 2
    }));
    let posts = site.posts();
    assert_ne!(posts[0].session, posts[1].session);
    assert_eq!(posts[1].seq, 0);
    stop(&ctx, t);
    assert_eq!(logs.lock().unwrap().iter().filter(|l| l.contains("403")).count(), 1, "said once");
}

/// A download the site refuses, or one in another VLESS version, is said
/// in the log.
#[test]
fn a_refused_download() {
    for (knobs, want) in [
        (Knobs { get_status: 404, ..Knobs::default() }, "answers the download with 404"),
        (Knobs { bad_version: Some(1), ..Knobs::default() }, "VLESS version 1"),
    ] {
        let site = Site::start(knobs);
        let (logs, log) = logger();
        let (ctx, t, addr) = udp_way(&site, log);
        let tunnel = UdpSocket::bind("127.0.0.1:0").unwrap();
        tunnel.send_to(b"one", addr).unwrap();
        if want.contains("version") {
            // The header comes with the first packet back.
            assert!(wait_for(Duration::from_secs(10), || !site.posts().is_empty()));
        }
        assert!(wait_for(Duration::from_secs(10), || logged(&logs, want)), "{want}: {:?}", logs);
        stop(&ctx, t);
    }
}

/// A site that never answers an upload: the way gives up after its
/// timeout, without waiting past a stop.
#[test]
fn a_silent_site_and_none() {
    let site = Site::start(Knobs { silent_posts: true, ..Knobs::default() });
    let (logs, log) = logger();
    let (ctx, t, addr) = udp_way(&site, log);
    let tunnel = UdpSocket::bind("127.0.0.1:0").unwrap();
    tunnel.send_to(b"one", addr).unwrap();
    assert!(wait_for(Duration::from_secs(5), || !site.posts().is_empty()));
    let at = Instant::now();
    stop(&ctx, t);
    assert!(at.elapsed() < Duration::from_secs(3), "stopping took {:?}", at.elapsed());
    drop(logs);

    // Nobody listens: the connection fails, and the log says where.
    let ln = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let mut gone = Site::start(Knobs::default());
    gone.addr = ln.local_addr().unwrap();
    drop(ln);
    let (logs, log) = logger();
    let (ctx, t, addr) = udp_way(&gone, log);
    tunnel.send_to(b"one", addr).unwrap();
    assert!(wait_for(Duration::from_secs(10), || logged(&logs, "cannot reach the forwarder's site")), "{:?}", logs);
    stop(&ctx, t);
}

/// Only packets from this computer go up, and at most MAX_QUEUE of them
/// wait.
#[test]
fn the_queue() {
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = udp.local_addr().unwrap();
    let ctx = Ctx {
        link: Link::from_offer(&Site::start(Knobs::default()).offer(ID)).unwrap(),
        endpoint: addr,
        tls: crate::nettest::xhttp::client_config(),
        header: Vec::new(),
        out: Out::Udp { udp, peer: Mutex::new(None) },
        stop: Arc::new(AtomicBool::new(false)),
        log: Arc::new(|_| {}),
    };
    let tunnel = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut q = VecDeque::new();
    let mut buf = [0u8; 64];
    for i in 0..(MAX_QUEUE + 5) as u8 {
        tunnel.send_to(&[i], addr).unwrap();
        assert!(receive(&ctx, &mut buf, &mut q, Some(Instant::now() + Duration::from_secs(1))));
    }
    assert_eq!(q.len(), MAX_QUEUE);
    assert_eq!(q.front().unwrap(), &vec![5u8]);
    assert!(!receive(&ctx, &mut buf, &mut q, Some(Instant::now())));
    // A stream's context takes no packets.
    let (a, _b) = pair();
    let s = Ctx { out: Out::Stream(a), ..ctx };
    assert!(!receive(&s, &mut buf, &mut q, None));
}

fn pair() -> (TcpStream, TcpStream) {
    let ln = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let a = TcpStream::connect(ln.local_addr().unwrap()).unwrap();
    let (b, _) = ln.accept().unwrap();
    (a, b)
}

/// A stream's bytes go up as they are, in one session whose first upload
/// carries the stream's header, and come back on its connection; closing
/// the local connection ends it.
#[test]
fn a_stream_there_and_back() {
    let site = Site::start(Knobs::default());
    let mut link = Link::from_offer(&site.offer(ID)).unwrap();
    link.path = cv::registration_path(&link.path).to_string();
    link.id = cv::REGISTRATION_ID;
    let (app, ours) = pair();
    ours.set_read_timeout(Some(POLL)).unwrap();
    let reader = ours.try_clone().unwrap();
    let (logs, log) = logger();
    let ctx = Arc::new(Ctx {
        header: cv::stream_header(&link.id, cv::REGISTRATION_PORT),
        link,
        endpoint: site.addr,
        tls: crate::nettest::xhttp::client_config(),
        out: Out::Stream(ours),
        stop: Arc::new(AtomicBool::new(false)),
        log,
    });
    let t = {
        let ctx = ctx.clone();
        std::thread::spawn(move || carry(&ctx, &reader))
    };
    let mut app_r = app.try_clone().unwrap();
    app_r.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let mut app_w = app;
    // More than one upload holds.
    let big: Vec<u8> = (0..(cv::MAX_POST * 2 + 100)).map(|i| i as u8).collect();
    app_w.write_all(b"hello").unwrap();
    let mut got = vec![0u8; 5];
    app_r.read_exact(&mut got).unwrap();
    assert_eq!(got, b"hello");
    app_w.write_all(&big).unwrap();
    let mut got = vec![0u8; big.len()];
    app_r.read_exact(&mut got).unwrap();
    assert_eq!(got, big);
    let posts = site.posts();
    assert!(posts.iter().all(|p| p.body.len() <= cv::MAX_POST));
    assert_eq!(&posts[0].body[..HEADER], &cv::stream_header(&cv::REGISTRATION_ID, cv::REGISTRATION_PORT)[..]);
    drop(app_w);
    drop(app_r);
    t.join().unwrap();
    assert!(ctx.stop.load(Ordering::SeqCst));
    assert!(logs.lock().unwrap().is_empty(), "{:?}", logs.lock().unwrap());
}

/// A stream whose site refuses its upload ends, and says why.
#[test]
fn a_stream_refused() {
    let site = Site::start(Knobs { post_status: 500, ..Knobs::default() });
    let link = Link::from_offer(&site.offer(ID)).unwrap();
    let (mut app, ours) = pair();
    ours.set_read_timeout(Some(POLL)).unwrap();
    let reader = ours.try_clone().unwrap();
    let (logs, log) = logger();
    let ctx = Arc::new(Ctx {
        header: cv::stream_header(&link.id, cv::REGISTRATION_PORT),
        link,
        endpoint: site.addr,
        tls: crate::nettest::xhttp::client_config(),
        out: Out::Stream(ours),
        stop: Arc::new(AtomicBool::new(false)),
        log,
    });
    app.write_all(b"x").unwrap();
    carry(&ctx, &reader);
    assert!(logged(&logs, "the stream over VLESS"), "{:?}", logs);
    app.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut b = [0u8; 8];
    assert!(matches!(app.read(&mut b), Ok(0) | Err(_)));
}

/// Client and Stream as the service starts them: the system's roots do
/// not take the test site's certificate, so the TLS fails and the log says
/// so; a stream nobody connects to ends with its drop. Offers that are
/// not XHTTP's are refused.
#[test]
fn started_as_the_service_starts_them() {
    let site = Site::start(Knobs::default());
    let (logs, log) = logger();
    let Ok(c) = Client::start(&site.offer(ID), log.clone()) else {
        // A system without CA certificates: tls_config said so.
        return;
    };
    let tunnel = UdpSocket::bind("127.0.0.1:0").unwrap();
    tunnel.send_to(b"one", c.addr()).unwrap();
    assert!(wait_for(Duration::from_secs(10), || logged(&logs, "the TLS with site.test fails")), "{:?}", logs);
    drop(c);
    let link = Link::from_offer(&site.offer(ID)).unwrap();
    let s = Stream::registration(&link, log.clone()).unwrap();
    let mut t = TcpStream::connect(s.addr()).unwrap();
    t.write_all(b"x").unwrap();
    assert!(wait_for(Duration::from_secs(10), || logged(&logs, "the stream over VLESS")), "{:?}", logs);
    drop(s);
    let s = Stream::registration(&link, log).unwrap();
    drop(s);
    assert!(check_offer(&site.offer(ID)).is_ok());
    let mut bad = site.offer(ID);
    bad["endpoint"] = "nowhere".into();
    assert!(Client::start(&bad, Arc::new(|_| {})).is_err());
    assert!(Stream::registration(&Link { endpoint: "nowhere".into(), ..link }, Arc::new(|_| {})).is_err());
}

/// The roots: a bundle's certificates, an entry that is not one skipped,
/// a file that is not there an error.
#[test]
fn roots_from_a_file() {
    let dir = std::env::temp_dir().join(format!("cbb-roots-{}", random_uuid()));
    std::fs::create_dir_all(&dir).unwrap();
    let f = dir.join("bundle.pem");
    let k = crate::nettest::new_key();
    let der = cbb_core::certs::server_cert_by(&crate::identity::ExternalKey::public(&*k), &mut |tbs| {
        crate::identity::sign_external(&*k, tbs)
    })
    .unwrap();
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(&der);
    std::fs::write(&f, format!("-----BEGIN CERTIFICATE-----\n{b64}\n-----END CERTIFICATE-----\n")).unwrap();
    assert_eq!(read_roots(&f).unwrap().len(), 1);
    assert!(read_roots(&dir.join("none.pem")).is_err());
    std::fs::remove_dir_all(&dir).unwrap();
    assert!(between(3, 3) == 3);
    assert!(timed_out(&io::Error::from(io::ErrorKind::TimedOut)));
    assert!(!timed_out(&io::Error::from(io::ErrorKind::BrokenPipe)));
}
