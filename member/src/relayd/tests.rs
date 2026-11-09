// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The tests of Go's internal/relay that look inside a relay, on this one:
//! the budget of an open relay counted at each payer, the registrations of
//! devices with no connection, and the records verified once. The tests
//! that check a relay from outside run in Go against cbb-relay
//! (internal/relay, CBB_TEST_RUST_RELAY).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::time::{Duration, Instant};

use cbb_core::admit::{OwnDevice, new_group};
use cbb_core::authority::{self, Body, Hash, Record};
use cbb_core::certs::{self, Cert, DeviceId};
use cbb_core::identity::{self, ExternalKey, FileKey};

use super::budget::{Count, Level};
use super::keys::Keys;
use super::limits::{self, DEFAULT_OPEN, Limits, SETUP_COST};
use super::server::{
    Config, GroupShare, Inner, MAX_REQUESTS_GROUP, MAX_REQUESTS_ONE, Member, MemberState, REQUEST_CAPS, Relay,
    SETUP_CAPS,
};

fn relay(open: bool, limits: Limits) -> Relay {
    let groups = if open { Vec::new() } else { vec!["0123456789abcdef".into()] };
    Relay::start(Config {
        listen: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        keys: Keys::new().unwrap(),
        groups,
        open,
        limits,
        log: Arc::new(|_| {}),
        verbose: false,
    })
    .unwrap()
}

fn v4(a: u8, b: u8, c: u8, d: u8) -> Option<IpAddr> {
    Some(IpAddr::V4(Ipv4Addr::new(a, b, c, d)))
}

fn v6(b: [u8; 16]) -> Option<IpAddr> {
    Some(IpAddr::V6(Ipv6Addr::from(b)))
}

/// An address of the IPv6 provider 2001:db8::/32 in its wide network w,
/// network n, with the host h.
fn from6(w: usize, n: usize, h: usize) -> Option<IpAddr> {
    v6([0x20, 0x01, 0x0d, 0xb8, 0, w as u8, 0, n as u8, 0, 0, 0, 0, 0, 0, (h >> 8) as u8, h as u8])
}

fn ip(s: &str) -> Option<IpAddr> {
    Some(s.parse().unwrap())
}

/// A connection for a member registered without a device behind it.
fn conn() -> TcpStream {
    static LISTENER: std::sync::OnceLock<std::sync::Mutex<TcpListener>> = std::sync::OnceLock::new();
    let ln = LISTENER.get_or_init(|| std::sync::Mutex::new(TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap()));
    let ln = ln.lock().unwrap();
    let c = TcpStream::connect(ln.local_addr().unwrap()).unwrap();
    drop(ln.accept().unwrap());
    c
}

fn share() -> Arc<GroupShare> {
    Arc::new(GroupShare { pairs: AtomicUsize::new(0), reads: AtomicUsize::new(0), bytes: None })
}

/// A member of a group of the share from the address from, known to the
/// relay's state but not in a group: what the counting of requests needs.
fn counted(inner: &Inner, from: Option<IpAddr>, share: &Arc<GroupShare>) -> Arc<Member> {
    let mut st = inner.lock();
    let id = st.next_id();
    st.members.insert(id, MemberState::default());
    Arc::new(Member {
        id,
        tag: String::new(),
        device: String::new(),
        leaf: [0; 32],
        chain: Vec::new(),
        key: certs::random_bytes(),
        psk: certs::random_bytes(),
        from,
        raw: conn(),
        share: share.clone(),
    })
}

/// Takes up to n requests of m; how many it took.
fn take(inner: &Inner, m: &Member, n: usize) -> usize {
    let mut st = inner.lock();
    (0..n).filter(|_| Inner::take_request_locked(&mut st, m)).count()
}

/// Registers a device of the group tag from the address from as a
/// registration does after its checks, without a device behind it.
fn fake_member(inner: &Inner, tag: &str, from: Option<IpAddr>) -> Result<Arc<Member>, String> {
    let mut st = inner.lock();
    let id = st.next_id();
    let m = Arc::new(Member {
        id,
        tag: tag.into(),
        device: DeviceId::random().to_string(),
        leaf: [0; 32],
        chain: Vec::new(),
        key: certs::random_bytes(),
        psk: certs::random_bytes(),
        from,
        raw: conn(),
        share: inner.share_locked(&st, tag),
    });
    inner.admit_locked(&mut st, &m, None)?;
    inner.add_locked(&mut st, &m).map_err(|e| e.to_string())?;
    Ok(m)
}

/// The requests being read are also counted by the address and the
/// network the devices registered from, and by group, so devices
/// registered by one source or one group cannot take all the slots between
/// them.
#[test]
fn requests_bound_by_source_and_group() {
    let r = relay(true, Limits::default());
    let inner = r.inner();
    // Devices of groups of their own, from one address.
    let one = ip("203.0.113.7");
    let first = counted(inner, one, &share());
    let mut got = take(inner, &first, MAX_REQUESTS_ONE);
    for _ in 1..REQUEST_CAPS.all / MAX_REQUESTS_ONE {
        got += take(inner, &counted(inner, one, &share()), MAX_REQUESTS_ONE);
    }
    assert_eq!(got, REQUEST_CAPS.address, "the requests of one address");
    // Addresses of one network.
    got = 0;
    for i in 0..16 {
        got += take(inner, &counted(inner, v4(192, 0, 2, i), &share()), REQUEST_CAPS.address);
    }
    assert_eq!(got, REQUEST_CAPS.network, "the requests of one network");
    // Devices of one group, from many networks.
    let group = share();
    got = 0;
    for i in 0..8 {
        got += take(inner, &counted(inner, v4(10, 0, i, 1), &group), MAX_REQUESTS_ONE);
    }
    assert_eq!(got, MAX_REQUESTS_GROUP, "the requests of one group");
    // What is left of the slots is for others, and what is read is freed.
    assert_eq!(take(inner, &counted(inner, ip("198.51.100.9"), &share()), 1), 1, "a device from elsewhere");
    for _ in 0..MAX_REQUESTS_ONE {
        inner.free_request(&first);
    }
    let held = inner.lock().requests.held(one, Level::Address);
    assert_eq!(held, REQUEST_CAPS.address - MAX_REQUESTS_ONE);
}

/// The requests being read are also counted by the wide network the
/// devices registered from.
#[test]
fn requests_bound_by_wide_network() {
    let r = relay(true, Limits::default());
    let inner = r.inner();
    let mut got = 0;
    for i in 0..8u8 {
        let from = v6([0x20, 0x01, 0x0d, 0xb8, 0, 7, 0, i, 0, 0, 0, 0, 0, 0, 0, 1]);
        for _ in 0..REQUEST_CAPS.network / MAX_REQUESTS_ONE {
            got += take(inner, &counted(inner, from, &share()), MAX_REQUESTS_ONE);
        }
    }
    assert_eq!(got, REQUEST_CAPS.wide, "the networks of one wide network");
    assert_eq!(take(inner, &counted(inner, ip("2001:db8:8::1"), &share()), 1), 1, "another wide network");
}

/// The requests being read are also counted by the IPv6 provider.
#[test]
fn requests_bound_by_provider() {
    let wides = 4;
    assert!(wides * REQUEST_CAPS.wide > REQUEST_CAPS.provider && REQUEST_CAPS.provider < REQUEST_CAPS.all);
    let r = relay(true, Limits::default());
    let inner = r.inner();
    let mut got = 0;
    for w in 0..wides {
        for h in 0..REQUEST_CAPS.wide / REQUEST_CAPS.address {
            for _ in 0..REQUEST_CAPS.address / MAX_REQUESTS_ONE {
                got += take(inner, &counted(inner, from6(w, 0, h + 1), &share()), MAX_REQUESTS_ONE);
            }
        }
    }
    assert_eq!(got, REQUEST_CAPS.provider, "the wide networks of one provider");
    assert_eq!(take(inner, &counted(inner, ip("2001:db9::1"), &share()), 1), 1, "another provider");
}

/// A device's requests take only its own share, so one device cannot hold
/// up the others', and a dropped device's are not read.
#[test]
fn requests_bound_by_device() {
    let r = relay(true, Limits::default());
    let inner = r.inner();
    let (a, b) = (counted(inner, ip("192.0.2.1"), &share()), counted(inner, ip("198.51.100.1"), &share()));
    assert_eq!(take(inner, &a, MAX_REQUESTS_ONE + 1), MAX_REQUESTS_ONE);
    assert_eq!(take(inner, &b, 1), 1);
    inner.lock().members.get_mut(&b.id).unwrap().dropped = true;
    assert_eq!(take(inner, &b, 1), 0, "a request of a dropped device");
}

/// What a source may start is paid for by the second: a setup costs
/// SETUP_COST, so a source that sets up and closes over and over runs out,
/// and earns more as time passes.
#[test]
fn setups_charged_per_second() {
    let r = relay(true, Limits::default());
    let inner = r.inner();
    let now = Instant::now();
    inner.lock().now = Some(now);
    let (one, other) = (ip("203.0.113.7"), ip("198.51.100.1"));
    let setups = || {
        let mut n = 0;
        while n < 1024 && inner.take_slot(one) {
            inner.free_slot(one);
            n += 1;
        }
        n
    };
    assert_eq!(setups(), (limits::ADDRESS.burst / SETUP_COST) as usize, "setups in a burst");
    assert!(inner.take_slot(other), "another source refused");
    inner.lock().now = Some(now + Duration::from_secs(1));
    assert_eq!(setups(), (limits::ADDRESS.per_second / SETUP_COST) as usize, "setups in the next second");
}

/// Connections that never finish their setup hold only their address's
/// and network's share of the setups.
#[test]
fn setups_bound_by_address() {
    let r = relay(true, Limits::default());
    let inner = r.inner();
    let one = ip("203.0.113.7");
    let held = (0..SETUP_CAPS.address + 10).filter(|_| inner.take_slot(one)).count();
    assert_eq!(held, SETUP_CAPS.address);
    let held = (0..SETUP_CAPS.network + 10).filter(|i| inner.take_slot(v4(192, 0, 2, *i as u8))).count();
    assert_eq!(held, SETUP_CAPS.network);
    assert_eq!(inner.lock().setups.held(None, Level::All), SETUP_CAPS.address + SETUP_CAPS.network);
}

/// The setups from the networks of one wide network are bounded by the
/// wide network, even when each network holds less than its own share.
#[test]
fn setups_bound_by_wide_network() {
    let networks = 3;
    assert!(networks * SETUP_CAPS.network > SETUP_CAPS.wide && networks * SETUP_CAPS.network < SETUP_CAPS.all);
    let r = relay(true, Limits::default());
    let inner = r.inner();
    inner.lock().now = Some(Instant::now());
    let mut held = 0;
    for n in 0..networks {
        for i in 0..SETUP_CAPS.network {
            held += usize::from(inner.take_slot(v4(198, 51, n as u8, i as u8)));
        }
    }
    assert_eq!(held, SETUP_CAPS.wide, "the networks of one wide network");
    assert!(inner.take_slot(ip("203.0.113.7")), "another wide network refused");
}

/// The setups from the wide networks of one IPv6 provider are bounded by
/// the provider's share, below the relay's total.
#[test]
fn setups_bound_by_provider() {
    let wides = 3;
    assert!(wides * SETUP_CAPS.wide > SETUP_CAPS.provider && SETUP_CAPS.provider < SETUP_CAPS.all);
    let r = relay(true, Limits::default());
    let inner = r.inner();
    inner.lock().now = Some(Instant::now());
    let mut held = 0;
    for w in 0..wides {
        for n in 0..SETUP_CAPS.wide / SETUP_CAPS.network {
            for i in 0..SETUP_CAPS.network {
                held += usize::from(inner.take_slot(from6(w, n, i + 1)));
            }
        }
    }
    assert_eq!(held, SETUP_CAPS.provider, "the wide networks of one provider");
    assert!(inner.take_slot(ip("2001:db9::1")), "another provider refused");
}

#[test]
fn allowance() {
    let now = Instant::now();
    let mut a = limits::allowance();
    // Addresses of one network share the network's allowance.
    for i in 0..5 {
        assert_eq!(a.take(v4(192, 0, 2, i), 1024.0, now), i < 4, "address {i}");
    }
    assert!(a.take(ip("198.51.100.1"), 1024.0, now), "another network refused");
    // A refused request charges nothing, and time earns it back.
    assert!(!a.take(ip("192.0.2.50"), 1024.0, now), "an exhausted network took more");
    assert!(a.take(ip("192.0.2.50"), 1.0, now + Duration::from_secs(10)), "nothing earned in 10 s");
    // Sources whose allowance is full again are forgotten.
    let later = now + Duration::from_secs(3600);
    a.sweep(later);
    a.take(ip("198.51.100.2"), 1.0, later);
    assert_eq!(a.payers(), 3, "the address, network and wide network of one source");
}

/// The work an IPv6 provider may start is bounded by its own allowance,
/// whatever wide networks of it ask.
#[test]
fn allowance_bound_by_provider() {
    let now = Instant::now();
    let mut a = limits::allowance();
    let chunk = 1024.0;
    let mut took = 0.0;
    for w in 0..3 {
        for n in 0..(limits::WIDE.burst / chunk) as usize {
            if a.take(from6(w, n, 1), chunk, now) {
                took += chunk;
            }
        }
    }
    assert_eq!(took, limits::PROVIDER.burst, "the wide networks of one provider");
    assert!(a.take(ip("2001:db9::1"), chunk, now), "another provider refused");
    // A second later the provider has earned its rate, and no more.
    let later = now + Duration::from_secs(1);
    for n in 0..(limits::PROVIDER.per_second / chunk) as usize {
        assert!(a.take(from6(9, n, 1), chunk, later), "network {n} refused what the provider earned");
    }
    assert!(!a.take(from6(9, 99, 1), 1.0, later), "the provider took more than it earned");
}

/// The records an open relay keeps are bounded by the wide network and by
/// the IPv6 provider they came from, each a few groups' worth.
#[test]
fn record_caps_of_wide_network_and_provider() {
    let g = DEFAULT_OPEN.group_record_bytes;
    let caps = DEFAULT_OPEN.record_caps();
    assert!(caps.wide == 16 * g && caps.provider == 64 * g && caps.all > caps.provider, "{caps:?}");
    let fill = |c: &mut Count, wides: usize, networks: usize| {
        let mut held = 0;
        for w in 0..wides {
            for n in 0..networks {
                while c.take(from6(w, n, 1), g) {
                    held += g;
                }
            }
        }
        held
    };
    assert_eq!(fill(&mut Count::new(caps), 1, 2 * caps.wide / caps.network), caps.wide);
    let mut c = Count::new(caps);
    assert_eq!(fill(&mut c, 2 * caps.provider / caps.wide, caps.wide / caps.network), caps.provider);
    assert!(c.take(ip("2001:db9::1"), g), "another provider refused");
}

/// The registrations from the wide networks of one IPv6 provider, however
/// many, are bounded by the provider's share.
#[test]
fn registrations_bound_by_provider() {
    let r = relay(true, Limits::default());
    let inner = r.inner();
    let l = DEFAULT_OPEN;
    let mut taken = 0;
    for w in 0..l.per_provider / l.per_wide + 2 {
        for n in 0..l.per_wide / l.per_network {
            for a in 0..l.per_network / l.per_address {
                for i in 0..l.per_address {
                    let tag = format!("{w:04x}{n:04x}{a:04x}{i:04x}");
                    taken += usize::from(fake_member(inner, &tag, from6(w, n, a + 1)).is_ok());
                }
            }
        }
    }
    assert_eq!(taken, l.per_provider, "the wide networks of one provider");
    assert!(fake_member(inner, "ffffffffffffffff", ip("2001:db9::1")).is_ok(), "a group from another provider");
}

/// A pseudo-random generator with a fixed seed, so a failure repeats.
struct Pcg(u64);

impl Pcg {
    fn below(&mut self, n: usize) -> usize {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        ((self.0 >> 33) as usize) % n
    }
}

/// Sources that hold all the registrations they may leave room for a group
/// from another wide network, and never push out a device registered
/// before them: random sources of a few wide networks, in random order.
#[test]
fn open_relay_budget_property() {
    let limits = Limits { groups: 64, per_address: 4, per_network: 8, per_wide: 16, ..Limits::default() };
    let r = relay(true, limits);
    let inner = r.inner();
    let mut rng = Pcg(62026);
    let first: Vec<_> = (0..4u8).map(|i| fake_member(inner, &format!("{i:016x}"), v4(100, i, 0, 1)).unwrap()).collect();
    for round in 0..6u8 {
        // A few wide networks, fewer than fill the relay, flood it with
        // devices of groups of their own and of each other's groups.
        let mut wides = Vec::new();
        for w in 0..1 + rng.below((limits.groups - first.len()) / limits.per_wide - 1) {
            if rng.below(2) == 0 {
                wides.push((vec![1 + w as u8, round, 0, 0], 2));
            } else {
                let mut b = vec![0u8; 16];
                b[..4].copy_from_slice(&[0x20, 0x01, w as u8, round]);
                wides.push((b, 6));
            }
        }
        let mut flood = Vec::new();
        for i in 0..40 * limits.per_wide {
            let (b, keep) = &wides[rng.below(wides.len())];
            let mut b = b.clone();
            for x in b.iter_mut().skip(*keep) {
                *x = rng.below(3) as u8;
            }
            let from = if b.len() == 4 {
                Some(IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3])))
            } else {
                v6(b.try_into().unwrap())
            };
            let tag = format!("{round:08x}{:08x}", rng.below(i + 1));
            if let Ok(m) = fake_member(inner, &tag, from) {
                flood.push(m);
            }
        }
        {
            let st = inner.lock();
            for m in &first {
                let kept = st.groups.get(&m.tag).and_then(|g| g.get(&m.device)).is_some_and(|o| Arc::ptr_eq(o, m));
                assert!(kept, "round {round}: a device registered first was pushed out");
            }
        }
        let other = fake_member(inner, &format!("{:016x}", 1000 + u32::from(round)), v4(203, 0, 113, round));
        assert!(
            other.is_ok(),
            "round {round}: {} wide networks left no room for a group from elsewhere: {:?}",
            wides.len(),
            other.as_ref().err()
        );
        // The flood leaves; the next round floods anew.
        let mut st = inner.lock();
        for m in &flood {
            inner.drop_locked(&mut st, m);
        }
    }
}

/// What an open relay holds after many strangers registered and left is
/// bounded by the budget's numbers: nothing of their groups, registrations
/// or records, and of what their sources may start, only the sources that
/// spent some in the last half minute, which it then forgets.
#[test]
fn open_relay_forgets_strangers() {
    let r = relay(true, Limits::default());
    let inner = r.inner();
    let mut now = Instant::now();
    inner.lock().now = Some(now);
    let strangers = 5000;
    for first in [0, strangers] {
        for i in first..first + strangers {
            let from = v4(1 + (i >> 16) as u8, (i >> 8) as u8, i as u8, 1);
            inner.lock().allow.take(from, SETUP_COST, now);
            let m = fake_member(inner, &format!("{i:016x}"), from).unwrap();
            // As its registration's thread does when it ends.
            let mut st = inner.lock();
            inner.drop_locked(&mut st, &m);
            st.members.remove(&m.id);
        }
        let mut st = inner.lock();
        // docs/relay-budget.md: until a source's allowance is full again,
        // which takes under 30 s, the relay holds it, three payers a source.
        assert!(st.allow.payers() <= 3 * strangers, "the allowance holds {} payers", st.allow.payers());
        now += Duration::from_secs(60);
        st.allow.sweep(now);
        assert_eq!(st.allow.payers(), 0, "a minute later the allowance holds sources");
        assert!(
            st.groups.is_empty()
                && st.by_addr.is_empty()
                && st.members.is_empty()
                && st.records.is_empty()
                && st.periods.is_empty()
                && st.tag_locks.is_empty(),
            "after the strangers left the relay holds {} groups, {} devices, {} states, {} groups' records, {} periods, {} locks",
            st.groups.len(),
            st.by_addr.len(),
            st.members.len(),
            st.records.len(),
            st.periods.len(),
            st.tag_locks.len()
        );
        assert!(
            st.held.payers() == 0 && st.record_bytes.payers() == 0 && st.held.held(None, Level::All) == 0,
            "after the strangers left the counts hold\n{}\n{}",
            st.held,
            st.record_bytes
        );
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64
}

fn new_key() -> FileKey {
    FileKey::new(&identity::new_key().unwrap()).unwrap()
}

/// A group of n devices: its root and its records, each device's signed by
/// the root.
fn group(n: usize) -> (Cert, Vec<Record>) {
    let root_key = new_key();
    let point = new_key().public();
    let now = now_ms();
    let own = OwnDevice {
        name: "computer",
        os: "linux",
        role: authority::ROLE_MEMBER,
        caps: &[],
        member_point: &point,
        store: "file",
        seal: Vec::new(),
    };
    let g = new_group(&root_key, &own, now).unwrap();
    let mut rs = g.records;
    for _ in 1..n {
        let b = Body {
            v: 2,
            alg: authority::ALG_ES256.into(),
            kind: authority::TYPE_DEVICE.into(),
            signer: Hash(g.root.key_hash()),
            time_ms: now,
            device: DeviceId::random().to_string(),
            name: "device".into(),
            role: authority::ROLE_MEMBER.into(),
            key: Some(Hash(certs::random_bytes())),
            ..Default::default()
        };
        let body = rs.next_body(b).unwrap();
        let sig = identity::sign_external(&root_key, &body).unwrap();
        assert!(rs.add(&Record::new(body, sig, None)).unwrap(), "a device record of the group");
    }
    (g.root, rs.all())
}

/// The relay verifies a record when it first gets it and keeps the
/// verified set: a group's later registrations, which send the same
/// records again, cost no more checks; new records are paid for by their
/// source; records that do not verify are not kept.
#[test]
fn records_verified_once() {
    let r = relay(true, Limits::default());
    let inner = r.inner();
    let now = Instant::now();
    inner.lock().now = Some(now);
    let from = ip("127.0.0.1");
    let (root, recs) = group(8);
    let tag = certs::tag(&root);
    let (set, fresh, err) = inner.check_records(&tag, &root, from, &recs);
    assert!(fresh && err.is_none(), "{err:?}");
    assert_eq!(set.unwrap().lock().unwrap().set.len(), recs.len());
    let left = || inner.lock().allow.left(from, Level::Address);
    let before = left();
    for _ in 0..3 {
        let (_, fresh, err) = inner.check_records(&tag, &root, from, &recs);
        assert!(!fresh && err.is_none(), "the same records again: {fresh} {err:?}");
    }
    assert_eq!(left(), before, "the same records again spent the allowance");
    // New records of another group, past what the source has left.
    let (other, more) = group(8);
    let other_tag = certs::tag(&other);
    inner.lock().allow.take(from, before - 4.0, now);
    let (_, _, err) = inner.check_records(&other_tag, &other, from, &more);
    assert!(err.as_deref().is_some_and(|e| e.contains("try again later")), "{err:?}");
    inner.forget_records(&other_tag);
    // A record whose signature is of another body is not kept, nor paid.
    inner.lock().now = Some(now + Duration::from_secs(60));
    let bad = Record::new(more[1].body.clone(), more[2].sig.clone(), None);
    let held = inner.lock().record_bytes.held(from, Level::Address);
    let (set, fresh, err) = inner.check_records(&other_tag, &other, from, &[bad]);
    assert!(!fresh && err.is_none(), "{err:?}");
    let set = set.unwrap();
    let s = set.lock().unwrap();
    assert!(s.set.is_empty() && s.bytes == 0 && s.paid.is_empty(), "{} records, {} bytes kept", s.set.len(), s.bytes);
    drop(s);
    assert_eq!(
        inner.lock().record_bytes.held(from, Level::Address),
        held,
        "a record that does not verify was paid for"
    );
}
