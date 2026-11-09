// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The accounting of the open relay: what state and work strangers may make
//! it hold, charged to whoever pays for it (docs/relay-budget.md), as Go's
//! internal/budget, which the forwarder keeps. A source address pays at each
//! of its levels, the address itself, its network (an IPv4 /24 or an IPv6
//! /64), its wide network (an IPv4 /16 or an IPv6 /48) and, for IPv6, its
//! provider (a /32), and all sources together at one more; each level has
//! its own cap, so one host, one site or one provider can take only its
//! share of what the server has. What is full refuses the new: nothing a
//! source holds is taken from it to make room for another.

use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Instant;

/// Who pays: an address, its network, its wide network, its provider, or
/// every source together.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Level {
    Address,
    Network,
    Wide,
    Provider,
    All,
}

const LEVELS: [Level; 4] = [Level::Address, Level::Network, Level::Wide, Level::Provider];

impl fmt::Display for Level {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Level::Address => "address",
            Level::Network => "network",
            Level::Wide => "wide network",
            Level::Provider => "provider",
            Level::All => "all sources",
        })
    }
}

/// The prefix lengths of each level, for IPv4 and for IPv6. A home usually
/// gets one IPv4 address of a /24 or a whole IPv6 /64, a site or a
/// provider's customer an IPv6 /48, and a provider an IPv6 /32, from which
/// it hands out tens of thousands of /48s; an IPv4 /16 is the closest IPv4
/// has to either, and it is its own provider: IPv4 addresses are too scarce
/// for one source to hold many /16s.
const BITS4: [u8; 4] = [32, 24, 16, 16];
const BITS6: [u8; 4] = [128, 64, 48, 32];

/// A payer: an address masked to the bits of its level. The zero prefix
/// (no address) pays for every source that has no address.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct Prefix {
    addr: Option<IpAddr>,
    bits: u8,
}

impl fmt::Display for Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.addr {
            Some(a) => write!(f, "{a}/{}", self.bits),
            None => f.write_str("invalid Prefix"),
        }
    }
}

/// a as IPv4 when it is an IPv4 address mapped into IPv6.
fn unmap(a: IpAddr) -> IpAddr {
    match a {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(a, IpAddr::V4),
        a => a,
    }
}

fn mask(a: IpAddr, bits: u8) -> IpAddr {
    match a {
        IpAddr::V4(v4) => {
            let m = if bits == 0 { 0 } else { u32::MAX << (32 - u32::from(bits)) };
            IpAddr::V4(Ipv4Addr::from(u32::from(v4) & m))
        }
        IpAddr::V6(v6) => {
            let m = if bits == 0 { 0 } else { u128::MAX << (128 - u32::from(bits)) };
            IpAddr::V6(Ipv6Addr::from(u128::from(v6) & m))
        }
    }
}

/// The prefix that pays for address a at level l (Address, Network, Wide or
/// Provider); the provider of an IPv4 address is its wide network.
pub fn of(a: Option<IpAddr>, l: Level) -> Prefix {
    let Some(a) = a.map(unmap) else { return Prefix { addr: None, bits: 0 } };
    let i = LEVELS.iter().position(|x| *x == l).unwrap_or(0);
    let bits = if a.is_ipv4() { BITS4[i] } else { BITS6[i] };
    Prefix { addr: Some(mask(a, bits)), bits }
}

/// The prefixes that pay for a, the one of each level in order: its
/// address, network and wide network, and for an IPv6 address its provider,
/// which for IPv4 is the wide network again and pays once. A source with no
/// address has one payer, the zero prefix, at every level.
pub fn payers(a: Option<IpAddr>) -> Vec<Prefix> {
    match a.map(unmap) {
        None => vec![Prefix { addr: None, bits: 0 }],
        Some(v4 @ IpAddr::V4(_)) => LEVELS[..3].iter().map(|l| of(Some(v4), *l)).collect(),
        Some(v6) => LEVELS.iter().map(|l| of(Some(v6), *l)).collect(),
    }
}

/// The level of a payer by its prefix length; an IPv4 /16 is a wide
/// network, which is its own provider.
fn level_of(p: &Prefix) -> usize {
    let bits = if p.addr.is_some_and(|a| a.is_ipv4()) { BITS4 } else { BITS6 };
    bits.iter().position(|b| *b == p.bits).unwrap_or(0)
}

/// Caps bound what one payer of each level may hold, and all what all hold
/// together; zero leaves a level without a cap.
#[derive(Clone, Copy, Default, Debug)]
pub struct Caps {
    pub address: usize,
    pub network: usize,
    pub wide: usize,
    pub provider: usize,
    pub all: usize,
}

impl Caps {
    fn of(&self, l: usize) -> usize {
        [self.address, self.network, self.wide, self.provider, self.all][l]
    }
}

/// What each source holds now: registrations, slots or bytes. A payer that
/// holds nothing is forgotten, so the count takes memory only for what is
/// held.
#[derive(Debug)]
pub struct Count {
    caps: Caps,
    held: HashMap<Prefix, usize>,
    all: usize,
}

impl Count {
    pub fn new(caps: Caps) -> Count {
        Count { caps, held: HashMap::new(), all: 0 }
    }

    /// The first level at which a source at a could not hold n more, or
    /// None when every level has room; it changes nothing.
    pub fn full(&self, a: Option<IpAddr>, n: usize) -> Option<Level> {
        for (l, p) in payers(a).iter().enumerate() {
            let limit = self.caps.of(l);
            if limit > 0 && self.held.get(p).copied().unwrap_or(0) + n > limit {
                return Some(LEVELS[l]);
            }
        }
        (self.caps.all > 0 && self.all + n > self.caps.all).then_some(Level::All)
    }

    /// Charges n to the source at a and to all, whether or not it fits: the
    /// caller asks full first.
    pub fn add(&mut self, a: Option<IpAddr>, n: usize) {
        for p in payers(a) {
            *self.held.entry(p).or_default() += n;
        }
        self.all += n;
    }

    /// Charges n to the source at a when it fits, and reports whether it
    /// did.
    pub fn take(&mut self, a: Option<IpAddr>, n: usize) -> bool {
        if self.full(a, n).is_some() {
            return false;
        }
        self.add(a, n);
        true
    }

    /// Gives back n that add charged to the source at a.
    pub fn remove(&mut self, a: Option<IpAddr>, n: usize) {
        for p in payers(a) {
            match self.held.get_mut(&p) {
                Some(h) if *h > n => *h -= n,
                _ => {
                    self.held.remove(&p);
                }
            }
        }
        self.all = self.all.saturating_sub(n);
    }

    /// What the payer of a at level l holds, or all sources at All.
    pub fn held(&self, a: Option<IpAddr>, l: Level) -> usize {
        if l == Level::All {
            return self.all;
        }
        self.held.get(&of(a, l)).copied().unwrap_or(0)
    }

    /// How many payers hold something, which is what the count takes in
    /// memory.
    pub fn payers(&self) -> usize {
        self.held.len()
    }
}

/// Lists what each payer holds, in order, and the total: two counts that
/// hold the same say the same.
impl fmt::Display for Count {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut ps: Vec<_> = self.held.iter().collect();
        ps.sort();
        for (p, n) in ps {
            writeln!(f, "{p} {n}")?;
        }
        write!(f, "all {}", self.all)
    }
}

/// What a payer earns a second, and the most it may save.
#[derive(Clone, Copy, Debug)]
pub struct Rate {
    pub per_second: f64,
    pub burst: f64,
}

struct Bucket {
    units: f64,
    at: Instant,
}

impl Bucket {
    fn refill(&mut self, now: Instant, r: Rate) {
        let earned = now.saturating_duration_since(self.at).as_secs_f64() * r.per_second;
        self.units = r.burst.min(self.units + earned);
        self.at = now;
    }
}

/// How many payers Rates holds before it looks for ones to forget.
const MIN_SWEEP: usize = 4096;

/// What each source may still start: work that costs the server time, paid
/// for in units that each payer earns by the second, at the levels of a
/// source.
pub struct Rates {
    rates: [Rate; 4],
    buckets: HashMap<Prefix, Bucket>,
    sweep_at: usize,
}

impl Rates {
    /// The rates of an address, a network, a wide network and a provider.
    pub fn new(address: Rate, network: Rate, wide: Rate, provider: Rate) -> Rates {
        Rates { rates: [address, network, wide, provider], buckets: HashMap::new(), sweep_at: MIN_SWEEP }
    }

    /// Charges n units to the source at a at every level, or charges nothing
    /// and returns false when any level lacks them. A source that is refused
    /// keeps its place, so asking again does not start it over with a full
    /// burst.
    pub fn take(&mut self, a: Option<IpAddr>, n: f64, now: Instant) -> bool {
        if self.buckets.len() >= self.sweep_at {
            self.sweep(now);
        }
        let ps = payers(a);
        let mut ok = true;
        for (l, p) in ps.iter().enumerate() {
            let r = self.rates[l];
            let b = self.buckets.entry(*p).or_insert(Bucket { units: r.burst, at: now });
            b.refill(now, r);
            ok = ok && b.units >= n;
        }
        if !ok {
            return false;
        }
        for p in &ps {
            if let Some(b) = self.buckets.get_mut(p) {
                b.units -= n;
            }
        }
        true
    }

    /// Forgets the payers whose units are full again, which a new payer
    /// would start with anyway.
    pub fn sweep(&mut self, now: Instant) {
        let rates = self.rates;
        self.buckets.retain(|p, b| {
            let r = rates[level_of(p)];
            b.units + now.saturating_duration_since(b.at).as_secs_f64() * r.per_second < r.burst
        });
        self.sweep_at = MIN_SWEEP.max(2 * self.buckets.len());
    }

    /// How many payers Rates holds now.
    pub fn payers(&self) -> usize {
        self.buckets.len()
    }

    /// The units the payer of a at level l has saved as of its last charge:
    /// a full burst for one that holds none.
    pub fn left(&self, a: Option<IpAddr>, l: Level) -> f64 {
        let i = LEVELS.iter().position(|x| *x == l).unwrap_or(0);
        self.buckets.get(&of(a, l)).map_or(self.rates[i].burst, |b| b.units)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn ip(s: &str) -> Option<IpAddr> {
        Some(s.parse().unwrap())
    }

    fn v6(b: [u8; 16]) -> Option<IpAddr> {
        Some(IpAddr::V6(Ipv6Addr::from(b)))
    }

    #[test]
    fn payers_of_each_level() {
        for (addr, want) in [
            ("192.0.2.7", vec!["192.0.2.7/32", "192.0.2.0/24", "192.0.0.0/16"]),
            ("::ffff:192.0.2.7", vec!["192.0.2.7/32", "192.0.2.0/24", "192.0.0.0/16"]),
            (
                "2001:db8:1:2:3:4:5:6",
                vec!["2001:db8:1:2:3:4:5:6/128", "2001:db8:1:2::/64", "2001:db8:1::/48", "2001:db8::/32"],
            ),
        ] {
            let ps = payers(ip(addr));
            assert_eq!(ps.iter().map(|p| p.to_string()).collect::<Vec<_>>(), want, "{addr}");
            for (l, p) in ps.iter().enumerate() {
                assert_eq!(level_of(p), l, "{addr}: {p}");
            }
            // An IPv4 address's provider is its wide network.
            assert_eq!(of(ip(addr), Level::Provider).to_string(), *want.last().unwrap());
        }
        assert_eq!(payers(None).len(), 1);
    }

    #[test]
    fn count() {
        let mut c = Count::new(Caps { address: 2, network: 3, wide: 4, all: 5, ..Caps::default() });
        let a = ip("192.0.2.1");
        for i in 0..3 {
            assert_eq!(c.take(a, 1), i < 2, "an address holds other than its cap of 2");
        }
        assert_eq!(c.full(a, 1), Some(Level::Address));
        assert!(c.take(ip("192.0.2.2"), 1) && !c.take(ip("192.0.2.3"), 1), "the network's cap of 3");
        assert!(c.take(ip("192.0.3.1"), 1) && !c.take(ip("192.0.4.1"), 1), "the wide network's cap of 4");
        assert!(c.take(ip("198.51.100.1"), 1) && !c.take(ip("203.0.113.1"), 1), "all's cap of 5");
        assert_eq!(c.full(ip("203.0.113.1"), 1), Some(Level::All));
        // Given back, everything is forgotten.
        for s in ["192.0.2.1", "192.0.2.1", "192.0.2.2", "192.0.3.1", "198.51.100.1"] {
            c.remove(ip(s), 1);
        }
        assert!(c.payers() == 0 && c.held(a, Level::All) == 0, "after all was given back the count holds\n{c}");
    }

    /// The wide networks of one IPv6 provider, however many, hold no more
    /// than the provider's cap between them; an IPv4 /16 is its own
    /// provider and pays for it once.
    #[test]
    fn count_provider() {
        let mut c = Count::new(Caps { wide: 2, provider: 5, ..Caps::default() });
        let mut got = 0;
        for w in 0..8u8 {
            for i in 0..3u8 {
                let mut b = [0u8; 16];
                b[..6].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, w]);
                b[15] = i + 1;
                if c.take(v6(b), 1) {
                    got += 1;
                }
            }
        }
        assert_eq!(got, 5);
        assert_eq!(c.full(ip("2001:db8:ff::1"), 1), Some(Level::Provider));
        assert!(c.take(ip("2001:db9::1"), 1), "a source of another provider refused");
        let mut c = Count::new(Caps { wide: 2, provider: 1, ..Caps::default() });
        assert!(c.take(ip("192.0.2.1"), 1) && c.take(ip("192.0.3.1"), 1) && !c.take(ip("192.0.4.1"), 1));
        assert_eq!(c.held(ip("192.0.9.9"), Level::Provider), 2);
    }

    /// A small PCG, for the same kind of random sources as Go's test.
    struct Pcg(u64);

    impl Pcg {
        fn below(&mut self, n: usize) -> usize {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            ((self.0 >> 33) as usize) % n
        }
    }

    /// For any sources in any order, sources of fewer wide networks than
    /// fill all leave room for one from another wide network, and nothing
    /// taken is lost: what a count holds is the sum of what it took.
    #[test]
    fn count_property() {
        let mut rng = Pcg(62026);
        for _ in 0..200 {
            let mut caps = Caps {
                address: 1 + rng.below(8),
                network: 1 + rng.below(32),
                wide: 1 + rng.below(64),
                ..Caps::default()
            };
            let k = 1 + rng.below(16);
            caps.all = k * caps.wide + 1 + rng.below(8);
            let mut c = Count::new(caps);
            let mut taken: HashMap<Option<IpAddr>, usize> = HashMap::new();
            for _ in 0..4 * caps.all {
                let w = rng.below(k) as u8;
                let a = if w.is_multiple_of(2) {
                    Some(IpAddr::V4(Ipv4Addr::new(10, w, rng.below(4) as u8, rng.below(8) as u8)))
                } else {
                    let mut b = [0u8; 16];
                    b[..4].copy_from_slice(&[0x20, 0x01, 0, w]);
                    b[7] = rng.below(4) as u8;
                    b[15] = rng.below(8) as u8;
                    v6(b)
                };
                if c.take(a, 1) {
                    *taken.entry(a).or_default() += 1;
                }
            }
            assert!(c.take(ip("203.0.113.9"), 1), "caps {caps:?}, {k} wide networks: no room for another source\n{c}");
            *taken.entry(ip("203.0.113.9")).or_default() += 1;
            let mut sum = 0;
            for (a, n) in taken {
                sum += n;
                c.remove(a, n);
            }
            assert!(c.payers() == 0 && sum <= caps.all, "caps {caps:?}: took {sum}, left\n{c}");
        }
    }

    #[test]
    fn rates() {
        let now = Instant::now();
        let r = |per_second, burst| Rate { per_second, burst };
        let mut rs = Rates::new(r(1.0, 4.0), r(2.0, 6.0), r(4.0, 8.0), r(8.0, 10.0));
        let (a, b) = (ip("192.0.2.1"), ip("192.0.2.2"));
        assert!(rs.take(a, 4.0, now) && !rs.take(a, 1.0, now), "an address spent other than its burst of 4");
        // The network has 2 left; a refusal charges nothing.
        assert!(!rs.take(b, 3.0, now) && rs.take(b, 2.0, now) && !rs.take(b, 1.0, now), "the network's burst of 6");
        assert_eq!(rs.left(a, Level::Wide), 2.0);
        assert!(rs.take(a, 1.0, now + Duration::from_secs(1)), "an address earned nothing in a second");
        // The wide networks of one IPv6 provider share its burst of 10.
        for w in 0..3u8 {
            let mut x = [0u8; 16];
            x[..6].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, w]);
            x[15] = 1;
            assert_eq!(rs.take(v6(x), 4.0, now), w != 2, "wide network {w}: the provider's burst is not shared");
        }
        assert_eq!(rs.left(ip("2001:db8:ff::1"), Level::Provider), 2.0);
        rs.sweep(now + Duration::from_secs(3600));
        assert_eq!(rs.payers(), 0, "an hour later payers are kept");
    }
}
