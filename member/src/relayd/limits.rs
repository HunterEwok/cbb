// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! What an open relay gives the groups and the sources they come from, and
//! the work a source may start each second, with the numbers of Go's
//! internal/relay (docs/relay-budget.md).

use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::budget::{Caps, Rate, Rates};

/// Limits bound what an open relay, which serves any group that registers,
/// gives the groups and the addresses they come from, so that groups nobody
/// vouches for cannot fill it or take all its bandwidth. A zero field takes
/// its value from DEFAULT_OPEN; a relay for the user's own groups has no
/// limits but the per-group ones.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Limits {
    /// Groups on the relay at once.
    pub groups: usize,
    /// Registrations from one IP address.
    pub per_address: usize,
    /// Registrations from one IPv4 /24 or IPv6 /64.
    pub per_network: usize,
    /// Registrations from one IPv4 /16 or IPv6 /48.
    pub per_wide: usize,
    /// Registrations from one IPv6 /32, which holds tens of thousands of
    /// /48s; an IPv4 /16 is its own provider.
    pub per_provider: usize,
    /// Bytes a second the relay copies for one group, both ways together.
    pub byte_rate: f64,
    /// The bytes of authority records the relay keeps for one group, and
    /// for all groups. The records a source brings are charged to it too: a
    /// network may bring 4 groups' worth, a wide network 16 and an IPv6
    /// provider 64.
    pub group_record_bytes: usize,
    pub record_bytes: usize,
    /// Connections through the relay's tunnel at once, of all devices
    /// together: half for the devices' watches, one each, so a device
    /// registers only while its watch has room; half for the calls they
    /// join, charged to the address each end registered from.
    pub streams: usize,
}

/// The open files the relay keeps besides its tunnel's connections and the
/// devices' registrations: setups, the listeners, the log; and the fewest
/// tunnel connections it is sized down to.
const FILES_BESIDES: u64 = 512;
const MIN_STREAMS: usize = 64;

/// Raises the process's soft limit of open files to its hard limit, and
/// returns the limit it has then, None where it cannot tell.
#[cfg(unix)]
pub fn raise_files() -> Option<u64> {
    let mut r = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // SAFETY: getrlimit and setrlimit only read and write r.
    unsafe {
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut r) != 0 {
            return None;
        }
        if r.rlim_cur < r.rlim_max {
            let want = libc::rlimit { rlim_cur: r.rlim_max, rlim_max: r.rlim_max };
            if libc::setrlimit(libc::RLIMIT_NOFILE, &want) == 0 {
                r.rlim_cur = r.rlim_max;
            }
        }
    }
    // rlim_t is u64 on Linux and macOS, i64 on FreeBSD.
    #[allow(clippy::unnecessary_cast)]
    Some(r.rlim_cur as u64)
}

/// Windows has no such limit for sockets.
#[cfg(not(unix))]
pub fn raise_files() -> Option<u64> {
    None
}

/// An open relay's limits: enough for clipboards, which are small, and for
/// a few thousand groups on a small server.
pub const DEFAULT_OPEN: Limits = Limits {
    groups: 4096,
    per_address: 16,
    per_network: 64,
    per_wide: 256,
    per_provider: 1024,
    byte_rate: (1 << 20) as f64,
    group_record_bytes: 256 << 10,
    record_bytes: 128 << 20,
    streams: 8192,
};

impl Limits {
    pub fn with_defaults(self) -> Limits {
        let d = DEFAULT_OPEN;
        let or = |v: usize, d: usize| if v == 0 { d } else { v };
        Limits {
            groups: or(self.groups, d.groups),
            per_address: or(self.per_address, d.per_address),
            per_network: or(self.per_network, d.per_network),
            per_wide: or(self.per_wide, d.per_wide),
            per_provider: or(self.per_provider, d.per_provider),
            byte_rate: if self.byte_rate > 0.0 { self.byte_rate } else { d.byte_rate },
            group_record_bytes: or(self.group_record_bytes, d.group_record_bytes),
            record_bytes: or(self.record_bytes, d.record_bytes),
            streams: or(self.streams, d.streams),
        }
    }

    /// The open files these limits need at most: each connection through
    /// the tunnel costs three (the hub's dial, the accepted end and its
    /// clone), for the watches, the calls, the requests and the openings
    /// and each device's floor of two; each device its registration's
    /// connection; and some for setups and the rest.
    pub fn files(&self) -> u64 {
        let l = self.with_defaults();
        let devices = l.devices() as u64;
        let tunnel = (l.streams + super::server::REQUEST_CAPS.all + l.opening_caps().all) as u64 + 2 * devices;
        3 * tunnel + devices + FILES_BESIDES
    }

    /// These limits within files open files: the tunnel's connections, and
    /// the devices with them, made fewer when it allows fewer.
    pub fn fit_files(self, files: u64) -> Limits {
        let mut l = self.with_defaults();
        while l.streams > MIN_STREAMS && l.files() > files {
            l.streams = (l.streams * 7 / 8).max(MIN_STREAMS);
        }
        l
    }

    /// The devices an open relay registers at once: each keeps a watch.
    pub fn devices(&self) -> usize {
        self.streams / 2
    }

    /// The caps of the joined calls' connections, by the address each end
    /// registered from: a network may hold 1/32 of them, a wide network
    /// 1/8, a provider 1/4, and all of them half of the relay's.
    pub fn stream_caps(&self) -> Caps {
        let half = self.streams / 2;
        Caps { address: half / 32, network: half / 16, wide: half / 4, provider: half / 2, all: half }
    }

    /// The caps of the connections being opened through the relay's
    /// tunnel at once, before a device acknowledged the relay's answer, by
    /// the source the device registered from: an eighth of streams in all,
    /// a provider a quarter of that, a wide network an eighth, a network
    /// 1/32 and an address 1/128. Each device's first two connections do
    /// not count (crate::hub::Limits::floor).
    pub fn opening_caps(&self) -> Caps {
        let all = self.streams / 8;
        Caps { address: all / 128, network: all / 32, wide: all / 8, provider: all / 4, all }
    }

    /// The caps of the registrations an open relay holds, by the source
    /// they came from.
    pub fn registration_caps(&self) -> Caps {
        Caps {
            address: self.per_address,
            network: self.per_network,
            wide: self.per_wide,
            provider: self.per_provider,
            all: 0,
        }
    }

    /// The caps of the records an open relay keeps, by the source that
    /// brought them and in all.
    pub fn record_caps(&self) -> Caps {
        Caps {
            address: 0,
            network: 4 * self.group_record_bytes,
            wide: 16 * self.group_record_bytes,
            provider: 64 * self.group_record_bytes,
            all: self.record_bytes,
        }
    }
}

/// The work a source may start each second, in units: a registration's
/// setup costs SETUP_COST, each record the relay must verify one more. An
/// address earns 64 units a second and may save up to 1536, a network 256
/// and 4096, a wide network 1024 and 8192, an IPv6 provider 2048 and 16384;
/// the burst lets one registration of a group with a full claim (1024
/// records) through, and the rates keep the checks of a source that
/// registers over and over to a small share of a processor (a record's
/// check takes about 45 microseconds).
pub const SETUP_COST: f64 = 4.0;
pub(super) const ADDRESS: Rate = Rate { per_second: 64.0, burst: 1536.0 };
pub(super) const NETWORK: Rate = Rate { per_second: 256.0, burst: 4096.0 };
pub(super) const WIDE: Rate = Rate { per_second: 1024.0, burst: 8192.0 };
pub(super) const PROVIDER: Rate = Rate { per_second: 2048.0, burst: 16384.0 };

/// What each source address, network, wide network and provider may still
/// start (docs/relay-budget.md).
pub fn allowance() -> Rates {
    Rates::new(ADDRESS, NETWORK, WIDE, PROVIDER)
}

/// A token bucket that holds up to two seconds of its rate, shared by a
/// group's connections; take waits until the tokens are there.
pub struct ByteRate {
    rate: f64,
    state: Mutex<(f64, Instant)>,
}

impl ByteRate {
    pub fn new(rate: f64) -> Arc<ByteRate> {
        Arc::new(ByteRate { rate, state: Mutex::new((2.0 * rate, Instant::now())) })
    }

    /// Waits for n tokens, or until stop; false then.
    pub fn take(&self, n: usize, stop: &AtomicBool) -> bool {
        let wait = {
            let Ok(mut s) = self.state.lock() else { return false };
            let now = Instant::now();
            let earned = now.saturating_duration_since(s.1).as_secs_f64() * self.rate;
            s.0 = (2.0 * self.rate).min(s.0 + earned) - n as f64;
            s.1 = now;
            if s.0 < 0.0 { Duration::from_secs_f64(-s.0 / self.rate) } else { Duration::ZERO }
        };
        let until = Instant::now() + wait;
        while Instant::now() < until {
            if stop.load(Ordering::SeqCst) {
                return false;
            }
            std::thread::sleep((until - Instant::now()).min(Duration::from_millis(100)));
        }
        true
    }
}

/// Copies src to dst until either ends, at the rate of b when there is one.
pub fn limited_copy(dst: &mut impl Write, src: &mut impl Read, b: Option<&ByteRate>, stop: &AtomicBool) {
    let mut buf = vec![0u8; 16 << 10];
    loop {
        let n = match src.read(&mut buf) {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        if let Some(b) = b
            && !b.take(n, stop)
        {
            return;
        }
        if dst.write_all(&buf[..n]).is_err() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_fill_zero_fields() {
        assert_eq!(Limits::default().with_defaults(), DEFAULT_OPEN);
        let l = Limits { groups: 3, byte_rate: 10.0, ..Limits::default() }.with_defaults();
        assert_eq!((l.groups, l.byte_rate, l.per_address), (3, 10.0, DEFAULT_OPEN.per_address));
        let c = DEFAULT_OPEN.record_caps();
        assert_eq!((c.network, c.wide, c.provider, c.all), (1 << 20, 4 << 20, 16 << 20, 128 << 20));
    }

    /// The limits fit the open files the relay may have, and the default
    /// ones fit what its unit allows.
    #[test]
    fn limits_fit_the_open_files() {
        let d = Limits::default();
        assert!(d.files() <= 65_536, "the defaults need {} open files", d.files());
        assert_eq!(d.fit_files(65_536), DEFAULT_OPEN);
        let small = d.fit_files(4096);
        assert!(small.files() <= 4096, "{} open files for {} connections", small.files(), small.streams);
        assert!(small.streams >= MIN_STREAMS && small.streams < DEFAULT_OPEN.streams);
        let n = raise_files();
        if cfg!(unix) {
            assert!(n.is_some_and(|n| n > 0));
        }
    }

    #[test]
    fn byte_rate_waits_for_its_tokens() {
        let b = ByteRate::new(1000.0);
        let stop = AtomicBool::new(false);
        let start = Instant::now();
        // Two seconds of tokens are there at once; the next 200 take a
        // fifth of a second.
        assert!(b.take(2000, &stop));
        assert!(start.elapsed() < Duration::from_millis(100));
        assert!(b.take(200, &stop));
        assert!(start.elapsed() >= Duration::from_millis(150));
        stop.store(true, Ordering::SeqCst);
        assert!(!b.take(10_000, &stop), "a stopped wait goes on");
    }
}
