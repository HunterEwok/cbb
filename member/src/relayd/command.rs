// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! cbb-relay's command line: cbb relay hands its
//! arguments to it, and its systemd unit runs it under a user of its own,
//! apart from cbb and the keys of cbb-helper.

use std::io::Write;
use std::net::{Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use super::keys::Keys;
use super::server::{Config, Relay};
use crate::error::{Error, Result};

const USAGE: &str = "usage: cbb relay [-listen ADDRESS] [-key FILE] (-group TAGS | -open) [-show-key]
  -listen ADDRESS  the address to listen on, UDP and TCP (default :8764)
  -key FILE        the relay's keys, made on the first run
  -group TAGS      the tags of the groups to serve, separated by commas, as cbb status shows them
  -open            serve every group that registers, within limits per group and per network, in place of -group
  -show-key        print the key for cbb global relay -key and stop";

/// The key file by default: in systemd's state directory for the relay, or
/// in cbb's own state directory; cbb relay names cbb's with -key.
pub fn default_key() -> PathBuf {
    let dir = std::env::var_os("STATE_DIRECTORY").map_or_else(|| PathBuf::from("/var/lib/cbb"), PathBuf::from);
    dir.join("relay.pem")
}

/// The flags, as Go's flag package takes them: -name value, -name=value,
/// with one dash or two.
struct Flags {
    listen: String,
    key: PathBuf,
    groups: String,
    open: bool,
    show_key: bool,
}

fn parse(args: &[String]) -> std::result::Result<Flags, String> {
    let mut f =
        Flags { listen: ":8764".into(), key: default_key(), groups: String::new(), open: false, show_key: false };
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let Some(name) = a.strip_prefix("--").or_else(|| a.strip_prefix('-')).filter(|n| !n.is_empty()) else {
            return Err("cbb: relay takes only flags".into());
        };
        let (name, inline) = match name.split_once('=') {
            Some((n, v)) => (n, Some(v.to_string())),
            None => (name, None),
        };
        let mut value =
            || inline.clone().or_else(|| it.next().cloned()).ok_or(format!("flag needs an argument: -{name}"));
        match name {
            "listen" => f.listen = value()?,
            "key" => f.key = PathBuf::from(value()?),
            "group" => f.groups = value()?,
            "open" => f.open = inline.as_deref().is_none_or(|v| v == "true" || v == "1"),
            "show-key" => f.show_key = inline.as_deref().is_none_or(|v| v == "true" || v == "1"),
            "h" | "help" => return Err(USAGE.into()),
            _ => return Err(format!("flag provided but not defined: -{name}\n{USAGE}")),
        }
    }
    Ok(f)
}

/// The address to listen on: ":port" for every address.
fn listen_addr(s: &str) -> Result<SocketAddr> {
    if let Some(port) = s.strip_prefix(':') {
        let port = port.parse::<u16>().map_err(|_| Error::msg(format!("{s:?} is not an address to listen on")))?;
        return Ok(SocketAddr::from((Ipv6Addr::UNSPECIFIED, port)));
    }
    s.to_socket_addrs()
        .ok()
        .and_then(|mut a| a.next())
        .ok_or_else(|| Error::msg(format!("{s:?} is not an address to listen on")))
}

/// An open relay's limits from CBB_RELAY_LIMITS, a JSON object of Limits'
/// fields, for the Go tests that run against this relay; the defaults
/// without it.
fn test_limits() -> Result<super::limits::Limits> {
    #[derive(serde::Deserialize, Default)]
    #[serde(default, deny_unknown_fields)]
    struct L {
        groups: usize,
        per_address: usize,
        per_network: usize,
        per_wide: usize,
        per_provider: usize,
        byte_rate: f64,
        group_record_bytes: usize,
        record_bytes: usize,
    }
    let Ok(v) = std::env::var("CBB_RELAY_LIMITS") else { return Ok(Default::default()) };
    let l: L = serde_json::from_str(&v).map_err(|e| Error::msg(format!("CBB_RELAY_LIMITS: {e}")))?;
    Ok(super::limits::Limits {
        groups: l.groups,
        per_address: l.per_address,
        per_network: l.per_network,
        per_wide: l.per_wide,
        per_provider: l.per_provider,
        byte_rate: l.byte_rate,
        group_record_bytes: l.group_record_bytes,
        record_bytes: l.record_bytes,
    })
}

/// The port of a listening address.
pub fn port_of(addr: &str) -> &str {
    addr.rsplit_once(':').map_or(addr, |(_, p)| p)
}

/// Runs the relay until it is stopped, and returns the exit code.
pub fn command(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let f = match parse(args) {
        Ok(f) => f,
        Err(msg) => {
            let _ = writeln!(stderr, "{msg}");
            return 2;
        }
    };
    let fail = |stderr: &mut dyn Write, e: Error| {
        let _ = writeln!(stderr, "cbb: {e}");
        1
    };
    let keys = match Keys::load(&f.key) {
        Ok(k) => k,
        Err(e) => return fail(stderr, e),
    };
    let pin = match keys.pin() {
        Ok(p) => p,
        Err(e) => return fail(stderr, e),
    };
    if f.show_key {
        let _ = writeln!(stdout, "{pin}");
        return 0;
    }
    let listen = match listen_addr(&f.listen) {
        Ok(a) => a,
        Err(e) => return fail(stderr, e),
    };
    let groups: Vec<String> = f.groups.split(',').map(str::trim).filter(|g| !g.is_empty()).map(String::from).collect();
    let debug = std::env::var("CBB_DEBUG").is_ok_and(|v| v == "1");
    let log: Arc<dyn Fn(&str) + Send + Sync> = Arc::new(|line: &str| eprintln!("{line}"));
    let serving = if f.open { "every group".to_string() } else { format!("{} groups", groups.len()) };
    let limits = match test_limits() {
        Ok(l) => l,
        Err(e) => return fail(stderr, e),
    };
    let relay =
        match Relay::start(Config { listen, keys, groups, open: f.open, limits, log: log.clone(), verbose: debug }) {
            Ok(r) => r,
            Err(e) => return fail(stderr, e),
        };
    log(&format!(
        "cbb relay: listening on UDP and TCP port {} for {serving}; its key, for cbb global relay -key: {pin}",
        relay.addr().port()
    ));
    // The Go tests that run against this relay (internal/relay) read its
    // counts more often than once a minute.
    let every = std::env::var("CBB_RELAY_STATS_MS").ok().and_then(|v| v.parse::<u64>().ok()).filter(|n| *n > 0);
    let tick = Duration::from_millis(every.unwrap_or(1000));
    let mut ticks = 0u64;
    // SIGTERM and SIGINT end it as an exit, not a kill: systemd's stop
    // returns at once, and a build with instrument-coverage writes what it
    // ran (CI's coverage of the Go tests that run it).
    #[cfg(unix)]
    // SAFETY: the handler only stores to an atomic.
    unsafe {
        libc::signal(libc::SIGTERM, on_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGINT, on_signal as *const () as libc::sighandler_t);
    }
    while !relay.stopped() && !STOP.load(Ordering::SeqCst) {
        std::thread::sleep(tick);
        ticks += 1;
        if every.is_some() || debug && ticks.is_multiple_of(60) {
            // Counts only: the relay logs nothing about a device.
            let (g, m) = relay.stats();
            log(&format!("cbb relay: {g} groups, {m} devices"));
        }
    }
    0
}

/// Set by SIGTERM or SIGINT: the relay ends.
static STOP: AtomicBool = AtomicBool::new(false);

#[cfg(unix)]
extern "C" fn on_signal(_: libc::c_int) {
    STOP.store(true, Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(args: &[&str]) -> (i32, String, String) {
        let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = command(&args, &mut out, &mut err);
        (code, String::from_utf8_lossy(&out).into(), String::from_utf8_lossy(&err).into())
    }

    /// cbb relay makes its key on the first run, keeps it, and prints the
    /// pin users give the hub; it takes only flags, and a damaged key file
    /// stops it.
    #[test]
    fn keys() {
        let dir = std::env::temp_dir().join(format!("cbb-relay-cmd-{}", cbb_core::certs::random_id()));
        let key = dir.join("relay.pem");
        let key = key.to_str().unwrap();
        let (code, first, err) = run(&["-key", key, "-show-key"]);
        assert_eq!(code, 0, "{err}");
        let inline = format!("--key={key}");
        let (_, again, _) = run(&[&inline, "-show-key"]);
        assert!(!first.trim().is_empty() && first == again, "the pins of two runs: {first:?} {again:?}");
        let (code, _, err) = run(&["extra"]);
        assert!(code == 2 && err.contains("takes only flags"), "{code} {err}");
        let bad = dir.join("bad.pem");
        std::fs::write(&bad, "not a key").unwrap();
        let (code, _, err) = run(&["-key", bad.to_str().unwrap(), "-show-key"]);
        assert!(code == 1 && !err.is_empty(), "a damaged key: {code} {err}");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn ports_and_addresses() {
        for (a, p) in [("[::]:8765", "8765"), ("0.0.0.0:443", "443"), ("8764", "8764")] {
            assert_eq!(port_of(a), p);
        }
        assert_eq!(listen_addr(":8764").unwrap(), "[::]:8764".parse().unwrap());
        assert_eq!(listen_addr("127.0.0.1:0").unwrap(), "127.0.0.1:0".parse().unwrap());
        assert!(listen_addr("nowhere").is_err());
    }
}
