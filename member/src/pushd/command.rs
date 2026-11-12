// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! cbb-push's command line. Its systemd unit runs it on cbb.tools under a
//! user of its own, with the platforms' keys in its state directory
//! (packaging/linux/cbb-push.service).

use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use super::apns::{Apns, Key};
use super::{Budgets, Config, Platform, Service};
use crate::error::{Error, Result};
use crate::relayd::keys::Keys;

const USAGE: &str = "usage: cbb-push [-listen ADDRESS] [-key FILE] [-state FILE] -apns-team ID [-apns-key FILE -apns-key-id ID] [-apns-sandbox-key FILE -apns-sandbox-key-id ID] [-roots FILE] [-show-key]
  -listen ADDRESS            the address to listen on, TCP (default :8767)
  -key FILE                  the service's TLS key, which members pin, made on the first run
  -state FILE                where the tokens' bindings to their send keys are kept across restarts
  -apns-team ID              the Apple team ID of the APNs keys
  -apns-key FILE             the team's APNs key for production (.p8): the iPhone and iPad apps of the stores and TestFlight
  -apns-key-id ID            its ID
  -apns-sandbox-key FILE     the team's APNs key for the sandbox (.p8): development builds
  -apns-sandbox-key-id ID    its ID
  -roots FILE       the CA certificates the platforms' servers are checked with (default the system's)
  -show-key         print the pin of the service's key and stop";

struct Flags {
    listen: String,
    key: PathBuf,
    state: PathBuf,
    apns_team: String,
    apns: [(Option<PathBuf>, String); 2],
    roots: PathBuf,
    show_key: bool,
}

fn state_dir() -> PathBuf {
    std::env::var_os("STATE_DIRECTORY").map_or_else(|| PathBuf::from("/var/lib/cbb-push"), PathBuf::from)
}

fn parse(args: &[String]) -> std::result::Result<Flags, String> {
    let mut f = Flags {
        listen: ":8767".into(),
        key: state_dir().join("push.pem"),
        state: state_dir().join("push.state"),
        apns_team: String::new(),
        apns: [(None, String::new()), (None, String::new())],
        roots: PathBuf::from("/etc/ssl/certs/ca-certificates.crt"),
        show_key: false,
    };
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let Some(name) = a.strip_prefix("--").or_else(|| a.strip_prefix('-')).filter(|n| !n.is_empty()) else {
            return Err(format!("cbb-push takes only flags\n{USAGE}"));
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
            "state" => f.state = PathBuf::from(value()?),
            "apns-team" => f.apns_team = value()?,
            "apns-key" => f.apns[0].0 = Some(PathBuf::from(value()?)),
            "apns-key-id" => f.apns[0].1 = value()?,
            "apns-sandbox-key" => f.apns[1].0 = Some(PathBuf::from(value()?)),
            "apns-sandbox-key-id" => f.apns[1].1 = value()?,
            "roots" => f.roots = PathBuf::from(value()?),
            "show-key" => f.show_key = inline.as_deref().is_none_or(|v| v == "true" || v == "1"),
            "h" | "help" => return Err(USAGE.into()),
            _ => return Err(format!("flag provided but not defined: -{name}\n{USAGE}")),
        }
    }
    Ok(f)
}

fn roots(path: &std::path::Path) -> Result<rustls::RootCertStore> {
    use rustls::pki_types::CertificateDer;
    use rustls::pki_types::pem::PemObject;
    let certs = CertificateDer::pem_file_iter(path)
        .map_err(|e| Error::msg(format!("cannot read {}: {e}", path.display())))?
        .filter_map(|c| c.ok());
    let mut store = rustls::RootCertStore::empty();
    store.add_parsable_certificates(certs);
    if store.is_empty() {
        return Err(Error::msg(format!("{} has no CA certificates", path.display())));
    }
    Ok(store)
}

fn platforms(f: &Flags) -> Result<HashMap<u64, Arc<dyn Platform>>> {
    let mut out: HashMap<u64, Arc<dyn Platform>> = HashMap::new();
    for (env, (path, id)) in [cbb_core::push::ENV_APNS, cbb_core::push::ENV_APNS_SANDBOX].into_iter().zip(&f.apns) {
        let Some(p) = path else { continue };
        let pem = std::fs::read_to_string(p).map_err(|e| Error::with(format!("cannot read {}", p.display()), e))?;
        let key = Key::from_p8(&pem, &f.apns_team, id)?;
        out.insert(env, Arc::new(Apns::new(env, key, roots(&f.roots)?)?));
    }
    // UnifiedPush needs no key of ours: it posts to the phone's endpoint.
    if !out.is_empty() {
        out.insert(cbb_core::push::ENV_UNIFIEDPUSH, Arc::new(super::unifiedpush::UnifiedPush::new(roots(&f.roots)?)?));
    }
    Ok(out)
}

/// Runs the service until it is stopped, and returns the exit code.
pub fn command(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let f = match parse(args) {
        Ok(f) => f,
        Err(msg) => {
            let _ = writeln!(stderr, "{msg}");
            return 2;
        }
    };
    let fail = |stderr: &mut dyn Write, e: Error| {
        let _ = writeln!(stderr, "cbb-push: {e}");
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
    let listen = match crate::relayd::command::listen_addr(&f.listen) {
        Ok(a) => a,
        Err(e) => return fail(stderr, e),
    };
    let platforms = match platforms(&f) {
        Ok(p) => p,
        Err(e) => return fail(stderr, e),
    };
    if platforms.is_empty() {
        return fail(
            stderr,
            Error::msg("no platform: give -apns-team with -apns-key and -apns-key-id, or the sandbox's"),
        );
    }
    let log: Arc<dyn Fn(&str) + Send + Sync> = Arc::new(|line: &str| eprintln!("{line}"));
    let service = match Service::start(Config {
        listen,
        cert: keys.cert.clone(),
        key: keys.key.clone(),
        platforms,
        budgets: Budgets::default(),
        state: Some(f.state.clone()),
        log: log.clone(),
    }) {
        Ok(s) => s,
        Err(e) => return fail(stderr, e),
    };
    log(&format!("cbb-push: listening on TCP port {}; its key's pin: {pin}", service.addr().port()));
    let debug = std::env::var("CBB_DEBUG").is_ok_and(|v| v == "1");
    loop {
        std::thread::sleep(Duration::from_secs(60));
        if debug {
            // Counts only: nothing about a group, a token or an address.
            let (tags, tokens, sent) = service.stats();
            log(&format!("cbb-push: {tags} groups, {tokens} tokens, {sent} sent"));
        }
    }
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

    /// cbb-push makes its key on the first run and prints its pin; it does
    /// not start without a platform, nor with a key that is not Apple's.
    #[test]
    fn keys_and_platforms() {
        let dir = std::env::temp_dir().join(format!("cbb-push-cmd-{}", cbb_core::certs::random_id()));
        let key = dir.join("push.pem");
        let key = key.to_str().unwrap();
        let (code, pin, err) = run(&["-key", key, "-show-key"]);
        assert_eq!(code, 0, "{err}");
        assert_eq!(run(&["-key", key, "-show-key"]).1, pin);
        let (code, _, err) = run(&["-key", key, "-listen", "127.0.0.1:0"]);
        assert_eq!(code, 1);
        assert!(err.contains("no platform"), "{err}");
        let p8 = dir.join("bad.p8");
        std::fs::write(&p8, "not a key").unwrap();
        let (code, _, err) = run(&[
            "-key",
            key,
            "-apns-team",
            "ABCDE12345",
            "-apns-key",
            p8.to_str().unwrap(),
            "-apns-key-id",
            "KEY0000001",
        ]);
        assert_eq!(code, 1);
        assert!(err.contains("APNs key"), "{err}");
        assert_eq!(run(&["stray"]).0, 2);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
