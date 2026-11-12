// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! cbb global, sync away from home on this device, as the Go cbb's
//! (cmd/cbb/global.go and entries.go): it shows it, turns it on or off,
//! makes this device or another a hub, moves the hub, meets at a blind
//! relay, lets the service reach the group's servers through the system's
//! limit (awaynet.rs) and opens the hub's port in the firewall (hubport.rs).

use std::io::{BufRead, Write};
use std::net::{SocketAddr, ToSocketAddrs};
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};

use crate::awaynet::{self, ALLOW_HINT, Grant, Net};
use crate::cli::usage;
use crate::control::{Away, Header, Message, Status};
use crate::error::{Context, Error, Result};
use crate::{Global, hubport, request, status_text};

/// The project's forwarder (as Go's forward.ProjectHost) and relay, and the
/// word that names them.
const PROJECT_FORWARDER: &str = "cbb.tools:8764";
const PROJECT_RELAY: &str = "cbb.tools:8765";
const PROJECT: &str = "default";

/// What a user agrees to before a device whose keys sit in files syncs away
/// from home (docs/design.md, "Turning it on, step by step").
pub(crate) const KEYS_WARNING: &str = "Sync away from home lets this device reach the group's hub from the internet,
through the group's own WireGuard tunnel, with the clipboard encrypted end to end.

This device keeps its keys in files, not in a security chip. Whoever copies those
files (with root on this device, from its disk or memory card, or from an
unencrypted backup) can act as this device from anywhere until you remove it from
the group. To keep that from happening:

  - encrypt the disk (LUKS, BitLocker, FileVault);
  - keep the service's state directory out of unencrypted backups;
  - remove the device at once (cbb remove, or Remove on the phone) when it is lost
    or someone else may have had root on it.

";

/// What a blind relay learns, said before the user agrees to meet there
/// (docs/design.md, "Blind relay").
const RELAY_NOTICE: &str = "A blind relay is a meeting point for the devices of a group that has no hub of its own.
The clipboard stays encrypted end to end between the devices: the relay cannot read it
or pose as a device. It does learn, while the devices use it:

  - which devices of the group are online, and their internet addresses;
  - which of them talk to each other, when, and how much they send.

A hub of the group's own lets none of this out. Use a relay you run yourself, or one
whose operator you trust with this; the project's relay keeps none of it in logs.

";

/// What depends on the hub being on.
const HUB_NOTE: &str = "
The hub does not have to stay on. While it is off, nothing syncs away from home;
at home the devices sync with each other without it. Keep it on all the time, turn
it on when you need it, or sync only at home.
";

/// What cbb global takes, as Go's.
fn usage_text() -> String {
    format!(
        "cbb global                     show sync away from home
       cbb global on                  turn it on here
       cbb global off [-yes]          turn it off here and forget its keys
       cbb global off -on DEVICE      on an admin: turn it off on another device, whose own user
                                      turns it on again
       cbb global hub [-away-on] [-keep] [-port N] [-firewall ask|yes|no] [-no-obfuscate] [-forwarder default|address:port -forwarder-key KEY] [-no-vless] [address:port...]
                                      make this device the group's hub, reached at these addresses
                                      or through the forwarder (without addresses, the project's at
                                      {PROJECT_FORWARDER}); it hides WireGuard with AmneziaWG and lets
                                      its clients reach the forwarder over VLESS, for networks that
                                      block WireGuard: -no-vless turns VLESS off, -no-obfuscate with it
                                      plain WireGuard; -away-on turns sync away from home on here first
       cbb global hub -on DEVICE [-forward-only] [-forwarder default|address:port -forwarder-key KEY] [address:port...]
                                      on an admin: make DEVICE, an admin computer with sync away from
                                      home on, a hub of the group as well, reached through the forwarder
                                      (without addresses, the project's) or at these addresses;
                                      -forward-only makes any computer that is no admin a hub that only
                                      passes the copies on, sealed, and reads none
       cbb global hub off [-on DEVICE] [-yes]
                                      stop being one of the group's hubs, or on an admin make DEVICE
                                      stop; its clients go to the next hub, and without one -yes
                                      agrees that they stop syncing away from home
       cbb global move DEVICE [-forwarder default|address:port -forwarder-key KEY] [address:port...]
                                      on the hub: make DEVICE, an admin computer with sync away from
                                      home on, the hub in its place, reached through this hub's
                                      forwarder unless others are given; its clients move with it
       cbb global relay default|address:port -key KEY [-yes]
                                      meet the group's other devices at a blind relay, for a group
                                      without a hub: the project's ({PROJECT_RELAY}) or this one
       cbb global hubs DEVICE...      on the root, or an admin that may be a hub: the group's main
                                      hubs, in the order they serve, before the others
       cbb global allow               let this computer's service reach the group's servers as they
                                      are now, after the hub's addresses changed
       cbb global entries [export [-qr] | import STRING]
                                      the signed entry points of the project's servers: show them,
                                      give them to another device, or take them from one"
    )
}

/// The flags of one subcommand, parsed as Go's flag package does: each
/// -name or --name, a value after it or after =, until the first argument
/// that is no flag or after --.
struct Flags {
    bools: Vec<(&'static str, bool)>,
    strings: Vec<(&'static str, Option<String>)>,
    rest: Vec<String>,
}

impl Flags {
    fn parse(args: &[String], bools: &[&'static str], strings: &[&'static str]) -> Result<Flags> {
        let mut f = Flags {
            bools: bools.iter().map(|b| (*b, false)).collect(),
            strings: strings.iter().map(|s| (*s, None)).collect(),
            rest: Vec::new(),
        };
        let mut it = args.iter();
        while let Some(a) = it.next() {
            if a == "--" {
                f.rest.extend(it.cloned());
                break;
            }
            let Some(name) = a.strip_prefix("--").or_else(|| a.strip_prefix('-')).filter(|n| !n.is_empty() && a != "-")
            else {
                f.rest.push(a.clone());
                f.rest.extend(it.cloned());
                break;
            };
            let (name, value) = match name.split_once('=') {
                Some((n, v)) => (n, Some(v.to_string())),
                None => (name, None),
            };
            if let Some(b) = f.bools.iter_mut().find(|(n, _)| *n == name) {
                b.1 = match value.as_deref() {
                    None | Some("true" | "1" | "t" | "T" | "TRUE" | "True") => true,
                    Some("false" | "0" | "f" | "F" | "FALSE" | "False") => false,
                    Some(_) => return Err(usage(usage_text())),
                };
            } else if let Some(s) = f.strings.iter_mut().find(|(n, _)| *n == name) {
                s.1 = Some(match value {
                    Some(v) => v,
                    None => it.next().cloned().ok_or_else(|| usage(usage_text()))?,
                });
            } else {
                return Err(usage(usage_text()));
            }
        }
        Ok(f)
    }

    fn on(&self, name: &str) -> bool {
        self.bools.iter().any(|(n, v)| *n == name && *v)
    }

    fn get(&self, name: &str) -> String {
        self.strings.iter().find(|(n, _)| *n == name).and_then(|(_, v)| v.clone()).unwrap_or_default()
    }

    fn given(&self, name: &str) -> bool {
        self.strings.iter().any(|(n, v)| *n == name && v.is_some())
    }
}

/// A line from standard input, for a question.
fn answer() -> Result<String> {
    let mut line = String::new();
    let n = std::io::stdin().lock().read_line(&mut line).context("cannot read the answer")?;
    if n == 0 {
        return Err(Error::msg("no answer on standard input"));
    }
    Ok(line)
}

/// Asks the question and ends cbb with the exit code 1, having said so,
/// unless the answer is yes.
fn confirm(question: &str) -> Result<()> {
    print!("{question}");
    std::io::stdout().flush().ok();
    if answer()?.trim().eq_ignore_ascii_case("yes") {
        return Ok(());
    }
    println!("{}", tr!("Nothing changed."));
    std::process::exit(1)
}

/// The service's status now.
fn status_now(g: &Global) -> Result<Status> {
    request(g, &Message::new(Header { op: "status".into(), ..Default::default() }, Vec::new()))?
        .header
        .status
        .ok_or_else(|| Error::msg("the service did not say what it reaches"))
}

/// cbb global.
pub(crate) fn global(g: &Global, args: &[String]) -> Result<()> {
    let net = Net::system();
    let Some(verb) = args.first() else {
        let st = status_now(g)?;
        if st.group.is_empty() {
            return Err(Error::msg("this device is in no group"));
        }
        print!("{}", away_text(&net, st.away.as_ref()));
        return Ok(());
    };
    let rest = &args[1..];
    let mut h = Header { op: "away".into(), name: verb.clone(), ..Default::default() };
    let mut firewall = "ask".to_string();
    match verb.as_str() {
        "on" => {
            if !rest.is_empty() {
                return Err(usage(usage_text()));
            }
            net.check()?;
            confirm(&format!("{KEYS_WARNING}Type yes to turn sync away from home on: "))?;
            h.consent = true;
        }
        "off" => {
            let f = Flags::parse(rest, &["yes"], &["on"])?;
            if !f.rest.is_empty() {
                return Err(usage(usage_text()));
            }
            if f.given("on") {
                h.device = f.get("on");
            } else {
                if net.granted(&Grant::default()).on {
                    net.check()?;
                }
                // The keys go with it, and new ones reach the hub only on
                // the home network: a device that meets the hub only through
                // the tunnel would be cut off from its group until it is at
                // home again.
                if let Ok(Some(a)) = status_now(g).map(|s| s.away)
                    && a.through
                    && !a.hub
                    && !f.on("yes")
                {
                    println!(
                        "This device reaches the hub {} only through the tunnel now. Turning sync away",
                        a.hub_device
                    );
                    println!("from home off forgets its keys; new ones reach the hub only on the home network, so");
                    println!("it syncs with its group again only once it is at home, even after cbb global on.");
                    confirm("Type yes to turn it off anyway: ")?;
                }
            }
        }
        "hubs" => return crate::cli::hubs(g, rest),
        "entries" => return entries(g, rest),
        "allow" => {
            if !rest.is_empty() {
                return Err(usage(usage_text()));
            }
            return allow(g, &net);
        }
        "hub" if rest.first().is_some_and(|a| a == "off") => {
            let f = Flags::parse(&rest[1..], &["yes"], &["on"])?;
            if !f.rest.is_empty() {
                return Err(usage(usage_text()));
            }
            (h.name, h.device, h.force) = ("hub-off".into(), f.get("on"), f.on("yes"));
        }
        "hub" => {
            let f = Flags::parse(
                rest,
                &["no-obfuscate", "no-vless", "forward-only", "away-on", "keep"],
                &["port", "firewall", "forwarder", "forwarder-key", "on"],
            )?;
            let port: i64 = match f.get("port") {
                p if p.is_empty() => 0,
                p => p.parse().map_err(|_| usage(usage_text()))?,
            };
            if f.given("firewall") {
                firewall = f.get("firewall");
            }
            let on = f.get("on");
            let (keep, away_on) = (f.on("keep"), f.on("away-on"));
            if f.on("forward-only") && on.is_empty() {
                return Err(usage_plain(
                    "-forward-only goes with -on DEVICE: an admin makes another computer such a hub",
                ));
            }
            if !on.is_empty() && keep {
                return Err(usage_plain("-keep changes this hub's own settings; -on makes another device a hub"));
            }
            if !on.is_empty() && (port != 0 || f.on("no-obfuscate") || f.on("no-vless") || away_on || firewall != "ask")
            {
                return Err(usage_plain(
                    "-on takes only -forwarder, -forwarder-key and the new hub's addresses; its own settings stay its own",
                ));
            }
            if on.is_empty() {
                net.check()?;
                // A hub needs sync away from home on here, which this
                // device's own user turns on: -away-on asks the question of
                // cbb global on.
                if away_on {
                    if keep {
                        return Err(usage_plain(
                            "-keep changes a hub's settings; -away-on comes with making this device a hub",
                        ));
                    }
                    print!("A hub needs sync away from home, so this turns it on here first, where it is off.\n\n");
                    confirm(&format!(
                        "{KEYS_WARNING}Type yes to turn sync away from home on and make this device a hub: "
                    ))?;
                    h.consent = true;
                }
            }
            if !["ask", "yes", "no"].contains(&firewall.as_str()) {
                return Err(usage(usage_text()));
            }
            let (mut fwd, mut fwd_key) = (f.get("forwarder"), f.get("forwarder-key"));
            // A hub without addresses of its own is reached through the
            // project's forwarder, whose address and key cbb knows.
            if f.rest.is_empty() && fwd.is_empty() && fwd_key.is_empty() && !keep {
                fwd = PROJECT.into();
            }
            project_forwarder(&mut fwd, &mut fwd_key)?;
            if !fwd.is_empty() {
                fwd = resolve_addr_port(&fwd)?;
            }
            (h.port, h.addrs, h.forwarder, h.forwarder_key) = (port, f.rest.clone(), fwd, fwd_key);
            (h.obfuscate_off, h.vless_off, h.keep) = (f.on("no-obfuscate"), f.on("no-vless"), keep);
            if !on.is_empty() {
                (h.device, h.forward_only) = (on, f.on("forward-only"));
            }
        }
        "move" => {
            let Some(device) = rest.first().filter(|d| !d.starts_with('-')) else {
                return Err(usage(usage_text()));
            };
            let f = Flags::parse(&rest[1..], &[], &["forwarder", "forwarder-key"])?;
            let (mut fwd, mut fwd_key) = (f.get("forwarder"), f.get("forwarder-key"));
            project_forwarder(&mut fwd, &mut fwd_key)?;
            if !fwd.is_empty() {
                fwd = resolve_addr_port(&fwd)?;
            }
            (h.device, h.addrs, h.forwarder, h.forwarder_key) = (device.clone(), f.rest.clone(), fwd, fwd_key);
        }
        "relay" => {
            net.check()?;
            // The address may come before the flag or after it.
            let (mut addr, rest) = match rest.split_first() {
                Some((a, r)) if !a.starts_with('-') => (a.clone(), r),
                _ => (String::new(), rest),
            };
            let f = Flags::parse(rest, &["yes"], &["key"])?;
            if addr.is_empty() && f.rest.len() == 1 {
                addr = f.rest[0].clone();
            } else if !f.rest.is_empty() {
                addr.clear();
            }
            let mut key = f.get("key");
            if addr != PROJECT && key == PROJECT {
                return Err(usage_plain("-key default goes with the project's relay, cbb global relay default"));
            }
            if addr == PROJECT {
                // The project's relay: the service takes its keys from the
                // newest signed keys.json, which may change them.
                if !key.is_empty() {
                    return Err(usage_plain(
                        "the project's relay (cbb global relay default) takes no -key: cbb knows it",
                    ));
                }
                (addr, key) = (PROJECT_RELAY.into(), PROJECT.into());
            }
            if addr.is_empty() || key.is_empty() {
                return Err(usage(usage_text()));
            }
            (h.relay, h.relay_key) = (resolve_addr_port(&addr)?, key);
            if !f.on("yes") {
                print!("{RELAY_NOTICE}");
                // The relay turns sync away from home on where it is off,
                // and the same yes agrees to that.
                if status_now(g).is_ok_and(|s| s.away.is_none()) {
                    print!("This turns sync away from home on here as well.\n\n{KEYS_WARNING}");
                }
                confirm("Type yes to meet at this relay: ")?;
            }
            h.consent = true;
        }
        _ => return Err(usage(usage_text())),
    }
    let m = request(g, &Message::new(h.clone(), Vec::new()))?;
    if h.name == "hub-off" && !h.device.is_empty() {
        println!("{} is no hub of the group any more.", h.device);
        return Ok(());
    }
    if !h.device.is_empty() && verb == "hub" {
        if h.forward_only {
            println!("{} is a hub of the group now; it passes the copies on, sealed, and reads none.", h.device);
        } else {
            println!("{} is a hub of the group now.", h.device);
        }
        return Ok(());
    }
    if let Some(st) = &m.header.status {
        let mut a = st.away.clone();
        if verb == "on" && net.confined() {
            a = wait_servers(g, a);
        }
        let grant = net.grant_for(a.as_ref());
        apply_grant(g, &net, &grant).map_err(|e| {
            Error::msg(format!("sync away from home changed, but the service's network did not: {}", e.message()))
        })?;
        // The service cannot change the system's limit itself, so a client
        // that has not heard its hub yet needs another cbb global allow.
        if net.confined() && grant.on && grant.hub_port == 0 && grant.addrs.is_empty() {
            println!(
                "The group's servers are not known yet, so this computer's service still reaches the home network only. Once cbb status shows the hub, {ALLOW_HINT}."
            );
        }
        if let Some(fw) = hubport::system() {
            let mut out = std::io::stdout();
            hubport::sync(fw.as_ref(), net.elevated, st.away.as_ref(), &firewall, &mut out, &mut || answer().ok());
        }
        print!("{}", away_text(&net, st.away.as_ref()));
    }
    if h.name == "hub-off" {
        println!("This device is no hub of the group any more.");
    } else if verb == "hub" {
        print!("{HUB_NOTE}");
    }
    Ok(())
}

/// A wrong use said in its own words, without the usage, as the Go cbb
/// says it: cbb ends with the exit code 2.
fn usage_plain(msg: &str) -> Error {
    eprintln!("cbb: {msg}");
    std::process::exit(2)
}

/// Sync away from home as status shows it, with what the system's limit
/// lets the service reach.
pub(crate) fn away_text(net: &Net, a: Option<&Away>) -> String {
    let mut out = String::new();
    status_text::write_away(&mut out, a, &awaynet::limit_note(net, a));
    out
}

/// Waits a little for a client that has just turned sync away from home on
/// to hear its hub's offer, which names the hub's addresses, so that the
/// system's limit can let them through at once.
fn wait_servers(g: &Global, mut a: Option<Away>) -> Option<Away> {
    let knows = |a: &Option<Away>| a.as_ref().is_some_and(|a| a.hub || a.relay.is_some() || !a.allow.is_empty());
    let deadline = Instant::now() + Duration::from_secs(10);
    while !knows(&a) && a.is_some() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(500));
        match status_now(g) {
            Ok(st) => a = st.away,
            Err(_) => break,
        }
    }
    a
}

/// Lets the service reach grant and says so. When the service restarted
/// for it, it returns once the service answers again, so that the next cbb
/// command finds it running.
fn apply_grant(g: &Global, net: &Net, grant: &Grant) -> Result<()> {
    let (changed, restarted) = net.set(grant)?;
    if restarted {
        let deadline = Instant::now() + Duration::from_secs(15);
        while let Err(e) = status_now(g) {
            if Instant::now() > deadline {
                return Err(Error::msg(format!("the service did not come back after its restart: {}", e.message())));
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    }
    if changed {
        let how = if restarted { "; it restarted for that" } else { "" };
        println!("This computer's service may now reach {grant}{how}.");
    }
    Ok(())
}

/// cbb global allow: lets the service reach the group's servers as the
/// service knows them now.
fn allow(g: &Global, net: &Net) -> Result<()> {
    let st = status_now(g)?;
    // In no group, or with sync away from home off, this takes back what a
    // limit allowed before; the installers run it after an update for that.
    let grant = net.grant_for(st.away.as_ref());
    if !net.confined() {
        println!("This computer has no limit outside the program; the service itself reaches only {grant}.");
        return Ok(());
    }
    if net.granted(&grant).same(&grant) {
        println!("This computer's service may already reach {grant}.");
        return Ok(());
    }
    net.check()?;
    apply_grant(g, net, &grant)
}

/// Turns -forwarder default into the project's forwarder: its address,
/// resolved like any other, and the key the service fills in.
fn project_forwarder(fwd: &mut String, key: &mut String) -> Result<()> {
    if fwd != PROJECT {
        if key == PROJECT {
            return Err(Error::msg("-forwarder-key default goes with -forwarder default, the project's forwarder"));
        }
        return Ok(());
    }
    if !key.is_empty() {
        return Err(Error::msg(
            "the project's forwarder (-forwarder default) takes no -forwarder-key: cbb knows its key",
        ));
    }
    (*fwd, *key) = (PROJECT_FORWARDER.into(), PROJECT.into());
    Ok(())
}

/// Turns a server's name and port, such as cbb.tools:8764, into an address
/// with the port, IPv4 first; the service keeps the address, so a server
/// that moves needs the command again.
fn resolve_addr_port(s: &str) -> Result<String> {
    if s.parse::<SocketAddr>().is_ok() {
        return Ok(s.to_string());
    }
    let bad = || Error::msg(format!("{s:?} is not an address or a name with a port, such as 203.0.113.9:8764"));
    let (host, port) = s.rsplit_once(':').ok_or_else(bad)?;
    let host = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(host);
    if host.is_empty() || port.is_empty() {
        return Err(bad());
    }
    let port: u16 = port.parse().map_err(|_| bad())?;
    let mut ips: Vec<SocketAddr> = (host, port)
        .to_socket_addrs()
        .map_err(|e| Error::msg(format!("could not find the address of {host}: {e}")))?
        .map(|a| SocketAddr::new(a.ip().to_canonical(), port))
        .collect();
    // IPv4 first: a home network without IPv6 is the more common case.
    ips.sort_by_key(|a| !a.is_ipv4());
    let ep = ips.first().ok_or_else(|| Error::msg(format!("could not find the address of {host}")))?;
    println!("{host} is at {ep}.");
    Ok(ep.to_string())
}

/// Starts the string that carries the signed entry points from one device
/// to another (docs/protocol.md, section 16, "Entry points").
const ENTRIES_PREFIX: &str = "cbb-entries:";

/// The largest body of a signed file.
const MAX_BODY: usize = cbb_core::release::MAX_BODY;

/// cbb global entries: shows the signed entry points this device holds,
/// gives them as a string or a QR code for another device, or takes them
/// from one.
fn entries(g: &Global, args: &[String]) -> Result<()> {
    const USE: &str = "cbb global entries               show the signed entry points of the project's servers
       cbb global entries export [-qr]   give them as a string, or a QR code, for another device
       cbb global entries import STRING  take them from another device's string";
    match args {
        [] => {
            let set = held_entries(g)?;
            let body = set["entries"]["body"].as_str().and_then(|b| STANDARD.decode(b).ok()).unwrap_or_default();
            let e: serde_json::Value =
                serde_json::from_slice(&body).map_err(|_| Error::msg("the entry points held do not decode"))?;
            let until = e["expires_ms"].as_i64().unwrap_or(0);
            println!("Signed entry points {}, valid until {}:", e["seq"].as_u64().unwrap_or(0), utc_date(until));
            for f in e["forwarders"].as_array().into_iter().flatten() {
                println!("  the forwarder {}", f["name"].as_str().unwrap_or(""));
                for v in f["vless"].as_array().into_iter().flatten() {
                    println!(
                        "    over VLESS: XHTTP at {}, port {}, {}",
                        v["server_name"].as_str().unwrap_or(""),
                        v["port"].as_u64().unwrap_or(0),
                        v["path"].as_str().unwrap_or("")
                    );
                }
            }
            Ok(())
        }
        [e] if e == "export" => {
            println!("{}", entries_string(&held_entries(g)?)?);
            Ok(())
        }
        [e, q] if e == "export" && q == "-qr" => {
            let text = crate::qr(&entries_string(&held_entries(g)?)?);
            if text.is_empty() {
                return Err(Error::msg(
                    "the entry points do not fit in a QR code; cbb global entries export gives them as a string",
                ));
            }
            print!("{text}");
            Ok(())
        }
        [i, s] if i == "import" => {
            let set = parse_entries(s)?;
            let data = serde_json::to_vec(&set).context("cannot encode the entry points")?;
            request(g, &Message::new(Header { op: "entries".into(), ..Default::default() }, data))?;
            println!(
                "The signed entry points check out; this device keeps the newest it has and passes them to its group."
            );
            Ok(())
        }
        _ => Err(usage(USE)),
    }
}

/// The signed entry points the service holds.
fn held_entries(g: &Global) -> Result<serde_json::Value> {
    let m = request(g, &Message::new(Header { op: "entries_get".into(), ..Default::default() }, Vec::new()))?;
    serde_json::from_slice(&m.payload).map_err(|_| Error::msg("the service sent entry points that do not decode"))
}

/// The signed entry points as a string: the prefix and their JSON in
/// unpadded base64url.
fn entries_string(set: &serde_json::Value) -> Result<String> {
    let data = serde_json::to_vec(set).context("cannot encode the entry points")?;
    Ok(format!("{ENTRIES_PREFIX}{}", URL_SAFE_NO_PAD.encode(data)))
}

/// Reads such a string; the service checks the signatures.
fn parse_entries(s: &str) -> Result<serde_json::Value> {
    let b64 = s.trim().strip_prefix(ENTRIES_PREFIX).ok_or_else(|| {
        Error::msg(format!("that is not a string of signed entry points, which starts with {ENTRIES_PREFIX:?}"))
    })?;
    let damaged = || Error::msg("the string of signed entry points is damaged");
    let data = URL_SAFE_NO_PAD.decode(b64).map_err(|_| damaged())?;
    if data.len() > 2 * MAX_BODY {
        return Err(damaged());
    }
    let set: serde_json::Value = serde_json::from_slice(&data).map_err(|_| damaged())?;
    if !set.is_object() {
        return Err(damaged());
    }
    Ok(set)
}

/// A wall-clock time in milliseconds as a UTC date, YYYY-MM-DD.
fn utc_date(ms: i64) -> String {
    // Days since 1970-01-01 to a civil date (Howard Hinnant's algorithm).
    let z = ms.div_euclid(86_400_000) + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn flags_as_go() {
        let f = Flags::parse(
            &strings(&["-port", "9000", "--no-obfuscate", "-forwarder=cbb.tools:8764", "203.0.113.9:8764", "-keep"]),
            &["no-obfuscate", "keep"],
            &["port", "forwarder"],
        )
        .unwrap();
        assert_eq!(f.get("port"), "9000");
        assert!(f.on("no-obfuscate") && !f.on("keep"));
        assert_eq!(f.get("forwarder"), "cbb.tools:8764");
        // Go's flag package stops at the first argument that is no flag.
        assert_eq!(f.rest, ["203.0.113.9:8764", "-keep"]);
        assert!(Flags::parse(&strings(&["-nope"]), &[], &[]).is_err());
        assert!(Flags::parse(&strings(&["-port"]), &[], &["port"]).is_err());
    }

    #[test]
    fn project_servers() {
        let (mut f, mut k) = (PROJECT.to_string(), String::new());
        project_forwarder(&mut f, &mut k).unwrap();
        assert_eq!((f.as_str(), k.as_str()), (PROJECT_FORWARDER, PROJECT));
        let (mut f, mut k) = (PROJECT.to_string(), "KEY".to_string());
        assert!(project_forwarder(&mut f, &mut k).is_err());
        let (mut f, mut k) = ("198.51.100.9:8764".to_string(), PROJECT.to_string());
        assert!(project_forwarder(&mut f, &mut k).is_err());
    }

    #[test]
    fn addresses() {
        for (s, want) in [("203.0.113.9:8764", "203.0.113.9:8764"), ("[2001:db8::1]:8764", "[2001:db8::1]:8764")] {
            assert_eq!(resolve_addr_port(s).unwrap(), want);
        }
        let got = resolve_addr_port("localhost:8764").unwrap();
        assert!(got == "127.0.0.1:8764" || got == "[::1]:8764", "{got}");
        for s in ["cbb.tools", ":8764", "203.0.113.9"] {
            assert!(resolve_addr_port(s).is_err(), "{s}");
        }
    }

    #[test]
    fn entries_round_trip() {
        let set = serde_json::json!({"keys": {"body": "e30="}, "entries": {"body": "e30="}});
        let s = entries_string(&set).unwrap();
        assert!(s.starts_with(ENTRIES_PREFIX));
        assert_eq!(parse_entries(&format!("  {s}\n")).unwrap(), set);
        for bad in ["", "entries", &format!("entries:{s}"), "cbb-entries:!!", "cbb-entries:e30x"] {
            assert!(parse_entries(bad).is_err(), "{bad:?} was taken");
        }
        assert_eq!(utc_date(0), "1970-01-01");
        assert_eq!(utc_date(1_793_404_800_000), "2026-10-31");
    }
}
