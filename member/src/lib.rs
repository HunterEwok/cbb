// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! cbb, the member of a group on computers and small devices such as
//! routers and small boards: a member without CA keys that joins by QR code
//! through the phone and syncs (docs/design.md); on computers its helper,
//! cbb-helper, does what needs Go.
//!
//! The program is this library and a main that calls [`main`]; the library
//! also lets the Aurora app run the same member in its own process
//! (`ffi/`, feature `aurora`).

#[macro_use]
mod l10n;

mod actions;
mod admin;
mod admit_cli;
mod agent;
#[cfg(feature = "tunnel")]
mod away;
#[cfg(not(feature = "tunnel"))]
#[path = "away_off.rs"]
mod away;
mod awaynet;
#[cfg(feature = "tunnel")]
mod awg;
mod benchtime;
#[cfg(feature = "tunnel")]
pub mod bugd;
mod bugs;
pub mod button;
mod cli;
pub mod content;
pub mod control;
mod copies;
pub mod credentials;
mod device;
mod devices_cli;
pub mod discovery;
pub mod entries;
pub mod error;
mod evidence;
pub mod files;
#[cfg(feature = "tunnel")]
pub mod forward;
#[cfg(feature = "fuzzing")]
#[allow(clippy::expect_used, clippy::panic, reason = "a fuzz target reports a broken promise by panicking")]
pub mod fuzzing;
mod global_cli;
pub mod helper;
#[cfg(feature = "tunnel")]
pub mod hub;
mod hubport;
pub mod identity;
mod interfaces;
mod inviter;
mod keys;
mod leave;
mod logfile;
mod media_cli;
mod mute;
pub mod networks;
mod next;
mod nextimage;
#[cfg(unix)]
mod nextlink;
pub mod node;
pub mod pair;
#[cfg(unix)]
mod pastehelper;
pub mod peer;
mod peripheral;
pub mod phone;
mod piv;
pub mod records;
#[cfg(feature = "tunnel")]
pub mod relay;
#[cfg(feature = "tunnel")]
pub mod relayd;
pub mod releases;
mod remotepaste;
pub mod restore;
mod rootless;
pub mod sealkey;
mod sekey;
mod status_text;
#[cfg(all(unix, not(target_os = "macos")))]
mod third_party {
    pub mod pcsclite;
}
mod servers;
mod service;
mod settings;
mod signed;
pub mod sync;
mod sys;
pub mod takeover;
pub mod tls;
#[cfg(feature = "tunnel")]
pub mod tunnel;
mod update;
mod update_os;
pub mod uptime;
pub mod view;
#[cfg(feature = "tunnel")]
pub mod vless;
pub mod why;
mod window;
pub mod wire;

use crate::sys::UnixStream;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::time::Duration;

use cbb_core::{certs, clip, hlc};
use error::{Context, Error, Result};
use identity::Stored as _;

const USAGE: &str = "Usage: cbb <command> [arguments]

Commands:
  copy [-secret]          Send standard input to the group.
  copy [-text TEXT] FILE...
                          Send files and folders to the group; -type png|jpeg|html FILE
                          sends one image or HTML as clipboard data.
  paste [-terminal [-lines] [-secret]]
                          Print this member's clipboard text; -terminal makes it
                          safe to paste into a terminal.
  paste -o DIR            Save the clipboard's images or files in the folder DIR.
  paste -on DEVICE [-type] [-enter] [-secret]
                          On an admin: put standard input, or this clipboard, where the
                          focus is on another device that allows remote paste.
  paste-receive [on [-enter] [-console] [-no-lock-check] | off]
                          Show, or turn on or off, remote paste on this device;
                          off -on DEVICE or off -all on an admin turns it off elsewhere.
  watch [-0]              Print every text the group sends here, one per line
                          (with -0, each followed by a zero byte).
  keyboard [on [-layout us|ru] [-rate N] [-pastes] | off | pair | type [TEXT]]
                          Make this Linux computer a Bluetooth keyboard for a TV, a tablet
                          or a computer near it: pair shows it to a new one for two minutes,
                          type types TEXT or standard input there.
  remote [add [-appletv | -roku -consent] [-name NAME] ADDRESS | code CODE | cancel
         | remove TV | pastes TV on|off | type [-tv TV] [TEXT]]
                          Be the remote of a TV on the home network: an Android TV, a
                          Google TV or an Apple TV pairs with the code it shows, a Roku over
                          plain HTTP; type types TEXT or standard input in its text field.
  action [enable NAME [-by KINDS] [-any-key] | disable NAME | off]
                          Show this device's quick actions, or turn one on or off here.
  action -on DEVICE NAME  On an admin: run the quick action NAME on another device;
                          action off -on DEVICE or -all turns them off elsewhere.
  status                  Show this device, its group and the group's devices.
  remove <name or ID>     Remove a device from the group.
  rename <name or ID> <new name>
                          Give a device of the group another name (on an admin).
  admin <name or ID>      Make a computer an admin of the group (on the group's root).
  takeover <name or ID>   Claim the group from its lost root computer (on an admin); it waits.
  takeover -delay <duration>
                          Set how long such a claim waits, 0s to 168h (on the root; 72h by default).
  keys [proven|hardware|files]
                          Show or set which keys may be the group's root, an admin or a hub
                          (on the root; hardware by default, files for a root with a key in a file).
  incoming [duration]     Show or set how long a copy from another device stays live after it
                          arrives, 5s to 1h (on the root or an admin; 1m by default): it goes
                          into the clipboard until then, and never after.
  recovery [-yubikey]     Claim the group with its recovery key, typed from the sheet or on a
                          YubiKey, when every phone with the group is lost; it waits as a
                          takeover does.
  handover <name or ID>   Let an admin take the group over at once, as a new phone (on the root).
  freeze <name or ID>     Stop an admin computer, as a stolen one, until the root decides.
  unfreeze <name or ID>   Make a frozen admin computer an admin again (on the group's root).
  resolve                 Void both histories of a key that signed two (on the group's root).
  global [on|off]         Show, or turn on or off, sync over the internet on this device;
                          cbb global -h lists the rest (hub, move, relay, allow, entries).
  global hub address:port Make this device the group's hub for sync over the internet.
  global relay address:port
                          Meet the group's other devices over the internet at a relay.
  global hubs <name or ID>...
                          Set the group's main hubs, in the order they serve, before the
                          others (on the root, or an admin that may be a hub).
  forward                 Run a forwarder for hubs that clients cannot reach directly
                          (cbb-forward, beside cbb).
  relay -group TAG        Run a blind relay for groups without a hub (cbb-relay, beside cbb).
  new                     Create a group with this computer as its root.
  leave [-yes]            Leave the group: delete this device's keys and the group's files,
                          keep the settings; then it can join this group or another one.
  sync [on | off [-for DURATION]]
                          Show or set whether this clipboard syncs with the group; off
                          for a while, or until cbb sync on. A new device syncs.
  sync -on DEVICE on|off  On an admin: turn sync on or off on another device of the group.
  mute -on DEVICE [-for DURATION]
                          On an admin: keep a device's copies from the group for a
                          while, or until another admin's cbb unmute -on.
  unmute -on DEVICE       On an admin: end a device's mute.
  config [max-copy|max-copy-away SIZE]
                          Show or set the largest copy of images and files this device
                          sends or fetches, at home and away from home.
  pair [-name name] [-port port] [-addr host[:port]]...
                          In no group: join one by the phone's QR code, shown here (-addr:
                          where the phone reaches this device, when the code would name
                          the wrong addresses); -caps joins as a member that can do a
                          comma-separated subset of admin,dials,hub (by default all three).
  pair [-admin]           In a group, on its root or an admin: show a code for a new
                          computer, or with -admin for a phone that becomes an admin.
  pair -qr [-admin]       In a group: admit the new device that shows a code and waits;
                          type its code, or paste its QR code's text.
  pair -code [address]    Join with the code from cbb pair on the root or an admin.
  pair -invite file       Join from afar with an invitation from cbb invite
                          (its file, or its text cbb://invite#...).
  invite [-for 1h] [-o file | -app FILE -answers FILE] [-hub DEVICE]
                          Invite a device from afar, on the root or an admin: shows a QR
                          code for the app and writes a file for a computer. Through the
                          group's hub, the first connected one or -hub's.
  update [-check]         Install the newest signed release, as root or administrator;
                          -check only says whether there is one. The previous version
                          goes back when the new one does not start.
  update -auto [on|off]   Show, or turn on or off, updating once a day by itself.
  update -mirror [URL|default]
                          Show or set where updates come from: GitHub, then dl.cbb.tools,
                          or another https:// mirror.
  version                 Print the version and the platform.
  help                    Print this help.

Rarely needed:
  network                 Take the network this computer is on now as one where the group
                          is: it publishes itself and takes connections only on those.
  install [options]       Windows, after winget: install the service from this copy
                          (the options of install.ps1, such as -Express).
  service [-name name] [-port port] [-peer host:port]... [-no-mdns] [-no-listen]
          [-tunnel-via host:port] [-caps list] [-user name]
                          Run the service (started by systemd, procd, launchd, an rc script
                          or Windows); -tunnel-via sends the tunnel's packets to a local UDP
                          port that leads to the hub (cbb next link -udp on the ZX Spectrum
                          Next); -caps: what this member says it can do in its hellos
                          (as for pair; its device record decides); -user: started as root, open the mDNS sockets, then run as
                          this user (FreeBSD's rc script).
  agent                   Link this desktop's clipboard to the service (started at sign-in).
  paste-helper tmux|console|uinput
                          Take remote pastes into tmux (started by cbb.conf)
                          or the Linux text console (the cbb-console unit), or press
                          their keys for the desktop (uinput, the cbb-uinput unit).
  next paste|copy|pair    The same for the ZX Spectrum Next's .cbb dot command, in frames
                          its Z80 reads (member/README.md).

The state directory is /var/lib/cbb (CBB_STATE), the control socket /run/cbb/control.sock
(CBB_SOCKET); on OpenWrt /etc/cbb/state and /var/run/cbb/control.sock; installed without
root (install.sh --rootless, CBB_ROOTLESS=1), ~/.local/state/cbb and
$XDG_RUNTIME_DIR/cbb/control.sock. CBB_INTERFACES limits the member port and mDNS to the
network devices it names. Before the command, -state DIR and -socket PATH name others, and
-debug, or CBB_DEBUG=1, shows the details of errors.
The design is in docs/design.md.
";

/// Reports whether this is an OpenWrt router, whose /var is in RAM and
/// which keeps /etc across upgrades.
pub(crate) fn openwrt() -> bool {
    std::path::Path::new("/etc/openwrt_release").exists()
}

#[derive(Clone)]
pub(crate) struct Global {
    state: PathBuf,
    socket: PathBuf,
}

/// The program cbb: reads the arguments and runs the command.
pub fn main() {
    error::from_env();
    benchtime::start();
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let mut g = Global {
        state: std::env::var_os("CBB_STATE").map(PathBuf::from).unwrap_or_else(|| {
            if rootless::is() {
                rootless::state_dir()
            } else {
                if openwrt() { PathBuf::from("/etc/cbb/state") } else { sys::default_state() }
            }
        }),
        socket: std::env::var_os("CBB_SOCKET")
            .map(PathBuf::from)
            .unwrap_or_else(|| if rootless::is() { rootless::socket() } else { sys::default_socket(openwrt()) }),
    };
    while let Some(a) = args.first().cloned() {
        match flag(&a) {
            Some("state") if args.len() > 1 => g.state = PathBuf::from(args.remove(1)),
            Some("socket") if args.len() > 1 => g.socket = PathBuf::from(args.remove(1)),
            Some("debug") => error::set_show_details(true),
            _ => break,
        }
        args.remove(0);
    }
    let code = match args.first().map(String::as_str) {
        None => {
            eprint!("{USAGE}");
            2
        }
        Some(cmd) => {
            let rest = &args[1..];
            let res = match cmd {
                "pair" if in_group(&g) => admit_cli::pair(&g, rest),
                "pair" => join(&g, rest, false),
                "invite" => admit_cli::invite(&g, rest),
                "keyboard" => devices_cli::keyboard(&g, rest),
                "recovery" => cli::recovery(&g, rest),
                "remote" => devices_cli::remote(&g, rest),
                "next" => std::process::exit(next::run(&g, rest)),
                "service" => cmd_service(&g, rest),
                "agent" if rest.is_empty() => agent::run(&g.socket),
                "agent" => Err(Error::msg("cbb agent takes no arguments")),
                "copy" => cmd_copy(&g, rest),
                "paste" => cmd_paste(&g, rest),
                "status" => cmd_status(&g, rest),
                "leave" => cmd_leave(&g, rest),
                "global" => global_cli::global(&g, rest),
                "watch" => cmd_watch(&g, rest),
                "sync" => cmd_sync(&g, rest),
                "paste-receive" => cmd_paste_receive(&g, rest),
                "action" => cmd_action(&g, rest),
                #[cfg(unix)]
                "paste-helper" => pastehelper::run(&g.socket, rest),
                "update" => cmd_update(&g, rest),
                "remove" => cli::remove(&g, rest),
                "rename" => cli::rename(&g, rest),
                "takeover" => cli::takeover(&g, rest),
                "keys" => cli::keys(&g, rest),
                "incoming" => cli::incoming(&g, rest),
                "handover" => cli::handover(&g, rest),
                "freeze" | "unfreeze" => cli::freeze(&g, rest, cmd == "freeze"),
                "resolve" => cli::resolve(&g, rest),
                "admin" => cli::admin(&g, rest),
                "new" => cli::new(&g, rest),
                "mute" | "unmute" => cli::mute(&g, rest, cmd == "unmute"),
                "config" => cli::config(&g, rest),
                "network" => cli::network(&g, rest),
                "forward" | "relay" => servers::run(&g, cmd, rest),
                "install" => servers::install(rest),
                "version" | "-version" | "--version" => {
                    // Never to be mistaken for a release: its certificates
                    // last minutes.
                    let scaled = if cbb_core::benchtime::ENABLED { " (time-scaled bench build)" } else { "" };
                    println!("cbb {} ({}/{}){scaled}", service::VERSION, std::env::consts::OS, std::env::consts::ARCH);
                    println!("{}", core_version());
                    Ok(())
                }
                "help" | "-h" | "-help" | "--help" => {
                    print!("{USAGE}");
                    Ok(())
                }
                // cbb cbb status: the program's name typed twice, as after a
                // path to cbb.exe.
                "cbb" if !rest.is_empty() => {
                    eprintln!(
                        "cbb: unknown command \"cbb\"; the command comes right after the program: cbb {}",
                        rest.join(" ")
                    );
                    std::process::exit(2)
                }
                _ => {
                    eprintln!("cbb: unknown command {cmd:?}; cbb help lists the commands");
                    std::process::exit(2)
                }
            };
            match res {
                Ok(()) => 0,
                Err(e) => {
                    eprintln!("cbb: {}", e.for_user());
                    if cli::is_usage(&e) { 2 } else { 1 }
                }
            }
        }
    };
    std::process::exit(code);
}

/// The name of a flag, with one dash or two.
pub(crate) fn flag(a: &str) -> Option<&str> {
    a.strip_prefix("--").or_else(|| a.strip_prefix('-')).filter(|f| !f.is_empty())
}

fn host_name() -> String {
    let name = sys::host_name();
    let name: String = name.split('.').next().unwrap_or("").chars().take(64).collect();
    if records::valid_name(&name) { name } else { "member".into() }
}

pub(crate) fn resolve(s: &str) -> Result<SocketAddr> {
    s.to_socket_addrs()
        .context(format!("{s:?} is not host:port"))?
        .next()
        .ok_or_else(|| Error::msg(format!("{s:?} has no address")))
}

/// host:port, with brackets around an IPv6 host.
fn join_host_port(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') { format!("[{host}]:{port}") } else { format!("{host}:{port}") }
}

/// What a member can do unless told otherwise: everything on a computer,
/// a Raspberry Pi or a router; the Pi inside a ZX Spectrum Next, which is
/// on only while the Next is and reaches the network through it, is never
/// a hub (docs/protocol.md, section 4, "Capabilities").
fn default_caps(for_next: bool) -> Vec<String> {
    let all = cbb_core::authority::CAPS.iter();
    all.filter(|c| !for_next || **c != cbb_core::authority::CAP_HUB).map(|c| (*c).to_string()).collect()
}

/// Reads -caps: names of cbb_core::authority::CAPS joined by commas, or
/// none for an empty list; sorted, each once.
fn parse_caps(list: &str) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for c in list.split(',').map(str::trim).filter(|c| !c.is_empty() && *c != "none") {
        if !cbb_core::authority::CAPS.contains(&c) {
            return Err(Error::msg(format!("-caps: {c:?} is none of admin, dials and hub")));
        }
        out.push(c.to_string());
    }
    out.sort();
    out.dedup();
    Ok(out)
}

/// The member port: 8764, or CBB_PORT from the environment or cbb.env.
fn member_port() -> u16 {
    settings::get("CBB_PORT").and_then(|p| p.trim().parse().ok()).unwrap_or(8764)
}

/// Joins a group. For the Next (for_next), the QR code and the outcome come
/// in its frames, and so do the log lines, as `CBB#` lines it skips.
/// cbb pair's usage in no group.
const PAIR_USE: &str =
    "cbb pair [-code [ADDRESS:PORT] | -invite FILE | -app FILE] [-caps LIST] [-name NAME] [-port PORT] [-addr ADDRESS]";

fn join(g: &Global, args: &[String], for_next: bool) -> Result<()> {
    let mut name = host_name();
    // The service's own port, which its firewall rule opens (OpenWrt's
    // init script passes the one in /etc/config/cbb); out of a group the
    // service does not listen on it, so the phone finds cbb pair there.
    let mut port = service_port(g).unwrap_or_else(member_port);
    let mut addrs = Vec::new();
    let mut code_addr = None;
    let mut caps = default_caps(for_next);
    let mut invite = None;
    let mut app = None;
    let mut i = 0;
    while i < args.len() {
        let next = || args.get(i + 1).cloned().ok_or_else(|| Error::msg(tr!("{} needs a value", args[i])));
        match flag(&args[i]) {
            Some("caps") if !for_next => caps = parse_caps(&next()?)?,
            Some("name") => name = next()?,
            Some("port") => port = next()?.parse().context("the port is a number")?,
            Some("addr") => addrs.push(next()?),
            // -code [address:port], as Go's: the code from standard input,
            // the address of the window when mDNS cannot find it.
            Some("code") if !for_next => match args.get(i + 1).filter(|a| !a.starts_with('-') && a.contains(':')) {
                Some(a) => code_addr = Some(a.clone()),
                None => {
                    code_addr = Some(String::new());
                    i += 1;
                    continue;
                }
            },
            Some("invite") if !for_next => invite = Some(next()?),
            Some("app") if !for_next => app = Some(next()?),
            _ => return Err(cli::usage(PAIR_USE)),
        }
        i += 2;
    }
    // The code comes from standard input, never from the command line, and
    // an invitation brings its own way in.
    if [invite.is_some(), code_addr.is_some(), app.is_some()].iter().filter(|b| **b).count() > 1 {
        return Err(cli::usage(PAIR_USE));
    }
    // For a desktop app, which runs cbb as the administrator and sees what
    // it prints only once it ends: the app's own file, opened before
    // anything else, gets the QR code's text.
    let app_file = match &app {
        Some(path) => Some(std::sync::Mutex::new(Some(open_app_file(path)?))),
        None => None,
    };
    if invite.is_none() && code_addr.as_deref() == Some("") {
        // As Go's joinWithCode: the service joins, by the window that mDNS
        // finds, and keeps the identity it gets. With an address, cbb joins
        // itself, into its state folder, before its service starts.
        use std::io::IsTerminal;
        if std::io::stdin().is_terminal() {
            print!("{}", tr!("Pairing code: "));
            std::io::stdout().flush().ok();
        }
        let mut line = String::new();
        std::io::stdin().read_line(&mut line).context("cannot read the code")?;
        let code = pair::normalize_code(line.trim())?;
        let h = control::Header { op: "join".into(), code: code.to_string(), ..Default::default() };
        request(g, &control::Message::new(h, Vec::new()))?;
        println!("{}", tr!("Joined the group."));
        return Ok(());
    }
    let invite = match invite {
        Some(path) => Some(invite_consent(&path)?),
        None => None,
    };
    let (joiner, save) = joiner(&g.state, &name)?;
    let joiner = joiner.as_member(admin::os_name(), &caps.iter().map(String::as_str).collect::<Vec<_>>());
    let save = &*save;
    let invited = invite.is_some();
    let id = match invite {
        Some((path, text)) => {
            let shown = |fp: &str| {
                println!("{}", tr!("\nThis device's key fingerprint:  {}", fp.get(..23).unwrap_or(fp)));
                println!("{}", tr!("Whoever invited you sees it on the hub and admits this device if it matches."));
                println!("{}", tr!("Waiting for them; press Ctrl+C to give up."));
                std::io::stdout().flush().ok();
            };
            let log: std::sync::Arc<dyn Fn(&str) + Send + Sync> = std::sync::Arc::new(|s: &str| eprintln!("{s}"));
            let id = away::join_invite(&g.state, &joiner, save, &text, &shown, log)?;
            // It is used up, and was a secret; nothing needs it any more.
            if !path.is_empty() {
                let _ = std::fs::remove_file(&path);
            }
            id
        }
        None if code_addr.is_some() => {
            let a = code_addr.unwrap_or_default();
            print!("{}", tr!("Pairing code: "));
            std::io::stdout().flush().ok();
            let mut line = String::new();
            std::io::stdin().read_line(&mut line).context("cannot read the code")?;
            let code = pair::normalize_code(line.trim())?;
            let sock = TcpStream::connect_timeout(&resolve(&a)?, Duration::from_secs(10))
                .context(format!("cannot connect to {a}"))?;
            pair::join(&joiner, sock, &code, save)?
        }
        None => {
            let ln = TcpListener::bind(("::", port))
                .or_else(|_| TcpListener::bind(("0.0.0.0", port)))
                .or_else(|_| TcpListener::bind(("0.0.0.0", 0)))
                .context("cannot listen for the phone")?;
            // An address without a port gets the one listened on.
            let bound = ln.local_addr().context("cannot listen for the phone")?.port();
            let addrs: Vec<String> =
                addrs.into_iter().map(|a| if resolve(&a).is_ok() { a } else { join_host_port(&a, bound) }).collect();
            let code = pair::new_code();
            let shown = |text: &str| {
                if let (Some(file), Some(path)) = (&app_file, &app) {
                    let f = file.lock().unwrap_or_else(|e| e.into_inner()).take();
                    if let Err(e) = f.map_or(Ok(()), |f| write_app_join(f, text, bound)) {
                        eprintln!("cbb: writing {path}: {}", e.for_user());
                        std::process::exit(1);
                    }
                    watch_app_file(path.clone());
                    return;
                }
                if for_next {
                    let frame = next::qr_frame(text);
                    let mut out = std::io::stdout();
                    if frame.is_empty() {
                        // Fail now rather than leave the Next waiting for a
                        // pairing nobody can start.
                        out.write_all(b"CBBERR cannot make the QR code\r").ok();
                        out.flush().ok();
                        std::process::exit(1);
                    }
                    out.write_all(&frame).ok();
                    out.flush().ok();
                    return;
                }
                println!(
                    "{}\n",
                    tr!("On a phone of the group, tap + in the CBB app, then Scan a code, and scan this:")
                );
                print!("{}", qr(text));
                println!("\n{}", tr!("Or paste this into the app: {}", text));
                println!("\n{}", tr!("Waiting up to 5 minutes. Press Ctrl+C to cancel."));
                println!(
                    "{}",
                    tr!("Without a phone: run cbb pair on a full member and cbb pair -code <its address> here.")
                );
                std::io::stdout().flush().ok();
            };
            let log = |s: &str| {
                if for_next {
                    print!("CBB# {}\r", next::to_spectrum(s).escape_ascii());
                    std::io::stdout().flush().ok();
                } else {
                    eprintln!("{s}");
                }
            };
            pair::listen(&joiner, ln, (!addrs.is_empty()).then_some(addrs), &code, pair::LIFETIME, &shown, save, &log)?
        }
    };
    wait_for_group(g);
    if for_next {
        print!("CBB# joined the group {} as {}\r", id.tag(), id.id);
    } else {
        println!("{}", tr!("Joined the group {} as {}.", id.tag(), id.id));
    }
    if invited {
        wait_for_hub(g);
    }
    Ok(())
}

/// After a join by invitation, waits a while for the service to hand this
/// device's own tunnel key to the hub through the invitation's guest
/// tunnel, and says how it went: the join is done either way, and the
/// service keeps trying for a day.
fn wait_for_hub(g: &Global) {
    let status = control::Message::new(control::Header { op: "status".into(), ..Default::default() }, Vec::new());
    println!("{}", tr!("Handing this device's tunnel key to the hub..."));
    std::io::stdout().flush().ok();
    let deadline = std::time::Instant::now() + Duration::from_secs(120);
    let mut running = false;
    while std::time::Instant::now() < deadline {
        match request(g, &status) {
            Ok(m) => {
                running = true;
                if m.header.status.as_ref().and_then(|s| s.away.as_ref()).is_some_and(|a| !a.hub_device.is_empty()) {
                    println!("{}", tr!("The hub took it: this device syncs from afar now."));
                    return;
                }
            }
            Err(_) if !running => break,
            Err(_) => {}
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    if running {
        println!("{}", tr!("The hub has not answered yet; the service keeps trying for a day."));
    } else {
        println!("{}", tr!("Start the service (cbb service) within a day: it hands this device's key to the hub."));
    }
}

/// Opens the desktop app's file for cbb pair -app once, at the start: a
/// regular file, the one the path named when cbb looked, and never one that
/// a link put in its place since leads to, since cbb runs as the
/// administrator and the file's folder may be the user's.
pub(crate) fn open_app_file(path: &str) -> Result<std::fs::File> {
    open_app_file_with(path, true)
}

/// As open_app_file, for reading what the app writes into it.
pub(crate) fn open_app_file_read(path: &str) -> Result<std::fs::File> {
    open_app_file_with(path, false)
}

fn open_app_file_with(path: &str, write: bool) -> Result<std::fs::File> {
    let before = std::fs::symlink_metadata(path).context(format!("cannot open {path}"))?;
    if !before.file_type().is_file() {
        return Err(Error::msg(format!("{path} is not a regular file")));
    }
    let mut o = std::fs::OpenOptions::new();
    if write {
        o.write(true);
    } else {
        o.read(true);
    }
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(&mut o, libc::O_NOFOLLOW);
    // FILE_FLAG_OPEN_REPARSE_POINT: a link opens as itself, not its target.
    #[cfg(windows)]
    std::os::windows::fs::OpenOptionsExt::custom_flags(&mut o, 0x0020_0000);
    let f = o.open(path).context(format!("cannot open {path}"))?;
    let opened = f.metadata().context(format!("cannot open {path}"))?;
    #[cfg(unix)]
    let same = {
        use std::os::unix::fs::MetadataExt;
        (before.dev(), before.ino()) == (opened.dev(), opened.ino())
    };
    #[cfg(not(unix))]
    let same = true;
    if !opened.file_type().is_file() || !same {
        return Err(Error::msg(format!("{path} changed while cbb opened it")));
    }
    Ok(f)
}

/// Writes what cbb pair -app hands the app, one line of JSON: the QR code's
/// text, how long the wait lasts, and the member port the phone dials.
fn write_app_join(mut f: std::fs::File, text: &str, port: u16) -> Result<()> {
    let line = serde_json::json!({"qr": text, "expires": pair::LIFETIME.as_secs(), "port": port});
    f.set_len(0)
        .and_then(|_| f.write_all(format!("{line}\n").as_bytes()))
        .and_then(|_| f.sync_all())
        .context("cannot write the code")
}

/// Ends cbb pair -app once the app removes its file: the app closed its
/// window, and the wait for the phone ends with it.
pub(crate) fn watch_app_file(path: String) {
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(Duration::from_millis(200));
            if std::fs::symlink_metadata(&path).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound) {
                eprintln!("cbb: cancelled");
                std::process::exit(1);
            }
        }
    });
}

/// Reads a remote invitation for cbb pair -invite, its file or its text
/// (cbb://invite#..., as a scanned code gives it), and asks the user to
/// agree that sync away from home goes on with the join; returns the path,
/// empty for a text, and the invitation's text.
fn invite_consent(path: &str) -> Result<(String, String)> {
    let (path, text) = if path.trim_start().starts_with(cbb_core::invite::PREFIX) {
        (String::new(), path.to_string())
    } else {
        (path.to_string(), std::fs::read_to_string(path).context(format!("cannot read {path}"))?)
    };
    let inv = cbb_core::invite::parse(&text).map_err(|r| Error::msg(r.message()))?;
    if inv.expired(uptime::wall_ms() / 1000) {
        return Err(Error::msg("the invitation has expired; ask for a new one"));
    }
    println!(
        "{}",
        tr!(
            "A device that joins with an invitation syncs away from home through the\ngroup's hub, so sync away from home is turned on here.\n"
        )
    );
    print!("{}", tr!("Type yes to join and turn sync away from home on: "));
    std::io::stdout().flush().ok();
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).context("cannot read the answer")?;
    if !line.trim().eq_ignore_ascii_case("yes") {
        return Err(Error::msg("nothing changed"));
    }
    Ok((path, text))
}

/// The joiner of a device in no group yet, and how it saves the group it
/// joins.
pub(crate) fn joiner(state: &std::path::Path, name: &str) -> Result<(pair::Joiner, Box<pair::Save>)> {
    if identity::Identity::load(state)?.is_some() {
        return Err(Error::msg(format!(
            "this device is already in a group, and it admits no devices here (use the phone app or \
             an admin computer); to join another group, stop the service and remove {}",
            state.join(identity::FILE_NAME).display()
        )));
    }
    std::fs::create_dir_all(state).context(format!(
        "cannot create {0}; make it for the service's user first: \
         sudo install -d -o cbb -g cbb -m 0700 {0}",
        state.display()
    ))?;
    let mut joiner = pair::Joiner::new(name)?;
    // The device key goes into the TPM or the Secure Enclave where cbb-helper
    // can put it there, as on a Go member, and into the identity file
    // otherwise.
    match keys::new_device_key() {
        (Some(key), _) => joiner = joiner.holding_key(key)?,
        (None, why) if !why.is_empty() => eprintln!("{}", tr!("cbb: the device key stays in a file: {}", why)),
        (None, _) => {}
    }
    // The key for sealed messages the service will offer in its hello goes
    // with the info, so that a phone records it as it admits this member.
    match sealkey::load(state)
        .and_then(|s| cbb_core::seal::public_key(&s).map_err(|e| e.context("the key for sealed messages")))
    {
        Ok(public) => joiner.seal = public,
        Err(e) => eprintln!("{}", tr!("cbb: the key for sealed commands: {}; commands will come unsealed", e)),
    }
    let state = state.to_path_buf();
    let save = move |id: &identity::Identity, rs: &[records::Record], ts: &[records::ClaimTime]| {
        let mut set = records::new(&id.group_ca);
        let _ = set.add_all(rs);
        set.take_claim_times(ts);
        records::Stored::save(&set, &state)?;
        id.save(&state)
    };
    Ok((joiner, Box::new(save)))
}

/// Joins with the code from cbb pair on a full member, through a
/// connection to it: the Next's link joins this way through the ESP.
#[cfg(unix)]
pub(crate) fn join_with_code(g: &Global, sock: TcpStream, code: &str) -> Result<identity::Identity> {
    let (joiner, save) = joiner(&g.state, &host_name())?;
    let code = pair::normalize_code(code)?;
    pair::join(&joiner, sock, &code, &*save)
}

/// Waits until a running service has taken the group that join saved: it
/// looks for the identity every two seconds, and a command right after cbb
/// join would otherwise find it in no group. A service that is not running
/// takes the group when it starts.
fn wait_for_group(g: &Global) {
    let status = control::Message::new(control::Header { op: "status".into(), ..Default::default() }, Vec::new());
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while std::time::Instant::now() < deadline {
        match request(g, &status) {
            Ok(m) if m.header.status.as_ref().is_some_and(|s| !s.group.is_empty()) => return,
            Ok(_) => std::thread::sleep(Duration::from_millis(200)),
            Err(_) => return,
        }
    }
}

/// Draws text as a QR code with half blocks, black on white whatever the
/// terminal's colors, as cbb pair does.
pub(crate) fn qr(text: &str) -> String {
    let Ok(code) = qrcode::QrCode::with_error_correction_level(text, qrcode::EcLevel::M) else {
        return String::new();
    };
    let size = code.width() as i32;
    let quiet = 2;
    let n = size + 2 * quiet;
    let black = |x: i32, y: i32| {
        let (x, y) = (x - quiet, y - quiet);
        x >= 0 && y >= 0 && x < size && y < size && code[(x as usize, y as usize)] == qrcode::Color::Dark
    };
    let mut out = String::new();
    for y in (0..n).step_by(2) {
        out.push_str("  ");
        for x in 0..n {
            let fg = if black(x, y) { "30" } else { "97" };
            let bg = if black(x, y + 1) { "40" } else { "107" };
            out.push_str(&format!("\x1b[{fg};{bg}m▀"));
        }
        out.push_str("\x1b[0m\n");
    }
    out
}

fn cmd_service(g: &Global, args: &[String]) -> Result<()> {
    let mut cfg = service::Config {
        state_dir: g.state.clone(),
        socket: g.socket.clone(),
        name: host_name(),
        peers: Vec::new(),
        mdns: true,
        port: Some(member_port()),
        tunnel_via: None,
        caps: default_caps(false),
    };
    let mut run_user = None;
    let mut i = 0;
    while i < args.len() {
        let next = || args.get(i + 1).cloned().ok_or_else(|| Error::msg(tr!("{} needs a value", args[i])));
        match flag(&args[i]) {
            Some("name") => cfg.name = next()?,
            // As the Go service takes them, after the command too (launchd's
            // plist and FreeBSD's rc script).
            Some("state") => cfg.state_dir = PathBuf::from(next()?),
            Some("socket") => cfg.socket = PathBuf::from(next()?),
            Some("user") => run_user = Some(next()?),
            Some("peer") => cfg.peers.push(resolve(&next()?)?),
            Some("tunnel-via") => cfg.tunnel_via = Some(resolve(&next()?)?),
            Some("port") => cfg.port = Some(next()?.parse().context("the port is a number")?),
            Some("no-mdns") => {
                cfg.mdns = false;
                i += 1;
                continue;
            }
            Some("no-listen") => {
                cfg.port = None;
                i += 1;
                continue;
            }
            Some("caps") => cfg.caps = parse_caps(&next()?)?,
            _ => return Err(Error::msg(format!("unknown argument {:?}; see cbb help", args[i]))),
        }
        i += 2;
    }
    if !records::valid_name(&cfg.name) {
        return Err(Error::msg("the device name must be 1 to 64 bytes without control characters"));
    }
    if let Some(u) = run_user {
        // Started as root: the mDNS sockets first, then the user.
        if let Err(e) = discovery::preopen() {
            eprintln!("cbb: opening the mDNS sockets as root: {e}");
        }
        sys::run_as(&u)?;
    }
    #[cfg(windows)]
    {
        // Under the service manager, which gives it no standard error, the
        // service logs to ProgramData\cbb\logs\service.log; started by
        // hand, in the console until Ctrl+C.
        let run: sys::service_windows::Run = Box::new(move |in_service| {
            if !in_service {
                return service::run(cfg);
            }
            logfile::set(&sys::program_data().join("cbb").join("logs").join("service.log"))?;
            let res = service::run(cfg);
            if let Err(e) = &res {
                service::log_line(&format!("cbb: {}", e.for_user()));
            }
            res
        });
        match sys::service_windows::run(run, service::request_stop) {
            Ok(res) => res,
            Err(run) => run(false),
        }
    }
    #[cfg(not(windows))]
    {
        // Started by launchd (packaging/macos/tools.cbb.plist), its own log,
        // moved aside past 1 MiB as on Windows; standard error follows it, so
        // a crash lands there too.
        #[cfg(target_os = "macos")]
        if std::env::var("XPC_SERVICE_NAME").as_deref() == Ok("tools.cbb")
            && let Err(e) = logfile::set(std::path::Path::new("/Library/Logs/cbb/service.log"))
        {
            eprintln!("cbb: the log: {}", e.for_user());
        }
        service::run(cfg)
    }
}

/// Connects to the service's control socket, which only the members of the
/// cbb group may use.
pub(crate) fn connect(g: &Global) -> Result<UnixStream> {
    match UnixStream::connect(&g.socket) {
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            Err(Error::msg("no permission to use the CBB service; add your user to the cbb group and log in again"))
        }
        c => c.context(tr!("cannot reach the CBB service at {}; {}", g.socket.display(), not_running())),
    }
}

/// The hint when the service cannot be reached: systemd's command where
/// systemd runs, else `cbb service` itself (NextPi on the ZX Spectrum Next, say,
/// has no systemd).
fn not_running() -> String {
    hint(std::path::Path::new("/run/systemd/system").is_dir(), rootless::systemctl())
}

fn hint(systemd: bool, systemctl: &str) -> String {
    if systemd {
        tr!("is it running ({} status cbb)?", systemctl)
    } else {
        tr!("is it running (start it with cbb service)?").to_string()
    }
}

/// The member port of the running service, None when none answers.
fn service_port(g: &Global) -> Option<u16> {
    let m =
        request(g, &control::Message::new(control::Header { op: "status".into(), ..Default::default() }, Vec::new()))
            .ok()?;
    m.header.status.and_then(|s| u16::try_from(s.port).ok()).filter(|p| *p != 0)
}

/// Whether the service runs in a group: cbb pair then admits a device
/// rather than joining.
fn in_group(g: &Global) -> bool {
    request(g, &control::Message::new(control::Header { op: "status".into(), ..Default::default() }, Vec::new()))
        .is_ok_and(|m| m.header.status.is_some_and(|s| !s.group.is_empty()))
}

/// Sends one request to the service and returns its answer.
pub(crate) fn request(g: &Global, m: &control::Message) -> Result<control::Message> {
    let conn = open(g, &m.header)?;
    let mut w = conn.try_clone().context("cannot reach the service")?;
    control::write(&mut w, m)?;
    let answer = control::Reader::new(conn).read()?.ok_or_else(|| Error::msg("the service closed the connection"))?;
    check(answer)
}

/// Connects to the socket for a request with the header h: the
/// administrator's for what changes the group, the control socket else.
pub(crate) fn open(g: &Global, h: &control::Header) -> Result<UnixStream> {
    Ok(if control::needs_admin(h) {
        let path = control::admin_socket(&g.socket);
        match UnixStream::connect(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                return Err(Error::msg(tr!(
                    "this command changes the group, so only the administrator may run it; run it with sudo"
                )));
            }
            c => c.context(tr!("cannot reach the CBB service at {}; {}", path.display(), not_running()))?,
        }
    } else {
        connect(g)?
    })
}

pub(crate) fn check(m: control::Message) -> Result<control::Message> {
    if m.header.error.is_empty() {
        return Ok(m);
    }
    let e = Error::msg(m.header.error.clone());
    if m.header.details.is_empty() { Err(e) } else { Err(Error::with(m.header.error, Detail(m.header.details))) }
}

/// The details the service sent with an error.
#[derive(Debug)]
struct Detail(String);

impl std::fmt::Display for Detail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Detail {}

fn cmd_copy(g: &Global, args: &[String]) -> Result<()> {
    const USE: &str = "cbb copy [-secret] < text\n       cbb copy [-text TEXT] [-type png|jpeg|gif|html] FILE...";
    let (mut secret, mut typ, mut alt, mut files) = (false, String::new(), String::new(), Vec::new());
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match flag(a) {
            Some("secret") => secret = true,
            Some("type") => typ = it.next().cloned().ok_or_else(|| cli::usage(USE))?,
            Some("text") => alt = it.next().cloned().ok_or_else(|| cli::usage(USE))?,
            Some(_) => return Err(cli::usage(USE)),
            None => {
                files.push(a.clone());
                files.extend(it.by_ref().cloned());
            }
        }
    }
    if !files.is_empty() {
        if secret {
            return Err(cli::usage("-secret is for a text, not for files"));
        }
        return media_cli::copy(g, &files, &typ, &alt);
    }
    if !typ.is_empty() || !alt.is_empty() {
        return Err(cli::usage("-type and -text go with FILE"));
    }
    let mut text = Vec::new();
    std::io::stdin().take(clip::MAX_TEXT as u64 + 1).read_to_end(&mut text).context("cannot read standard input")?;
    let h = control::Header {
        op: "copy".into(),
        kind: if secret { "secret".into() } else { String::new() },
        ..Default::default()
    };
    request(g, &control::Message::new(h, text))?;
    Ok(())
}

fn cmd_paste(g: &Global, args: &[String]) -> Result<()> {
    if args.iter().any(|a| flag(a) == Some("on")) {
        return media_cli::paste_on(g, args);
    }
    let (mut terminal, mut lines, mut secret, mut out) = (false, false, false, None);
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match flag(a) {
            Some("terminal") => terminal = true,
            Some("lines") => lines = true,
            Some("secret") => secret = true,
            Some("o") => out = Some(it.next().cloned().ok_or_else(|| cli::usage("-o takes a folder"))?),
            _ => return Err(cli::usage("cbb paste [-terminal [-lines] [-secret]] | -o DIR | -on DEVICE ...")),
        }
    }
    if let Some(dir) = out {
        if terminal || lines || secret {
            return Err(cli::usage("-o saves images or files; -terminal, -lines and -secret are for a text"));
        }
        return media_cli::paste_to(g, &dir);
    }
    if (lines || secret) && !terminal {
        return Err(cli::usage("-lines and -secret go with -terminal"));
    }
    let m =
        request(g, &control::Message::new(control::Header { op: "paste".into(), ..Default::default() }, Vec::new()))?;
    let mut out = m.payload;
    if terminal {
        if m.header.kind == "secret" && !secret {
            return Err(Error::msg("the clipboard holds a secret; add -secret to paste it"));
        }
        let (text, dropped) = terminal_text(&String::from_utf8_lossy(&out), lines);
        if dropped > 0 {
            eprintln!(
                "{}",
                tr!("cbb: pasted only the first line; {} more left out (add -lines to paste them)", dropped)
            );
        }
        out = text.into_bytes();
    }
    // Flushed here: a full disk fails the paste rather than lose the text
    // quietly at exit.
    let mut stdout = std::io::stdout();
    stdout.write_all(&out).and_then(|_| stdout.flush()).context("cannot write the text")?;
    Ok(())
}

/// Makes a text safe to paste into a terminal, as the full member's
/// terminalText does: it drops the control characters of C0 but tab and line
/// feed, DEL and those of C1, ends with no line feed, and unless `all` keeps
/// only the first line, returning how many lines it left out.
fn terminal_text(text: &str, all: bool) -> (String, usize) {
    let text: String = text
        .replace("\r\n", "\n")
        .chars()
        .filter(|&c| c == '\t' || c == '\n' || !(c < ' ' || ('\u{7f}'..'\u{a0}').contains(&c)))
        .filter(|&c| c != char::REPLACEMENT_CHARACTER)
        .collect();
    let text = text.trim_matches('\n');
    match text.split_once('\n') {
        Some((first, rest)) if !all => (first.to_string(), rest.matches('\n').count() + 1),
        _ => (text.to_string(), 0),
    }
}

fn cmd_status(g: &Global, args: &[String]) -> Result<()> {
    if !args.is_empty() {
        return Err(cli::usage("status takes no arguments"));
    }
    let ask = |op: &str| {
        request(g, &control::Message::new(control::Header { op: op.into(), ..Default::default() }, Vec::new()))
    };
    let s = ask("status")?.header.status.ok_or_else(|| Error::msg("the service sent no status"))?;
    let devs = if s.group.is_empty() { Vec::new() } else { ask("devices")?.header.devices };
    let limit = awaynet::limit_note(&awaynet::Net::system(), s.away.as_ref());
    print!("{}", status_text::write_status(&s, &devs, uptime::wall_ms(), &limit));
    Ok(())
}

/// The question cbb leave asks before it deletes the keys.
fn leave_question() -> &'static str {
    tr!("This device leaves its group: its keys and the group's files here are deleted, remote paste
and the quick actions are turned off, and the rest of the settings stay. It can then join this
group again or another one (cbb pair). The group keeps listing it until an admin removes it.
Leave the group? [y/N] ")
}

/// cbb leave (D-83): through the service, or by itself when the service
/// does not run, as cbb pair joins.
fn cmd_leave(g: &Global, args: &[String]) -> Result<()> {
    let yes = match args {
        [] => false,
        [a] if flag(a) == Some("yes") => true,
        _ => return Err(Error::msg("usage: cbb leave [-yes]")),
    };
    // In no group there is nothing to ask about; a state this user cannot
    // read gets the question, and the service says what it can do.
    if matches!(identity::Identity::load(&g.state), Ok(None)) && !g.state.join(records::FILE_NAME).exists() {
        return Err(Error::msg(leave::NOTHING_TO_LEAVE));
    }
    if !yes {
        print!("{}", leave_question());
        std::io::stdout().flush().ok();
        let mut line = String::new();
        std::io::stdin().read_line(&mut line).ok();
        if !matches!(line.trim().to_lowercase().as_str(), "y" | "yes") {
            println!("{}", tr!("Nothing changed. (cbb leave -yes leaves without the question.)"));
            std::process::exit(1);
        }
    }
    let running = UnixStream::connect(control::admin_socket(&g.socket))
        .map(|_| true)
        .or_else(|e| match e.kind() {
            std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused => Ok(false),
            _ => Err(e),
        })
        .unwrap_or(true);
    if running {
        request(g, &control::Message::new(control::Header { op: "leave".into(), ..Default::default() }, Vec::new()))?;
        println!("{}", tr!("Left the group. The service restarts in no group: cbb pair joins one."));
    } else {
        if identity::Identity::load(&g.state).ok().flatten().is_none() && !g.state.join(records::FILE_NAME).exists() {
            return Err(Error::msg(leave::NOTHING_TO_LEAVE));
        }
        leave::leave_group(&g.state)?;
        println!("{}", tr!("Left the group: cbb pair joins one."));
    }
    Ok(())
}

/// Shows sync, or turns it on or off here, as cbb sync on a full member.
fn cmd_sync(g: &Global, args: &[String]) -> Result<()> {
    const USE: &str = "cbb sync [on | off [-for DURATION]]\n       cbb sync -on DEVICE on|off";
    let (mut on, mut for_ms, mut word) = (String::new(), 0, None);
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match flag(a) {
            Some("on") => on = it.next().cloned().ok_or_else(|| cli::usage(USE))?,
            Some("for") => {
                let d = it.next().ok_or_else(|| cli::usage(USE))?;
                for_ms = go_duration_ms(d).ok_or_else(|| cli::usage(USE))?;
                if for_ms == 0 || for_ms > mute::MAX_MS {
                    return Err(cli::usage(format!("-for is from 1ms to {}", cli::go_duration(mute::MAX_MS))));
                }
            }
            None if word.is_none() && (a == "on" || a == "off") => word = Some(a.clone()),
            _ => return Err(cli::usage(USE)),
        }
    }
    if !on.is_empty() && word.is_none() {
        return Err(cli::usage(USE));
    }
    if for_ms != 0 && (word.as_deref() != Some("off") || !on.is_empty()) {
        return Err(cli::usage("-for goes with cbb sync off on this device"));
    }
    let h = match &word {
        Some(w) => {
            control::Header { op: "sync".into(), on: Some(w == "on"), device: on.clone(), for_ms, ..Default::default() }
        }
        None => control::Header { op: "status".into(), ..Default::default() },
    };
    request(g, &control::Message::new(h, Vec::new()))?;
    if let Some(w) = word.as_ref().filter(|_| !on.is_empty()) {
        println!("Sync is {w} on {on} now.");
        return Ok(());
    }
    let m =
        request(g, &control::Message::new(control::Header { op: "status".into(), ..Default::default() }, Vec::new()))?;
    let st = m.header.status.unwrap_or_default();
    if st.group.is_empty() {
        return Err(Error::msg("this device is in no group; run cbb new here to start one, or cbb pair to join one"));
    }
    println!("{}", status_text::sync_line(&st));
    Ok(())
}

/// The tunnel address of a device (docs/protocol.md, section 11):
/// fd00:cbb::/32 followed by the first 96 bits of its ID (32 lowercase hex
/// characters).
pub(crate) fn tunnel_addr(id: &str) -> Option<std::net::Ipv6Addr> {
    if !certs::is_id(id) {
        return None;
    }
    let mut a = [0u8; 16];
    a[0..4].copy_from_slice(&[0xfd, 0x00, 0x0c, 0xbb]);
    for (i, b) in a[4..].iter_mut().enumerate() {
        *b = u8::from_str_radix(&id[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(std::net::Ipv6Addr::from(a))
}

/// The tunnel address of a remote invitation's guest (docs/protocol.md,
/// section 12): fd00:cbc::/32 followed by the first 96 bits of SHA-256 of
/// the guest's public key, as hub::guest_addr; here also without the
/// tunnel, for an admin that makes invitations through a hub.
pub(crate) fn tunnel_guest_addr(key: &[u8]) -> std::net::Ipv6Addr {
    let sum = certs::sha256(key);
    let mut a = [0u8; 16];
    a[0..4].copy_from_slice(&[0xfd, 0x00, 0x0c, 0xbc]);
    a[4..].copy_from_slice(&sum[..12]);
    std::net::Ipv6Addr::from(a)
}

/// Reads a duration as Go writes one, such as 0s, 90s, 15m, 72h or 1h30m,
/// in milliseconds.
pub(crate) fn go_duration_ms(s: &str) -> Option<i64> {
    let mut total: i64 = 0;
    let mut num = String::new();
    let mut rest = s;
    if rest.is_empty() {
        return None;
    }
    while !rest.is_empty() {
        let digits = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
        num.clear();
        num.push_str(&rest[..digits]);
        rest = &rest[digits..];
        let unit_len = rest.find(|c: char| c.is_ascii_digit()).unwrap_or(rest.len());
        let unit = match &rest[..unit_len] {
            "ms" => 1,
            "s" => 1000,
            "m" => 60_000,
            "h" => 3_600_000,
            _ => return None,
        };
        rest = &rest[unit_len..];
        total = total.checked_add(num.parse::<i64>().ok()?.checked_mul(unit)?)?;
    }
    Some(total)
}

fn cmd_paste_receive(g: &Global, args: &[String]) -> Result<()> {
    const USE: &str = "cbb paste-receive [on [-enter] [-console] [-no-lock-check] | off [-on DEVICE | -all]]";
    // As on Go's flag package, the flags may come before on or off too.
    let mut h = control::Header { op: "status".into(), ..Default::default() };
    let (mut on_flags, mut off_flags) = (false, false);
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match (a.as_str(), flag(a)) {
            ("on" | "off", _) if h.name.is_empty() => {
                h.op = "paste_receive".into();
                h.name = a.clone();
            }
            (_, Some("enter")) => (h.enter, on_flags) = (true, true),
            (_, Some("console")) => (h.console, on_flags) = (true, true),
            (_, Some("no-lock-check")) => (h.no_lock_check, on_flags) = (true, true),
            (_, Some("on")) => {
                h.device = it.next().cloned().ok_or_else(|| cli::usage(USE))?;
                off_flags = true;
            }
            (_, Some("all")) => (h.all, off_flags) = (true, true),
            _ => return Err(cli::usage(USE)),
        }
    }
    if on_flags && h.name != "on" || off_flags && h.name != "off" {
        return Err(cli::usage(USE));
    }
    if h.all && !h.device.is_empty() {
        return Err(cli::usage(USE));
    }
    if h.console && rootless::is() {
        return Err(Error::msg(
            "text consoles need the console helper, which runs as root; this device is installed without root, so remote paste reaches tmux only",
        ));
    }
    let (all, device) = (h.all, h.device.clone());
    let m = request(g, &control::Message::new(h, Vec::new()))?;
    if all {
        println!("{}", tr!("Remote paste is off on every device of the group."));
        return Ok(());
    }
    if !device.is_empty() {
        println!("{}", tr!("Remote paste is off on {}.", device));
        return Ok(());
    }
    let p = m.header.status.and_then(|s| s.paste).ok_or_else(|| Error::msg("this device is in no group"))?;
    println!("{}", paste_line(&p));
    Ok(())
}

/// How remote paste stands here, as cbb paste-receive on a full member says
/// it.
fn paste_line(p: &control::Paste) -> String {
    if !p.on {
        return "Remote paste is off: the group's admins cannot paste here.".into();
    }
    let line = match (p.enter, p.console) {
        (true, true) => "Remote paste is on: the group's admins may paste here, press Enter, and reach text consoles.",
        (true, false) => "Remote paste is on: the group's admins may paste here and press Enter.",
        (false, true) => {
            "Remote paste is on: the group's admins may paste here and reach text consoles, without Enter."
        }
        (false, false) => "Remote paste is on: the group's admins may paste here, without Enter.",
    };
    let line = if p.no_lock_check {
        format!("{line} It pastes also where nothing tells whether the session is locked.")
    } else {
        line.to_string()
    };
    if p.targets.is_empty() {
        return format!(
            "{line} Nothing here can paste yet: the desktop connector, the Mac app or the tmux and console helpers do it."
        );
    }
    line
}

const ACTION_USAGE: &str = "usage: cbb action [enable NAME [-by root,phone,computer,watch] [-any-key] [-yes] | disable NAME | off |\n                   add NAME [-by KINDS] [-any-key] [-yes] -- PROGRAM ARGS | remove NAME]";

/// cbb action: shows this device's quick actions and sets them, as on a
/// full member (docs/design.md, "Quick actions"). Enabling says what it lets
/// the group's admins do and asks first; for reboot, as root, it writes the
/// polkit rule that lets the service ask logind, and disabling takes it
/// back.
fn cmd_action(g: &Global, args: &[String]) -> Result<()> {
    let usage = || Error::msg(ACTION_USAGE);
    let (verb, name) = match args {
        [] => {
            let m = request(
                g,
                &control::Message::new(control::Header { op: "status".into(), ..Default::default() }, Vec::new()),
            )?;
            let st = m
                .header
                .status
                .filter(|s| !s.group.is_empty())
                .ok_or_else(|| Error::msg("this device is in no group"))?;
            for a in &st.actions {
                println!("{:<16} {}", a.name, action_line(a));
            }
            return Ok(());
        }
        [v, a, d] if v == "off" && flag(a) == Some("on") => {
            let h = control::Header { op: "actions_off".into(), device: d.clone(), ..Default::default() };
            request(g, &control::Message::new(h, Vec::new()))?;
            println!("{}", tr!("The quick actions are off on {}.", d));
            return Ok(());
        }
        [v, a] if v == "off" && flag(a) == Some("all") => {
            let h = control::Header { op: "actions_off".into(), all: true, ..Default::default() };
            request(g, &control::Message::new(h, Vec::new()))?;
            println!("{}", tr!("The quick actions are off on every device of the group."));
            return Ok(());
        }
        [a, d, name] if flag(a) == Some("on") && flag(name).is_none() => {
            let h =
                control::Header { op: "action_on".into(), device: d.clone(), name: name.clone(), ..Default::default() };
            request(g, &control::Message::new(h, Vec::new()))?;
            println!("{}", tr!("{} ran {}.", d, name));
            return Ok(());
        }
        [v] if v == "off" => {
            let m = request(
                g,
                &control::Message::new(control::Header { op: "actions_off".into(), ..Default::default() }, Vec::new()),
            )?;
            // The rights go too, when this runs as root here.
            if let Err(e) = grant(&m)
                && is_root()
            {
                eprintln!("{}", tr!("cbb: the actions are off, but the rights stay: {}", e.for_user()));
            }
            println!("{}", tr!("The quick actions are off here."));
            return Ok(());
        }
        [v, name] if v == "remove" => {
            let h = control::Header { op: "action_remove".into(), name: name.clone(), ..Default::default() };
            let m = request(g, &control::Message::new(h, Vec::new()))?;
            grant(&m)?;
            println!("{}", tr!("{} is removed.", name));
            return Ok(());
        }
        [v, name, ..] if v == "enable" || v == "disable" || v == "add" => (v.as_str(), name.clone()),
        _ => return Err(usage()),
    };
    let mut a = control::Action { name, on: verb != "disable", ..Default::default() };
    let mut yes = false;
    let mut rest = args[2..].iter();
    while let Some(arg) = rest.next() {
        match flag(arg) {
            _ if arg == "--" && verb == "add" => {
                a.command = rest.by_ref().cloned().collect();
                break;
            }
            Some("by") if a.on => a.by = actions::parse_kinds(rest.next().ok_or_else(usage)?)?,
            Some("any-key") if a.on => a.any_key = true,
            Some("yes") if a.on => yes = true,
            _ => return Err(usage()),
        }
    }
    if verb == "add"
        && let Some(why) = actions::check_own(&a.name, &a.command)
    {
        return Err(Error::msg(why));
    }
    if a.on && rootless::is() && !actions::rights(std::slice::from_ref(&a.name)).is_empty() {
        return Err(Error::msg(format!(
            "{} needs a polkit rule, which only root writes; this device is installed without root, so it runs only the actions that need none",
            a.name
        )));
    }
    if a.on && !yes {
        print!("{}{}", action_warning(&a), tr!("Type yes to turn it on: "));
        std::io::stdout().flush().ok();
        let mut line = String::new();
        std::io::stdin().read_line(&mut line).context("cannot read the answer")?;
        if !line.trim().eq_ignore_ascii_case("yes") {
            println!("{}", tr!("Nothing changed."));
            return Err(Error::msg("the action stays as it was"));
        }
    }
    let h = control::Header { op: "action_set".into(), actions: vec![a.clone()], ..Default::default() };
    let m = request(g, &control::Message::new(h, Vec::new()))?;
    if let Err(e) = grant(&m) {
        if a.on {
            // Without the right the action would only fail; leave it off.
            let off = control::Action { on: false, ..a.clone() };
            let h = control::Header { op: "action_set".into(), actions: vec![off], ..Default::default() };
            let _ = request(g, &control::Message::new(h, Vec::new()));
        }
        return Err(e.context(format!("giving the service the right to {}", a.name)));
    }
    println!("{}: {}.", a.name, action_line(&a));
    Ok(())
}

/// Writes or removes the polkit rule for the actions a status says are on;
/// a rootless install has none.
fn grant(m: &control::Message) -> Result<()> {
    if rootless::is() {
        return Ok(());
    }
    let on = on_actions(m.header.status.as_ref());
    // Only root writes the rule; a user's actions that need no right leave it
    // to root, as the polkit directory is not theirs to read.
    if actions::rights(&on).is_empty() && !is_root() {
        return Ok(());
    }
    actions::grant(std::path::Path::new("/"), &on).map(|_| ())
}

/// The names of the actions a status says are on.
fn on_actions(st: Option<&control::Status>) -> Vec<String> {
    st.iter().flat_map(|s| &s.actions).filter(|a| a.on).map(|a| a.name.clone()).collect()
}

fn is_root() -> bool {
    sys::is_root()
}

/// How an action stands and who may run it, as on a full member.
fn action_line(a: &control::Action) -> String {
    let run = if a.command.is_empty() { String::new() } else { format!(": {}", a.command.join(" ")) };
    if !a.on {
        return format!("off{run}");
    }
    let mut who = if a.by.is_empty() { "every admin".to_string() } else { a.by.join(", ") };
    if actions::hardware_by_default(&a.name) && !a.any_key {
        who += ", keys in hardware only";
    }
    format!("on, for {who}{run}")
}

/// What turning a on lets the group's admins do, and the rights it grants
/// here.
fn action_warning(a: &control::Action) -> String {
    let what = match a.name.as_str() {
        actions::LOCK => "lock this device's screen",
        actions::SLEEP => "put this device to sleep",
        actions::REBOOT => "reboot this device, a minute after they ask",
        actions::SHUTDOWN => "shut this device down, a minute after they ask",
        actions::CANCEL => "cancel a reboot or shutdown that is pending",
        actions::RESTART => "restart the CBB service here",
        actions::LAYOUT => "switch the layout this device's Bluetooth keyboard types in",
        _ => "run this action here",
    };
    let what = if a.command.is_empty() {
        what.to_string()
    } else {
        format!("run {} here as the user signed in", a.command.join(" "))
    };
    let mut who = if a.by.is_empty() {
        "the group's admins".to_string()
    } else {
        format!("the group's admins of the kinds {}", a.by.join(", "))
    };
    if actions::hardware_by_default(&a.name) && !a.any_key {
        who += " whose keys are in hardware (phones, computers with the key in a TPM)";
    }
    let mut s = format!("Turning {} on lets {who} {what}, from wherever they are in the group.\n", a.name);
    let rights = actions::rights(std::slice::from_ref(&a.name));
    if !rights.is_empty() {
        s += "It gives the CBB service these rights, in a polkit rule, and no others:\n";
        for r in rights {
            s += &format!("  {r}\n");
        }
        if !is_root() {
            s += "Writing the rule needs root: run this with sudo.\n";
        }
    }
    s + "Any admin can turn it off from afar, and only you turn it on again.\n\n"
}

fn cmd_watch(g: &Global, args: &[String]) -> Result<()> {
    let zero = match args {
        [] => false,
        [a] if a == "-0" => true,
        _ => return Err(Error::msg("usage: cbb watch [-0]")),
    };
    let conn = connect(g)?;
    let mut w = conn.try_clone().context("cannot reach the service")?;
    control::write(
        &mut w,
        &control::Message::new(control::Header { op: "watch".into(), ..Default::default() }, Vec::new()),
    )?;
    let mut r = control::Reader::new(conn);
    let first = r.read()?.ok_or_else(|| Error::msg("the service closed the connection"))?;
    check(first)?;
    let mut last = 0;
    let mut out = std::io::stdout();
    while let Some(m) = r.read()? {
        if m.header.op != "write" || m.header.seq <= last {
            continue;
        }
        last = m.header.seq;
        out.write_all(&m.payload).context("cannot write the text")?;
        out.write_all(if zero { b"\0" } else { b"\n" }).context("cannot write the text")?;
        out.flush().ok();
    }
    Err(Error::msg("the service stopped"))
}

/// cbb update: checks for and installs the newest signed release
/// (update.rs), and sets automatic updates and the mirror.
fn cmd_update(g: &Global, args: &[String]) -> Result<()> {
    const USAGE: &str = "usage: cbb update [-check] | -auto [on|off] | -mirror [URL|default]";
    let (mut check, mut timer) = (false, false);
    let (mut auto, mut mirror, mut method): (Option<String>, Option<String>, Option<String>) = (None, None, None);
    let mut i = 0;
    while i < args.len() {
        let value = |i: &mut usize| -> String {
            match args.get(*i + 1) {
                Some(v) if !v.starts_with('-') => {
                    *i += 1;
                    v.clone()
                }
                _ => String::new(),
            }
        };
        match flag(&args[i]) {
            Some("check") => check = true,
            Some("timer") => timer = true,
            Some("auto") => auto = Some(value(&mut i)),
            Some("mirror") => mirror = Some(value(&mut i)),
            Some("installed-by") => method = Some(value(&mut i)),
            _ => return Err(Error::msg(USAGE)),
        }
        i += 1;
    }
    let modes = [check || timer, auto.is_some(), mirror.is_some(), method.is_some()].iter().filter(|b| **b).count();
    if modes > 1 || (check && timer) {
        return Err(Error::msg(USAGE));
    }
    // Refused before anything on the system is looked at.
    if auto.as_deref().is_some_and(|a| !["", "on", "off"].contains(&a)) {
        return Err(Error::msg("usage: cbb update -auto [on|off]"));
    }
    if method.as_deref().is_some_and(|m| !["get", "brew", "winget", "docker", "package"].contains(&m)) {
        return Err(Error::msg("usage: cbb update -installed-by get|brew|winget|docker|package"));
    }
    // A rootless install's user owns its files and updates it.
    let root = is_root() || rootless::is();
    let need_root = || {
        Err(Error::msg(if cfg!(windows) { "run it in a terminal opened as administrator" } else { "run it with sudo" }))
    };
    let (dir, work) = update::paths();
    let mut st = if root { update::load_state(&dir)? } else { update::State::default() };
    let exe = update_os::installed_program()?;
    if let Some(m) = method {
        if !["get", "brew", "winget", "docker", "package"].contains(&m.as_str()) {
            return Err(Error::msg("-installed-by takes get, brew, winget, docker or package"));
        }
        if !root {
            return need_root();
        }
        st.method = m;
        return update::save_state(&dir, &st);
    }
    let method = if st.method.is_empty() { "get" } else { st.method.as_str() }.to_string();
    if let Some(a) = auto {
        if !root {
            return need_root();
        }
        let on = match a.as_str() {
            "" => {
                println!(
                    "{}",
                    match st.auto {
                        None => "unset",
                        Some(true) => "on",
                        Some(false) => "off",
                    }
                );
                return Ok(());
            }
            "on" => true,
            "off" => false,
            _ => return Err(Error::msg("-auto takes on or off")),
        };
        if on && method != "get" {
            return Err(Error::msg(format!(
                "this copy came from {method}, which updates it: {}",
                method_command(&method)
            )));
        }
        update::set_timer(on, &exe)?;
        st.auto = Some(on);
        update::save_state(&dir, &st)?;
        println!(
            "{}",
            if on {
                tr!("Automatic updates are on: once a day this device checks for a signed release and installs it.")
            } else {
                tr!("Automatic updates are off; cbb update installs a release by hand.")
            }
        );
        return Ok(());
    }
    if let Some(m) = mirror {
        if !root {
            return need_root();
        }
        match m.as_str() {
            "" if st.mirror.is_empty() => {
                println!("{}", tr!("Updates come from GitHub, or {} when GitHub does not answer.", update::MIRROR))
            }
            "" => println!("{}", tr!("Updates come from {}.", st.mirror)),
            "default" => {
                st.mirror.clear();
                update::save_state(&dir, &st)?;
            }
            url => {
                update::Source::mirror(url)?;
                st.mirror = url.trim_end_matches('/').into();
                update::save_state(&dir, &st)?;
            }
        }
        return Ok(());
    }
    if !check && !root {
        return need_root();
    }
    // install.ps1 stops every program in Program Files\cbb, this one too:
    // the update runs from a copy outside it.
    if cfg!(windows) && !check && std::env::var_os("CBB_UPDATE_FROM").is_none() {
        return update_os::update_from_copy(&dir, &exe, args);
    }

    // The timer logs to update.log, each line stamped.
    let log_file = if timer {
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("update.log");
        if std::fs::metadata(&path).map(|m| m.len() > 1 << 20).unwrap_or(false) {
            let _ = std::fs::rename(&path, dir.join("update.log.old"));
        }
        std::fs::OpenOptions::new().create(true).append(true).open(&path).ok().map(std::cell::RefCell::new)
    } else {
        None
    };
    let log = |line: &str| {
        if let Some(f) = &log_file {
            let _ = writeln!(f.borrow_mut(), "{} {line}", stamp(update::now_ms()));
        }
        println!("{line}");
    };
    if timer && !update::due(&st, update::now_ms()) {
        return Ok(());
    }
    let res = (|| -> Result<()> {
        let (roots, sources) = match std::env::var_os("CBB_RELEASE_DIR") {
            Some(d) => {
                let roots = match std::env::var_os("CBB_RELEASE_ROOTS") {
                    Some(f) => update::read_roots(std::path::Path::new(&f))?,
                    None => update::ROOTS.iter().map(|r| r.to_vec()).collect(),
                };
                (roots, vec![update::Source::Dir(PathBuf::from(d))])
            }
            None => (update::ROOTS.iter().map(|r| r.to_vec()).collect(), update::Source::defaults(&st.mirror)?),
        };
        let archive = update_os::archive_name().ok_or_else(|| {
            Error::msg(format!("the release has no archive for {}/{}", std::env::consts::OS, std::env::consts::ARCH))
        })?;
        let status = || -> Result<String> {
            let m = request(
                g,
                &control::Message::new(control::Header { op: "version".into(), ..Default::default() }, Vec::new()),
            )?;
            Ok(m.header.status.map(|s| s.version).unwrap_or_default())
        };
        let healthy = |v: &str, within: Duration| update::wait_healthy(&status, v, within);
        let work =
            if root { work.clone() } else { std::env::temp_dir().join(format!("cbb-update-{}", std::process::id())) };
        let _ = std::fs::create_dir_all(&work);
        let link = ServiceLink(g);
        let u = update::Updater {
            work: work.clone(),
            roots,
            sources,
            installed: service::VERSION.into(),
            archive,
            programs: update_os::programs(&exe),
            now_ms: update::now_ms(),
            install: &update::install,
            healthy: &healthy,
            log: &log,
            group: Some(&link),
        };
        let found = u.check(&st);
        if !root {
            let _ = std::fs::remove_dir_all(&work);
        }
        let found = match found {
            Err(e) if timer && e.message().starts_with("this build pins no release keys") => return Ok(()),
            r => r.map_err(|e| update::prefixed(e, "checking for an update"))?,
        };
        let r = &found.release;
        if root {
            st.seen = found.seen.clone();
            st.checked_ms = update::now_ms();
            st.available = if found.newer && !found.failed { r.version.clone() } else { String::new() };
            update::save_state(&dir, &st)?;
            if found.source != update::FROM_GROUP {
                u.archives_for_group(found.source, r);
            }
        }
        let v = service::VERSION;
        match () {
            _ if !found.newer => log(&format!("CBB {} is the newest release; this device runs {v}.", r.version)),
            _ if method != "get" => {
                if !timer {
                    log(&format!(
                        "CBB {} is available; this device runs {v}. It came from {method}, which updates it: {}",
                        r.version,
                        method_command(&method)
                    ));
                }
            }
            _ if check => {
                let how = if cfg!(windows) { "cbb update, as administrator" } else { "sudo cbb update" };
                log(&format!("CBB {} is available; this device runs {v}. To install it: {how}", r.version))
            }
            _ if v == "dev" => {
                return Err(Error::msg(format!(
                    "this is a development build; cbb update installs {} only over a release",
                    r.version
                )));
            }
            _ if found.failed && timer => {
                log(&format!("Skipping {}, which did not start here before; cbb update tries it again.", r.version))
            }
            _ => {
                if found.failed {
                    log(&format!("{} did not start here before; trying it again.", r.version));
                }
                let res = u.apply(found.source, &mut st, r);
                update::save_state(&dir, &st)?;
                return res;
            }
        }
        Ok(())
    })();
    if let (Err(e), true) = (&res, timer) {
        log(&format!("cbb update: {}", e.for_user()));
    }
    res
}

/// The service as cbb update's link to the group (update::Group), as Go's
/// cbb update asks it: a service that does not run costs nothing but the
/// group's help.
struct ServiceLink<'a>(&'a Global);

impl ServiceLink<'_> {
    fn open(&self, op: &str, wait: Duration) -> Result<(UnixStream, control::Reader<UnixStream>)> {
        let path = if control::is_admin(op) { control::admin_socket(&self.0.socket) } else { self.0.socket.clone() };
        let c = UnixStream::connect(&path).context("cannot reach the service")?;
        let _ = c.set_read_timeout(Some(wait));
        let _ = c.set_write_timeout(Some(wait));
        let r = control::Reader::new(c.try_clone().context("cannot reach the service")?);
        Ok((c, r))
    }

    fn answer(r: &mut control::Reader<UnixStream>) -> Result<control::Message> {
        check(r.read()?.ok_or_else(|| Error::msg("the service closed the connection"))?)
    }

    fn ask(&self, op: &str, payload: Vec<u8>) -> Result<control::Message> {
        let (mut c, mut r) = self.open(op, Duration::from_secs(10))?;
        control::write(
            &mut c,
            &control::Message::new(control::Header { op: op.into(), ..Default::default() }, payload),
        )?;
        Self::answer(&mut r)
    }
}

impl update::Group for ServiceLink<'_> {
    fn share(&self, set: &serde_json::Value) {
        if let Ok(data) = serde_json::to_vec(set) {
            let _ = self.ask("release", data);
        }
    }

    fn held(&self) -> Result<serde_json::Value> {
        let m = self.ask("release_held", Vec::new())?;
        serde_json::from_slice(&m.payload).context("the service's release does not decode")
    }

    fn get(&self, sha: &str, size: i64, path: &std::path::Path) -> Result<()> {
        use std::io::Write;
        // The service tries its peers for a while before it answers.
        let (mut c, mut r) = self.open("release_get", Duration::from_secs(15 * 60))?;
        let h = control::Header { op: "release_get".into(), value: sha.into(), ..Default::default() };
        control::write(&mut c, &control::Message::new(h, Vec::new()))?;
        let first = Self::answer(&mut r)?;
        if first.header.part.as_ref().map(|p| p.size) != Some(size) {
            return Err(Error::msg("the service answered with another file"));
        }
        let mut f = std::fs::File::create(path).context("cannot keep the archive")?;
        let mut got: i64 = 0;
        loop {
            let m = Self::answer(&mut r)?;
            got += m.payload.len() as i64;
            if got > size {
                return Err(Error::msg("the service sent more than the archive"));
            }
            f.write_all(&m.payload).context("cannot keep the archive")?;
            if m.header.done {
                break;
            }
        }
        if got != size {
            return Err(Error::msg("the service sent less than the archive"));
        }
        Ok(())
    }

    fn keep(&self, sha: &str, size: i64, path: &std::path::Path) {
        use std::io::Read;
        let res = (|| -> Result<()> {
            let mut f = std::fs::File::open(path).context("cannot read the archive")?;
            let (mut c, mut r) = self.open("release_file", Duration::from_secs(120))?;
            let part = control::Part { size, ..Default::default() };
            let h = control::Header {
                op: "release_file".into(),
                value: sha.into(),
                part: Some(part),
                ..Default::default()
            };
            control::write(&mut c, &control::Message::new(h, Vec::new()))?;
            let mut buf = vec![0; 1 << 20];
            loop {
                let n = f.read(&mut buf).context("cannot read the archive")?;
                if n == 0 {
                    break;
                }
                let h = control::Header { op: "data".into(), ..Default::default() };
                control::write(&mut c, &control::Message::new(h, buf[..n].to_vec()))?;
            }
            Self::answer(&mut r).map(|_| ())
        })();
        if let Err(e) = res {
            eprintln!("cbb: the service did not take the archive to serve to the group: {}", e.for_log());
        }
    }

    fn want(&self) -> Vec<String> {
        self.ask("release_want", Vec::new())
            .ok()
            .and_then(|m| serde_json::from_slice::<Option<Vec<String>>>(&m.payload).ok().flatten())
            .unwrap_or_default()
    }
}

/// The command that updates a copy from method.
fn method_command(method: &str) -> &'static str {
    match method {
        "package" => "apk update && apk upgrade",
        "docker" => "docker compose pull && docker compose up -d",
        _ => "its own update command",
    }
}

/// A time in UTC as 2006-01-02T15:04:05Z, for the update log.
fn stamp(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", rem / 3600, rem / 60 % 60, rem % 60)
}

/// The line of `cbb version` that names the core: its version, the ABI of
/// its entry point and, in a release build, the commit it was built from
/// (docs/core-api.md).
fn core_version() -> String {
    use cbb_core::api;
    let source = if api::SOURCE.is_empty() { String::from("unknown") } else { String::from(api::SOURCE) };
    // As the Go cbb's line, which the installers and sign.sh look for.
    format!("rules: the Rust core {}, abi {}, source {source} (built in)", api::VERSION, api::ABI)
}

#[cfg(test)]
mod tests {
    use super::{control, core_version, hint, on_actions, qr, terminal_text};

    #[test]
    fn only_the_actions_that_are_on() {
        assert!(on_actions(None).is_empty());
        let a = |name: &str, on| control::Action { name: name.into(), on, ..Default::default() };
        let st = control::Status {
            actions: vec![a("lock", true), a("sleep", false), a("reboot", true)],
            ..Default::default()
        };
        assert_eq!(on_actions(Some(&st)), ["lock", "reboot"]);
    }

    /// Without systemd (NextPi), the hint names cbb service, not systemctl.
    #[test]
    fn hint_without_systemd() {
        assert_eq!(hint(true, "systemctl --user"), "is it running (systemctl --user status cbb)?");
        assert_eq!(hint(false, "systemctl"), "is it running (start it with cbb service)?");
    }

    /// cbb version names the core's version and the ABI of its entry
    /// point.
    #[test]
    fn names_the_core() {
        let line = core_version();
        assert!(
            line.starts_with(&format!(
                "rules: the Rust core {}, abi {}, source ",
                cbb_core::api::VERSION,
                cbb_core::api::ABI
            )),
            "{line}"
        );
    }

    #[test]
    fn qr_reads_back() {
        // Two modules a line, a quiet zone of two on each side: read the
        // modules back from the colors and compare.
        let url = "http://192.168.1.20:8766/";
        let out = qr(url);
        let code = qrcode::QrCode::with_error_correction_level(url, qrcode::EcLevel::M).unwrap();
        let size = code.width() as i32;
        let lines: Vec<&str> = out.trim_end_matches('\n').split('\n').collect();
        assert_eq!(lines.len() as i32, (size + 4 + 1) / 2);
        for (i, line) in lines.iter().enumerate() {
            let cells: Vec<&str> = line.split("\x1b[").skip(1).collect();
            let cells = &cells[..cells.len() - 1]; // the reset
            assert_eq!(cells.len() as i32, size + 4, "line {i}");
            for (x, cell) in cells.iter().enumerate() {
                let colors: Vec<&str> = cell.trim_end_matches("m▀").split(';').collect();
                for (half, y) in [2 * i as i32, 2 * i as i32 + 1].into_iter().enumerate() {
                    let (mx, my) = (x as i32 - 2, y - 2);
                    let want = mx >= 0
                        && my >= 0
                        && mx < size
                        && my < size
                        && code[(mx as usize, my as usize)] == qrcode::Color::Dark;
                    assert_eq!(colors[half] == "30" || colors[half] == "40", want, "module {mx},{my}");
                }
            }
        }
    }

    #[test]
    fn terminal_text_is_safe() {
        for (input, all, want, dropped) in [
            ("ls -l\n", false, "ls -l", 0),
            ("a\tb", false, "a\tb", 0),
            ("echo \x1b[201~; rm -rf ~\n", false, "echo [201~; rm -rf ~", 0),
            ("x\u{9b}31my\x7f\0", false, "x31my", 0),
            ("one\r\ntwo\nthree\n", false, "one", 2),
            ("one\r\ntwo\nthree\n", true, "one\ntwo\nthree", 0),
            ("\n\nfirst\n", false, "first", 0),
            ("line\rover", false, "lineover", 0),
        ] {
            assert_eq!(terminal_text(input, all), (want.to_string(), dropped), "{input:?}");
        }
    }
}
