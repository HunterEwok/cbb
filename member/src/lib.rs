// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! cbb is the lite member of cbb for small Linux devices,
//! such as routers and small boards: a member without CA keys that only
//! dials the computers, joins by QR code through the
//! phone, and syncs (docs/design.md, roadmap item 11).
//!
//! The program is this library and a main that calls [`main`]; the library
//! also lets the Aurora app run the same member in its own process
//! (`ffi/`, feature `aurora`).

mod actions;
mod admin;
mod agent;
#[cfg(feature = "tunnel")]
mod away;
#[cfg(not(feature = "tunnel"))]
#[path = "away_off.rs"]
mod away;
#[cfg(feature = "tunnel")]
mod awg;
pub mod button;
mod cli;
pub mod content;
mod control;
mod copies;
pub mod credentials;
mod device;
pub mod discovery;
pub mod entries;
pub mod error;
pub mod files;
#[cfg(feature = "tunnel")]
pub mod forward;
pub mod helper;
#[cfg(feature = "tunnel")]
pub mod hub;
pub mod identity;
mod interfaces;
mod keys;
mod leave;
mod logfile;
mod mute;
pub mod networks;
mod next;
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
pub mod releases;
mod remotepaste;
mod rootless;
pub mod sealkey;
mod sekey;
#[cfg(all(unix, not(target_os = "macos")))]
mod third_party {
    pub mod pcsclite;
}
mod service;
mod signed;
mod sync;
mod sys;
pub mod tls;
#[cfg(feature = "tunnel")]
pub mod tunnel;
mod update;
pub mod uptime;
#[cfg(feature = "tunnel")]
pub mod vless;
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

const USAGE: &str = "Usage: cbb [-state dir] [-socket path] [-debug] <command> [arguments]

Commands:
  pair [-name name] [-port port] [-addr host[:port]]...
                       Join a group: show a QR code for the phone app to scan
                       (-addr: where the phone reaches this device, when the
                       code would name the wrong addresses).
  pair -code host:port Join with the code from cbb pair on a full member.
  pair -invite file    Join with a remote invitation from cbb invite on the
                       group's hub, through its tunnel; sync away from home
                       goes on.
  pair -full ...       Join as a computer with the service, a full member
                       that may become an admin, rather than a lite member.
  agent                Link this session's clipboard with the service
                       (started at sign-in), through cbb-helper.
  service [-name name] [-port port] [-peer host:port]... [-no-mdns]
          [-no-listen] [-tunnel-via host:port] [-full] [-state dir]
          [-socket path] [-user name]
                       Run the service (started by systemd, procd, launchd,
                       an rc script or Windows' service manager): it
                       dials the computers, and phones and other lite
                       members dial it on the member port (8764, CBB_PORT).
                       -tunnel-via: the tunnel to the hub sends its packets
                       there, a local UDP port that leads to the hub (cbb
                       next link -udp on the ZX Spectrum Next).
                       -full: as a computer's service, a full member.
                       -state and -socket as before the command; -user:
                       started as root, open the mDNS sockets, then run
                       as this user (FreeBSD's rc script).
  copy [-secret]       Send standard input to the group.
  paste [-terminal [-lines] [-secret]]
                       Print this member's clipboard text; -terminal makes
                       it safe to paste into a terminal: no control
                       characters, only the first line unless -lines, and
                       no secret unless -secret.
  status               Show this device, its group and the group's devices.
  leave [-yes]         Leave the group: delete this device's keys and the
                       group's files, keep the settings, turn remote paste
                       and the quick actions off; then cbb pair joins this
                       group or another one.
  sync [on | off [-for DURATION]]
                       Show sync, or turn it on or off here: off, the
                       clipboard is this device's own, for a while or until
                       cbb sync on (cbb copy and cbb paste work either way).
  global [on|off]      Show sync away from home, or turn it on or off here:
                       through the group's own WireGuard tunnel to its hub.
  watch [-0]           Print every text the group sends here, one per line
                       (with -0, each followed by a zero byte).
  paste-receive [on [-enter] [-console] | off]
                       Show remote paste here, or turn it on or off: whether
                       the group's admins may put a text into tmux, or with
                       -console into the active text console, here (-enter:
                       and press Enter after it).
  action [enable NAME [-by root,phone,computer,watch] [-any-key] [-yes] |
         disable NAME | off]
                       Show the quick actions here, or turn one on or off
                       for the group's admins: reboot (a minute later, and
                       only for keys in hardware unless -any-key),
                       cancel-shutdown and restart. enable, with sudo, writes
                       the polkit rule that lets the service reboot.
  paste-helper tmux|console
                       The paste targets: tmux starts the one for tmux, the
                       cbb-console unit the one for the console.
  next paste|copy|pair The same for the ZX Spectrum Next's .cbb dot command,
                       in frames its Z80 reads (member/README.md).
  update [-check]      Install the newest signed release, with sudo; -check
                       only says whether there is one. The previous version
                       goes back when the new one does not start.
  update -auto [on|off]
                       Show, or turn on or off, updating once a day by
                       itself (a systemd timer, or cron on OpenWrt).
  update -mirror [URL|default]
                       Show or set where updates come from: GitHub, then
                       dl.cbb.tools, or another https:// mirror.
  version              Print the version and that this is the lite member.
  help                 Print this help.

This is the lite member: the commands of a full member, such as invite or
remove, are not here, and pair only joins a group. The state directory is
/var/lib/cbb (CBB_STATE), the control socket /run/cbb/control.sock
(CBB_SOCKET); on OpenWrt /etc/cbb/state and
/var/run/cbb/control.sock; installed without root (install.sh
--rootless, CBB_ROOTLESS=1), ~/.local/state/cbb and
$XDG_RUNTIME_DIR/cbb/control.sock. CBB_INTERFACES limits the member
port and mDNS to the network devices it names. -debug, or CBB_DEBUG=1, shows the details of errors.
";

/// The commands of a full member (cmd/cbb) that the lite member does not
/// have, so that it says so instead of "unknown command".
const FULL_ONLY: &[&str] = &["invite", "forward", "relay"];

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
                "pair" => join(&g, rest, false),
                "next" => std::process::exit(next::run(&g, rest)),
                "service" => cmd_service(&g, rest),
                "agent" if rest.is_empty() => agent::run(&g.socket),
                "agent" => Err(Error::msg("cbb agent takes no arguments")),
                "copy" => cmd_copy(&g, rest),
                "paste" => cmd_paste(&g, rest),
                "status" => cmd_status(&g, rest),
                "leave" => cmd_leave(&g, rest),
                "global" => cmd_global(&g, rest),
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
                "version" | "-version" | "--version" => {
                    println!(
                        "cbb {} ({}/{}), the lite member",
                        service::VERSION,
                        std::env::consts::OS,
                        std::env::consts::ARCH
                    );
                    println!("{}", core_version());
                    Ok(())
                }
                "help" | "-h" | "-help" | "--help" => {
                    print!("{USAGE}");
                    Ok(())
                }
                _ if FULL_ONLY.contains(&cmd) => Err(Error::msg(format!(
                    "cbb {cmd} is a command of a full member; this device runs the lite member (see cbb help)"
                ))),
                _ => Err(Error::msg(format!("unknown command {cmd:?}; see cbb help"))),
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
    if records::valid_name(&name) { name } else { "lite".into() }
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

/// The member port: 8764, or CBB_PORT.
fn member_port() -> u16 {
    std::env::var("CBB_PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(8764)
}

/// Joins a group. For the Next (for_next), the QR code and the outcome come
/// in its frames, and so do the log lines, as `CBB#` lines it skips.
fn join(g: &Global, args: &[String], for_next: bool) -> Result<()> {
    let mut name = host_name();
    let mut port = member_port();
    let mut addrs = Vec::new();
    let mut code_addr = None;
    let mut invite = None;
    let mut full = false;
    let mut i = 0;
    while i < args.len() {
        let next = || args.get(i + 1).cloned().ok_or_else(|| Error::msg(format!("{} needs a value", args[i])));
        match flag(&args[i]) {
            Some("full") if !for_next => {
                full = true;
                i += 1;
                continue;
            }
            Some("name") => name = next()?,
            Some("port") => port = next()?.parse().context("the port is a number")?,
            Some("addr") => addrs.push(next()?),
            Some("code") if !for_next => code_addr = Some(next()?),
            Some("invite") if !for_next => invite = Some(next()?),
            _ => return Err(Error::msg(format!("unknown argument {:?}; see cbb help", args[i]))),
        }
        i += 2;
    }
    let invite = match invite {
        Some(path) => Some(invite_consent(&path)?),
        None => None,
    };
    let (mut joiner, save) = joiner(&g.state, &name)?;
    if full {
        joiner = joiner.as_computer(admin::os_name());
    }
    let save = &*save;
    let id = match (invite, code_addr) {
        (Some((path, text)), _) => {
            let shown = |fp: &str| {
                println!("\nThis device's key fingerprint:  {}", fp.get(..23).unwrap_or(fp));
                println!("Whoever invited you sees it on the hub and admits this device if it matches.");
                println!("Waiting for them; press Ctrl+C to give up.");
                std::io::stdout().flush().ok();
            };
            let log: std::sync::Arc<dyn Fn(&str) + Send + Sync> = std::sync::Arc::new(|s: &str| eprintln!("{s}"));
            let id = away::join_invite(&g.state, &joiner, save, &text, &shown, log)?;
            // It is used up, and was a secret; nothing needs it any more.
            let _ = std::fs::remove_file(&path);
            id
        }
        (None, Some(a)) => {
            print!("Pairing code: ");
            std::io::stdout().flush().ok();
            let mut line = String::new();
            std::io::stdin().read_line(&mut line).context("cannot read the code")?;
            let code = pair::normalize_code(line.trim())?;
            let sock = TcpStream::connect_timeout(&resolve(&a)?, Duration::from_secs(10))
                .context(format!("cannot connect to {a}"))?;
            pair::join(&joiner, sock, &code, save)?
        }
        (None, None) => {
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
                println!("In the CBB app, tap \"Connect a new device\" and scan this:\n");
                print!("{}", qr(text));
                println!("\nOr paste this into the app: {text}");
                println!("\nWaiting up to 5 minutes. Press Ctrl+C to cancel.");
                println!("Without a phone: run cbb pair on a full member and cbb pair -code <its address> here.");
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
        println!("Joined the group {} as {}.", id.tag(), id.id);
    }
    Ok(())
}

/// Reads a remote invitation's file for cbb pair -invite and asks the user
/// to agree that sync away from home goes on with the join; returns the
/// path and the invitation's text.
fn invite_consent(path: &str) -> Result<(String, String)> {
    let text = std::fs::read_to_string(path).context(format!("cannot read {path}"))?;
    let inv = cbb_core::invite::parse(&text).map_err(|r| Error::msg(r.message()))?;
    if inv.expired(uptime::wall_ms() / 1000) {
        return Err(Error::msg("the invitation has expired; ask for a new one"));
    }
    println!("A device that joins with an invitation syncs away from home through the");
    println!("group's hub, so sync away from home is turned on here.\n");
    print!("Type yes to join and turn sync away from home on: ");
    std::io::stdout().flush().ok();
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).context("cannot read the answer")?;
    if !line.trim().eq_ignore_ascii_case("yes") {
        return Err(Error::msg("nothing changed"));
    }
    Ok((path.to_string(), text))
}

/// The joiner of a device in no group yet, and how it saves the group it
/// joins.
pub(crate) fn joiner(state: &std::path::Path, name: &str) -> Result<(pair::Joiner, Box<pair::Save>)> {
    if identity::Identity::load(state)?.is_some() {
        return Err(Error::msg(format!(
            "this device is already in a group, and a lite member admits no devices (use the phone app or \
             a full member); to join another group, stop the service and remove {}",
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
        (None, why) if !why.is_empty() => eprintln!("cbb: the device key stays in a file: {why}"),
        (None, _) => {}
    }
    // The key for sealed messages the service will offer in its hello goes
    // with the info, so that a phone records it as it admits this member.
    match sealkey::load(state)
        .and_then(|s| cbb_core::seal::public_key(&s).map_err(|e| e.context("the key for sealed messages")))
    {
        Ok(public) => joiner.seal = public,
        Err(e) => eprintln!("cbb: the key for sealed commands: {e}; commands will come unsealed"),
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
fn qr(text: &str) -> String {
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
        full: false,
    };
    let mut run_user = None;
    let mut i = 0;
    while i < args.len() {
        let next = || args.get(i + 1).cloned().ok_or_else(|| Error::msg(format!("{} needs a value", args[i])));
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
            Some("full") => {
                cfg.full = true;
                i += 1;
                continue;
            }
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
fn connect(g: &Global) -> Result<UnixStream> {
    match UnixStream::connect(&g.socket) {
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            Err(Error::msg("no permission to use the CBB service; add your user to the cbb group and log in again"))
        }
        c => c.context(format!("cannot reach the lite member's service at {}; {}", g.socket.display(), not_running())),
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
        format!("is it running ({systemctl} status cbb)?")
    } else {
        "is it running (start it with cbb service)?".to_string()
    }
}

/// Sends one request to the service and returns its answer.
pub(crate) fn request(g: &Global, m: &control::Message) -> Result<control::Message> {
    let conn = if control::needs_admin(&m.header) {
        let path = control::admin_socket(&g.socket);
        match UnixStream::connect(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                return Err(Error::msg(
                    "this command changes the group, so only the administrator may run it; run it with sudo",
                ));
            }
            c => {
                c.context(format!("cannot reach the lite member's service at {}; {}", path.display(), not_running()))?
            }
        }
    } else {
        connect(g)?
    };
    let mut w = conn.try_clone().context("cannot reach the service")?;
    control::write(&mut w, m)?;
    let answer = control::Reader::new(conn).read()?.ok_or_else(|| Error::msg("the service closed the connection"))?;
    check(answer)
}

fn check(m: control::Message) -> Result<control::Message> {
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
    let secret = match args {
        [] => false,
        [a] if flag(a) == Some("secret") => true,
        _ => return Err(Error::msg("usage: cbb copy [-secret] < text")),
    };
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

/// Names an operating system for the user, as cbb status does.
fn os_name(os: &str) -> &str {
    match os {
        "linux" => "Linux",
        "windows" => "Windows",
        "macos" => "macOS",
        "ios" => "iOS",
        "android" => "Android",
        "aurora" => "Aurora OS",
        "sailfish" => "Sailfish OS",
        "none" => "device",
        _ => "?",
    }
}

fn cmd_paste(g: &Global, args: &[String]) -> Result<()> {
    let (mut terminal, mut lines, mut secret) = (false, false, false);
    for a in args {
        match flag(a) {
            Some("terminal") => terminal = true,
            Some("lines") => lines = true,
            Some("secret") => secret = true,
            _ => return Err(Error::msg("usage: cbb paste [-terminal [-lines] [-secret]]")),
        }
    }
    if (lines || secret) && !terminal {
        return Err(Error::msg("-lines and -secret go with -terminal"));
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
            eprintln!("cbb: pasted only the first line; {dropped} more left out (add -lines to paste them)");
        }
        out = text.into_bytes();
    }
    std::io::stdout().write_all(&out).context("cannot write the text")?;
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
        return Err(Error::msg("status takes no arguments"));
    }
    let m =
        request(g, &control::Message::new(control::Header { op: "status".into(), ..Default::default() }, Vec::new()))?;
    let s = m.header.status.unwrap_or_default();
    if s.group.is_empty() {
        // As Go's writeStatus.
        println!("{}", s.version);
        if s.left_old_group {
            println!("This device left its group, which was made before 0.6: groups are set up again from 0.6 on.");
        }
        println!("Not in a group. Run cbb new here to start one, or cbb pair to join one.");
        return Ok(());
    }
    println!("device  {}\ngroup   {}\nrole    {}\nversion {}", s.device, s.group, s.role, s.version);
    if !s.mode.is_empty() {
        println!("mode    {}", s.mode);
    }
    match s.stop.as_str() {
        "full" => println!(
            "The group is stopped: its members exchange records only, no clipboard, until the group's root decides."
        ),
        "secrets" => println!("The group sends no secrets until its root decides."),
        _ => {}
    }
    if s.removed {
        println!(
            "This device was removed from the group: its members refuse it. To join this group again or another one, leave it here first: sudo cbb leave, then cbb pair."
        );
    }
    if s.peers.is_empty() {
        println!("no members connected");
    }
    print_away(s.away.as_ref());
    if s.group.is_empty() {
        return Ok(());
    }
    let devs =
        request(g, &control::Message::new(control::Header { op: "devices".into(), ..Default::default() }, Vec::new()))?;
    for d in devs.header.devices {
        let mut marks = [(d.this, "this device"), (d.online, "online"), (d.admin, "admin")]
            .iter()
            .filter(|(on, _)| *on)
            .map(|(_, s)| s.to_string())
            .collect::<Vec<_>>();
        if let Some(p) = s.peers.iter().find(|p| p.id == d.id) {
            marks.push(format!("clock {:+} ms", p.skew_ms));
        }
        println!("{}  {:<24} {:<8} {:<8} {}", d.id, d.name, os_name(&d.os), d.role, marks.join(", "));
    }
    Ok(())
}

/// The question cbb leave asks before it deletes the keys.
const LEAVE_QUESTION: &str =
    "This device leaves its group: its keys and the group's files here are deleted, remote paste
and the quick actions are turned off, and the rest of the settings stay. It can then join this
group again or another one (cbb pair). The group keeps listing it until an admin removes it.
Leave the group? [y/N] ";

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
        print!("{LEAVE_QUESTION}");
        std::io::stdout().flush().ok();
        let mut line = String::new();
        std::io::stdin().read_line(&mut line).ok();
        if !matches!(line.trim().to_lowercase().as_str(), "y" | "yes") {
            println!("Nothing changed. (cbb leave -yes leaves without the question.)");
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
        println!("Left the group. The service restarts in no group: cbb pair joins one.");
    } else {
        if identity::Identity::load(&g.state).ok().flatten().is_none() && !g.state.join(records::FILE_NAME).exists() {
            return Err(Error::msg(leave::NOTHING_TO_LEAVE));
        }
        leave::leave_group(&g.state)?;
        println!("Left the group: cbb pair joins one.");
    }
    Ok(())
}

/// Shows sync, or turns it on or off here, as cbb sync on a full member.
fn cmd_sync(g: &Global, args: &[String]) -> Result<()> {
    let usage = || Error::msg("usage: cbb sync [on | off [-for DURATION]]");
    let mut h = control::Header { op: "sync".into(), ..Default::default() };
    let mut it = args.iter();
    match it.next().map(String::as_str) {
        None => h.op = "status".into(),
        Some(n @ ("on" | "off")) => h.name = n.into(),
        Some(_) => return Err(usage()),
    }
    while let Some(a) = it.next() {
        match flag(a) {
            Some("for") if h.name == "off" => {
                let d = it.next().ok_or_else(usage)?;
                h.for_ms = parse_duration_ms(d).ok_or_else(|| Error::msg(format!("-for: {d:?} is no duration")))?;
                if h.for_ms == 0 {
                    return Err(Error::msg("-for is from 1ms to 720h"));
                }
            }
            _ => return Err(usage()),
        }
    }
    if h.op == "sync" {
        request(g, &control::Message::new(h, Vec::new()))?;
    }
    let m =
        request(g, &control::Message::new(control::Header { op: "status".into(), ..Default::default() }, Vec::new()))?;
    let st = m.header.status.unwrap_or_default();
    println!("{}", sync_line(&st.mode, st.sync_until_ms));
    Ok(())
}

/// Reads a duration as Go writes one, such as 90s, 15m, 1h or 1h30m, in
/// milliseconds, for a mute.
fn parse_duration_ms(s: &str) -> Option<i64> {
    go_duration_ms(s).filter(|ms| *ms <= mute::MAX_MS)
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

/// What sync on or off means, as cbb sync on a full member says it.
fn sync_line(mode: &str, until_ms: i64) -> String {
    match mode {
        "shared" => "Sync is on: copies here go to the group, and the group's copies come here.".into(),
        "own" if until_ms > 0 => format!(
            "Sync is off for {} min more: the clipboard is this device's own; cbb paste prints the group's text, and cbb copy sends to the group.",
            ((until_ms - uptime::wall_ms()).max(0) + 59_999) / 60_000
        ),
        "own" => "Sync is off until cbb sync on: the clipboard is this device's own; cbb paste prints the group's text, and cbb copy sends to the group.".into(),
        "" => "This lite member's service does not know sync on and off yet; update it.".into(),
        m => format!("Sync mode {m}."),
    }
}

fn cmd_paste_receive(g: &Global, args: &[String]) -> Result<()> {
    let usage = || Error::msg("usage: cbb paste-receive [on [-enter] [-console] [-no-lock-check] | off]");
    let mut h = control::Header { op: "status".into(), ..Default::default() };
    for (i, a) in args.iter().enumerate() {
        match (i, a.as_str(), flag(a)) {
            (0, "on" | "off", _) => {
                h.op = "paste-receive".into();
                h.name = a.clone();
            }
            (1.., _, Some("enter")) if h.name == "on" => h.enter = true,
            (1.., _, Some("console")) if h.name == "on" => h.console = true,
            (1.., _, Some("no-lock-check")) if h.name == "on" => h.no_lock_check = true,
            _ => return Err(usage()),
        }
    }
    if h.console && rootless::is() {
        return Err(Error::msg(
            "text consoles need the console helper, which runs as root; this device is installed without root, so remote paste reaches tmux only",
        ));
    }
    let m = request(g, &control::Message::new(h, Vec::new()))?;
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
        return format!("{line} Nothing here can paste yet: the tmux and console helpers do it.");
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
            let st = m.header.status.ok_or_else(|| Error::msg("this device is in no group"))?;
            for a in &st.actions {
                println!("{:<16} {}", a.name, action_line(a));
            }
            return Ok(());
        }
        [v] if v == "off" => {
            let m = request(
                g,
                &control::Message::new(control::Header { op: "actions-off".into(), ..Default::default() }, Vec::new()),
            )?;
            // The rights go too, when this runs as root here.
            if let Err(e) = grant(&m)
                && is_root()
            {
                eprintln!("cbb: the actions are off, but the rights stay: {}", e.for_user());
            }
            println!("The quick actions are off here.");
            return Ok(());
        }
        [v, name] if v == "remove" => {
            let h = control::Header { op: "action-remove".into(), name: name.clone(), ..Default::default() };
            let m = request(g, &control::Message::new(h, Vec::new()))?;
            grant(&m)?;
            println!("{name} is removed.");
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
        print!("{}Type yes to turn it on: ", action_warning(&a));
        std::io::stdout().flush().ok();
        let mut line = String::new();
        std::io::stdin().read_line(&mut line).context("cannot read the answer")?;
        if !line.trim().eq_ignore_ascii_case("yes") {
            println!("Nothing changed.");
            return Err(Error::msg("the action stays as it was"));
        }
    }
    let h = control::Header { op: "action-set".into(), actions: vec![a.clone()], ..Default::default() };
    let m = request(g, &control::Message::new(h, Vec::new()))?;
    if let Err(e) = grant(&m) {
        if a.on {
            // Without the right the action would only fail; leave it off.
            let off = control::Action { on: false, ..a.clone() };
            let h = control::Header { op: "action-set".into(), actions: vec![off], ..Default::default() };
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
    let on: Vec<String> =
        m.header.status.iter().flat_map(|s| &s.actions).filter(|a| a.on).map(|a| a.name.clone()).collect();
    actions::grant(std::path::Path::new("/"), &on).map(|_| ())
}

fn is_root() -> bool {
    sys::is_root()
}

/// How an action stands and who may run it, as on a full member.
fn action_line(a: &control::Action) -> String {
    if !a.on {
        return "off".into();
    }
    let mut who = if a.by.is_empty() { "every admin".to_string() } else { a.by.join(", ") };
    if actions::hardware_by_default(&a.name) && !a.any_key {
        who += ", keys in hardware only";
    }
    format!("on, for {who}")
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

/// What a user agrees to before the lite member, whose keys sit in files,
/// syncs away from home (docs/design.md, "Turning it on, step by step").
const KEYS_WARNING: &str = "Sync away from home lets this device reach the group's hub from the internet,
through the group's own WireGuard tunnel, with the clipboard encrypted end to end.

This device keeps its keys in files, not in a security chip. Whoever copies those
files (with root on this device, from its disk or memory card, or from an
unencrypted backup) can act as this device from anywhere until you remove it from
the group. To keep that from happening:

  - encrypt the disk or memory card where you can (LUKS);
  - keep the service's state directory out of unencrypted backups;
  - remove the device at once (Remove on the phone, or cbb remove on a full
    member) when it is lost or someone else may have had root on it.

";

fn cmd_global(g: &Global, args: &[String]) -> Result<()> {
    let mut h = control::Header { op: "away".into(), ..Default::default() };
    match args {
        // Only showing it needs no root: the status carries it.
        [] => h.op = "status".into(),
        [a] if a == "on" => {
            print!("{KEYS_WARNING}Type yes to turn sync away from home on: ");
            std::io::stdout().flush().ok();
            let mut line = String::new();
            std::io::stdin().read_line(&mut line).context("cannot read the answer")?;
            if !line.trim().eq_ignore_ascii_case("yes") {
                println!("Nothing changed.");
                return Err(Error::msg("sync away from home stays as it was"));
            }
            h.name = "on".into();
            h.consent = true;
        }
        [a] if a == "off" => h.name = "off".into(),
        [a, rest @ ..] if a == "hubs" => return cli::hubs(g, rest),
        _ => return Err(cli::usage("cbb global [on|off]")),
    }
    let m = request(g, &control::Message::new(h, Vec::new()))?;
    print_away(m.header.status.and_then(|s| s.away).as_ref());
    Ok(())
}

/// Prints sync away from home as cbb global on a full member does.
fn print_away(a: Option<&control::Away>) {
    let Some(a) = a else {
        println!("Sync away from home: off (cbb global on turns it on).");
        return;
    };
    match () {
        _ if a.hub_device.is_empty() && !a.keys_in_file => println!("Sync away from home: off."),
        _ if a.hub_device.is_empty() => {
            println!("Sync away from home: on; waiting to meet the group's hub on the home network.")
        }
        _ if a.through => {
            println!("Sync away from home: on; connected to the hub {} through the tunnel.", a.hub_device)
        }
        _ => println!(
            "Sync away from home: on; the hub is {}, at {}; not connected through the tunnel.",
            a.hub_device,
            a.endpoints.join(", ")
        ),
    }
    if !a.error.is_empty() {
        println!("  Last problem: {}.", a.error.trim_end_matches('.'));
        if !a.detail.is_empty() && error::show_details() {
            println!("  Detail: {}", a.detail);
        }
    }
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
    // A rootless install's user owns its files and updates it.
    let root = is_root() || rootless::is();
    let need_root = || Err(Error::msg("run it with sudo"));
    let (dir, work) = update::paths();
    let mut st = if root { update::load_state(&dir)? } else { update::State::default() };
    let exe = std::env::current_exe().context("cannot find this program")?;
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
                "Automatic updates are on: once a day this device checks for a signed release and installs it."
            } else {
                "Automatic updates are off; cbb update installs a release by hand."
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
                println!("Updates come from GitHub, or {} when GitHub does not answer.", update::MIRROR)
            }
            "" => println!("Updates come from {}.", st.mirror),
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
        let archive = update::archive_name()
            .ok_or_else(|| Error::msg(format!("there is no lite member's release for {}", std::env::consts::ARCH)))?;
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
            program: exe.clone(),
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
                log(&format!("CBB {} is available; this device runs {v}. To install it: sudo cbb update", r.version))
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
        let m = self.ask("release-held", Vec::new())?;
        serde_json::from_slice(&m.payload).context("the service's release does not decode")
    }

    fn get(&self, sha: &str, size: i64, path: &std::path::Path) -> Result<()> {
        use std::io::Write;
        // The service tries its peers for a while before it answers.
        let (mut c, mut r) = self.open("release-get", Duration::from_secs(15 * 60))?;
        let h = control::Header { op: "release-get".into(), value: sha.into(), ..Default::default() };
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
            let (mut c, mut r) = self.open("release-file", Duration::from_secs(120))?;
            let part = control::Part { size, ..Default::default() };
            let h = control::Header {
                op: "release-file".into(),
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
        self.ask("release-want", Vec::new())
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
    format!("core {}, abi {}, source {source}", api::VERSION, api::ABI)
}

#[cfg(test)]
mod tests {
    use super::{core_version, hint, terminal_text};

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
            line.starts_with(&format!("core {}, abi {}, source ", cbb_core::api::VERSION, cbb_core::api::ABI)),
            "{line}"
        );
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
