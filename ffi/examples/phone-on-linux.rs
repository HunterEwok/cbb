// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The phone apps through the C functions of ffi (include/cbb_core.h), on
//! Linux with software keys, for internal/service's TestFFI* tests.
//!
//! On a group of 0.6: -group06 makes one in -dir (the admin key standing
//! for the root key) and prints "Group <device> <group tag>"; -join-window
//! <QR code text> joins one by its home window, or -join-digits <six
//! digits> by the one window announced at home, keeping the set in -dir,
//! and prints "Joined <device> <group tag> <member's name>" or "JOIN FAILED
//! <message>"; with -admin it offers its admin key too, for the root to
//! make it an admin later (cbb admin). The member of 0.6 then runs in -dir,
//! dialing each -peer, and takes "WINDOW", which opens its home window (at
//! once with -window): see window_new for what it prints. -invite TEXT
//! joins by a remote invitation of 0.6 through its guest tunnel, printing
//! "Fingerprint <fingerprint>" first, then as -join-window does.
//!
//! The member prints "WRITE <kind> <text>" for each text for the
//! clipboard, "IDENTITY <certificate in base64>" when an admin renewed its
//! certificate (a group of 0.5), "MUTE <true|false> <for_ms> <by>" when an
//! admin muted it or ended the mute, "SYNC <off> <by>" when an admin turned
//! its sync off or on (a group of 0.6), "CHANGE <copy as JSON>" for each
//! copy that became the group's, "PEER <peer as JSON>" for each peer whose
//! hello it took, "COMMAND <token> <command as JSON>" for each command for
//! the phone itself, and "LOG <line>" for each log line. It takes "COPY
//! <text>" (printing "REFUSED <reason>" when the member does not send it),
//! "PEERS", answered "PEERS <count>", "SYNC OFF <ms>", "SYNC ON" and
//! "MUTED", answered "MUTED <sync off> <muted>", "DEVICES", answered
//! "DEVICES <the devices as a JSON array>", "CALL <request as JSON>",
//! answered "ANSWER <answer as JSON>" (cbb_member_call), and "MANAGE
//! <request as JSON>" (cbb_member_manage with the admin key), answered
//! "MANAGED <answer as JSON>", on standard input, and "INVITE <seconds>",
//! which makes a remote invitation with the admin key and prints "INVITE
//! <text>", then "INVITE JOINING <name> <fingerprint>" for each device that
//! uses it, "INVITE DONE <name>" or "INVITE FAILED <message>"; "INVITE
//! ANSWER <yes|no>" answers about the joining device. "SERVERS" makes the
//! member serve the servers (cbb_member_servers) with software keys for
//! them, answered "SERVERS <answer as JSON>".
//!
//! On a group of 0.5: -new-group makes a group of its own, the admin key
//! standing for the root key, prints "Group <device> <group tag>", and runs
//! the member as the group's root. With -restore <the recovery sheet's QR
//! code> it restores the group as a new phone (cbb_restore), asking each
//! -peer, prints "Restored <device> <group tag>" or "RESTORE FAILED
//! <message>", and runs the member, the admin key standing for the new root
//! key, which "MANAGE" signs root_ca with. With -card FILE a YubiKey kept
//! in FILE stands for the one the app reads over NFC: "PIV <request as
//! JSON>" (cbb_piv) is answered "PIV <answer as JSON>", "MANAGE_CARD
//! <request>" signs with its key as "MANAGE" with the admin key, and
//! -restore-card PIN restores with its recovery keys as -restore does with
//! a sheet. -keys N gives a second phone keys of its own.
//!
//!   phone-on-linux -name phone -dir /tmp/p -join-window 'cbb://pair?…' -peer 127.0.0.1:8765

use std::process::ExitCode;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use cbb_ffi::{
    cbb_free, cbb_group_new, cbb_invite_answer, cbb_invite_free, cbb_invite_new, cbb_invite_next, cbb_joiner_free,
    cbb_joiner_new, cbb_joiner_new_admin, cbb_joiner_next, cbb_member_call, cbb_member_manage, cbb_member_manage_card,
    cbb_member_manage_watch, cbb_member_servers, cbb_member_start, cbb_piv, cbb_restore, cbb_window_free,
    cbb_window_new, cbb_window_next,
};
use p256::ecdsa::SigningKey;
use p256::ecdsa::signature::hazmat::PrehashSigner;

/// The key's signing callback, as the app's KeyStore::sign is.
/// The secret for sealed messages.
const SEAL: [u8; 32] = [9u8; 32];

unsafe extern "C" fn sign(ctx: *mut core::ffi::c_void, digest: *const u8, sig: *mut u8, sig_len: *mut usize) -> i32 {
    // SAFETY: ctx is the key main keeps alive; digest is 32 bytes and sig
    // has 72 bytes of room, as cbb_core.h says.
    unsafe {
        let key = &*(ctx as *const SigningKey);
        let d = std::slice::from_raw_parts(digest, 32);
        let Ok(s): Result<p256::ecdsa::Signature, _> = key.sign_prehash(d) else { return 1 };
        let der = s.to_der();
        let b = der.as_bytes();
        std::ptr::copy_nonoverlapping(b.as_ptr(), sig, b.len());
        sig_len.write(b.len());
    }
    0
}

/// The keys for the servers, by name, as the app's KeyStore keeps them.
static SERVER_KEYS: std::sync::Mutex<Vec<(String, SigningKey)>> = std::sync::Mutex::new(Vec::new());

/// The callback of the keys for the servers (cbb_member_servers).
unsafe extern "C" fn server_keys(
    _: *mut core::ffi::c_void,
    op: i32,
    name: *const u8,
    name_len: usize,
    digest: *const u8,
    out: *mut u8,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: the library gives name_len bytes at name, 32 at digest when
    // it signs, and 72 bytes of room at out.
    unsafe {
        let name = String::from_utf8_lossy(std::slice::from_raw_parts(name, name_len)).into_owned();
        let mut keys = SERVER_KEYS.lock().unwrap();
        let write = |b: &[u8]| {
            std::ptr::copy_nonoverlapping(b.as_ptr(), out, b.len());
            out_len.write(b.len());
        };
        match op {
            0 => i32::from(!keys.iter().any(|(n, _)| *n == name)),
            1 => {
                if !keys.iter().any(|(n, _)| *n == name) {
                    let seed = u8::try_from(keys.len() + 20).unwrap_or(250);
                    keys.push((name.clone(), SigningKey::from_slice(&[seed; 32]).expect("a valid scalar")));
                }
                let k = &keys.iter().find(|(n, _)| *n == name).expect("made above").1;
                write(k.verifying_key().to_sec1_point(false).as_bytes());
                0
            }
            2 => {
                let Some((_, k)) = keys.iter().find(|(n, _)| *n == name) else { return 1 };
                let d = std::slice::from_raw_parts(digest, 32);
                let Ok(s): Result<p256::ecdsa::Signature, _> = k.sign_prehash(d) else { return 1 };
                write(s.to_der().as_bytes());
                0
            }
            3 => {
                let kept: Vec<&str> = name.split('\n').collect();
                keys.retain(|(n, _)| kept.contains(&n.as_str()));
                0
            }
            _ => 1,
        }
    }
}

/// Takes an answer of the library as JSON.
fn take(p: *mut u8, n: usize) -> serde_json::Value {
    // SAFETY: p and n are an answer of the library, given back once.
    let v = unsafe { serde_json::from_slice(std::slice::from_raw_parts(p, n)).unwrap_or_default() };
    // SAFETY: as above.
    unsafe { cbb_free(p, n) };
    v
}

fn b64(v: &serde_json::Value) -> Vec<u8> {
    STANDARD.decode(v.as_str().unwrap_or_default()).unwrap_or_default()
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let arg = |name: &str| args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned();
    let name = arg("-name").unwrap_or_else(|| "phone".into());
    // -keys N gives a second phone keys of its own.
    let keys: u8 = arg("-keys").and_then(|k| k.parse().ok()).unwrap_or(0);
    if let Some(f) = arg("-card") {
        card::set(&f);
    }
    let key = SigningKey::from_slice(&[7u8.wrapping_add(keys.wrapping_mul(2)); 32]).expect("a valid scalar");
    let public = key.verifying_key().to_sec1_point(false);
    let public_b64 = STANDARD.encode(public.as_bytes());
    let admin = args.iter().any(|a| a == "-admin");
    let admin_key = SigningKey::from_slice(&[8u8.wrapping_add(keys.wrapping_mul(2)); 32]).expect("a valid scalar");
    let admin_public = STANDARD.encode(admin_key.verifying_key().to_sec1_point(false).as_bytes());
    // The secret for sealed messages, and its public key for the device
    // record, as the app has them.
    let seal_req =
        serde_json::json!({"abi": cbb_ffi::abi(), "op": "seal_public", "args": {"secret": STANDARD.encode(SEAL)}});
    let seal = serde_json::from_slice::<serde_json::Value>(&cbb_ffi::call(seal_req.to_string().into_bytes()))
        .map(|v| v["ok"]["key"].clone())
        .unwrap_or_default();
    let peers: Vec<String> =
        args.windows(2).filter(|w| w.first().is_some_and(|a| a == "-peer")).filter_map(|w| w.get(1).cloned()).collect();
    // A group of 0.6 (-group06, the admin key standing for the root key)
    // or joining one by a home window (-join-window <QR code text>, or
    // -join-digits <six digits> with the one window announced at home); then
    // the member of 0.6 runs in -dir, which takes "WINDOW" too (and opens it
    // at once with -window).
    let window = args.iter().any(|a| a == "-window");
    if args.iter().any(|a| a == "-group06") {
        let Some(dir) = arg("-dir") else {
            eprintln!("phone-on-linux: -group06 needs -dir");
            return ExitCode::FAILURE;
        };
        let req = serde_json::json!({
            "dir": dir, "name": name, "os": "aurora", "store": "hardware", "root_public": admin_public,
            "public": public_b64,
        })
        .to_string();
        let mut n = 0usize;
        let ctx = &admin_key as *const SigningKey as *mut _;
        // SAFETY: req and n live for the call, the key too.
        let made = take(unsafe { cbb_group_new(req.as_ptr(), req.len(), sign, ctx, &mut n) }, n);
        let group = made["ok"].clone();
        if group.is_null() {
            eprintln!("phone-on-linux: {made}");
            return ExitCode::FAILURE;
        }
        let device = group["device"].as_str().unwrap_or_default().to_string();
        let id = group["group"].as_str().unwrap_or_default();
        println!("Group {device} {}", id.get(..16).unwrap_or(id));
        let admin = Some((&admin_key, admin_public.as_str()));
        return run_live(&key, &public_b64, &name, &dir, peers, &device, admin, window);
    }
    let (qr, digits, invite) = (arg("-join-window"), arg("-join-digits"), arg("-invite"));
    if qr.is_some() || digits.is_some() || invite.is_some() {
        let Some(dir) = arg("-dir") else {
            eprintln!("phone-on-linux: -join-window, -join-digits and -invite need -dir");
            return ExitCode::FAILURE;
        };
        let code = (qr.unwrap_or_default(), digits.unwrap_or_default(), invite.unwrap_or_default());
        let admin = admin.then_some((&admin_key, admin_public.as_str()));
        let Some(device) = join_window(&key, &public_b64, admin, &name, &dir, &code) else {
            return ExitCode::FAILURE;
        };
        return run_live(&key, &public_b64, &name, &dir, peers, &device, admin, window);
    }
    if args.iter().any(|a| a == "-new-group") {
        // A group of its own, the admin key standing for the root key the
        // Aurora app keeps in its TEE; the phone then admits as the root.
        let req = serde_json::json!({
            "name": name, "os": "aurora", "store": "hardware", "root_public": admin_public,
            "public": public_b64, "seal": seal,
        })
        .to_string();
        let mut n = 0usize;
        let ctx = &admin_key as *const SigningKey as *mut _;
        // SAFETY: req and n live for the call, the key too.
        let made = take(unsafe { cbb_group_new(req.as_ptr(), req.len(), sign, ctx, &mut n) }, n);
        let group = made["ok"].clone();
        if group.is_null() {
            eprintln!("phone-on-linux: {made}");
            return ExitCode::FAILURE;
        }
        let tag = cbb_core::certs::Cert::parse(&b64(&group["group_ca"]))
            .map(|ca| cbb_core::certs::tag(&ca))
            .unwrap_or_default();
        println!("Group {} {tag}", group["device"].as_str().unwrap_or_default());
        let Some(dir) = arg("-dir") else { return ExitCode::SUCCESS };
        return run_member(
            &key,
            &public_b64,
            &name,
            &dir,
            peers,
            &group,
            Some((&admin_key, admin_public.as_str())),
            None,
        );
    }
    // With -restore-card PIN the recovery keys on the -card YubiKey issue
    // this phone's member certificates first (cbb_piv's issue).
    let card_keys = match arg("-restore-card") {
        Some(pin) => {
            let got = card::piv(&serde_json::json!({"op": "issue", "pin": pin, "public": public_b64}));
            if got["ok"].is_null() {
                println!("RESTORE FAILED {}", got["error"]["message"].as_str().unwrap_or_default());
                return ExitCode::FAILURE;
            }
            Some(got["ok"]["keys"].clone())
        }
        None => None,
    };
    if let Some(sheet) = arg("-restore").or(card_keys.as_ref().map(|_| String::new())) {
        let mut req = serde_json::json!({
            "sheet": sheet, "public": public_b64, "name": name, "os": "aurora", "addrs": peers,
        });
        if let Some(k) = &card_keys {
            req["card"] = k.clone();
        }
        let req = req.to_string();
        let mut n = 0usize;
        let ctx = &key as *const SigningKey as *mut _;
        // SAFETY: req and n live for the call, the key too.
        let got = take(unsafe { cbb_restore(req.as_ptr(), req.len(), sign, ctx, &mut n) }, n);
        let restored = got["ok"].clone();
        if restored.is_null() {
            println!("RESTORE FAILED {}", got["error"]["message"].as_str().unwrap_or_default());
            return ExitCode::FAILURE;
        }
        let tag = cbb_core::certs::Cert::parse(&b64(&restored["group_ca"]))
            .map(|ca| cbb_core::certs::tag(&ca))
            .unwrap_or_default();
        println!("Restored {} {tag}", restored["device"].as_str().unwrap_or_default());
        let Some(dir) = arg("-dir") else { return ExitCode::SUCCESS };
        return run_member(
            &key,
            &public_b64,
            &name,
            &dir,
            peers,
            &restored,
            Some((&admin_key, admin_public.as_str())),
            None,
        );
    }
    eprintln!("phone-on-linux: give -group06, -join-window, -join-digits, -invite, -new-group or -restore");
    ExitCode::FAILURE
}

unsafe extern "C" fn event(_: *mut core::ffi::c_void, ev: *const u8, len: usize) {
    // SAFETY: the library gives len readable bytes at ev for the call.
    let v: serde_json::Value =
        unsafe { serde_json::from_slice(std::slice::from_raw_parts(ev, len)).unwrap_or_default() };
    let s = |k: &str| v[k].as_str().unwrap_or_default().replace('\n', "\\n");
    match v["type"].as_str() {
        Some("write") => println!("WRITE {} {}", s("kind"), s("text")),
        Some("log") => println!("LOG {}", s("line")),
        Some("identity") => println!("IDENTITY {}", s("cert")),
        Some("copy") => println!("CHANGE {}", v["copy"]),
        Some("peer") => println!("PEER {}", v["peer"]),
        Some("command") => println!("COMMAND {} {}", v["token"], v["command"]),
        Some("mute") => println!("MUTE {} {} {}", v["muted"], v["for_ms"], s("by")),
        Some("sync") => println!("SYNC {} {}", v["off"], s("by")),
        Some("message") if v["message"]["t"] == "admin" => {
            println!("ADMIN CA {}", v["message"]["admin_ca"].as_str().unwrap_or_default())
        }
        _ => {}
    }
}

/// Runs the member as the app does once it joined, until standard input
/// ends; invite is the remote invitation it joined by.
#[allow(clippy::too_many_arguments)]
fn run_member(
    key: &SigningKey,
    public_b64: &str,
    name: &str,
    dir: &str,
    peers: Vec<String>,
    joined: &serde_json::Value,
    admin: Option<(&SigningKey, &str)>,
    invite: Option<&str>,
) -> ExitCode {
    let records = b64(&joined["records"]);
    if std::fs::create_dir_all(dir).is_err() || std::fs::write(format!("{dir}/records.json"), records).is_err() {
        eprintln!("phone-on-linux: cannot write the records in {dir}");
        return ExitCode::FAILURE;
    }
    let req = serde_json::json!({
        "dir": dir, "name": name, "os": "aurora", "os_version": "Aurora OS 5.1.5", "version": "0.5.0",
        "device": joined["device"], "public": public_b64,
        "seal": STANDARD.encode(SEAL), "cert": joined["cert"], "issuer": joined["issuer"],
        "group_ca": joined["group_ca"], "roots": joined["roots"], "peers": peers, "mdns": false,
        "admin_key": joined.get("offer_admin_key"),
    })
    .to_string();
    serve(key, &req, joined, admin, invite, false)
}

/// Runs the member of 0.6 whose group's set is in dir, as the app does
/// once it made or joined the group, until standard input ends; with
/// window, it opens its pairing window at once.
#[allow(clippy::too_many_arguments)]
fn run_live(
    key: &SigningKey,
    public_b64: &str,
    name: &str,
    dir: &str,
    peers: Vec<String>,
    device: &str,
    admin: Option<(&SigningKey, &str)>,
    window: bool,
) -> ExitCode {
    let req = serde_json::json!({
        "dir": dir, "name": name, "os": "aurora", "os_version": "Aurora OS 5.1.5", "version": "0.6.0",
        "device": device, "public": public_b64, "peers": peers, "mdns": false,
    })
    .to_string();
    serve(key, &req, &serde_json::Value::Null, admin, None, window)
}

/// Starts the member with req and takes the commands on standard input
/// until it ends.
fn serve(
    key: &SigningKey,
    req: &str,
    joined: &serde_json::Value,
    admin: Option<(&SigningKey, &str)>,
    invite: Option<&str>,
    window: bool,
) -> ExitCode {
    let (mut ans, mut n) = (std::ptr::null_mut(), 0usize);
    let ctx = key as *const SigningKey as *mut core::ffi::c_void;
    // SAFETY: req, ans and n live for the call; the key outlives the member,
    // which runs until the process ends.
    let m = unsafe { cbb_member_start(req.as_ptr(), req.len(), sign, event, ctx, &mut ans, &mut n) };
    let started = take(ans, n);
    if m.is_null() {
        eprintln!("phone-on-linux: {started}");
        return ExitCode::FAILURE;
    }
    let call = |req: String| -> serde_json::Value {
        let mut n = 0usize;
        // SAFETY: m runs; req and n live for the call.
        take(unsafe { cbb_member_call(m, req.as_ptr(), req.len(), &mut n) }, n)
    };
    if let Some(text) = invite {
        let a = call(serde_json::json!({ "op": "joined_by_invite", "args": { "invite": text } }).to_string());
        if let Some(e) = a.get("error") {
            eprintln!("phone-on-linux: joined_by_invite: {e}");
            return ExitCode::FAILURE;
        }
    }
    let mut inviting: Option<std::sync::Arc<Inviting>> = None;
    let mut windows: Option<std::sync::Arc<Windowing>> = None;
    if window {
        windows = window_new(m, admin);
    }
    for line in std::io::stdin().lines() {
        let Ok(line) = line else { break };
        if line == "WINDOW" {
            // The one open window closes before the next opens.
            drop(windows.take());
            windows = window_new(m, admin);
        } else if let Some(text) = line.strip_prefix("COPY ") {
            let a = call(serde_json::json!({ "op": "copy", "args": { "text": text } }).to_string());
            if let Some(e) = a.get("error") {
                println!("REFUSED {}", e["message"].as_str().unwrap_or_default());
            }
        } else if line == "PEERS" {
            let a = call(serde_json::json!({ "op": "peers" }).to_string());
            println!("PEERS {}", a["ok"]["peers"].as_array().map_or(0, Vec::len));
        } else if line == "DEVICES" {
            let a = call(serde_json::json!({ "op": "devices" }).to_string());
            println!("DEVICES {}", a["ok"]["devices"]);
        } else if line == "SERVERS" {
            let mut n = 0usize;
            // SAFETY: m runs; the callback needs no context.
            println!(
                "SERVERS {}",
                take(unsafe { cbb_member_servers(m, server_keys, std::ptr::null_mut(), &mut n) }, n)
            );
        } else if let Some(req) = line.strip_prefix("CALL ") {
            println!("ANSWER {}", call(req.to_string()));
        } else if line == "MUTED" || line == "SYNC ON" || line.starts_with("SYNC OFF ") {
            let a = if line == "MUTED" {
                call(serde_json::json!({ "op": "muted" }).to_string())
            } else {
                let ms: i64 = line.strip_prefix("SYNC OFF ").and_then(|v| v.parse().ok()).unwrap_or(0);
                let args = serde_json::json!({ "on": line == "SYNC ON", "for_ms": ms });
                call(serde_json::json!({ "op": "sync", "args": args }).to_string())
            };
            println!("MUTED {} {}", a["ok"]["sync_off"], a["ok"]["muted"]);
        } else if let Some(req) = line.strip_prefix("PIV ") {
            let r: serde_json::Value = serde_json::from_str(req).unwrap_or_default();
            println!("PIV {}", card::piv(&r));
        } else if let Some(req) = line.strip_prefix("MANAGE_CARD ") {
            // Signed with the key on the YubiKey (cbb_member_manage_card):
            // the request names its slot, its key's point as public, and
            // the PIN.
            let mut n = 0usize;
            // SAFETY: m runs; req and n live for the call; carry needs no
            // context.
            let got = take(
                unsafe {
                    cbb_member_manage_card(m, req.as_ptr(), req.len(), card::carry, std::ptr::null_mut(), &mut n)
                },
                n,
            );
            println!("MANAGED {got}");
        } else if let Some(name) = line.strip_prefix("WATCH ADD ") {
            // The root makes its watch an admin with the key the watch made
            // (add_watch); the watch keeps its device ID and admin CA.
            match admin {
                Some((k, public)) => {
                    let req = serde_json::json!({
                        "action": "add_watch", "name": name, "os": "harmonyos",
                        "key": STANDARD.encode(watch::spki()),
                    })
                    .to_string();
                    let got = manage(m, k, public, &joined["admin_ca"], &req);
                    watch::admitted(&got["ok"]);
                    println!("WATCH ADDED {got}");
                }
                None => println!("WATCH ADDED {{\"error\":{{\"message\":\"this phone is not an admin\"}}}}"),
            }
        } else if let Some(req) = line.strip_prefix("WATCH ") {
            // What the watch asked from the wrist, signed on the watch
            // (cbb_member_manage_watch); "refuse" makes the watch refuse.
            let mut r: serde_json::Value = serde_json::from_str(req).unwrap_or_default();
            watch::fill(&mut r);
            let refuse = r["refuse"].as_bool().unwrap_or(false);
            let req = r.to_string();
            let mut n = 0usize;
            let ctx = usize::from(refuse) as *mut core::ffi::c_void;
            // SAFETY: m runs; req and n live for the call; the callback's
            // context is a flag, no pointer.
            let got = take(unsafe { cbb_member_manage_watch(m, req.as_ptr(), req.len(), watch::sign, ctx, &mut n) }, n);
            println!("WATCH SAW {}", watch::seen());
            println!("WATCHED {got}");
        } else if let Some(req) = line.strip_prefix("MANAGE ") {
            match admin {
                Some((k, public)) => println!("MANAGED {}", manage(m, k, public, &joined["admin_ca"], req)),
                None => println!("MANAGED {{\"error\":{{\"message\":\"this phone is not an admin\"}}}}"),
            }
        } else if let Some(yes) = line.strip_prefix("INVITE ANSWER ") {
            if let Some(i) = &inviting {
                // SAFETY: the invitation lives until inviting is dropped.
                unsafe { cbb_invite_answer(i.0, i32::from(yes == "yes")) };
            }
        } else if let Some(secs) = line.strip_prefix("INVITE ") {
            inviting = None;
            match admin {
                Some((k, public)) => inviting = invite_new(m, k, public, &joined["admin_ca"], secs),
                None => println!("INVITE FAILED this phone is not an admin"),
            }
        }
    }
    ExitCode::SUCCESS
}

/// A pairing window of 0.6 the phone opened, freed when dropped.
struct Windowing(*mut cbb_ffi::window::Window);

// SAFETY: the library's window may be used from any thread.
unsafe impl Send for Windowing {}
unsafe impl Sync for Windowing {}

impl Drop for Windowing {
    fn drop(&mut self) {
        // SAFETY: the window is freed once, here.
        unsafe { cbb_window_free(self.0) };
    }
}

/// Opens the member's home window of 0.6 with the admin key (the root key
/// on a phone that made its group), as the app does: the member port
/// listens first. It prints "WINDOW <QR code text>" and "WINDOW DIGITS
/// <six digits>", then from a thread of its own "WINDOW JOINING" when a
/// device dials it, "WINDOW DONE <name>" when one joined (the window then
/// closes), "WINDOW FAILED <message>" for an attempt that failed (the
/// window stays open) and "WINDOW CLOSED <message>" when its time is up or
/// it took three wrong codes.
fn window_new(
    m: *const cbb_ffi::member::Member,
    admin: Option<(&SigningKey, &str)>,
) -> Option<std::sync::Arc<Windowing>> {
    let Some((key, public)) = admin else {
        println!("WINDOW FAILED this phone has no admin key");
        return None;
    };
    let listen = serde_json::json!({ "op": "listen", "args": { "kind": "home", "port": 0 } }).to_string();
    let mut n = 0usize;
    // SAFETY: m runs; listen and n live for the call.
    let got = take(unsafe { cbb_member_call(m, listen.as_ptr(), listen.len(), &mut n) }, n);
    if let Some(e) = got.get("error") {
        println!("WINDOW FAILED {}", e["message"].as_str().unwrap_or_default());
        return None;
    }
    let req = serde_json::json!({ "public": public, "addrs": ["127.0.0.1"], "expires": 0, "mdns": false }).to_string();
    let mut ans = std::ptr::null_mut();
    let ctx = key as *const SigningKey as *mut core::ffi::c_void;
    // SAFETY: m runs; req, ans and n live for the call; the key outlives the
    // window.
    let w = unsafe { cbb_window_new(m, req.as_ptr(), req.len(), sign, ctx, &mut ans, &mut n) };
    let created = take(ans, n);
    if w.is_null() {
        println!("WINDOW FAILED {}", created["error"]["message"].as_str().unwrap_or_default());
        return None;
    }
    println!("WINDOW {}", created["ok"]["qr"].as_str().unwrap_or_default());
    println!("WINDOW DIGITS {}", created["ok"]["digits"].as_str().unwrap_or_default());
    let windowing = std::sync::Arc::new(Windowing(w));
    let held = std::sync::Arc::downgrade(&windowing);
    std::thread::spawn(move || {
        let mut version = 0u64;
        loop {
            // Holds the window only for one wait, so that dropping it
            // (another WINDOW, or the end) ends this thread.
            let Some(w) = held.upgrade() else { return };
            let mut n = 0usize;
            // SAFETY: w keeps the window for the call.
            let st = take(unsafe { cbb_window_next(w.0, version, 1000, &mut n) }, n);
            drop(w);
            let ok = &st["ok"];
            let v = ok["version"].as_u64().unwrap_or(version);
            if v == version {
                continue;
            }
            version = v;
            let text = |k: &str| ok[k].as_str().unwrap_or_default().to_string();
            match ok["state"].as_str() {
                Some("joining") => println!("WINDOW JOINING"),
                Some("done") => {
                    println!("WINDOW DONE {}", text("name"));
                    return;
                }
                Some("failed") => {
                    println!("WINDOW FAILED {}", ok["error"]["message"].as_str().unwrap_or_default())
                }
                Some("closed") => {
                    println!("WINDOW CLOSED {}", ok["error"]["message"].as_str().unwrap_or_default());
                    return;
                }
                _ => {}
            }
        }
    });
    Some(windowing)
}

/// Joins a group of 0.6 by a home window's QR code, or by its six digits
/// with the one window announced at home, as the app does, keeping the set
/// in dir: it prints "Joined <device> <group tag> <member's name>", the tag
/// the first 16 hex characters of the group's ID, or "JOIN FAILED
/// <message>". With admin it offers that key, for the root to make it an
/// admin later. code is the QR code's text, the digits and a remote
/// invitation's text, one of them given: by an invitation it prints
/// "Fingerprint <fingerprint>" first, which the inviting admin compares.
/// It answers the device ID.
fn join_window(
    key: &SigningKey,
    public_b64: &str,
    admin: Option<(&SigningKey, &str)>,
    name: &str,
    dir: &str,
    (qr, digits, invite): &(String, String, String),
) -> Option<String> {
    let mut req = serde_json::json!({
        "dir": dir, "qr": qr, "digits": digits, "invite": invite, "name": name, "os": "aurora",
        "public": public_b64,
    });
    if let Some((_, public)) = admin {
        req["admin_public"] = public.into();
    }
    let req = req.to_string();
    let (mut ans, mut n) = (std::ptr::null_mut(), 0usize);
    let ctx = key as *const SigningKey as *mut core::ffi::c_void;
    // SAFETY: req, ans and n live for the call; the keys outlive the joiner.
    let j = unsafe {
        match admin {
            Some((k, _)) => {
                let admin_ctx = k as *const SigningKey as *mut core::ffi::c_void;
                cbb_joiner_new_admin(req.as_ptr(), req.len(), sign, ctx, sign, admin_ctx, &mut ans, &mut n)
            }
            None => cbb_joiner_new(req.as_ptr(), req.len(), sign, ctx, &mut ans, &mut n),
        }
    };
    let created = take(ans, n);
    if j.is_null() {
        println!("JOIN FAILED {}", created["error"]["message"].as_str().unwrap_or_default());
        return None;
    }
    if let Some(fp) = created["ok"]["fingerprint"].as_str() {
        println!("Fingerprint {fp}");
    }
    let mut version = 0u64;
    let joined = loop {
        // SAFETY: j is the joiner, used by this thread only.
        let st = take(unsafe { cbb_joiner_next(j, version, 1000, &mut n) }, n);
        let ok = &st["ok"];
        if ok.is_null() {
            println!("JOIN FAILED {}", st["error"]["message"].as_str().unwrap_or_default());
            break None;
        }
        let v = ok["version"].as_u64().unwrap_or(version);
        if v == version {
            continue;
        }
        version = v;
        match ok["state"].as_str() {
            Some("done") => {
                let group = ok["group"].as_str().unwrap_or_default();
                let device = ok["device"].as_str().unwrap_or_default().to_string();
                println!(
                    "Joined {device} {} {}",
                    group.get(..16).unwrap_or(group),
                    ok["name"].as_str().unwrap_or_default()
                );
                break Some(device);
            }
            Some("failed") => {
                println!("JOIN FAILED {}", ok["error"]["message"].as_str().unwrap_or_default());
                break None;
            }
            _ => {}
        }
    };
    // SAFETY: j is freed once.
    unsafe { cbb_joiner_free(j) };
    joined
}

/// An invitation the phone made, freed when dropped.
struct Inviting(*mut cbb_ffi::invite::Invite);

// SAFETY: the library's invitation may be used from any thread.
unsafe impl Send for Inviting {}
unsafe impl Sync for Inviting {}

impl Drop for Inviting {
    fn drop(&mut self) {
        // SAFETY: the invitation is freed once, here.
        unsafe { cbb_invite_free(self.0) };
    }
}

/// Makes a remote invitation with the admin key, as the app does, and
/// prints its states from a thread of its own until it ends.
fn invite_new(
    m: *const cbb_ffi::member::Member,
    key: &SigningKey,
    public: &str,
    admin_ca: &serde_json::Value,
    secs: &str,
) -> Option<std::sync::Arc<Inviting>> {
    let req = serde_json::json!({
        "public": public, "admin_ca": admin_ca, "expires": secs.trim().parse::<u64>().unwrap_or(0),
    })
    .to_string();
    let (mut ans, mut n) = (std::ptr::null_mut(), 0usize);
    let ctx = key as *const SigningKey as *mut core::ffi::c_void;
    // SAFETY: m runs; req, ans and n live for the call; the key outlives the
    // invitation.
    let i = unsafe { cbb_invite_new(m, req.as_ptr(), req.len(), sign, ctx, &mut ans, &mut n) };
    let created = take(ans, n);
    if i.is_null() {
        println!("INVITE FAILED {}", created["error"]["message"].as_str().unwrap_or_default());
        return None;
    }
    println!("INVITE {}", created["ok"]["invite"].as_str().unwrap_or_default());
    let inviting = std::sync::Arc::new(Inviting(i));
    let held = inviting.clone();
    std::thread::spawn(move || {
        let i = held.0 as *const cbb_ffi::invite::Invite;
        let mut version = 0u64;
        loop {
            let mut n = 0usize;
            // SAFETY: held keeps the invitation until this thread ends.
            let st = take(unsafe { cbb_invite_next(i, version, 1000, &mut n) }, n);
            let ok = &st["ok"];
            let v = ok["version"].as_u64().unwrap_or(version);
            if v == version {
                continue;
            }
            version = v;
            match ok["state"].as_str() {
                Some("joining") => println!(
                    "INVITE JOINING {} {}",
                    ok["joining"]["name"].as_str().unwrap_or_default(),
                    ok["joining"]["fingerprint"].as_str().unwrap_or_default()
                ),
                Some("done") => {
                    println!("INVITE DONE {}", ok["name"].as_str().unwrap_or_default());
                    return;
                }
                Some("failed") => {
                    println!("INVITE FAILED {}", ok["error"]["message"].as_str().unwrap_or_default());
                    return;
                }
                _ => {}
            }
        }
    });
    Some(inviting)
}

/// Signs an admin's change or command (cbb_member_manage): req is the
/// request without the key, which the admin key fills in.
fn manage(
    m: *const cbb_ffi::member::Member,
    key: &SigningKey,
    public: &str,
    admin_ca: &serde_json::Value,
    req: &str,
) -> serde_json::Value {
    let mut r: serde_json::Value = serde_json::from_str(req).unwrap_or_default();
    r["public"] = public.into();
    if !admin_ca.is_null() {
        r["admin_ca"] = admin_ca.clone();
    }
    let req = r.to_string();
    let mut n = 0usize;
    let ctx = key as *const SigningKey as *mut core::ffi::c_void;
    // SAFETY: m runs; req, n and the key live for the call.
    take(unsafe { cbb_member_manage(m, req.as_ptr(), req.len(), sign, ctx, &mut n) }, n)
}

/// A YubiKey with the PIV application kept in a file, for the tests: the
/// retired slots' keys and certificates, the PIN 123456 and the factory
/// AES-192 management key, as member/src/piv.rs's fake card in its tests.
mod card {
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    use aes::cipher::{Array, BlockCipherEncrypt as _, KeyInit as _};
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use p256::ecdsa::SigningKey;
    use p256::ecdsa::signature::hazmat::PrehashSigner as _;

    use cbb_member::piv::DEFAULT_MANAGEMENT_KEY as KEY;

    #[derive(Default)]
    struct Session {
        selected: bool,
        verified: bool,
        authed: bool,
        witness: Option<[u8; 16]>,
        chain: Vec<u8>,
    }

    static FILE: Mutex<Option<String>> = Mutex::new(None);
    static SESSION: Mutex<Option<Session>> = Mutex::new(None);

    pub fn set(f: &str) {
        *FILE.lock().unwrap() = Some(f.to_string());
    }

    /// The slots in the file: slot → (key, certificate).
    fn load() -> BTreeMap<u8, (Vec<u8>, Vec<u8>)> {
        let f = FILE.lock().unwrap().clone().unwrap_or_default();
        let v: serde_json::Value =
            std::fs::read(&f).ok().and_then(|d| serde_json::from_slice(&d).ok()).unwrap_or_default();
        let mut out = BTreeMap::new();
        for (k, e) in v.as_object().into_iter().flatten() {
            let b = |x: &serde_json::Value| STANDARD.decode(x.as_str().unwrap_or_default()).unwrap_or_default();
            out.insert(k.parse().unwrap_or(0), (b(&e["key"]), b(&e["cert"])));
        }
        out
    }

    fn save(slots: &BTreeMap<u8, (Vec<u8>, Vec<u8>)>) {
        let f = FILE.lock().unwrap().clone().unwrap_or_default();
        let v: serde_json::Map<String, serde_json::Value> = slots
            .iter()
            .map(|(k, (key, cert))| {
                (k.to_string(), serde_json::json!({"key": STANDARD.encode(key), "cert": STANDARD.encode(cert)}))
            })
            .collect();
        let _ = std::fs::write(f, serde_json::Value::Object(v).to_string());
    }

    fn tlv(tag: u8, v: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        match v.len() {
            n if n < 0x80 => out.push(n as u8),
            n if n < 0x100 => out.extend_from_slice(&[0x81, n as u8]),
            n => out.extend_from_slice(&[0x82, (n >> 8) as u8, n as u8]),
        }
        out.extend_from_slice(v);
        out
    }

    fn read(b: &[u8], tag: u8) -> Option<(&[u8], &[u8])> {
        if b.len() < 2 || b[0] != tag {
            return None;
        }
        let (n, i) = match b[1] {
            0x81 => (usize::from(*b.get(2)?), 3),
            0x82 => (usize::from(*b.get(2)?) << 8 | usize::from(*b.get(3)?), 4),
            l => (usize::from(l), 2),
        };
        Some((b.get(i..i + n)?, b.get(i + n..)?))
    }

    fn encrypt(block: &[u8]) -> Vec<u8> {
        let c = aes::Aes192::new_from_slice(&KEY).unwrap();
        let mut b: Array<u8, _> = <[u8; 16]>::try_from(block).unwrap().into();
        c.encrypt_block(&mut b);
        b.to_vec()
    }

    fn sw(mut data: Vec<u8>, w: u16) -> Vec<u8> {
        data.extend_from_slice(&w.to_be_bytes());
        data
    }

    /// One APDU to the card.
    fn transmit(apdu: &[u8]) -> Vec<u8> {
        let mut guard = SESSION.lock().unwrap();
        let s = guard.get_or_insert_with(Session::default);
        let (cla, ins, _p1, p2) = (apdu[0], apdu[1], apdu[2], apdu[3]);
        let data = if apdu.len() > 5 { apdu[5..5 + usize::from(apdu[4])].to_vec() } else { Vec::new() };
        if cla & 0x10 != 0 {
            s.chain.extend(data);
            return sw(vec![], 0x9000);
        }
        let data = [std::mem::take(&mut s.chain), data].concat();
        let mut slots = load();
        match ins {
            0xa4 => {
                *s = Session { selected: true, ..Session::default() };
                sw(vec![], 0x9000)
            }
            _ if !s.selected => sw(vec![], 0x6d00),
            0xcb => match slots.get(&(0x82 + data[4] - 0x0d)) {
                Some((_, cert)) if !cert.is_empty() => {
                    sw(tlv(0x53, &[tlv(0x70, cert), tlv(0x71, &[0])].concat()), 0x9000)
                }
                _ => sw(vec![], 0x6a82),
            },
            0x20 => {
                let mut want = [0xffu8; 8];
                want[..6].copy_from_slice(b"123456");
                s.verified = data == want;
                sw(vec![], if s.verified { 0x9000 } else { 0x63c2 })
            }
            0xf7 if p2 == 0x9b => sw(tlv(0x01, &[0x0b]), 0x9000),
            0xf7 => match slots.get(&p2) {
                Some(_) => sw(tlv(0x01, &[0x11]), 0x9000),
                None => sw(vec![], 0x6a82),
            },
            0x87 if p2 == 0x9b => {
                let (outer, _) = read(&data, 0x7c).unwrap();
                let (first, rest) = read(outer, 0x80).unwrap();
                if first.is_empty() {
                    let w = [0x5au8; 16];
                    s.witness = Some(w);
                    return sw(tlv(0x7c, &tlv(0x80, &encrypt(&w))), 0x9000);
                }
                if Some(first) != s.witness.as_ref().map(|w| &w[..]) {
                    return sw(vec![], 0x6982);
                }
                let (challenge, _) = read(rest, 0x81).unwrap();
                s.authed = true;
                sw(tlv(0x7c, &tlv(0x82, &encrypt(challenge))), 0x9000)
            }
            0x87 => {
                if !s.verified {
                    return sw(vec![], 0x6982);
                }
                // The PIN before each signature.
                s.verified = false;
                let Some((key, _)) = slots.get(&p2) else { return sw(vec![], 0x6a82) };
                let k = SigningKey::from_slice(key).unwrap();
                let (outer, _) = read(&data, 0x7c).unwrap();
                let (_, rest) = read(outer, 0x82).unwrap();
                let (digest, _) = read(rest, 0x81).unwrap();
                let sig: p256::ecdsa::Signature = k.sign_prehash(digest).unwrap();
                sw(tlv(0x7c, &tlv(0x82, sig.to_der().as_bytes())), 0x9000)
            }
            0x47 => {
                if !s.authed {
                    return sw(vec![], 0x6982);
                }
                let k = SigningKey::from_slice(&[0x40 + p2 % 0x40; 32]).unwrap();
                let point = k.verifying_key().to_sec1_point(false).as_bytes().to_vec();
                slots.insert(p2, (k.to_bytes().to_vec(), Vec::new()));
                save(&slots);
                let mut out = vec![0x7f];
                out.extend(tlv(0x49, &tlv(0x86, &point)));
                sw(out, 0x9000)
            }
            0xdb => {
                if !s.authed {
                    return sw(vec![], 0x6982);
                }
                let (id, rest) = read(&data, 0x5c).unwrap();
                let slot = 0x82 + id[2] - 0x0d;
                let (obj, _) = read(rest, 0x53).unwrap();
                let (der, _) = read(obj, 0x70).unwrap();
                let Some(e) = slots.get_mut(&slot) else { return sw(vec![], 0x6a82) };
                e.1 = der.to_vec();
                save(&slots);
                sw(vec![], 0x9000)
            }
            _ => sw(vec![], 0x6d00),
        }
    }

    pub unsafe extern "C" fn carry(
        _: *mut core::ffi::c_void,
        apdu: *const u8,
        len: usize,
        out: *mut u8,
        cap: usize,
        out_len: *mut usize,
    ) -> i32 {
        // SAFETY: as cbb_core.h's cbb_transmit_fn says.
        unsafe {
            let r = transmit(std::slice::from_raw_parts(apdu, len));
            if r.len() > cap {
                return 1;
            }
            std::ptr::copy_nonoverlapping(r.as_ptr(), out, r.len());
            out_len.write(r.len());
        }
        0
    }

    /// cbb_piv on the card.
    pub fn piv(req: &serde_json::Value) -> serde_json::Value {
        let req = req.to_string();
        let mut n = 0usize;
        // SAFETY: req and n live for the call; carry needs no context.
        super::take(unsafe { super::cbb_piv(req.as_ptr(), req.len(), carry, std::ptr::null_mut(), &mut n) }, n)
    }
}

/// The app's watch as an admin: its key, its device ID and admin CA, and
/// what it was shown to sign.
mod watch {
    use std::sync::Mutex;

    use p256::ecdsa::SigningKey;
    use p256::ecdsa::signature::hazmat::PrehashSigner as _;

    /// The watch's admin key; fixed, as a test's, and none of the phone's
    /// own keys (seeds 7 and 8 up).
    fn key() -> SigningKey {
        SigningKey::from_slice(&[0x77u8; 32]).unwrap()
    }

    static ADMITTED: Mutex<Option<serde_json::Value>> = Mutex::new(None);
    static SEEN: Mutex<Vec<String>> = Mutex::new(Vec::new());

    /// The key point the watch hands the phone, SEC1 uncompressed.
    fn point() -> Vec<u8> {
        key().verifying_key().to_sec1_point(false).as_bytes().to_vec()
    }

    pub fn spki() -> Vec<u8> {
        cbb_core::certs::p256_spki_of(&point())
    }

    pub fn admitted(ok: &serde_json::Value) {
        if !ok.is_null() {
            *ADMITTED.lock().unwrap() = Some(ok.clone());
        }
    }

    /// Adds the watch's own fields to a request from the wrist.
    pub fn fill(r: &mut serde_json::Value) {
        use base64::Engine as _;
        let a = ADMITTED.lock().unwrap().clone().unwrap_or_default();
        r["watch"] = a["device"].clone();
        r["admin_ca"] = a["admin_ca"].clone();
        r["public"] = base64::engine::general_purpose::STANDARD.encode(point()).into();
    }

    /// The types of the records and commands the watch was shown, since
    /// the last call.
    pub fn seen() -> String {
        std::mem::take(&mut *SEEN.lock().unwrap()).join(",")
    }

    /// The watch's side of the link: it reads what it is shown and signs
    /// it, unless ctx says it refuses.
    pub unsafe extern "C" fn sign(
        ctx: *mut core::ffi::c_void,
        body: *const u8,
        len: usize,
        sig: *mut u8,
        sig_len: *mut usize,
    ) -> i32 {
        // SAFETY: body is len readable bytes, as cbb_core.h says.
        let body = unsafe { std::slice::from_raw_parts(body, len) };
        let v: serde_json::Value = serde_json::from_slice(body).unwrap_or_default();
        let kind = v["type"].as_str().or(v["command"]["action"].as_str()).unwrap_or("?");
        SEEN.lock().unwrap().push(kind.to_string());
        if !ctx.is_null() {
            return 1;
        }
        let Ok(s): Result<p256::ecdsa::Signature, _> = key().sign_prehash(&cbb_core::certs::sha256(body)) else {
            return 1;
        };
        let der = s.to_der();
        let b = der.as_bytes();
        // SAFETY: sig has 72 bytes of room and sig_len is writable.
        unsafe {
            std::ptr::copy_nonoverlapping(b.as_ptr(), sig, b.len());
            sig_len.write(b.len());
        }
        0
    }
}
