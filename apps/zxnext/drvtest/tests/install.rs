// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! `.cbb install` as the user runs it, on the Next played by cbb_drvtest::next
//! with the ESP and cbb.tools, and the Pi, played by cbb_drvtest::peers:
//! the whole of build/CBB, its overlays and NextZXOS's calls, with the
//! failures that a real network and a real Pi have (README.md, "Testing on
//! a played Next").
//!
//! It needs `make PI_CBB=build/PIBRIDGE` first, as CI's job does: the
//! small PIBRIDGE stands in for the Pi's cbb, so that a run takes seconds.
//! Without build/CBB the tests say so and pass.

use std::path::{Path, PathBuf};

use cbb_drvtest::next::{Key, Run};
use cbb_drvtest::peers::{Esp, Pi, SIGNED_OK};
use cbb_drvtest::sha256;

/// What CBB was built with, and a site with its files.
struct Kit {
    dot: PathBuf,
    map: String,
    pages: Vec<u8>,
    pi_cbb: Vec<u8>,
    site: PathBuf,
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                crc >> 1 ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

fn kit(name: &str) -> Option<Kit> {
    let build = Path::new(env!("CARGO_MANIFEST_DIR")).join("../build");
    let dot = build.join("CBB");
    if !dot.exists() {
        eprintln!("{name}: no build/CBB; `make PI_CBB=build/PIBRIDGE` first");
        return None;
    }
    let map = std::fs::read_to_string(build.join("cbb.map")).expect("build/cbb.map");
    let pins = std::fs::read_to_string(build.join("pins.h")).expect("build/pins.h");
    let pinned = pins
        .split("PIN_PI_SHA256 \"")
        .nth(1)
        .expect("PIN_PI_SHA256")
        .get(..64)
        .unwrap()
        .to_string();
    // The Pi's cbb that CBB was built with: PIBRIDGE, or CBB_PI.
    let pi_path = std::env::var("CBB_PI")
        .map(PathBuf::from)
        .unwrap_or_else(|_| build.join("PIBRIDGE"));
    let pi_cbb = std::fs::read(&pi_path).unwrap_or_default();
    assert_eq!(
        sha256::hex(&pi_cbb),
        pinned,
        "{} is not the Pi's cbb that build/CBB was built with: make PI_CBB=build/PIBRIDGE, or name it in CBB_PI",
        pi_path.display()
    );
    let mut pages: Vec<u8> = std::fs::read_dir(&build)
        .unwrap()
        .filter_map(|e| {
            let n = e.unwrap().file_name().into_string().unwrap();
            n.strip_prefix("cbb_PAGE_")?
                .strip_suffix(".bin")?
                .parse()
                .ok()
        })
        .collect();
    pages.sort();
    // The site, as packaging/zxnext/site.sh lays it out.
    let site = std::env::temp_dir().join(format!("cbb-site-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&site);
    std::fs::create_dir_all(&site).unwrap();
    let mut list = String::new();
    for (f, data) in [
        ("CBB", std::fs::read(&dot).unwrap()),
        ("CBB.DRV", std::fs::read(build.join("CBB.DRV")).unwrap()),
        ("CBB.OVL", std::fs::read(build.join("CBB.OVL")).unwrap()),
        ("cbb", pi_cbb.clone()),
    ] {
        std::fs::write(site.join(f), &data).unwrap();
        list += &format!(
            "{f} {} {:08x} {}\n",
            data.len(),
            crc32(&data),
            sha256::hex(&data)
        );
    }
    sign_list(&site, &list);
    Some(Kit {
        dot,
        map,
        pages,
        pi_cbb,
        site,
    })
}

/// The site's LIST, and its SIGNED as the played Pi takes it.
fn sign_list(site: &Path, list: &str) {
    std::fs::write(site.join("LIST"), list).unwrap();
    std::fs::write(site.join("SIGNED"), format!("{SIGNED_OK}\n{list}")).unwrap();
}

/// A card with /cbb/CBB, as `.http` leaves it.
fn card(name: &str) -> PathBuf {
    let card = std::env::temp_dir().join(format!("cbb-card-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&card);
    std::fs::create_dir_all(card.join("cbb")).unwrap();
    std::fs::create_dir_all(card.join("dot")).unwrap();
    std::fs::create_dir_all(card.join("nextzxos")).unwrap();
    card
}

/// One run of .cbb: the install screen before the key, and the run after it.
struct Outcome {
    screen: String,
    run: Run,
}

impl Outcome {
    fn esp(&mut self) -> &mut Esp {
        self.run.hw.esp.peer.as_any().downcast_mut().unwrap()
    }
    fn pi(&mut self) -> &mut Pi {
        self.run.hw.pi.peer.as_any().downcast_mut().unwrap()
    }
    fn has(&self, s: &str) -> bool {
        self.screen.contains(s)
    }
    /// The pages .cbb still has from NextZXOS.
    fn taken(&self) -> usize {
        self.run.hw.ours.iter().filter(|&&p| p).count()
    }
}

/// Runs .cbb ARGS until the install screen asks for a key (at most secs
/// seconds of the Next's time), presses ENTER, and lets it end; keys adds
/// SPACE from the time given.
fn run(
    kit: &Kit,
    card: &Path,
    args: &str,
    esp: Esp,
    pi: Pi,
    secs: f64,
    space: Option<f64>,
) -> Outcome {
    std::fs::copy(&kit.dot, card.join("cbb/CBB")).unwrap();
    // A Pi in a group already: the install ends with its screen, where a
    // Pi in none would go on to pair (installs_then_pairs).
    let mut pi = pi;
    pi.in_group = true;
    // CBB.OVL as the install left it, for the commands after it.
    if !args.starts_with("install") && !args.starts_with("update") {
        std::fs::copy(kit.site.join("CBB.OVL"), card.join("cbb/CBB.OVL")).unwrap();
    }
    let mut run = Run::new(&kit.dot, card, args, Box::new(esp), Box::new(pi));
    // .cbb runs the one in C:/DOT.
    if card.join("dot/CBB").exists() {
        run.hw.running = "c:/dot/CBB".into();
    }
    let table = kit
        .map
        .lines()
        .find(|l| l.starts_with("__z_page_table "))
        .expect("__z_page_table");
    run.page_table =
        u16::from_str_radix(table.split('$').nth(1).unwrap().get(..4).unwrap(), 16).unwrap();
    run.overlay_logical = kit.pages.clone();
    if let Some(t) = space {
        let t = (t * 1e6) as u64;
        run.hw.keys.push(Key {
            from: t,
            until: t + 300_000,
            row: 0x7F,
            bit: 0,
        });
    }
    let mut t = 0.0;
    while !run.done && t < secs && !run.hw.screen_text().contains("PRESS ANY KEY") {
        run.run(1.0);
        t += 1.0;
    }
    let screen = run.hw.screen_text();
    assert!(
        screen.contains("PRESS ANY KEY"),
        "no PRESS ANY KEY after {t}s:\n{screen}"
    );
    let now = run.hw.now as u64;
    run.hw.keys.push(Key {
        from: now + 500_000,
        until: now + 700_000,
        row: 0xBF,
        bit: 0,
    });
    // The Pi's shell tells whether it is in a group, then the network starts.
    for _ in 0..30 {
        if run.done {
            break;
        }
        run.run(1.0);
    }
    assert!(
        run.done,
        ".cbb did not end after the key:\n{}",
        run.hw.screen_text()
    );
    // Back to BASIC with no error of its own, and no rule of NextZXOS's
    // broken on the way.
    assert_eq!(run.result.map(|r| r.0), Some(false), "an error to BASIC");
    let breaches: Vec<String> = run
        .hw
        .breaches
        .iter()
        .map(|b| format!("{:#06x}: {}", b.pc, b.what))
        .collect();
    assert!(breaches.is_empty(), "breaches:\n{}", breaches.join("\n"));
    // BASIC's 3.5 MHz back, after 28 MHz while it ran.
    assert_eq!(run.hw.nr[0x07] & 3, 0, "the CPU's speed");
    Outcome { screen, run }
}

#[test]
fn installs_then_finds_all_current() {
    let Some(kit) = kit("clean") else { return };
    let card = card("clean");
    let mut o = run(
        &kit,
        &card,
        "install",
        Esp::new(kit.site.clone()),
        Pi::new(),
        300.0,
        None,
    );
    assert!(o.has("CBB.DRV FETCHED"), "{}", o.screen);
    // AUTOEXEC.BAS, new: .cbb net on at power-on.
    assert_eq!(
        std::fs::read(card.join("nextzxos/AUTOEXEC.BAS")).unwrap(),
        plus3_basic(&[(10, b".cbb net on")], b"", 10)
    );
    assert!(
        o.has("SERVICE FETCHED") && o.has("TO PI   DONE"),
        "{}",
        o.screen
    );
    assert!(
        o.has("CBB.DRV IS INSTALLED.") && o.has("DONE."),
        "{}",
        o.screen
    );
    assert!(o.pi_cbb_is(&kit.pi_cbb));
    // The driver keeps its bank; every other page is back.
    assert_eq!(o.run.hw.drivers.len(), 1);
    assert_eq!(o.taken(), 1);
    assert_eq!(
        std::fs::read(card.join("cbb/CBB.DRV")).unwrap(),
        std::fs::read(kit.site.join("CBB.DRV")).unwrap()
    );
    // Remote paste stays off after the first install: no setting for the
    // Pi, and no word of remote paste on.
    assert!(!o.has("REMOTE PASTE ON"), "{}", o.screen);
    assert!(!card.join("cbb/PASTE.CFG").exists());
    assert!(
        !o.pi().log.iter().any(|l| l.contains("-paste")),
        "{:?}",
        o.pi().log
    );
    // The network starts after the install: it looks for a computer.
    assert!(
        o.esp().log.iter().any(|l| l.contains("AT+CIPSTART=4")),
        "{:?}",
        o.esp().log
    );

    // Again, with the Pi's cbb in place: nothing to fetch or send.
    let mut pi = Pi::new();
    pi.cbb_sha = Some(sha256::hex(&kit.pi_cbb));
    let mut o = run(
        &kit,
        &card,
        "install",
        Esp::new(kit.site.clone()),
        pi,
        120.0,
        None,
    );
    assert!(
        o.has("CBB.DRV CURRENT")
            && o.has("SERVICE CURRENT")
            && o.has("TO PI   CURRENT")
            && o.has("DONE."),
        "{}",
        o.screen
    );
    assert!(o.pi().received.is_empty());
    assert!(
        !o.esp()
            .log
            .iter()
            .any(|l| l.contains("HTTP: GET /zxnext/cbb "))
    );
    let _ = std::fs::remove_dir_all(&card);
}

#[test]
fn says_when_the_site_has_not_the_files() {
    let Some(kit) = kit("404") else { return };
    let card = card("404");
    let mut esp = Esp::new(kit.site.clone());
    esp.faults.status = Some(404);
    let mut o = run(&kit, &card, "install", esp, Pi::new(), 120.0, None);
    assert!(
        o.has("CBB.DRV NOT THERE") && o.has("HAS NO SUCH FILE"),
        "{}",
        o.screen
    );
    // Once: trying again does not help.
    assert_eq!(
        o.esp().log.iter().filter(|l| l.contains("HTTP: ")).count(),
        1
    );
    assert_eq!(o.taken(), 0);
    let _ = std::fs::remove_dir_all(&card);
}

#[test]
fn says_when_the_esp_has_no_network() {
    let Some(kit) = kit("nowifi") else { return };
    let card = card("nowifi");
    let mut esp = Esp::new(kit.site.clone());
    esp.wifi = false;
    let o = run(&kit, &card, "install", esp, Pi::new(), 120.0, None);
    assert!(o.has("CANNOT REACH CBB.TOOLS"), "{}", o.screen);
    assert_eq!(o.taken(), 0);
    let _ = std::fs::remove_dir_all(&card);
}

#[test]
fn installs_the_driver_without_the_pi() {
    let Some(kit) = kit("nopi") else { return };
    let card = card("nopi");
    let mut pi = Pi::new();
    pi.answers = false;
    let o = run(
        &kit,
        &card,
        "install",
        Esp::new(kit.site.clone()),
        pi,
        300.0,
        None,
    );
    assert!(
        o.has("THE PI DOES NOT ANSWER") && o.has("TO PI   NO PI") && o.has("CBB.DRV IS INSTALLED."),
        "{}",
        o.screen
    );
    assert_eq!(o.run.hw.drivers.len(), 1);
    let _ = std::fs::remove_dir_all(&card);
}

#[test]
fn opens_the_connection_again_when_the_site_closes_it() {
    let Some(kit) = kit("close") else { return };
    let card = card("close");
    let mut esp = Esp::new(kit.site.clone());
    esp.faults.close_after = Some(2);
    let mut o = run(&kit, &card, "install", esp, Pi::new(), 600.0, None);
    assert!(
        o.has("SERVICE FETCHED") && o.has("TO PI   DONE") && o.has("DONE."),
        "{}",
        o.screen
    );
    assert!(o.pi_cbb_is(&kit.pi_cbb));
    assert!(
        o.esp()
            .log
            .iter()
            .filter(|l| l.contains("CIPSTART"))
            .count()
            > 1
    );
    let _ = std::fs::remove_dir_all(&card);
}

#[test]
fn sends_to_the_pi_at_its_own_speed_when_the_tty_takes_no_other() {
    let Some(kit) = kit("nofast") else { return };
    let card = card("nofast");
    let mut pi = Pi::new();
    pi.fast = false;
    let mut o = run(
        &kit,
        &card,
        "install",
        Esp::new(kit.site.clone()),
        pi,
        600.0,
        None,
    );
    assert!(o.has("TO PI   DONE") && o.has("DONE."), "{}", o.screen);
    assert!(o.pi_cbb_is(&kit.pi_cbb));
    let _ = std::fs::remove_dir_all(&card);
}

#[test]
fn stops_on_space_and_goes_on_from_there() {
    let Some(kit) = kit("space") else { return };
    let card = card("space");
    // SPACE while the site is asked for the first file.
    let o = run(
        &kit,
        &card,
        "install",
        Esp::new(kit.site.clone()),
        Pi::new(),
        120.0,
        Some(1.0),
    );
    assert!(o.has("STOPPED"), "{}", o.screen);
    assert_eq!(o.taken(), 0);
    let o = run(
        &kit,
        &card,
        "install",
        Esp::new(kit.site.clone()),
        Pi::new(),
        300.0,
        None,
    );
    assert!(o.has("DONE."), "{}", o.screen);
    let _ = std::fs::remove_dir_all(&card);
}

impl Outcome {
    fn pi_cbb_is(&mut self, want: &[u8]) -> bool {
        self.pi().received == want
    }
}

/// Runs .cbb ARGS that needs no key, until it ends.
fn run_plain(kit: &Kit, args: &str, pi: Pi) -> Run {
    run_with(kit, args, Esp::new(kit.site.clone()), pi)
}

/// The same with this ESP, and CBB.DRV on the card.
fn run_with(kit: &Kit, args: &str, esp: Esp, pi: Pi) -> Run {
    // Tests run at once, some with the same arguments: a card each.
    static CARDS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = CARDS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let card = card(&format!("plain-{}-{n}", args.replace(' ', "-")));
    std::fs::copy(&kit.dot, card.join("cbb/CBB")).unwrap();
    std::fs::copy(kit.site.join("CBB.DRV"), card.join("cbb/CBB.DRV")).unwrap();
    let run = run_on(kit, &card, args, esp, pi, Vec::new());
    let _ = std::fs::remove_dir_all(&card);
    run
}

/// Runs .cbb ARGS on this card, with these keys, until it ends.
fn run_on(kit: &Kit, card: &Path, args: &str, esp: Esp, pi: Pi, keys: Vec<Key>) -> Run {
    run_after(kit, card, args, esp, pi, keys, |_| {})
}

/// The same, on a Next that `before` sets up (a driver installed before).
fn run_after(
    kit: &Kit,
    card: &Path,
    args: &str,
    esp: Esp,
    pi: Pi,
    keys: Vec<Key>,
    before: impl FnOnce(&mut Run),
) -> Run {
    if !args.starts_with("install")
        && !args.starts_with("update")
        && !card.join("cbb/CBB.OVL").exists()
    {
        std::fs::copy(kit.site.join("CBB.OVL"), card.join("cbb/CBB.OVL")).unwrap();
    }
    let mut run = Run::new(&kit.dot, card, args, Box::new(esp), Box::new(pi));
    run.hw.keys = keys;
    before(&mut run);
    let earlier = run.hw.drivers.len();
    let table = kit
        .map
        .lines()
        .find(|l| l.starts_with("__z_page_table "))
        .expect("__z_page_table");
    run.page_table =
        u16::from_str_radix(table.split('$').nth(1).unwrap().get(..4).unwrap(), 16).unwrap();
    run.overlay_logical = kit.pages.clone();
    let mut t = 0;
    while !run.done && t < 60 {
        run.run(1.0);
        t += 1;
    }
    assert!(
        run.done,
        ".cbb {args} did not end:\n{}",
        run.hw.screen_text()
    );
    // Outside the install screen, the ROM may scroll, as for any command.
    let breaches: Vec<String> = run
        .hw
        .breaches
        .iter()
        .filter(|b| !b.what.contains("scroll"))
        .map(|b| format!("{:#06x}: {}", b.pc, b.what))
        .collect();
    assert!(breaches.is_empty(), "breaches:\n{}", breaches.join("\n"));
    // Only an installed driver keeps its bank.
    assert_eq!(
        run.hw.ours.iter().filter(|&&p| p).count(),
        run.hw.drivers.len() - earlier,
        "pages still taken"
    );
    run
}

#[test]
fn shows_the_usage() {
    let Some(kit) = kit("usage") else { return };
    let run = run_plain(&kit, "", Pi::new());
    let s = run.hw.screen_text();
    // Two columns in 32, every line whole, and no "scroll?".
    assert!(s.contains("|install       fetch the rest"), "{s}");
    assert!(s.contains("|              or cbb pair CODE"), "{s}");
    assert!(s.contains("|leave         leave the group"), "{s}");
    assert!(!s.contains("scroll?"), "{s}");
}

#[test]
fn says_when_the_pi_does_not_answer_a_paste() {
    let Some(kit) = kit("paste") else { return };
    let mut pi = Pi::new();
    pi.answers = false;
    let run = run_plain(&kit, "paste", pi);
    let s = run.hw.screen_text();
    assert!(s.to_uppercase().contains("CBB:"), "{s}");
}

#[test]
fn finds_a_computer_of_the_group_for_the_network() {
    let Some(kit) = kit("find") else { return };
    let mut esp = Esp::new(kit.site.clone());
    esp.members = vec![
        ("192.168.0.50".into(), 8764, "r=lite".into()),
        ("192.168.0.60".into(), 8764, "r=phone".into()),
        ("192.168.0.175".into(), 8770, String::new()),
    ];
    let mut run = run_with(&kit, "net on", esp, Pi::new());
    let s = run.hw.screen_text();
    assert!(s.contains("192.168.0.175:8770"), "{s}");
    let pi: &mut Pi = run.hw.pi.peer.as_any().downcast_mut().unwrap();
    assert!(
        pi.log
            .iter()
            .any(|l| l.contains("next link -to 192.168.0.175:8770 -serve 8764:8764 ")),
        "{:?}",
        pi.log
    );
    let esp: &mut Esp = run.hw.esp.peer.as_any().downcast_mut().unwrap();
    assert!(esp.log.iter().any(|l| l.contains("AT+CIPDINFO=0")));
}

#[test]
fn says_when_no_computer_answers() {
    let Some(kit) = kit("nofind") else { return };
    let mut esp = Esp::new(kit.site.clone());
    esp.members = vec![("192.168.0.50".into(), 8764, "r=lite".into())];
    let run = run_with(&kit, "net on", esp, Pi::new());
    let s = run.hw.screen_text().to_uppercase();
    assert!(s.contains("FOUND NO COMPUTER"), "{s}");
}

/// A card as .cbb install and .cbb net on leave it, and a Pi with its cbb.
fn installed(kit: &Kit, name: &str) -> (PathBuf, Pi) {
    let card = card(name);
    std::fs::copy(&kit.dot, card.join("cbb/CBB")).unwrap();
    std::fs::copy(kit.site.join("CBB.DRV"), card.join("cbb/CBB.DRV")).unwrap();
    std::fs::write(card.join("cbb/NET.CFG"), "-serve 8764:8764").unwrap();
    let mut pi = Pi::new();
    pi.cbb_sha = Some(sha256::hex(&kit.pi_cbb));
    (card, pi)
}

#[test]
fn uninstalls_everything_after_y() {
    let Some(kit) = kit("uninstall") else { return };
    let (card, pi) = installed(&kit, "uninstall");
    // Y: the half-row 0xDF, bit 4.
    let y = vec![Key {
        from: 500_000,
        until: 800_000,
        row: 0xDF,
        bit: 4,
    }];
    let mut run = run_on(&kit, &card, "uninstall", Esp::new(kit.site.clone()), pi, y);
    let s = run.hw.screen_text().to_uppercase();
    assert!(
        s.contains("THE PI'S CBB IS REMOVED") && s.contains("ERASE \"/CBB/CBB\""),
        "{s}"
    );
    let pi: &mut Pi = run.hw.pi.peer.as_any().downcast_mut().unwrap();
    assert!(pi.cbb_sha.is_none(), "{:?}", pi.log);
    // Only the CBB that runs, which NextZXOS keeps.
    let left: Vec<_> = std::fs::read_dir(card.join("cbb"))
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    assert_eq!(left, ["CBB"]);
    let _ = std::fs::remove_dir_all(&card);
}

/// A +3DOS BASIC file: its header, then the lines and the variables.
fn plus3_basic(lines: &[(u16, &[u8])], vars: &[u8], line: u16) -> Vec<u8> {
    let mut prog = Vec::new();
    for (n, text) in lines {
        prog.extend_from_slice(&n.to_be_bytes());
        prog.extend_from_slice(&(text.len() as u16 + 1).to_le_bytes());
        prog.extend_from_slice(text);
        prog.push(13);
    }
    let plen = prog.len() as u16;
    prog.extend_from_slice(vars);
    let mut f = vec![0u8; 128];
    f[..10].copy_from_slice(b"PLUS3DOS\x1A\x01");
    f[11..15].copy_from_slice(&(128 + prog.len() as u32).to_le_bytes());
    f[16..18].copy_from_slice(&(prog.len() as u16).to_le_bytes());
    f[18..20].copy_from_slice(&line.to_le_bytes());
    f[20..22].copy_from_slice(&plen.to_le_bytes());
    f[127] = f[..127].iter().fold(0u8, |a, &b| a.wrapping_add(b));
    f.extend_from_slice(&prog);
    f
}

/// .cbb install puts .cbb net on last in the user's AUTOEXEC.BAS, before
/// its variables, and .cbb uninstall takes it out again, leaving the file
/// as it was.
#[test]
fn starts_the_network_from_autoexec() {
    let Some(kit) = kit("autoexec") else { return };
    let card = card("autoexec");
    let user: &[(u16, &[u8])] = &[(10, b"\xF5\"hello\""), (20, b"\xF5\"world\"")];
    let vars = b"\x80";
    let before = plus3_basic(user, vars, 10);
    let ax = card.join("nextzxos/AUTOEXEC.BAS");
    std::fs::write(&ax, &before).unwrap();
    let mut pi = Pi::new();
    pi.in_group = true;
    run(
        &kit,
        &card,
        "install",
        Esp::new(kit.site.clone()),
        pi,
        300.0,
        None,
    );
    let mut ours = user.to_vec();
    ours.push((30, b".cbb net on"));
    assert_eq!(std::fs::read(&ax).unwrap(), plus3_basic(&ours, vars, 10));
    let y = vec![Key {
        from: 500_000,
        until: 800_000,
        row: 0xDF,
        bit: 4,
    }];
    let mut pi = Pi::new();
    pi.cbb_sha = Some(sha256::hex(&kit.pi_cbb));
    run_on(&kit, &card, "uninstall", Esp::new(kit.site.clone()), pi, y);
    assert_eq!(std::fs::read(&ax).unwrap(), before);
    let _ = std::fs::remove_dir_all(&card);
}

/// CBB in C:/DOT, as .cbb from anywhere: /cbb goes, and C:/DOT/CBB is the
/// user's to erase.
#[test]
fn uninstalls_from_dot() {
    let Some(kit) = kit("uninstalldot") else {
        return;
    };
    let (card, pi) = installed(&kit, "uninstalldot");
    std::fs::rename(card.join("cbb/CBB"), card.join("dot/CBB")).unwrap();
    let y = vec![Key {
        from: 500_000,
        until: 800_000,
        row: 0xDF,
        bit: 4,
    }];
    let run = run_after(
        &kit,
        &card,
        "uninstall",
        Esp::new(kit.site.clone()),
        pi,
        y,
        |run| {
            run.hw.running = "c:/dot/CBB".into();
        },
    );
    let s = run.hw.screen_text();
    assert!(
        s.contains("C:/DOT/CBB stays") && s.contains("ERASE \"C:/DOT/CBB\""),
        "{s}"
    );
    assert!(!card.join("cbb").exists());
    assert!(card.join("dot/CBB").exists());
    let _ = std::fs::remove_dir_all(&card);
}

#[test]
fn keeps_everything_without_y() {
    let Some(kit) = kit("keep") else { return };
    let (card, pi) = installed(&kit, "keep");
    let n = vec![Key {
        from: 500_000,
        until: 800_000,
        row: 0x7F,
        bit: 3,
    }];
    let mut run = run_on(&kit, &card, "uninstall", Esp::new(kit.site.clone()), pi, n);
    let s = run.hw.screen_text().to_uppercase();
    assert!(s.contains("NOTHING REMOVED"), "{s}");
    let pi: &mut Pi = run.hw.pi.peer.as_any().downcast_mut().unwrap();
    assert!(pi.cbb_sha.is_some());
    assert!(card.join("cbb/CBB.DRV").exists() && card.join("cbb/NET.CFG").exists());
    let _ = std::fs::remove_dir_all(&card);
}

#[test]
fn finds_a_computer_after_the_network_ran() {
    let Some(kit) = kit("findmux") else { return };
    let mut esp = Esp::new(kit.site.clone());
    esp.mux = true;
    esp.server = true;
    esp.members = vec![("192.168.0.175".into(), 8764, String::new())];
    let run = run_with(&kit, "net on", esp, Pi::new());
    let s = run.hw.screen_text();
    assert!(s.contains("192.168.0.175:8764"), "{s}");
}

#[test]
fn installs_after_the_network_ran() {
    let Some(kit) = kit("installmux") else { return };
    let card = card("installmux");
    let mut esp = Esp::new(kit.site.clone());
    esp.mux = true;
    esp.server = true;
    let mut o = run(&kit, &card, "install", esp, Pi::new(), 600.0, None);
    assert!(o.has("DONE."), "{}", o.screen);
    assert!(o.esp().log.iter().any(|l| l.contains("AT+RST")));
    let _ = std::fs::remove_dir_all(&card);
}

#[test]
fn joins_with_a_computers_code() {
    let Some(kit) = kit("paircode") else { return };
    let mut esp = Esp::new(kit.site.clone());
    // The VM answers first, but only the Mac's cbb pair has its window open.
    esp.members = vec![
        ("192.168.0.177".into(), 8764, String::new()),
        ("192.168.0.175".into(), 8764, "p=1".into()),
    ];
    let mut run = run_with(&kit, "pair 123-456", esp, Pi::new());
    let pi: &mut Pi = run.hw.pi.peer.as_any().downcast_mut().unwrap();
    assert!(
        pi.log.iter().any(|l| l.contains("next link -to 192.168.0.175:8764 -serve 8764:8764 -join 123-456 ")),
        "{:?}",
        pi.log
    );
}

#[test]
fn finds_a_computer_with_a_client_left_on_the_server() {
    let Some(kit) = kit("findclient") else { return };
    let mut esp = Esp::new(kit.site.clone());
    // After .cbb net off a computer still holds a connection to the
    // server, and the ESP refuses AT+CIPMUX until it restarts.
    esp.mux = true;
    esp.server = true;
    esp.connected = true;
    esp.members = vec![("192.168.0.175".into(), 8764, String::new())];
    let run = run_with(&kit, "net on", esp, Pi::new());
    let s = run.hw.screen_text();
    assert!(s.contains("192.168.0.175:8764"), "{s}");
}

#[test]
fn pairs_while_the_network_runs() {
    let Some(kit) = kit("pairnet") else { return };
    let (card, pi) = installed(&kit, "pairnet");
    let mut esp = Esp::new(kit.site.clone());
    esp.mux = true;
    esp.server = true;
    esp.members = vec![("192.168.0.175".into(), 8764, "p=1".into())];
    let mut run = run_after(&kit, &card, "pair 123-456", esp, pi, Vec::new(), |run| {
        run.hw.drivers.push((124, vec![0; 512]));
        run.hw.net = true;
    });
    // The played Pi has no link: it is asked for, after the network stopped.
    let s = run.hw.screen_text();
    assert!(
        s.contains("The network stopped.") && s.contains("Found 192.168.0.175:8764"),
        "{s}"
    );
    let pi: &mut Pi = run.hw.pi.peer.as_any().downcast_mut().unwrap();
    assert!(
        pi.log.iter().any(|l| l.contains("-join 123-456 ")),
        "{:?}",
        pi.log
    );
    let _ = std::fs::remove_dir_all(&card);
}

#[test]
fn says_when_the_pi_is_in_a_group_already() {
    let Some(kit) = kit("pairin") else { return };
    let mut pi = Pi::new();
    pi.in_group = true;
    let mut run = run_with(&kit, "pair 123-456", Esp::new(kit.site.clone()), pi);
    let s = run.hw.screen_text();
    assert!(s.contains("already: .cbb leave first"), "{s}");
    let pi: &mut Pi = run.hw.pi.peer.as_any().downcast_mut().unwrap();
    assert!(
        !pi.log.iter().any(|l| l.contains("next pair")),
        "{:?}",
        pi.log
    );
}

#[test]
fn leaves_the_group_after_y() {
    let Some(kit) = kit("leave") else { return };
    let (card, mut pi) = installed(&kit, "leave");
    pi.in_group = true;
    // CAPS SHIFT first, then the Y with it: still yes.
    let y = vec![
        Key {
            from: 3_000_000,
            until: 3_600_000,
            row: 0xFE,
            bit: 0,
        },
        Key {
            from: 3_200_000,
            until: 3_500_000,
            row: 0xDF,
            bit: 4,
        },
    ];
    let mut run = run_on(&kit, &card, "leave", Esp::new(kit.site.clone()), pi, y);
    let s = run.hw.screen_text();
    assert!(s.contains("Left. Remove the Next"), "{s}");
    let pi: &mut Pi = run.hw.pi.peer.as_any().downcast_mut().unwrap();
    // Only the group goes: the Pi's cbb and the card's files stay.
    assert!(!pi.in_group && pi.cbb_sha.is_some(), "{:?}", pi.log);
    assert!(card.join("cbb/NET.CFG").exists() || card.join("cbb/PASTE.CFG").exists());
    let _ = std::fs::remove_dir_all(&card);
}

#[test]
fn says_when_there_is_no_group_to_leave() {
    let Some(kit) = kit("leavenone") else { return };
    let (card, pi) = installed(&kit, "leavenone");
    let mut run = run_on(
        &kit,
        &card,
        "leave",
        Esp::new(kit.site.clone()),
        pi,
        Vec::new(),
    );
    let s = run.hw.screen_text();
    assert!(s.contains("nothing to leave") && !s.contains("y/n"), "{s}");
    let pi: &mut Pi = run.hw.pi.peer.as_any().downcast_mut().unwrap();
    assert!(!pi.log.iter().any(|l| l.contains("rm -rf")), "{:?}", pi.log);
    let _ = std::fs::remove_dir_all(&card);
}

#[test]
fn turns_remote_paste_off_for_the_link() {
    let Some(kit) = kit("pasteoff") else { return };
    let (card, _) = installed(&kit, "pasteoff");
    let run = run_on(
        &kit,
        &card,
        "paste-receive off",
        Esp::new(kit.site.clone()),
        Pi::new(),
        Vec::new(),
    );
    assert!(
        run.hw.screen_text().contains("Remote paste off"),
        "{}",
        run.hw.screen_text()
    );
    assert_eq!(
        std::fs::read_to_string(card.join("cbb/PASTE.CFG")).unwrap(),
        "off"
    );
    let mut esp = Esp::new(kit.site.clone());
    esp.members = vec![("192.168.0.175".into(), 8764, String::new())];
    let mut run = run_on(&kit, &card, "net on", esp, Pi::new(), Vec::new());
    let pi: &mut Pi = run.hw.pi.peer.as_any().downcast_mut().unwrap();
    assert!(
        pi.log
            .iter()
            .any(|l| l.contains("-serve 8764:8764 -paste off -log")),
        "{:?}",
        pi.log
    );
    // The link takes the setting once: the next start leaves the Pi's own,
    // which an admin's paste-off may have changed since.
    assert!(!card.join("cbb/PASTE.CFG").exists());
    let mut esp = Esp::new(kit.site.clone());
    esp.members = vec![("192.168.0.175".into(), 8764, String::new())];
    let mut run = run_on(&kit, &card, "net on", esp, Pi::new(), Vec::new());
    let pi: &mut Pi = run.hw.pi.peer.as_any().downcast_mut().unwrap();
    assert!(
        pi.log.iter().any(|l| l.contains("-serve 8764:8764 -log"))
            && !pi.log.iter().any(|l| l.contains("-paste")),
        "{:?}",
        pi.log
    );
    let run = run_on(
        &kit,
        &card,
        "paste-receive on -x",
        Esp::new(kit.site.clone()),
        Pi::new(),
        Vec::new(),
    );
    assert!(
        run.hw.screen_text().contains("paste-receive"),
        "{}",
        run.hw.screen_text()
    );
    // A wrong command writes no setting.
    assert!(!card.join("cbb/PASTE.CFG").exists());
    let _ = std::fs::remove_dir_all(&card);
}

#[test]
fn sends_text_while_the_network_runs() {
    let Some(kit) = kit("textnet") else { return };
    let (card, pi) = installed(&kit, "textnet");
    let mut esp = Esp::new(kit.site.clone());
    esp.members = vec![("192.168.0.175".into(), 8764, String::new())];
    let mut run = run_after(
        &kit,
        &card,
        "text Hello from Next",
        esp,
        pi,
        Vec::new(),
        |run| {
            run.hw.drivers.push((124, vec![0; 512]));
            run.hw.net = true;
        },
    );
    // The network stops for the Pi's shell, and starts again after.
    let s = run.hw.screen_text();
    assert!(
        s.contains("The network stopped.") && s.contains("Found 192.168.0.175:8764"),
        "{s}"
    );
    let pi: &mut Pi = run.hw.pi.peer.as_any().downcast_mut().unwrap();
    let copy = pi
        .log
        .iter()
        .position(|l| l.contains("next copy"))
        .unwrap_or_else(|| panic!("{:?}", pi.log));
    let link = pi
        .log
        .iter()
        .position(|l| l.contains("next link"))
        .unwrap_or_else(|| panic!("{:?}", pi.log));
    assert!(copy < link, "{:?}", pi.log);
    assert_eq!(pi.copied, b"Hello from Next");
    let _ = std::fs::remove_dir_all(&card);
}

/// .cbb ARGS with the network running and a driver that carries the
/// commands (cbb.drv 0.2): the network goes on.
fn through_the_driver(name: &str, args: &str) -> Option<Run> {
    let kit = kit(name)?;
    let (card, pi) = installed(&kit, name);
    let run = run_after(
        &kit,
        &card,
        args,
        Esp::new(kit.site.clone()),
        pi,
        Vec::new(),
        |run| {
            run.hw.drivers.push((124, vec![0; 512]));
            run.hw.net = true;
            run.hw.via = true;
        },
    );
    let _ = std::fs::remove_dir_all(&card);
    assert!(run.hw.net, "the network stopped:\n{}", run.hw.screen_text());
    assert!(
        !run.hw.screen_text().contains("The network stopped."),
        "{}",
        run.hw.screen_text()
    );
    Some(run)
}

#[test]
fn sends_text_through_the_driver() {
    let Some(mut run) = through_the_driver("textvia", "text Hello from Next") else {
        return;
    };
    let s = run.hw.screen_text();
    assert!(s.contains("15 bytes sent to the group"), "{s}");
    let sent = String::from_utf8_lossy(&run.hw.via_sent).to_string();
    assert!(sent.contains("cbb next copy 15 "), "{sent:?}");
    let pi: &mut Pi = run.hw.pi.peer.as_any().downcast_mut().unwrap();
    assert_eq!(pi.copied, b"Hello from Next");
}

#[test]
fn pastes_through_the_driver() {
    let Some(run) = through_the_driver("pastevia", "paste") else {
        return;
    };
    let s = run.hw.screen_text();
    assert!(s.contains("Hello from the group"), "{s}");
}

/// After the first install, a Pi in no group goes on to pair at once: the
/// QR code's command runs on the Pi once the install's screen has its key.
#[test]
fn installs_then_pairs() {
    let Some(kit) = kit("thenpair") else { return };
    let (card, pi) = installed(&kit, "thenpair");
    std::fs::copy(kit.site.join("CBB.OVL"), card.join("cbb/CBB.OVL")).unwrap();
    let keys = (0..6)
        .map(|i| Key {
            from: 8_000_000 + i * 5_000_000,
            until: 8_300_000 + i * 5_000_000,
            row: 0xBF,
            bit: 0,
        })
        .collect();
    let mut run = run_on(&kit, &card, "install", Esp::new(kit.site.clone()), pi, keys);
    let pi: &mut Pi = run.hw.pi.peer.as_any().downcast_mut().unwrap();
    let probe = pi
        .log
        .iter()
        .position(|l| l.contains("cbb-state/identity.json"));
    let pair = pi.log.iter().position(|l| l.contains("next pair -addr"));
    assert!(probe.is_some() && pair > probe, "{:?}", pi.log);
    let _ = std::fs::remove_dir_all(&card);
}

/// .cbb update with a newer CBB on the site fetches it next to this one
/// in C:/DOT, where .cbb runs it from anywhere, then closes its own file,
/// which NextZXOS keeps open, and puts the new one in its place; the
/// network, if it ran, is left to the new CBB.
#[test]
fn updates_itself_in_dot() {
    let Some(kit) = kit("newerdot") else { return };
    let (card, pi) = installed(&kit, "newerdot");
    let (newer, list) = newer_cbb(&kit);
    sign_list(&kit.site, &list);
    std::fs::copy(&kit.dot, card.join("dot/CBB")).unwrap();
    let o = run(
        &kit,
        &card,
        "update",
        Esp::new(kit.site.clone()),
        pi,
        120.0,
        None,
    );
    assert!(o.has("CBB AND ITS FILES ARE NEW"), "{}", o.screen);
    // The new CBB and its CBB.OVL on one bar, their sizes summed.
    assert!(o.has("64K OF    64K"), "{}", o.screen);
    assert_eq!(std::fs::read(card.join("dot/CBB")).unwrap(), newer);
    assert!(!card.join("dot/CBB.NEW").exists());
    let _ = std::fs::remove_dir_all(&card);
}

/// .cbb update takes a newer CBB only from a list the Pi's cbb checked:
/// not from one the release keys did not sign, nor with a Pi that does not
/// answer or a cbb there too old to check it.
#[test]
fn updates_only_from_a_list_the_pi_checked() {
    let Some(kit) = kit("unsigned") else { return };
    let (newer, list) = newer_cbb(&kit);
    std::fs::write(kit.site.join("LIST"), &list).unwrap();
    for (case, signed, answers, checks, want) in [
        ("unsigned", false, true, true, "CBB REFUSED THE SI"),
        ("no pi", true, false, true, "THE PI DOES NOT ANSWER"),
        ("old pi", true, true, false, "CBB REFUSED THE SI"),
    ] {
        let first = if signed {
            SIGNED_OK
        } else {
            "{\"played\":\"forged\"}"
        };
        std::fs::write(kit.site.join("SIGNED"), format!("{first}\n{list}")).unwrap();
        let (card, mut pi) = installed(&kit, "unsigned");
        pi.answers = answers;
        pi.checks_lists = checks;
        std::fs::copy(&kit.dot, card.join("dot/CBB")).unwrap();
        let o = run(
            &kit,
            &card,
            "update",
            Esp::new(kit.site.clone()),
            pi,
            60.0,
            None,
        );
        assert!(o.has(want), "{case}: {}", o.screen);
        assert!(!o.has("CBB AND ITS FILES ARE NEW"), "{case}: {}", o.screen);
        assert_ne!(
            std::fs::read(card.join("dot/CBB")).unwrap(),
            newer,
            "{case}"
        );
        assert!(!card.join("dot/CBB.NEW").exists(), "{case}");
        let _ = std::fs::remove_dir_all(&card);
    }
}

/// A newer CBB on the site, and the list that names it: another one of the
/// same size will do, as it does not run here.
fn newer_cbb(kit: &Kit) -> (Vec<u8>, String) {
    let mut newer = std::fs::read(&kit.dot).unwrap();
    let last = newer.len() - 1;
    newer[last] ^= 0xFF;
    std::fs::write(kit.site.join("CBB"), &newer).unwrap();
    let list = std::fs::read_to_string(kit.site.join("LIST")).unwrap();
    let list: String = list
        .lines()
        .map(|l| match l.strip_prefix("CBB ") {
            Some(_) => format!(
                "CBB {} {:08x} {}\n",
                newer.len(),
                crc32(&newer),
                sha256::hex(&newer)
            ),
            None => format!("{l}\n"),
        })
        .collect();
    (newer, list)
}

/// .cbb update with nothing new says so.
#[test]
fn says_when_there_are_no_updates() {
    let Some(kit) = kit("noupdates") else { return };
    let (card, pi) = installed(&kit, "noupdates");
    std::fs::copy(kit.site.join("CBB.OVL"), card.join("cbb/CBB.OVL")).unwrap();
    let o = run(
        &kit,
        &card,
        "update",
        Esp::new(kit.site.clone()),
        pi,
        60.0,
        None,
    );
    assert!(o.has("NO UPDATES"), "{}", o.screen);
    let _ = std::fs::remove_dir_all(&card);
}

/// Just after power-on .cbb net on hands the line that starts the link to
/// the driver and returns at once, typing nothing to the Pi; until the
/// driver started it, the other commands wait, .cbb net says so and .cbb
/// net off ends it.
#[test]
fn leaves_the_start_to_the_driver_after_power_on() {
    let Some(kit) = kit("boot") else { return };
    let card = card("boot");
    std::fs::copy(&kit.dot, card.join("cbb/CBB")).unwrap();
    std::fs::copy(kit.site.join("CBB.DRV"), card.join("cbb/CBB.DRV")).unwrap();
    let mut esp = Esp::new(kit.site.clone());
    esp.members = vec![("192.168.0.175".into(), 8764, String::new())];
    let mut run = run_after(&kit, &card, "net on", esp, Pi::new(), Vec::new(), |run| {
        run.hw.os_write16(23672, 500); // ten seconds after power-on
    });
    let s = run.hw.screen_text().to_uppercase();
    assert!(s.contains("BACKGROUND"), "{s}");
    let line = String::from_utf8(run.hw.boot_line.clone()).unwrap();
    assert!(
        line.contains("next link -to 192.168.0.175:8764 -serve 8764:8764 -log /ram/link.log\n"),
        "{line:?}"
    );
    assert_eq!(run.hw.boot_state, 1);
    let pi: &mut Pi = run.hw.pi.peer.as_any().downcast_mut().unwrap();
    assert!(
        !pi.log.iter().any(|l| l.contains("next link")),
        "{:?}",
        pi.log
    );
    let waiting = |run: &mut Run| {
        run.hw.boot_state = 1;
        run.hw.drivers.push((124, Vec::new()));
    };
    for (args, says) in [
        ("text hello", "TRY AGAIN THEN"),
        ("net", "STARTS ONCE THE PI"),
        ("net off", "WILL NOT START"),
    ] {
        let run = run_after(
            &kit,
            &card,
            args,
            Esp::new(kit.site.clone()),
            Pi::new(),
            Vec::new(),
            waiting,
        );
        let s = run.hw.screen_text().to_uppercase().replace('\n', " ");
        assert!(s.contains(says), "{args}: {s}");
        if args == "net off" {
            assert_eq!(run.hw.boot_state, 0, "net off ends it");
        }
    }
    let _ = std::fs::remove_dir_all(&card);
}
