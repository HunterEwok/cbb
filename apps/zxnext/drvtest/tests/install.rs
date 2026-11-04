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
use cbb_drvtest::peers::{Esp, Pi};
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
            crc = if crc & 1 != 0 { crc >> 1 ^ 0xEDB8_8320 } else { crc >> 1 };
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
    let pinned = pins.split("PIN_PI_SHA256 \"").nth(1).expect("PIN_PI_SHA256").get(..64).unwrap().to_string();
    // The Pi's cbb that CBB was built with: PIBRIDGE, or CBB_PI.
    let pi_path = std::env::var("CBB_PI").map(PathBuf::from).unwrap_or_else(|_| build.join("PIBRIDGE"));
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
            n.strip_prefix("cbb_PAGE_")?.strip_suffix(".bin")?.parse().ok()
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
        ("cbb", pi_cbb.clone()),
    ] {
        std::fs::write(site.join(f), &data).unwrap();
        list += &format!("{f} {} {:08x} {}\n", data.len(), crc32(&data), sha256::hex(&data));
    }
    std::fs::write(site.join("LIST"), list).unwrap();
    Some(Kit { dot, map, pages, pi_cbb, site })
}

/// A card with /cbb/CBB, as `.http` leaves it.
fn card(name: &str) -> PathBuf {
    let card = std::env::temp_dir().join(format!("cbb-card-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&card);
    std::fs::create_dir_all(card.join("cbb")).unwrap();
    std::fs::create_dir_all(card.join("dot")).unwrap();
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
fn run(kit: &Kit, card: &Path, args: &str, esp: Esp, pi: Pi, secs: f64, space: Option<f64>) -> Outcome {
    std::fs::copy(&kit.dot, card.join("cbb/CBB")).unwrap();
    let mut run = Run::new(&kit.dot, card, args, Box::new(esp), Box::new(pi));
    let table = kit.map.lines().find(|l| l.starts_with("__z_page_table ")).expect("__z_page_table");
    run.page_table = u16::from_str_radix(table.split('$').nth(1).unwrap().get(..4).unwrap(), 16).unwrap();
    run.overlay_logical = kit.pages.clone();
    if let Some(t) = space {
        let t = (t * 1e6) as u64;
        run.hw.keys.push(Key { from: t, until: t + 300_000, row: 0x7F, bit: 0 });
    }
    let mut t = 0.0;
    while !run.done && t < secs && !run.hw.screen_text().contains("PRESS A KEY") {
        run.run(1.0);
        t += 1.0;
    }
    let screen = run.hw.screen_text();
    assert!(screen.contains("PRESS A KEY"), "no PRESS A KEY after {t}s:\n{screen}");
    let now = run.hw.now as u64;
    run.hw.keys.push(Key { from: now + 500_000, until: now + 700_000, row: 0xBF, bit: 0 });
    run.run(5.0);
    assert!(run.done, ".cbb did not end after the key:\n{}", run.hw.screen_text());
    // Back to BASIC with no error of its own, and no rule of NextZXOS's
    // broken on the way.
    assert_eq!(run.result.map(|r| r.0), Some(false), "an error to BASIC");
    let breaches: Vec<String> = run.hw.breaches.iter().map(|b| format!("{:#06x}: {}", b.pc, b.what)).collect();
    assert!(breaches.is_empty(), "breaches:\n{}", breaches.join("\n"));
    // BASIC's 3.5 MHz back, after 28 MHz while it ran.
    assert_eq!(run.hw.nr[0x07] & 3, 0, "the CPU's speed");
    Outcome { screen, run }
}

#[test]
fn installs_then_finds_all_current() {
    let Some(kit) = kit("clean") else { return };
    let card = card("clean");
    let mut o = run(&kit, &card, "install", Esp::new(kit.site.clone()), Pi::new(), 300.0, None);
    assert!(o.has("CBB.DRV FETCHED"), "{}", o.screen);
    assert!(o.has("SERVICE FETCHED") && o.has("TO PI   DONE"), "{}", o.screen);
    assert!(o.has("CBB.DRV IS INSTALLED.") && o.has("DONE."), "{}", o.screen);
    assert!(o.pi_cbb_is(&kit.pi_cbb));
    // The driver keeps its bank; every other page is back.
    assert_eq!(o.run.hw.drivers.len(), 1);
    assert_eq!(o.taken(), 1);
    assert_eq!(std::fs::read(card.join("cbb/CBB.DRV")).unwrap(), std::fs::read(kit.site.join("CBB.DRV")).unwrap());

    // Again, with the Pi's cbb in place: nothing to fetch or send.
    let mut pi = Pi::new();
    pi.cbb_sha = Some(sha256::hex(&kit.pi_cbb));
    let mut o = run(&kit, &card, "install", Esp::new(kit.site.clone()), pi, 120.0, None);
    assert!(o.has("CBB.DRV CURRENT") && o.has("SERVICE CURRENT") && o.has("TO PI   CURRENT") && o.has("DONE."), "{}", o.screen);
    assert!(o.pi().received.is_empty());
    assert!(!o.esp().log.iter().any(|l| l.contains("HTTP: GET /zxnext/cbb ")));
    let _ = std::fs::remove_dir_all(&card);
}

#[test]
fn says_when_the_site_has_not_the_files() {
    let Some(kit) = kit("404") else { return };
    let card = card("404");
    let mut esp = Esp::new(kit.site.clone());
    esp.faults.status = Some(404);
    let mut o = run(&kit, &card, "install", esp, Pi::new(), 120.0, None);
    assert!(o.has("CBB.DRV NOT THERE") && o.has("HAS NO SUCH FILE"), "{}", o.screen);
    // Once: trying again does not help.
    assert_eq!(o.esp().log.iter().filter(|l| l.contains("HTTP: ")).count(), 1);
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
    let o = run(&kit, &card, "install", Esp::new(kit.site.clone()), pi, 300.0, None);
    assert!(o.has("THE PI DOES NOT ANSWER") && o.has("TO PI   NO PI") && o.has("CBB.DRV IS INSTALLED."), "{}", o.screen);
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
    assert!(o.has("SERVICE FETCHED") && o.has("TO PI   DONE") && o.has("DONE."), "{}", o.screen);
    assert!(o.pi_cbb_is(&kit.pi_cbb));
    assert!(o.esp().log.iter().filter(|l| l.contains("CIPSTART")).count() > 1);
    let _ = std::fs::remove_dir_all(&card);
}

#[test]
fn stops_on_space_and_goes_on_from_there() {
    let Some(kit) = kit("space") else { return };
    let card = card("space");
    // SPACE while the site is asked for the first file.
    let o = run(&kit, &card, "install", Esp::new(kit.site.clone()), Pi::new(), 120.0, Some(1.0));
    assert!(o.has("STOPPED"), "{}", o.screen);
    assert_eq!(o.taken(), 0);
    let o = run(&kit, &card, "install", Esp::new(kit.site.clone()), Pi::new(), 300.0, None);
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
    let card = card(&format!("plain-{}", args.replace(' ', "-")));
    std::fs::copy(&kit.dot, card.join("cbb/CBB")).unwrap();
    let mut run = Run::new(&kit.dot, &card, args, Box::new(Esp::new(kit.site.clone())), Box::new(pi));
    let table = kit.map.lines().find(|l| l.starts_with("__z_page_table ")).expect("__z_page_table");
    run.page_table = u16::from_str_radix(table.split('$').nth(1).unwrap().get(..4).unwrap(), 16).unwrap();
    run.overlay_logical = kit.pages.clone();
    let mut t = 0;
    while !run.done && t < 60 {
        run.run(1.0);
        t += 1;
    }
    assert!(run.done, ".cbb {args} did not end:\n{}", run.hw.screen_text());
    // Outside the install screen, the ROM may scroll, as for any command.
    let breaches: Vec<String> = run
        .hw
        .breaches
        .iter()
        .filter(|b| !b.what.contains("scroll"))
        .map(|b| format!("{:#06x}: {}", b.pc, b.what))
        .collect();
    assert!(breaches.is_empty(), "breaches:\n{}", breaches.join("\n"));
    assert_eq!(run.hw.ours.iter().filter(|&&p| p).count(), 0, "pages still taken");
    let _ = std::fs::remove_dir_all(&card);
    run
}

#[test]
fn shows_the_usage() {
    let Some(kit) = kit("usage") else { return };
    let run = run_plain(&kit, "", Pi::new());
    let s = run.hw.screen_text();
    assert!(s.contains(".CBB INSTALL") || s.contains(".cbb install"), "{s}");
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
