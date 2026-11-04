// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Runs `.cbb ARGS` on the Next played here and shows what happened:
//! cargo run --example run -- CBB SITE_DIR SECONDS ARGS...

use std::path::PathBuf;

use cbb_drvtest::next::Run;
use cbb_drvtest::peers::{Esp, Pi};

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let dot = PathBuf::from(&a[1]);
    let site = PathBuf::from(&a[2]);
    let secs: f64 = a[3].parse().unwrap();
    let args = a[4..].join(" ");
    let card = std::env::temp_dir().join(format!("cbb-card-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&card);
    std::fs::create_dir_all(card.join("cbb")).unwrap();
    std::fs::create_dir_all(card.join("dot")).unwrap();
    std::fs::copy(&dot, card.join("cbb/CBB")).unwrap();
    let esp = Box::new(Esp::new(site));
    let pi = Box::new(Pi::new());
    let mut run = Run::new(&dot, &card, &args, esp, pi);
    // The overlays' pages, from the map that zcc -m writes beside the file.
    let map = std::fs::read_to_string(std::env::var("CBB_MAP").expect("CBB_MAP: the map of CBB")).unwrap();
    let table = map.lines().find(|l| l.starts_with("__z_page_table ")).expect("__z_page_table");
    let hex = table.split('$').nth(1).unwrap().split(' ').next().unwrap();
    run.page_table = u16::from_str_radix(hex, 16).unwrap();
    run.overlay_logical = vec![13, 15, 17, 19];
    let mut shown = 0;
    let mut t = 0.0;
    while !run.done && t < secs {
        run.run(1.0);
        t += 1.0;
        let b = &run.hw.breaches;
        for x in &b[shown..] {
            println!("{:7.2}s BREACH at {:#06x}: {}", run.hw.now / 1e6, x.pc, x.what);
        }
        shown = b.len();
    }
    // A key for "press a key", as the user would.
    if !run.done && run.hw.screen_text().contains("PRESS A KEY") {
        let now = run.hw.now as u64;
        run.hw.keys.push(cbb_drvtest::next::Key { from: now + 500_000, until: now + 700_000, row: 0xBF, bit: 0 });
        run.run(5.0);
        for x in &run.hw.breaches[shown..] {
            println!("{:7.2}s BREACH at {:#06x}: {}", run.hw.now / 1e6, x.pc, x.what);
        }
    }
    if run.done && run.result.is_none() {
        for (pc, sp, p7) in run.trace.iter() {
            println!("trace {pc:04x} sp {sp:04x} mmu7 {p7}");
        }
    }
    println!("--- after {:.2}s, done {}, result {:?}", run.hw.now / 1e6, run.done, run.result);
    println!("{}", run.hw.screen_text());
    let kept: Vec<usize> = (0..run.hw.ours.len()).filter(|&p| run.hw.ours[p]).collect();
    println!("pages still taken: {kept:?}, drivers {:?}", run.hw.drivers.iter().map(|d| d.0).collect::<Vec<_>>());
    println!("border {}, frames {}, esp overflows {}, pi overflows {}", run.hw.border, run.frames, run.hw.esp.overflows, run.hw.pi.overflows);
    let mut sw: Vec<u16> = run.hw.screen_writes.iter().map(|w| w.0).collect();
    sw.sort();
    sw.dedup();
    println!("screen written from {} places: {:04x?}", sw.len(), &sw[..sw.len().min(40)]);
    if std::env::var("PRINTED").is_ok() {
        println!("printed: {}", run.hw.printed);
    }
    for l in run.hw.log.iter().take(80) {
        println!("log: {l}");
    }
    let _ = std::fs::remove_dir_all(&card);
}
