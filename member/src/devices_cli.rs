// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The command line's devices near this one, as the Go cbb's (cmd/cbb):
//! cbb keyboard, this computer as a Bluetooth keyboard, and cbb remote,
//! this device as a TV's remote. The service's peripherals (cbb-helper)
//! do the work; these say how they stand.

use std::io::Read;

use serde::Deserialize;

use crate::cli::usage;
use crate::control::{Header, Message};
use crate::error::{Context, Error, Result};
use crate::{Global, flag, request};

/// The Bluetooth keyboard in the status, as Go's control.Keyboard.
#[derive(Deserialize, Default)]
#[serde(default)]
struct Keyboard {
    on: bool,
    layout: String,
    rate: i64,
    pastes: bool,
    connected: bool,
    visible_until_ms: i64,
    problem: String,
}

/// A TV in the status, as Go's control.TV.
#[derive(Deserialize, Default)]
#[serde(default)]
struct Tv {
    name: String,
    kind: String,
    host: String,
    pastes: bool,
    pairing: bool,
}

/// A text to type: TEXT, or standard input without its last line ending.
fn text(rest: &[String]) -> Result<Vec<u8>> {
    if let [t] = rest {
        return Ok(t.as_bytes().to_vec());
    }
    let mut b = Vec::new();
    std::io::stdin().take(1 << 20).read_to_end(&mut b).context("cannot read standard input")?;
    if b.last() == Some(&b'\n') {
        b.pop();
    }
    Ok(b)
}

/// cbb keyboard: shows or sets this computer as a Bluetooth keyboard,
/// makes it visible to a new device, or types a text on the connected one,
/// as Go's cmdKeyboard.
pub(crate) fn keyboard(g: &Global, args: &[String]) -> Result<()> {
    const USE: &str = "cbb keyboard [on [-layout us|ru] [-rate N] [-pastes] | off | pair | type [TEXT]]";
    let (mut verb, args) = match args {
        [v, rest @ ..] if flag(v).is_none() => (v.clone(), rest),
        _ => (String::new(), args),
    };
    let (mut layout, mut rate, mut pastes) = (String::new(), 0i64, false);
    let mut rest: Vec<String> = Vec::new();
    if verb == "type" {
        rest = args.to_vec();
    } else {
        let mut it = args.iter();
        while let Some(a) = it.next() {
            match flag(a) {
                Some("layout") => layout = it.next().cloned().ok_or_else(|| usage(USE))?,
                Some("rate") => {
                    rate = it.next().and_then(|r| r.parse().ok()).ok_or_else(|| usage(USE))?;
                }
                Some("pastes") => pastes = true,
                Some(_) => return Err(usage(USE)),
                None => {
                    rest.push(a.clone());
                    rest.extend(it.by_ref().cloned());
                }
            }
        }
        if verb.is_empty() && !rest.is_empty() {
            verb = rest.remove(0);
        }
    }
    let mut h = Header { op: "keyboard".into(), name: verb.clone(), ..Default::default() };
    let mut payload = Vec::new();
    match verb.as_str() {
        "on" if rest.is_empty() => {
            let mut k = serde_json::Map::new();
            if !layout.is_empty() {
                k.insert("layout".into(), layout.into());
            }
            if rate != 0 {
                k.insert("rate".into(), rate.into());
            }
            if pastes {
                k.insert("pastes".into(), true.into());
            }
            h.keyboard = Some(serde_json::Value::Object(k));
        }
        _ if !layout.is_empty() || rate != 0 || pastes => return Err(usage(USE)),
        "" | "off" | "pair" if rest.is_empty() => {}
        "type" if rest.len() <= 1 => payload = text(&rest)?,
        _ => return Err(usage(USE)),
    }
    let m = request(g, &Message::new(h, payload))?;
    if verb == "type" {
        println!("Typed.");
        return Ok(());
    }
    let k = m
        .header
        .status
        .and_then(|s| s.keyboard)
        .and_then(|k| serde_json::from_value::<Keyboard>(k).ok())
        .ok_or_else(|| Error::msg("this computer cannot be a Bluetooth keyboard"))?;
    println!("{}", keyboard_line(&k));
    Ok(())
}

/// How the Bluetooth keyboard stands, as Go's keyboardLine.
fn keyboard_line(k: &Keyboard) -> String {
    if !k.on {
        return "The Bluetooth keyboard is off: cbb keyboard on makes this computer one, for a TV, a tablet or a computer near it.".into();
    }
    let mut line =
        format!("The Bluetooth keyboard is on, typing in the {} layout at {} characters a second", k.layout, k.rate);
    if k.pastes {
        line += "; remote pastes go to the device it types into";
    }
    if !k.problem.is_empty() {
        return format!("{line}.\nIt does not run: {}", k.problem);
    }
    if k.connected {
        line += ". A device is connected";
    } else {
        line += ". No device is connected; pair one with cbb keyboard pair, then connect it from the device";
    }
    if k.visible_until_ms != 0 {
        let t = crate::sys::local_time_at(k.visible_until_ms);
        line += &format!(". New devices find it until {:02}:{:02}:{:02}", t.hour, t.minute, t.second);
    }
    line + "."
}

/// What cbb remote takes, as Go's remoteUsage.
const REMOTE_USE: &str = "cbb remote [add [-appletv | -roku -consent] [-name NAME] ADDRESS | code < CODE | cancel | remove TV | pastes TV on|off | type [-tv TV] [TEXT]]";

/// cbb remote: shows the TVs this device is the remote of, pairs with one,
/// sends the remote pastes to one, or types a text on one, as Go's
/// cmdRemote. Flags may come before, between and after the words.
pub(crate) fn remote(g: &Global, args: &[String]) -> Result<()> {
    let (mut roku, mut apple, mut consent) = (false, false, false);
    let (mut name, mut tv) = (String::new(), String::new());
    let mut words: Vec<String> = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match flag(a) {
            Some("roku") => roku = true,
            Some("appletv") => apple = true,
            Some("consent") => consent = true,
            Some("name") => name = it.next().cloned().ok_or_else(|| usage(REMOTE_USE))?,
            Some("tv") => tv = it.next().cloned().ok_or_else(|| usage(REMOTE_USE))?,
            Some(_) => return Err(usage(REMOTE_USE)),
            None => words.push(a.clone()),
        }
    }
    let (verb, rest) = match words.split_first() {
        Some((v, r)) => (v.clone(), r.to_vec()),
        None => (String::new(), Vec::new()),
    };
    if verb != "add" && (roku || apple || consent || !name.is_empty())
        || verb != "type" && !tv.is_empty()
        || roku && apple
    {
        return Err(usage(REMOTE_USE));
    }
    let mut h = Header { op: "remote".into(), name: verb.clone(), ..Default::default() };
    let mut payload = Vec::new();
    match (verb.as_str(), rest.as_slice()) {
        ("", []) | ("cancel", []) => {}
        ("add", [address]) => {
            (h.address, h.new_name, h.consent) = (address.clone(), name, consent);
            if roku {
                h.value = "roku".into();
            } else if apple {
                h.value = "appletv".into();
            }
        }
        // The TV's code from standard input, never the command line, as
        // the other codes.
        ("code", []) => {
            use std::io::{IsTerminal, Write};
            if std::io::stdin().is_terminal() {
                print!("Code the TV shows: ");
                std::io::stdout().flush().ok();
            }
            let mut line = String::new();
            std::io::stdin().read_line(&mut line).context("cannot read the code")?;
            h.code = line.trim().to_string();
            if h.code.is_empty() {
                return Err(usage(REMOTE_USE));
            }
        }
        ("remove", [tv]) => h.device = tv.clone(),
        ("pastes", [tv, on]) if on == "on" || on == "off" => (h.device, h.value) = (tv.clone(), on.clone()),
        ("type", r) if r.len() <= 1 => {
            h.device = tv;
            payload = text(r)?;
        }
        _ => return Err(usage(REMOTE_USE)),
    }
    let m = request(g, &Message::new(h, payload))?;
    match verb.as_str() {
        "type" => println!("Typed."),
        "add" if apple => println!("The Apple TV shows a PIN now: run cbb remote code and type it within two minutes."),
        "add" if !roku => println!("The TV shows a code now: run cbb remote code and type it within two minutes."),
        _ => {
            let tvs: Vec<Tv> = m
                .header
                .status
                .map(|s| s.tvs.into_iter().filter_map(|t| serde_json::from_value(t).ok()).collect())
                .unwrap_or_default();
            print!("{}", remote_lines(&tvs));
        }
    }
    Ok(())
}

/// The TVs, one a line, as Go's remoteLines.
fn remote_lines(tvs: &[Tv]) -> String {
    if tvs.is_empty() {
        return "This device is the remote of no TV: cbb remote add ADDRESS pairs with an Android TV or a Google TV, cbb remote add -appletv ADDRESS with an Apple TV, cbb remote add -roku -consent ADDRESS takes a Roku.\n".into();
    }
    let mut w = String::new();
    for t in tvs {
        let kind = match t.kind.as_str() {
            "roku" => "Roku, plain HTTP",
            "appletv" => "Apple TV",
            _ => "Android TV",
        };
        if t.pairing {
            let what = if t.kind == "appletv" { "a PIN" } else { "a code" };
            w += &format!("Pairing with the TV at {}: it shows {what} for cbb remote code.\n", t.host);
        } else if t.pastes {
            w += &format!("{} ({kind}) at {}: remote pastes go to it.\n", t.name, t.host);
        } else {
            w += &format!("{} ({kind}) at {}.\n", t.name, t.host);
        }
    }
    w
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines() {
        let k = Keyboard { on: true, layout: "us".into(), rate: 20, connected: true, ..Default::default() };
        assert_eq!(
            keyboard_line(&k),
            "The Bluetooth keyboard is on, typing in the us layout at 20 characters a second. A device is connected."
        );
        let tvs = [
            Tv {
                name: "Living room".into(),
                kind: "androidtv".into(),
                host: "10.0.0.5".into(),
                pastes: true,
                ..Default::default()
            },
            Tv { kind: "appletv".into(), host: "10.0.0.6".into(), pairing: true, ..Default::default() },
        ];
        assert_eq!(
            remote_lines(&tvs),
            "Living room (Android TV) at 10.0.0.5: remote pastes go to it.\nPairing with the TV at 10.0.0.6: it shows a PIN for cbb remote code.\n"
        );
    }
}
