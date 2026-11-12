// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The bug report (docs/core-api.md, "Bug reports"): when something in CBB
//! breaks and the user allows it, the app sends a short report to
//! `https://bug.cbb.tools/`. This module builds it: what broke, the
//! versions of CBB and the system, the device's model and CBB's own log,
//! each line filtered so that no clipboard text, key, code, invitation,
//! device name or address goes out. The report is sealed to the robot's
//! key (crate::seal: HPKE with X-Wing, HKDF-SHA256 and ChaCha20-Poly1305),
//! so the server keeps only what it cannot read; the robot opens it
//! elsewhere. Nothing names the user or the device: the report is
//! anonymous.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::Error;

/// Where the apps send a report.
pub const URL: &str = "https://bug.cbb.tools/";

/// The robot's public key for sealed messages (crate::seal), whose secret
/// stays off the internet-facing server; empty until it is made, and then
/// nothing is sent (`build` refuses).
pub const ROBOT_KEY_B64: &str = "";

/// The associated data every report is sealed with, so that a report is
/// never mistaken for another sealed message.
pub const AAD: &[u8] = b"cbb bug report v1";

/// The most log lines a report keeps, the newest.
pub const MAX_LINES: usize = 300;
/// The most bytes of a log line, and of a report's details.
pub const MAX_LINE: usize = 400;
pub const MAX_DETAILS: usize = 8 * 1024;
/// The most bytes of a short field (versions, model, the message).
pub const MAX_FIELD: usize = 256;
/// The most bytes of a report's JSON before it is sealed: the oldest log
/// lines go until it fits.
pub const MAX_REPORT: usize = 160 * 1024;
/// The most bytes of the body the app posts, `{"v", "fingerprint",
/// "version", "sealed"}` with the sealed report in base64: what the
/// server's limit, twice this, is checked against.
pub const MAX_POST: usize = 4 * (MAX_REPORT + crate::seal::OVERHEAD).div_ceil(3) + 512;

/// What the app tells about the break and itself.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Input {
    /// `panic` or `error`.
    pub kind: String,
    #[serde(default)]
    pub code: i64,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub message: String,
    #[serde(default)]
    pub details: String,
    /// `ios`, `android`, `aurora`, `mac`, `tray` or `cbb`.
    pub app: String,
    pub version: String,
    #[serde(default)]
    pub build: String,
    #[serde(default)]
    pub os: String,
    #[serde(default)]
    pub os_version: String,
    #[serde(default)]
    pub model: String,
    #[serde(default)]
    pub arch: String,
    /// CBB's log, oldest first.
    #[serde(default)]
    pub log: Vec<String>,
    /// Words that must not leave the device: the group's device names and
    /// the user's own, which the filter replaces.
    #[serde(default)]
    pub names: Vec<String>,
    /// The day of the break, Unix milliseconds; the report keeps the day
    /// only.
    #[serde(default)]
    pub now_ms: i64,
}

/// The report as it is sealed, and as "Technical details" shows it.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Report {
    pub v: u32,
    pub kind: String,
    pub code: i64,
    pub name: String,
    #[serde(rename = "where")]
    pub at: String,
    pub message: String,
    pub details: String,
    pub app: String,
    pub version: String,
    pub build: String,
    pub os: String,
    pub os_version: String,
    pub model: String,
    pub arch: String,
    pub day: String,
    pub log: Vec<String>,
}

/// A report ready to send: what it says, the fingerprint the robot and
/// the app count it by, and the body to post.
#[derive(Debug, Clone, Serialize)]
pub struct Built {
    pub report: Report,
    pub fingerprint: String,
    pub post: String,
}

/// The body posted to URL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Post {
    pub v: u32,
    pub fingerprint: String,
    pub version: String,
    pub sealed: String,
}

/// The first `max` bytes of s, cut at a character's boundary.
fn cut(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    s.get(..end).unwrap_or_default().to_string()
}

/// A character that a word of the filter is made of.
fn word_char(c: char) -> bool {
    c.is_alphanumeric() || matches!(c, '+' | '/' | '=' | '_' | '-' | '.' | ':' | '@' | '%' | '[' | ']')
}

/// What splits a word into the parts an address or a host name can hide
/// in: `peer=10.0.0.2:7300`, `https://10.0.0.2:7300/x`.
const PART_SPLIT: [char; 2] = ['=', '/'];

/// The keys of `key=value` whose value is a name that may not leave the
/// device.
const NAME_KEYS: [&str; 11] =
    ["ssid", "bssid", "essid", "wifi", "network", "host", "hostname", "device", "name", "user", "username"];

/// The endings of the home network's host names, which often carry the
/// owner's name (`dens-macbook.local`).
const LOCAL_HOSTS: [&str; 6] = [".local", ".lan", ".home", ".internal", ".home.arpa", ".localdomain"];

/// A host name of the home network, with a port or not.
fn local_host(w: &str) -> bool {
    let host = w.rsplit_once(':').filter(|(_, p)| p.bytes().all(|b| b.is_ascii_digit())).map_or(w, |(h, _)| h);
    let lower = host.to_ascii_lowercase();
    LOCAL_HOSTS.iter().any(|end| lower.len() > end.len() && lower.ends_with(end))
}

fn is_hex(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// An IPv4 address, with a port or not.
fn ipv4(w: &str) -> bool {
    let host = w.split(':').next().unwrap_or_default();
    let parts: Vec<&str> = host.split('.').collect();
    parts.len() == 4 && parts.iter().all(|p| !p.is_empty() && p.len() <= 3 && p.bytes().all(|b| b.is_ascii_digit()))
}

/// An IPv6 address, in brackets with a port or not.
fn ipv6(w: &str) -> bool {
    let w = w.trim_start_matches('[');
    let host = w.split(']').next().unwrap_or_default();
    // A link-local address names its interface after '%'.
    let host = host.split('%').next().unwrap_or_default();
    host.matches(':').count() >= 2
        && host.bytes().all(|b| b.is_ascii_hexdigit() || b == b':' || b == b'.')
        && host.bytes().any(|b| b.is_ascii_hexdigit())
}

/// A MAC address, with colons or dashes.
fn mac(w: &str) -> bool {
    let parts: Vec<&str> = w.split([':', '-']).collect();
    parts.len() == 6 && parts.iter().all(|p| p.len() == 2 && is_hex(p))
}

/// What a part of a word becomes when it is an address, a host name of
/// the home network, an e-mail address or a MAC address; None otherwise.
fn redact_place(core: &str) -> Option<&'static str> {
    if core.contains('@') && core.rsplit('@').next().is_some_and(|d| d.contains('.')) {
        return Some("<email>");
    }
    if ipv4(core) {
        return Some("<address>");
    }
    if mac(core) {
        return Some("<mac>");
    }
    if ipv6(core) {
        return Some("<address>");
    }
    if local_host(core) {
        return Some("<host>");
    }
    None
}

/// What a word of a log line becomes: itself, or with what may not leave
/// the device replaced.
fn redact_word(w: &str) -> Option<String> {
    if let Some(p) = redact_whole(w) {
        return Some(p.to_string());
    }
    // A name in `key=value`: a network's, a host's, a device's or a user's.
    if let Some((key, value)) = w.split_once('=')
        && !value.is_empty()
        && NAME_KEYS.contains(&key.to_ascii_lowercase().as_str())
    {
        return Some(alloc::format!("{key}=<name>"));
    }
    // An address or a host name inside a word: `peer=...`, a URL.
    if !w.contains(PART_SPLIT) {
        return None;
    }
    let mut out = String::new();
    let mut changed = false;
    let mut rest = w;
    loop {
        let (part, sep, next) = match rest.find(PART_SPLIT) {
            Some(i) => {
                let sep = rest.get(i..).and_then(|r| r.chars().next()).unwrap_or('/');
                (rest.get(..i).unwrap_or_default(), Some(sep), rest.get(i.saturating_add(1)..).unwrap_or_default())
            }
            None => (rest, None, ""),
        };
        let core = part.trim_end_matches(['.', ':', ',']);
        match redact_place(core) {
            Some(p) if !core.is_empty() => {
                out.push_str(p);
                changed = true;
            }
            _ => out.push_str(part),
        }
        match sep {
            Some(c) => out.push(c),
            None => break,
        }
        rest = next;
    }
    changed.then_some(out)
}

/// What a whole word becomes when it may not leave the device.
fn redact_whole(w: &str) -> Option<&'static str> {
    let core = w.trim_end_matches(['.', ':', ',']);
    // A word in another script than Latin is the user's text: the
    // programs log in English.
    if !core.is_ascii() {
        return Some("<text>");
    }
    if let Some(p) = redact_place(core) {
        return Some(p);
    }
    if core.len() >= 16 && is_hex(core) {
        return Some("<id>");
    }
    if core.len() >= 6 && core.bytes().all(|b| b.is_ascii_digit()) {
        return Some("<number>");
    }
    // Base64 of a key, a secret, an invitation or a copy: long, of the
    // base64 alphabets only, and mixing upper and lower case letters and
    // digits as random bytes do; a path or a word does not.
    let b64 = core.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'_' | b'-'));
    let mixed = core.bytes().any(|b| b.is_ascii_uppercase())
        && core.bytes().any(|b| b.is_ascii_lowercase())
        && core.bytes().any(|b| b.is_ascii_digit());
    if core.len() >= 20 && b64 && mixed {
        return Some("<data>");
    }
    None
}

/// The home folders in paths, whose next part is a user's name.
const HOMES: [&str; 3] = ["/home/", "/Users/", "\\Users\\"];

/// Replaces the user's name after a home folder.
fn redact_homes(s: &str) -> String {
    let mut out = s.to_string();
    for h in HOMES {
        let mut from = 0;
        while let Some(i) = out.get(from..).and_then(|r| r.find(h)) {
            let start = from.saturating_add(i).saturating_add(h.len());
            let rest = out.get(start..).unwrap_or_default();
            let end = rest.find(['/', '\\', ' ', '"', '\'']).unwrap_or(rest.len());
            if end == 0 || rest.get(..end) == Some("<user>") {
                from = start;
                continue;
            }
            out.replace_range(start..start.saturating_add(end), "<user>");
            from = start;
        }
    }
    out
}

/// A device's name as its host name: lower case, with a dash for each run
/// of anything but letters and digits (`Den's MacBook` is `den-s-macbook`).
fn slug(name: &str) -> String {
    let mut out = String::new();
    for c in name.chars().flat_map(char::to_lowercase) {
        if c.is_alphanumeric() {
            out.push(c);
        } else if !out.is_empty() && !out.ends_with('-') {
            out.push('-');
        }
    }
    out.trim_end_matches('-').to_string()
}

/// Whether two characters are the same letter in any case.
fn same_letter(a: char, b: char) -> bool {
    a == b || a.to_lowercase().eq(b.to_lowercase())
}

/// s with every occurrence of what, in any case, replaced by with.
fn replace_any_case(s: &str, what: &str, with: &str) -> String {
    let want: Vec<char> = what.chars().collect();
    let have: Vec<char> = s.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < have.len() {
        let end = i.saturating_add(want.len());
        let hit =
            !want.is_empty() && have.get(i..end).is_some_and(|w| w.iter().zip(&want).all(|(&a, &b)| same_letter(a, b)));
        if hit {
            out.push_str(with);
            i = end;
        } else {
            if let Some(&c) = have.get(i) {
                out.push(c);
            }
            i = i.saturating_add(1);
        }
    }
    out
}

/// The part of a panic's message that says what kind of break it was,
/// without the values the standard library puts in it: up to the first
/// `: ` (`called ... on an Err value: <the error>`), quote, or ` of `
/// before a backtick (`... of` and the text in backticks).
/// A message the program wrote itself (`panic!`, `expect`) may hold any
/// value, so only the standard library's own kinds are kept, and any other
/// is "a panic": its file and line say where it is.
pub fn panic_kind(what: &str) -> String {
    let mut end = what.len();
    for stop in [": ", "'", "\"", " of `", "\n"] {
        if let Some(i) = what.find(stop) {
            end = end.min(i);
        }
    }
    let kind = what.get(..end).unwrap_or_default().trim_end();
    if STD_PANICS.iter().any(|p| kind.starts_with(p)) { kind.to_string() } else { "a panic".to_string() }
}

/// The beginnings of the standard library's panic messages.
const STD_PANICS: [&str; 18] = [
    "called `Option::unwrap()`",
    "called `Option::expect()`",
    "called `Result::unwrap()`",
    "called `Result::unwrap_err()`",
    "index out of bounds",
    "attempt to ",
    "byte index ",
    "range end index ",
    "range start index ",
    "slice index ",
    "assertion failed",
    "assertion `left",
    "already borrowed",
    "already mutably borrowed",
    "capacity overflow",
    "explicit panic",
    "not yet implemented",
    "internal error: entered unreachable code",
];

/// A panic's details with only the kind of its message kept:
/// `panic: <message> at <file:line:col>[ in thread <name>]` becomes
/// `panic: <kind> at ...`. Details of another shape stay as they are.
fn panic_details(details: &str) -> String {
    let first = details.lines().next().unwrap_or_default();
    let Some(body) = first.strip_prefix("panic: ") else { return details.to_string() };
    let (what, at) = match body.rsplit_once(" at ") {
        Some((w, a)) => (w, alloc::format!(" at {a}")),
        None => (body, String::new()),
    };
    alloc::format!("panic: {}{at}", panic_kind(what))
}

/// A line of text with everything that may not leave the device replaced:
/// the given names, addresses, MAC addresses, IDs and hashes, long numbers
/// (codes), e-mail addresses, base64 data and the users' names in paths.
pub fn redact(line: &str, names: &[String]) -> String {
    let mut s = line.to_string();
    // Each name as it is and as a host name (`office-pc`), in any case.
    let mut forms: Vec<String> = Vec::new();
    for n in names.iter().filter(|n| n.chars().count() >= 2) {
        forms.push(n.clone());
        let slug = slug(n);
        if slug.chars().count() >= 2 && !forms.contains(&slug) {
            forms.push(slug);
        }
    }
    forms.sort_by_key(|n| core::cmp::Reverse(n.len()));
    for n in &forms {
        s = replace_any_case(&s, n, "<name>");
    }
    s = redact_homes(&s);
    let mut out = String::new();
    let mut word = String::new();
    let flush = |word: &mut String, out: &mut String| {
        if !word.is_empty() {
            match redact_word(word) {
                Some(r) => out.push_str(&r),
                None => out.push_str(word),
            }
            word.clear();
        }
    };
    for c in s.chars() {
        if word_char(c) {
            word.push(c);
        } else {
            flush(&mut word, &mut out);
            out.push(if c.is_control() { ' ' } else { c });
        }
    }
    flush(&mut word, &mut out);
    out
}

/// Where a panic's details say it broke: the `file:line:col` after the
/// last " at ", since the message itself may hold one.
fn where_of(details: &str) -> String {
    details
        .lines()
        .find_map(|l| l.rsplit_once(" at ").map(|(_, w)| w))
        .map(|w| w.split(' ').next().unwrap_or_default().to_string())
        .unwrap_or_default()
}

/// The fingerprint the app and the robot count a break by: the same
/// break in any version, on any device, has the same one. It hashes the
/// kind, the error's name, where it broke, and the first line of its
/// details with the numbers taken out.
pub fn fingerprint(kind: &str, name: &str, at: &str, details: &str) -> String {
    let first: String = details.lines().next().unwrap_or_default().chars().filter(|c| !c.is_ascii_digit()).collect();
    let mut h = Sha256::new();
    for part in ["cbb bug v1", kind, name, at, &first] {
        h.update(part.as_bytes());
        h.update([0]);
    }
    let d = h.finalize();
    let mut out = String::new();
    for b in d.iter().take(8) {
        out.push_str(&alloc::format!("{b:02x}"));
    }
    out
}

/// The day of ms, `YYYY-MM-DD` in UTC.
pub fn day(ms: i64) -> String {
    if ms <= 0 {
        return String::new();
    }
    // Days since 1970-01-01, then the civil date (Howard Hinnant's days
    // to civil algorithm).
    let z = ms.div_euclid(86_400_000).saturating_add(719_468);
    let era = z.div_euclid(146_097);
    let doe = z.saturating_sub(era.saturating_mul(146_097));
    let yoe = doe.saturating_sub(doe / 1460).saturating_add(doe / 36_524).saturating_sub(doe / 146_096).div_euclid(365);
    let y = yoe.saturating_add(era.saturating_mul(400));
    let doy = doe.saturating_sub(yoe.saturating_mul(365).saturating_add(yoe / 4).saturating_sub(yoe / 100));
    let mp = doy.saturating_mul(5).saturating_add(2) / 153;
    let d = doy.saturating_sub(mp.saturating_mul(153).saturating_add(2) / 5).saturating_add(1);
    let m = if mp < 10 { mp.saturating_add(3) } else { mp.saturating_sub(9) };
    let y = if m <= 2 { y.saturating_add(1) } else { y };
    alloc::format!("{y:04}-{m:02}-{d:02}")
}

/// The report of a break, filtered and cut to its limits.
pub fn report(i: &Input) -> Result<Report, Error> {
    if i.kind != "panic" && i.kind != "error" {
        return Err(Error::msg(alloc::format!("a report is of a panic or an error, not {:?}", i.kind)));
    }
    if !matches!(i.app.as_str(), "ios" | "android" | "aurora" | "mac" | "tray" | "cbb") {
        return Err(Error::msg(alloc::format!("a report names the app, not {:?}", i.app)));
    }
    let f = |s: &str| redact(&cut(s, MAX_FIELD), &i.names);
    // A panic's message may carry the values it broke on, the user's
    // text among them: only its kind and place go.
    let shaped = if i.kind == "panic" { panic_details(&i.details) } else { i.details.clone() };
    let details = redact(&cut(&shaped, MAX_DETAILS), &i.names);
    let at = redact(&where_of(&i.details), &i.names);
    let mut r = Report {
        v: 1,
        kind: i.kind.clone(),
        code: i.code,
        name: f(&i.name),
        at,
        message: f(&i.message),
        details,
        app: i.app.clone(),
        version: f(&i.version),
        build: f(&i.build),
        os: f(&i.os),
        os_version: f(&i.os_version),
        model: f(&i.model),
        arch: f(&i.arch),
        day: day(i.now_ms),
        log: Vec::new(),
    };
    let skip = i.log.len().saturating_sub(MAX_LINES);
    r.log = i.log.iter().skip(skip).map(|l| redact(&cut(l, MAX_LINE), &i.names)).collect();
    while serde_json::to_vec(&r).map_err(|_| Error::msg("a report does not encode"))?.len() > MAX_REPORT {
        if r.log.is_empty() {
            return Err(Error::msg("a report is too large without its log"));
        }
        r.log.remove(0);
    }
    Ok(r)
}

/// The robot's key, once it is made.
fn robot_key() -> Result<Vec<u8>, Error> {
    use base64::Engine as _;
    if ROBOT_KEY_B64.is_empty() {
        return Err(Error::msg("this build has no key to seal a bug report to"));
    }
    base64::engine::general_purpose::STANDARD
        .decode(ROBOT_KEY_B64)
        .map_err(|_| Error::msg("the robot's key does not decode"))
}

/// Builds the report and the body to post, sealed to key (the robot's,
/// from `build`).
pub fn build_for(i: &Input, key: &[u8]) -> Result<Built, Error> {
    use base64::Engine as _;
    let report = report(i)?;
    let fingerprint = fingerprint(&report.kind, &report.name, &report.at, &report.details);
    let plain = serde_json::to_vec(&report).map_err(|_| Error::msg("a report does not encode"))?;
    let sealed = crate::seal::seal(key, AAD, &plain)?;
    let post = Post {
        v: 1,
        fingerprint: fingerprint.clone(),
        version: report.version.clone(),
        sealed: base64::engine::general_purpose::STANDARD.encode(sealed),
    };
    let post = serde_json::to_string(&post).map_err(|_| Error::msg("a report does not encode"))?;
    if post.len() > MAX_POST {
        return Err(Error::msg("a report is larger than the server takes"));
    }
    Ok(Built { report, fingerprint, post })
}

/// Builds the report, sealed to the robot's key.
pub fn build(i: &Input) -> Result<Built, Error> {
    build_for(i, &robot_key()?)
}

/// Opens a posted report with the robot's secret: the robot's side.
pub fn open(secret: &[u8], post: &[u8]) -> Result<(Post, Report), Error> {
    use base64::Engine as _;
    let p: Post = serde_json::from_slice(post).map_err(|_| Error::msg("a posted report does not decode"))?;
    let sealed = base64::engine::general_purpose::STANDARD
        .decode(&p.sealed)
        .map_err(|_| Error::msg("a posted report's seal does not decode"))?;
    let plain = crate::seal::open(secret, AAD, &sealed)?;
    let r: Report = serde_json::from_slice(&plain).map_err(|_| Error::msg("a report does not decode"))?;
    Ok((p, r))
}

/// How many reports wait to be sent, at most, and for how long.
pub const MAX_QUEUED: usize = 5;
pub const QUEUE_MS: i64 = 7 * 24 * 60 * 60 * 1000;
/// How many sent reports the app remembers, the newest.
pub const MAX_SENT: usize = 200;

/// A report the app sent, or the robot says was fixed.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Sent {
    pub fingerprint: String,
    pub version: String,
    /// The version the robot said fixes it; empty when it did not say.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub fixed_in: String,
}

/// A report that could not be sent yet: the app tries again later.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Queued {
    pub fingerprint: String,
    pub version: String,
    pub post: String,
    pub at_ms: i64,
}

/// What the app keeps between reports, as the core gives it: which
/// reports went (one for each fingerprint and version), how many times
/// the user allowed one, whether always, and the reports waiting.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct State {
    pub sent: Vec<Sent>,
    pub allowed: u32,
    pub always: bool,
    pub queue: Vec<Queued>,
}

/// What the app does with a new report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    /// Ask the user ("Oops, something broke"), and send when allowed.
    Ask,
    /// Send without asking: the user allowed always.
    Send,
    /// Neither: this break was reported for this version already, or
    /// this build has no key to seal to.
    Skip,
}

impl State {
    /// The reports waiting, without those older than QUEUE_MS at now_ms.
    pub fn prune(&mut self, now_ms: i64) {
        self.queue.retain(|q| now_ms.saturating_sub(q.at_ms) <= QUEUE_MS);
        let extra = self.queue.len().saturating_sub(MAX_QUEUED);
        self.queue.drain(..extra);
        let extra = self.sent.len().saturating_sub(MAX_SENT);
        self.sent.drain(..extra);
    }

    /// Whether a report of fingerprint in version went or waits.
    fn known(&self, fingerprint: &str, version: &str) -> bool {
        self.sent.iter().any(|s| s.fingerprint == fingerprint && s.version == version)
            || self.queue.iter().any(|q| q.fingerprint == fingerprint && q.version == version)
    }

    /// The version that fixes fingerprint, as the robot said, if any.
    pub fn fixed_in(&self, fingerprint: &str) -> String {
        self.sent
            .iter()
            .rev()
            .find(|s| s.fingerprint == fingerprint && !s.fixed_in.is_empty())
            .map(|s| s.fixed_in.clone())
            .unwrap_or_default()
    }

    /// What to do with a report of fingerprint in version; sealed says
    /// whether it could be sealed.
    pub fn action(&self, fingerprint: &str, version: &str, sealed: bool) -> Action {
        if !sealed || self.known(fingerprint, version) {
            Action::Skip
        } else if self.always {
            Action::Send
        } else {
            Action::Ask
        }
    }

    /// Whether the dialog offers "Always allow": after the user allowed
    /// twice.
    pub fn offer_always(&self) -> bool {
        !self.always && self.allowed >= 2
    }

    /// The user allowed a report, and maybe always.
    pub fn allow(&mut self, always: bool) {
        self.allowed = self.allowed.saturating_add(1);
        self.always |= always;
    }

    /// A report was sent (ok), and the robot maybe said which version
    /// fixes it; or it could not be sent, and it waits with its post.
    pub fn sent(&mut self, q: Queued, ok: bool, fixed_in: &str, now_ms: i64) {
        self.queue.retain(|w| !(w.fingerprint == q.fingerprint && w.version == q.version));
        if ok {
            self.sent.retain(|s| !(s.fingerprint == q.fingerprint && s.version == q.version));
            self.sent.push(Sent { fingerprint: q.fingerprint, version: q.version, fixed_in: cut(fixed_in, MAX_FIELD) });
        } else if !q.post.is_empty() && q.post.len() <= MAX_POST {
            self.queue.push(Queued { at_ms: if q.at_ms > 0 { q.at_ms } else { now_ms }, ..q });
        }
        self.prune(now_ms);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input() -> Input {
        Input {
            kind: "panic".into(),
            code: 5,
            name: "panic".into(),
            message: "Something in CBB broke, and the request did nothing.".into(),
            details:
                "panic: index out of bounds: the len is 3 but the index is 7 at member/src/sync.rs:120:9 in thread node"
                    .into(),
            app: "ios".into(),
            version: "0.6.0".into(),
            build: "abc123".into(),
            os: "ios".into(),
            os_version: "18.1".into(),
            model: "iPhone15,2".into(),
            arch: "arm64".into(),
            log: alloc::vec!["member: started".into()],
            names: alloc::vec!["Den's MacBook".into(), "steamdeck".into()],
            now_ms: 1_762_646_400_000,
        }
    }

    /// What must never leave the device does not, in any field or line:
    /// clipboard texts are never logged, and the filter catches what a
    /// line might still carry.
    #[test]
    fn nothing_private_leaves() {
        let mut i = input();
        let private = [
            "connected to Den's MacBook at 192.168.0.175:8764",
            "peer steamdeck fd00:cbb::1a2b:3c4d dialed [fe80::1%eth0]:8764",
            "device 0123456789abcdef0123456789abcdef joined, mac 3c:22:fb:01:02:03",
            "pairing code 482913, invitation cbb1QmFzZTY0RGF0YUhlcmVXaXRoMTIzNDU2Nzg5MA",
            "key AAAAC3NzaC1lZDI1NTE5AAAAIK8m7pYqX3Rv9Lz2wN1sT4uV6yZ0aB5cD7eF9gH1jK2l",
            "wrote /Users/den/Library/cbb/state.json and /home/den/.config/cbb",
            "mail from den@example.org",
        ];
        i.log = private.iter().map(|s| s.to_string()).collect();
        i.details = "panic: at 10.0.0.2 failed at member/src/net.rs:7:3".into();
        let r = report(&i).unwrap();
        let all = serde_json::to_string(&r).unwrap();
        for private_part in [
            "Den's MacBook",
            "steamdeck",
            "192.168.0.175",
            "fd00:cbb::1a2b",
            "fe80::1",
            "0123456789abcdef",
            "3c:22:fb",
            "482913",
            "QmFzZTY0",
            "AAAAC3Nz",
            "/Users/den",
            "/home/den",
            "den@example.org",
            "10.0.0.2",
        ] {
            assert!(!all.contains(private_part), "{private_part} left in {all}");
        }
        assert!(all.contains("<name>") && all.contains("<address>") && all.contains("<data>"), "{all}");
        assert_eq!(r.at, "member/src/net.rs:7:3");
        // A file and a line stay readable.
        assert_eq!(redact("at member/src/sync.rs:120:9", &[]), "at member/src/sync.rs:120:9");
        assert_eq!(redact("sync is off for 15m", &[]), "sync is off for 15m");
    }

    /// Addresses and host names inside words, names in another case or as
    /// host names, the user's text in another script, and the values in a
    /// panic's message do not leave either.
    #[test]
    fn nothing_private_leaves_from_inside_words() {
        let names = alloc::vec![String::from("Office PC"), String::from("Den's MacBook")];
        for (line, gone) in [
            ("dial https://192.168.1.5:7300/x failed", "192.168.1.5"),
            ("peer=192.168.1.5:7300 closed", "192.168.1.5"),
            ("dial http://[fe80::1]:7300/ failed", "fe80::1"),
            ("host dimas-macbook-pro.local answered", "dimas-macbook-pro"),
            ("host=nas.lan:445 down", "nas.lan"),
            ("ssid=HomeNet-5G joined", "HomeNet-5G"),
            (
                "from \u{43c}\u{43e}\u{439} \u{43f}\u{430}\u{440}\u{43e}\u{43b}\u{44c} \u{43e}\u{442} \u{431}\u{430}\u{43d}\u{43a}\u{430} 4276 1234",
                "\u{43f}\u{430}\u{440}\u{43e}\u{43b}\u{44c}",
            ),
            ("office pc dialed", "office pc"),
            ("OFFICE PC dialed", "OFFICE PC"),
            ("office-pc.local answered", "office-pc"),
            ("den-s-macbook dialed", "den-s-macbook"),
        ] {
            let out = redact(line, &names);
            assert!(!out.contains(gone), "{gone} left in {out}");
        }
        assert_eq!(redact("peer=192.168.1.5:7300 closed", &[]), "peer=<address> closed");
        assert_eq!(redact("dial https://192.168.1.5:7300/x", &[]), "dial https://<address>/x");
        // Paths, files and the program's words stay readable.
        assert_eq!(redact("wrote state/bug.json, kept=3", &[]), "wrote state/bug.json, kept=3");
        assert_eq!(redact("at member/src/sync.rs:120:9", &[]), "at member/src/sync.rs:120:9");

        let mut i = input();
        i.kind = "panic".into();
        for (what, gone) in [
            (
                "byte index 3 is not a char boundary; it is inside 'x' (bytes 2..4) of `my bank password hunter2`",
                "hunter2",
            ),
            ("called `Result::unwrap()` on an `Err` value: Io(\"/srv/secret-plan.txt\")", "secret-plan"),
            ("wrote my secret password hunter2: done", "hunter2"),
        ] {
            i.details = alloc::format!("panic: {what} at member/src/net.rs:7:3 in thread main");
            let r = report(&i).unwrap();
            assert!(!r.details.contains(gone), "{gone} left in {}", r.details);
            assert!(r.details.ends_with(" at member/src/net.rs:7:3 in thread main"), "{}", r.details);
            assert_eq!(r.at, "member/src/net.rs:7:3");
        }
        assert_eq!(panic_kind("index out of bounds: the len is 3 but the index is 5"), "index out of bounds");
        assert_eq!(panic_kind("attempt to subtract with overflow"), "attempt to subtract with overflow");
        assert_eq!(panic_kind("the store is damaged: hunter2"), "a panic");
        // An error's details are the app's own and stay, filtered.
        let mut i = input();
        i.kind = "error".into();
        i.details = "sync: refused at 10.0.0.2".into();
        assert_eq!(report(&i).unwrap().details, "sync: refused at <address>");
    }

    #[test]
    fn the_fingerprint_ignores_numbers_and_versions() {
        let a = fingerprint("panic", "panic", "x.rs:1:1", "index 3 of 7");
        assert_eq!(a, fingerprint("panic", "panic", "x.rs:1:1", "index 4 of 9"));
        assert_ne!(a, fingerprint("panic", "panic", "x.rs:2:1", "index 3 of 7"));
        assert_eq!(a.len(), 16);
        let mut i = input();
        let k = crate::seal::public_key(&[7u8; 32]).unwrap();
        let one = build_for(&i, &k).unwrap();
        i.version = "0.6.1".into();
        assert_eq!(one.fingerprint, build_for(&i, &k).unwrap().fingerprint);
    }

    /// The robot opens what the app sealed; nothing else does.
    #[test]
    fn sealed_to_the_robot() {
        let secret = [9u8; 32];
        let key = crate::seal::public_key(&secret).unwrap();
        let b = build_for(&input(), &key).unwrap();
        let (p, r) = open(&secret, b.post.as_bytes()).unwrap();
        assert_eq!(r, b.report);
        assert_eq!(p.fingerprint, b.fingerprint);
        assert_eq!(r.day, "2025-11-09");
        assert!(open(&[8u8; 32], b.post.as_bytes()).is_err());
        assert!(!b.post.contains("member: started"));
    }

    /// The largest report the app can build fits MAX_POST, which the
    /// server's limit is twice of.
    #[test]
    fn the_largest_report_fits() {
        let mut i = input();
        i.details = "\u{1}".repeat(MAX_DETAILS * 2);
        i.message = "\"".repeat(MAX_FIELD * 4);
        i.log = (0..MAX_LINES * 2).map(|_| "\u{2}\"\\".repeat(MAX_LINE)).collect();
        let key = crate::seal::public_key(&[7u8; 32]).unwrap();
        let b = build_for(&i, &key).unwrap();
        assert!(b.post.len() <= MAX_POST, "{} > {MAX_POST}", b.post.len());
        assert!(serde_json::to_vec(&b.report).unwrap().len() <= MAX_REPORT);
        assert!(!b.report.log.is_empty());
    }

    #[test]
    fn refuses_what_is_not_a_report() {
        let mut i = input();
        i.kind = "crash".into();
        assert!(report(&i).is_err());
        let mut i = input();
        i.app = "web".into();
        assert!(report(&i).is_err());
        assert!(build(&input()).is_err() || !ROBOT_KEY_B64.is_empty());
    }

    #[test]
    fn days() {
        assert_eq!(day(0), "");
        assert_eq!(day(86_400_000), "1970-01-02");
        assert_eq!(day(951_782_400_000), "2000-02-29");
        assert_eq!(day(1_762_646_400_000), "2025-11-09");
    }

    #[test]
    fn one_report_for_each_break_and_version() {
        let mut st = State::default();
        let q = |fp: &str, v: &str, at: i64| Queued {
            fingerprint: fp.into(),
            version: v.into(),
            post: "{}".into(),
            at_ms: at,
        };
        assert_eq!(st.action("aa", "0.6.0", false), Action::Skip, "nothing goes without the robot's key");
        assert_eq!(st.action("aa", "0.6.0", true), Action::Ask);
        assert!(!st.offer_always());
        st.allow(false);
        st.sent(q("aa", "0.6.0", 0), true, "0.6.1", 1);
        assert_eq!(st.action("aa", "0.6.0", true), Action::Skip, "the same break in the same version");
        assert_eq!(st.action("aa", "0.6.1", true), Action::Ask, "the same break in a new version");
        assert_eq!(st.fixed_in("aa"), "0.6.1");
        st.allow(false);
        assert!(st.offer_always(), "offered after the second time");
        st.allow(true);
        assert!(!st.offer_always());
        assert_eq!(st.action("bb", "0.6.0", true), Action::Send);
        // Unsent reports wait: five at most, for seven days.
        let day = 24 * 60 * 60 * 1000;
        for n in 0..7 {
            st.sent(q(&alloc::format!("q{n}"), "0.6.0", n), false, "", n);
        }
        assert_eq!(st.queue.len(), MAX_QUEUED);
        assert_eq!(st.queue.first().map(|w| w.fingerprint.as_str()), Some("q2"));
        assert_eq!(st.action("q3", "0.6.0", true), Action::Skip, "a waiting report is not made twice");
        st.sent(q("q3", "0.6.0", 0), true, "", 10);
        assert_eq!(st.queue.len(), MAX_QUEUED - 1);
        st.prune(8 * day);
        assert!(st.queue.is_empty(), "{:?}", st.queue);
        for n in 0..MAX_SENT + 5 {
            st.sent(q(&alloc::format!("s{n}"), "0.6.0", 0), true, "", 8 * day);
        }
        assert_eq!(st.sent.len(), MAX_SENT);
        // The state survives its JSON, and an old or empty one reads.
        let back: State = serde_json::from_str(&serde_json::to_string(&st).unwrap()).unwrap();
        assert_eq!(back, st);
        assert_eq!(serde_json::from_str::<State>("{}").unwrap(), State::default());
    }
}
