// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! cbb-bug, the receiver of bug reports at `https://bug.cbb.tools/`
//! (docs/core-api.md, "Bug reports"), behind nginx, which ends TLS, keeps
//! no client address in its log and passes each POST to a loopback port.
//! It checks that a body is a sealed report, keeps it in a folder of the
//! day and the break, and answers `{"fixed_in"}` from `fixed.json` (the
//! fingerprints the robot knows a fixing version for). It cannot read a
//! report: the robot opens them elsewhere with its secret.
//!
//! The robot's safeguards: a body larger than twice the largest report an
//! app builds is refused; at most `PER_BREAK` reports of one break and
//! version are kept each day, and further ones are answered as taken and
//! dropped, so that an app never sends them again; past `PER_DAY` reports
//! in a day or `MAX_TOTAL` bytes in all it answers 503, so that the apps
//! keep theirs and send them later; one source takes at most its share of
//! the day (`PER_SOURCE` for an IPv4 address or an IPv6 /64, `PER_WIDE`
//! for an IPv6 /48), past which it answers 503 too, so that no one source
//! fills the day; and a day's reports go after `KEEP_DAYS`. The source is
//! the prefix nginx names in `X-CBB-Source` and `X-CBB-Source-Wide`; it is
//! counted in memory for the day only, never written or logged.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use cbb_core::bug;

use crate::error::{Context, Error, Result};

/// The largest body taken: twice the largest an app posts. nginx's
/// `client_max_body_size` in packaging/linux/nginx-bug.conf is the same.
pub const MAX_BODY: usize = 2 * bug::MAX_POST;
/// The reports of one break and version kept in a day.
pub const PER_BREAK: usize = 20;
/// The reports kept in a day, in all.
pub const PER_DAY: usize = 5000;
/// The reports one IPv4 address or IPv6 /64 may have kept in a day.
pub const PER_SOURCE: usize = PER_DAY / 50;
/// The reports one IPv6 /48 may have kept in a day.
pub const PER_WIDE: usize = PER_DAY / 10;
/// The longest source name taken from nginx.
const MAX_SOURCE: usize = 64;
/// The bytes of reports kept in all; past them it takes no more.
pub const MAX_TOTAL: u64 = 2 << 30;
/// The days a day's reports are kept.
pub const KEEP_DAYS: i64 = 30;
/// The connections served at once.
const CONNECTIONS: usize = 64;
/// How long a connection may take.
const TIMEOUT: Duration = Duration::from_secs(20);
/// The most bytes of the request line and headers.
const MAX_HEAD: usize = 8 * 1024;

/// What the receiver counts within a day.
#[derive(Default)]
struct Day {
    day: String,
    all: usize,
    breaks: HashMap<String, usize>,
    /// The bytes of every report kept, of all days.
    total: u64,
    /// The reports kept today from each source, by its prefix.
    sources: HashMap<String, usize>,
}

/// Where a request came from, as nginx names it: an IPv4 address or an
/// IPv6 /64, and an IPv4 address or an IPv6 /48; empty when not named.
#[derive(Default, Debug, PartialEq)]
pub struct Source {
    pub narrow: String,
    pub wide: String,
}

/// The receiver: where it keeps the reports, and today's counts.
pub struct Receiver {
    dir: PathBuf,
    day: Mutex<Day>,
}

/// The answer to a request: its status and body.
#[derive(Debug, PartialEq)]
pub struct Answer {
    pub status: u16,
    pub body: String,
}

impl Answer {
    fn error(status: u16, why: &str) -> Answer {
        Answer { status, body: serde_json::json!({ "error": why }).to_string() }
    }
}

/// Whether s is a version as the apps name theirs: digits, letters, dots,
/// pluses and dashes.
fn version_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes().next().is_some_and(|b| b.is_ascii_alphanumeric())
        && !s.contains("..")
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'+' | b'-'))
}

/// Whether name is a day's folder, `YYYY-MM-DD`.
fn day_folder(name: &str) -> bool {
    name.len() == 10
        && name.bytes().enumerate().all(|(i, b)| if i == 4 || i == 7 { b == b'-' } else { b.is_ascii_digit() })
}

/// The bytes of the files under dir.
fn bytes(dir: &Path) -> u64 {
    let mut total = 0u64;
    for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let Ok(meta) = std::fs::symlink_metadata(e.path()) else { continue };
        total = total.saturating_add(if meta.is_dir() { bytes(&e.path()) } else { meta.len() });
    }
    total
}

/// How many files each folder in dir holds, by its name.
fn files_in_each(dir: &Path) -> HashMap<String, usize> {
    let mut out = HashMap::new();
    for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        if !e.file_type().is_ok_and(|t| t.is_dir()) {
            continue;
        }
        let n = std::fs::read_dir(e.path())
            .into_iter()
            .flatten()
            .flatten()
            .filter(|f| f.file_type().is_ok_and(|t| t.is_file()))
            .count();
        out.insert(e.file_name().to_string_lossy().into_owned(), n);
    }
    out
}

impl Receiver {
    pub fn new(dir: &Path) -> Result<Receiver> {
        std::fs::create_dir_all(dir).context(format!("cannot make {}", dir.display()))?;
        Ok(Receiver { dir: dir.to_path_buf(), day: Mutex::new(Day::default()) })
    }

    /// The version that fixes fingerprint, from fixed.json; empty when the
    /// robot knows none.
    fn fixed_in(&self, fingerprint: &str) -> String {
        std::fs::read(self.dir.join("fixed.json"))
            .ok()
            .and_then(|b| serde_json::from_slice::<HashMap<String, String>>(&b).ok())
            .and_then(|m| m.get(fingerprint).cloned())
            .filter(|v| version_ok(v))
            .unwrap_or_default()
    }

    /// The counts at the start of today, or at the receiver's start on a
    /// day: the days older than KEEP_DAYS removed, the bytes of the rest,
    /// and today's reports as its folder holds them.
    fn new_day(&self, today: &str, now_ms: i64) -> Day {
        let oldest = bug::day(now_ms.saturating_sub(KEEP_DAYS.saturating_mul(86_400_000)));
        for e in std::fs::read_dir(&self.dir).into_iter().flatten().flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if day_folder(&name)
                && name < oldest
                && let Err(err) = std::fs::remove_dir_all(e.path())
            {
                eprintln!("cbb-bug: cannot remove the old reports in {}: {err}", e.path().display());
            }
        }
        let total = bytes(&self.dir);
        let breaks = files_in_each(&self.dir.join(today));
        let all = breaks.values().sum();
        Day { day: today.to_string(), all, breaks, total, sources: HashMap::new() }
    }

    /// Takes a posted body at now_ms: keeps it when the day's counts allow,
    /// and answers.
    pub fn take(&self, body: &[u8], now_ms: i64) -> Answer {
        self.take_from(body, now_ms, &Source::default())
    }

    /// take, counting the report against the shares of from.
    pub fn take_from(&self, body: &[u8], now_ms: i64, from: &Source) -> Answer {
        use base64::Engine as _;
        if body.len() > MAX_BODY {
            return Answer::error(413, "the report is too large");
        }
        let Ok(p) = serde_json::from_slice::<bug::Post>(body) else {
            return Answer::error(400, "this is not a report");
        };
        let sealed = base64::engine::general_purpose::STANDARD.decode(&p.sealed).unwrap_or_default();
        if p.v != 1
            || p.fingerprint.len() != 16
            || !p.fingerprint.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            || !version_ok(&p.version)
            || sealed.len() <= cbb_core::seal::OVERHEAD
        {
            return Answer::error(400, "this is not a report");
        }
        let answer =
            Answer { status: 200, body: serde_json::json!({ "fixed_in": self.fixed_in(&p.fingerprint) }).to_string() };
        let today = bug::day(now_ms);
        let key = format!("{}-{}", p.fingerprint, p.version);
        let n = {
            let mut d = self.day.lock().unwrap();
            if d.day != today {
                *d = self.new_day(&today, now_ms);
            }
            let seen = d.breaks.get(&key).copied().unwrap_or(0);
            if seen >= PER_BREAK {
                return answer;
            }
            if d.all >= PER_DAY || d.total.saturating_add(body.len() as u64) > MAX_TOTAL {
                return Answer::error(503, "no more reports are taken now");
            }
            let narrow = (!from.narrow.is_empty()).then(|| format!("n {}", from.narrow));
            let wide = (!from.wide.is_empty() && from.wide != from.narrow).then(|| format!("w {}", from.wide));
            let over = |k: &Option<String>, max: usize| {
                k.as_ref().is_some_and(|k| d.sources.get(k).copied().unwrap_or(0) >= max)
            };
            if over(&narrow, PER_SOURCE) || over(&wide, PER_WIDE) {
                return Answer::error(503, "no more reports are taken from here today");
            }
            for k in [narrow, wide].into_iter().flatten() {
                *d.sources.entry(k).or_insert(0) += 1;
            }
            d.all += 1;
            d.total = d.total.saturating_add(body.len() as u64);
            d.breaks.insert(key.clone(), seen + 1);
            seen
        };
        let folder = self.dir.join(&today).join(&key);
        let kept = std::fs::create_dir_all(&folder).and_then(|()| {
            let path = folder.join(format!("{n:02}-{now_ms}.json"));
            let tmp = path.with_extension("tmp");
            std::fs::write(&tmp, body)?;
            std::fs::rename(&tmp, &path)
        });
        if let Err(e) = kept {
            eprintln!("cbb-bug: cannot keep a report in {}: {e}", folder.display());
            return Answer::error(503, "the report cannot be kept now");
        }
        answer
    }

    /// Serves one connection: one request, then it closes.
    fn serve_one(&self, stream: TcpStream) -> Result<()> {
        stream.set_read_timeout(Some(TIMEOUT)).context("a connection")?;
        stream.set_write_timeout(Some(TIMEOUT)).context("a connection")?;
        let mut r = BufReader::new(stream.try_clone().context("a connection")?);
        let answer = match read_request(&mut r) {
            Ok((method, body, from)) if method == "POST" => self.take_from(&body, crate::uptime::wall_ms(), &from),
            Ok(_) => Answer::error(405, "post a report"),
            Err(e) => {
                let status = if e.to_string().contains("too large") { 413 } else { 400 };
                Answer::error(status, "the request does not read")
            }
        };
        write_answer(stream, &answer)
    }
}

/// Reads a request's method and body: the head at most MAX_HEAD bytes, the
/// body as long as its Content-Length and at most MAX_BODY.
/// Whether s is a source as nginx names it: an address or a prefix.
fn source_ok(s: &str) -> bool {
    s.len() <= MAX_SOURCE && s.bytes().all(|b| b.is_ascii_hexdigit() || b == b'.' || b == b':')
}

fn read_request(r: &mut impl BufRead) -> Result<(String, Vec<u8>, Source)> {
    let mut head = 0usize;
    let mut line = String::new();
    let mut next = |r: &mut dyn BufRead, line: &mut String| -> Result<()> {
        line.clear();
        let n = r.take((MAX_HEAD - head.min(MAX_HEAD)) as u64).read_line(line).context("the request does not read")?;
        head += n;
        if n == 0 || !line.ends_with('\n') {
            return Err(Error::msg("the request's head is too large or cut short"));
        }
        Ok(())
    };
    next(r, &mut line)?;
    let method = line.split(' ').next().unwrap_or_default().to_string();
    let mut len: Option<usize> = None;
    let mut from = Source::default();
    loop {
        next(r, &mut line)?;
        let l = line.trim_end();
        if l.is_empty() {
            break;
        }
        if let Some((k, v)) = l.split_once(':') {
            if k.trim().eq_ignore_ascii_case("content-length") {
                len = Some(v.trim().parse().map_err(|_| Error::msg("the content length does not read"))?);
            } else if k.trim().eq_ignore_ascii_case("x-cbb-source") && source_ok(v.trim()) {
                from.narrow = v.trim().to_string();
            } else if k.trim().eq_ignore_ascii_case("x-cbb-source-wide") && source_ok(v.trim()) {
                from.wide = v.trim().to_string();
            } else if k.trim().eq_ignore_ascii_case("transfer-encoding") {
                return Err(Error::msg("a request without a content length"));
            }
        }
    }
    let len = len.unwrap_or(0);
    if len > MAX_BODY {
        return Err(Error::msg("the request is too large"));
    }
    let mut body = vec![0; len];
    r.read_exact(&mut body).context("the request is cut short")?;
    Ok((method, body, from))
}

fn write_answer(mut w: impl Write, a: &Answer) -> Result<()> {
    let reason = match a.status {
        200 => "OK",
        400 => "Bad Request",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        _ => "Service Unavailable",
    };
    write!(
        w,
        "HTTP/1.1 {} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        a.status,
        a.body.len(),
        a.body
    )
    .context("cannot answer")?;
    w.flush().context("cannot answer")?;
    Ok(())
}

/// Serves on listen until the process ends.
pub fn serve(listen: SocketAddr, dir: &Path) -> Result<()> {
    let rx = Arc::new(Receiver::new(dir)?);
    let ln = TcpListener::bind(listen).context(format!("cannot listen on {listen}"))?;
    eprintln!("cbb-bug: taking reports on {listen} into {}", dir.display());
    let busy = Arc::new(AtomicUsize::new(0));
    for s in ln.incoming() {
        let Ok(s) = s else { continue };
        if busy.load(Ordering::SeqCst) >= CONNECTIONS {
            let _ = write_answer(s, &Answer::error(503, "busy"));
            continue;
        }
        busy.fetch_add(1, Ordering::SeqCst);
        let (rx, busy) = (rx.clone(), busy.clone());
        std::thread::spawn(move || {
            let _ = rx.serve_one(s);
            busy.fetch_sub(1, Ordering::SeqCst);
        });
    }
    Ok(())
}

/// Makes the robot's key: writes the secret to `secret` (readable by its
/// owner only, never on the server) and returns the public key in base64,
/// for `cbb_core::bug::ROBOT_KEY_B64`.
pub fn keygen(secret: &Path) -> Result<String> {
    use base64::Engine as _;
    if secret.exists() {
        return Err(Error::msg(format!("{} is there already: the robot keeps one key", secret.display())));
    }
    let s = cbb_core::seal::generate_secret().map_err(|e| e.context("cannot make a secret"))?;
    let public = cbb_core::seal::public_key(&s).map_err(|e| e.context("cannot make the public key"))?;
    crate::files::write_atomic(secret, base64::engine::general_purpose::STANDARD.encode(s).as_bytes(), 0o600)
        .map_err(|e| e.context(format!("cannot write {}", secret.display())))?;
    Ok(base64::engine::general_purpose::STANDARD.encode(public))
}

/// Opens the reports under each folder or file with the robot's secret
/// and writes each as readable JSON, with the file it came from; a report
/// that does not open is named on err.
pub fn read(secret: &Path, paths: &[PathBuf], out: &mut impl Write, err: &mut impl Write) -> Result<usize> {
    use base64::Engine as _;
    let text = std::fs::read_to_string(secret).context(format!("cannot read {}", secret.display()))?;
    let s = base64::engine::general_purpose::STANDARD
        .decode(text.trim())
        .map_err(|_| Error::msg("the secret does not decode"))?;
    let mut files = Vec::new();
    let mut todo: Vec<PathBuf> = paths.to_vec();
    while let Some(p) = todo.pop() {
        if p.is_dir() {
            for e in std::fs::read_dir(&p).context(format!("cannot read {}", p.display()))? {
                todo.push(e.context("cannot read a folder")?.path());
            }
        } else if p.extension().is_some_and(|e| e == "json") {
            files.push(p);
        }
    }
    files.sort();
    let mut opened = 0;
    for f in files {
        let body = std::fs::read(&f).context(format!("cannot read {}", f.display()))?;
        match bug::open(&s, &body) {
            Ok((_, r)) => {
                let pretty = serde_json::to_string_pretty(&r).context("cannot encode a report")?;
                writeln!(out, "# {}\n{pretty}", f.display()).context("cannot write")?;
                opened += 1;
            }
            Err(e) => {
                let _ = writeln!(err, "cbb-bug: {}: {e}", f.display());
            }
        }
    }
    Ok(opened)
}

/// cbb-bug's command line: `cbb-bug [-listen ADDRESS:PORT] [-dir FOLDER]`
/// serves; `cbb-bug keygen SECRET` makes the robot's key and
/// `cbb-bug read SECRET FOLDER...` opens the reports, both on the robot's
/// own computer.
pub fn command(args: &[String], err: &mut impl Write) -> i32 {
    match args.first().map(String::as_str) {
        Some("keygen") if args.len() == 2 => {
            return match keygen(Path::new(&args[1])) {
                Ok(public) => {
                    println!("{public}");
                    0
                }
                Err(e) => {
                    let _ = writeln!(err, "cbb-bug: {e:#}");
                    1
                }
            };
        }
        Some("read") if args.len() >= 3 => {
            let paths: Vec<PathBuf> = args[2..].iter().map(PathBuf::from).collect();
            return match read(Path::new(&args[1]), &paths, &mut std::io::stdout(), err) {
                Ok(_) => 0,
                Err(e) => {
                    let _ = writeln!(err, "cbb-bug: {e:#}");
                    1
                }
            };
        }
        Some("keygen" | "read") => {
            let _ = writeln!(err, "usage: cbb-bug keygen SECRET | cbb-bug read SECRET FOLDER...");
            return 2;
        }
        _ => {}
    }
    let mut listen: SocketAddr = ([127, 0, 0, 1], 8791).into();
    let mut dir = PathBuf::from("/var/lib/cbb-bug");
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let flag = a.trim_start_matches('-');
        let value = it.next();
        match (flag, value) {
            ("listen", Some(v)) => match v.parse() {
                Ok(l) => listen = l,
                Err(_) => {
                    let _ = writeln!(err, "cbb-bug: -listen takes address:port, not {v}");
                    return 2;
                }
            },
            ("dir", Some(v)) => dir = PathBuf::from(v),
            _ => {
                let _ = writeln!(err, "usage: cbb-bug [-listen 127.0.0.1:8791] [-dir /var/lib/cbb-bug]");
                return 2;
            }
        }
    }
    match serve(listen, &dir) {
        Ok(()) => 0,
        Err(e) => {
            let _ = writeln!(err, "cbb-bug: {e:#}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn post(fp: &str, version: &str) -> Vec<u8> {
        use base64::Engine as _;
        let sealed = base64::engine::general_purpose::STANDARD.encode(vec![7u8; cbb_core::seal::OVERHEAD + 10]);
        serde_json::json!({"v": 1, "fingerprint": fp, "version": version, "sealed": sealed}).to_string().into_bytes()
    }

    #[test]
    fn keeps_reports_within_the_days_limits() {
        let tmp = std::env::temp_dir().join(format!("cbb-bugd-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        struct Gone(PathBuf);
        impl Drop for Gone {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let dir = Gone(tmp.clone());
        let rx = Receiver::new(&tmp).unwrap();
        let day = 1_762_646_400_000;
        let a = rx.take(&post("0123456789abcdef", "0.6.0"), day);
        assert_eq!(a, Answer { status: 200, body: r#"{"fixed_in":""}"#.into() });
        let kept = dir.0.join("2025-11-09").join("0123456789abcdef-0.6.0");
        assert_eq!(std::fs::read_dir(&kept).unwrap().count(), 1);
        // The robot says which version fixes it.
        std::fs::write(dir.0.join("fixed.json"), r#"{"0123456789abcdef":"0.6.1"}"#).unwrap();
        assert_eq!(rx.take(&post("0123456789abcdef", "0.6.0"), day).body, r#"{"fixed_in":"0.6.1"}"#);
        for _ in 0..PER_BREAK + 5 {
            assert_eq!(rx.take(&post("0123456789abcdef", "0.6.0"), day).status, 200);
        }
        assert_eq!(std::fs::read_dir(&kept).unwrap().count(), PER_BREAK, "no more than PER_BREAK of one break a day");
        // A new day counts again.
        rx.take(&post("0123456789abcdef", "0.6.0"), day + 86_400_000);
        assert!(dir.0.join("2025-11-10").exists());
        // What is not a report.
        for bad in [
            b"{}".to_vec(),
            post("0123456789ABCDEF", "0.6.0"),
            post("0123", "0.6.0"),
            post("0123456789abcdef", "0.6.0/../x"),
            br#"{"v":1,"fingerprint":"0123456789abcdef","version":"1","sealed":"AAAA"}"#.to_vec(),
        ] {
            assert_eq!(rx.take(&bad, day).status, 400, "{}", String::from_utf8_lossy(&bad));
        }
        assert_eq!(rx.take(&vec![b' '; MAX_BODY + 1], day).status, 413);
        for bad in [".", "..", "-1", "0.6..1"] {
            assert_eq!(rx.take(&post("0123456789abcdef", bad), day).status, 400, "{bad}");
        }
    }

    /// Past the day's count or the bytes in all it answers 503, so that the
    /// apps keep their reports; a restart keeps the day's count; old days go.
    #[test]
    fn full_store_asks_to_send_later() {
        let tmp = std::env::temp_dir().join(format!("cbb-bugd-full-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let day = 1_762_646_400_000;
        let rx = Receiver::new(&tmp).unwrap();
        // A day older than KEEP_DAYS, and one within.
        let old = tmp.join(bug::day(day - (KEEP_DAYS + 1) * 86_400_000)).join("0123456789abcdef-0.5.0");
        let recent = tmp.join(bug::day(day - 86_400_000)).join("0123456789abcdef-0.5.0");
        for d in [&old, &recent] {
            std::fs::create_dir_all(d).unwrap();
            std::fs::write(d.join("00-1.json"), "x").unwrap();
        }
        assert_eq!(rx.take(&post("0123456789abcdef", "0.6.0"), day).status, 200);
        assert!(!old.exists(), "a day older than KEEP_DAYS stays");
        assert!(recent.exists());
        {
            let mut d = rx.day.lock().unwrap();
            d.all = PER_DAY;
        }
        assert_eq!(rx.take(&post("1123456789abcdef", "0.6.0"), day).status, 503);
        {
            let mut d = rx.day.lock().unwrap();
            d.all = 0;
            d.total = MAX_TOTAL;
        }
        assert_eq!(rx.take(&post("1123456789abcdef", "0.6.0"), day).status, 503);
        {
            let mut d = rx.day.lock().unwrap();
            d.total = 0;
        }
        // One source takes at most its share of the day, and others still go.
        let fp = |i: usize| format!("{:016x}", 0x2000_0000_0000_0000u64 + i as u64);
        let home = Source { narrow: "2001:db8:1:2".into(), wide: "2001:db8:1".into() };
        for i in 0..PER_SOURCE {
            assert_eq!(rx.take_from(&post(&fp(i), "0.6.0"), day, &home).status, 200);
        }
        assert_eq!(rx.take_from(&post(&fp(PER_SOURCE), "0.6.0"), day, &home).status, 503);
        // The rest of its /48 up to the wider share.
        let mut n = PER_SOURCE;
        for k in 0.. {
            let next = Source { narrow: format!("2001:db8:1:{k:x}0"), wide: "2001:db8:1".into() };
            let a = rx.take_from(&post(&fp(1000 + k), "0.6.0"), day, &next);
            if a.status == 503 {
                break;
            }
            n += 1;
        }
        assert_eq!(n, PER_WIDE, "a /48 takes its share and no more");
        let other = Source { narrow: "198.51.100.7".into(), wide: "198.51.100.7".into() };
        assert_eq!(rx.take_from(&post(&fp(9999), "0.6.0"), day, &other).status, 200);
        // A new receiver on the same day counts what the folder holds.
        let again = Receiver::new(&tmp).unwrap();
        let d = again.new_day(&bug::day(day), day);
        assert_eq!(d.all, 1 + PER_WIDE + 1);
        assert_eq!(d.breaks.get("0123456789abcdef-0.6.0"), Some(&1));
        assert!(d.total > 0);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn the_robot_opens_what_an_app_sealed() {
        let tmp = std::env::temp_dir().join(format!("cbb-bugd-robot-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join("2025-11-09/f-0.6.0")).unwrap();
        struct Gone(PathBuf);
        impl Drop for Gone {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let _gone = Gone(tmp.clone());
        let secret = tmp.join("robot.key");
        let public = keygen(&secret).unwrap();
        assert!(keygen(&secret).is_err(), "a second key must not replace the first");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(std::fs::metadata(&secret).unwrap().permissions().mode() & 0o777, 0o600);
        }
        use base64::Engine as _;
        let key = base64::engine::general_purpose::STANDARD.decode(&public).unwrap();
        let input = bug::Input {
            kind: "panic".into(),
            name: "panic".into(),
            message: "Something in CBB broke.".into(),
            details: "panic: boom at member/src/x.rs:1:2".into(),
            app: "cbb".into(),
            version: "0.6.0".into(),
            ..Default::default()
        };
        let built = bug::build_for(&input, &key).unwrap();
        std::fs::write(tmp.join("2025-11-09/f-0.6.0/01-1.json"), &built.post).unwrap();
        std::fs::write(tmp.join("2025-11-09/f-0.6.0/02-2.json"), post("f", "0.6.0")).unwrap();
        let (mut out, mut err) = (Vec::new(), Vec::new());
        assert_eq!(read(&secret, &[tmp.join("2025-11-09")], &mut out, &mut err).unwrap(), 1);
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("member/src/x.rs:1:2"), "{out}");
        assert!(String::from_utf8(err).unwrap().contains("02-2.json"));
    }

    #[test]
    fn reads_requests() {
        let body = post("0123456789abcdef", "0.6.0");
        let req = [
            format!("POST / HTTP/1.1\r\nHost: bug.cbb.tools\r\nContent-Length: {}\r\n\r\n", body.len()).as_bytes(),
            &body,
        ]
        .concat();
        let (m, b, from) = read_request(&mut &req[..]).unwrap();
        assert_eq!((m.as_str(), b), ("POST", body.clone()));
        assert_eq!(from, Source::default());
        let req = [
            format!(
                "POST / HTTP/1.1\r\nX-CBB-Source: 2001:db8:1:2\r\nX-CBB-Source-Wide: 2001:db8:1\r\nContent-Length: {}\r\n\r\n",
                body.len()
            )
            .as_bytes(),
            &body,
        ]
        .concat();
        let (_, _, from) = read_request(&mut &req[..]).unwrap();
        assert_eq!(from, Source { narrow: "2001:db8:1:2".into(), wide: "2001:db8:1".into() });
        let big = format!("POST / HTTP/1.1\r\nContent-Length: {}\r\n\r\n", MAX_BODY + 1);
        assert!(read_request(&mut big.as_bytes()).unwrap_err().to_string().contains("too large"));
        let long = format!("GET / HTTP/1.1\r\nX: {}\r\n\r\n", "a".repeat(MAX_HEAD));
        assert!(read_request(&mut long.as_bytes()).is_err());
        assert!(read_request(&mut &b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"[..]).is_err());
    }

    /// nginx takes what the receiver takes: twice the largest report an
    /// app can build (bug::MAX_POST, checked against the largest report in
    /// cbb_core's tests).
    #[test]
    fn nginx_takes_twice_the_largest_report() {
        let conf = include_str!("../../packaging/linux/nginx-bug.conf");
        let size = conf
            .lines()
            .find_map(|l| l.trim().strip_prefix("client_max_body_size "))
            .and_then(|v| v.trim_end_matches(';').parse::<usize>().ok())
            .expect("client_max_body_size in nginx-bug.conf");
        assert_eq!(size, MAX_BODY, "set client_max_body_size {MAX_BODY}; in packaging/linux/nginx-bug.conf");
        assert!(conf.contains("access_log off;"), "nginx keeps no client address for bug reports");
    }
}
