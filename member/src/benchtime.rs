// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The bench's time-scaled build (feature `benchtime`, never a release's;
//! docs/maintainers/testbench-catalogue.md, section 0.1, "time"), as Go's
//! internal/benchtime: the core's long times run CBB_TEST_SCALE times
//! faster (100000 without it, 1 for the cases that move only the clock),
//! and CBB_TEST_CLOCK, or the file CBB_TEST_CLOCK_FILE names, moves the
//! wall clock: a Go duration such as "48h" or "-1h30m", or an RFC 3339 time
//! the clock reads at start. In every other build nothing here runs.

/// Sets the core's scale from CBB_TEST_SCALE; the time-scaled build only.
#[cfg(feature = "benchtime")]
pub fn start() {
    let scale = match crate::testbuild::env("CBB_TEST_SCALE") {
        Some(s) => match s.trim().parse::<u32>() {
            Ok(n) if n >= 1 => n,
            _ => {
                eprintln!("benchtime: CBB_TEST_SCALE {s:?} is not a whole number of 1 or more");
                std::process::exit(2);
            }
        },
        None => cbb_core::benchtime::DEFAULT_SCALE,
    };
    cbb_core::benchtime::set_scale(scale);
    let _ = clock_offset_ms();
}

#[cfg(not(feature = "benchtime"))]
pub fn start() {}

/// What CBB_TEST_CLOCK adds to the wall clock, in milliseconds, read once.
#[cfg(feature = "benchtime")]
pub fn clock_offset_ms() -> i64 {
    static OFFSET: std::sync::OnceLock<i64> = std::sync::OnceLock::new();
    *OFFSET.get_or_init(|| {
        let mut s = crate::testbuild::env("CBB_TEST_CLOCK").unwrap_or_default();
        if s.is_empty()
            && let Some(file) = crate::testbuild::env_os("CBB_TEST_CLOCK_FILE")
        {
            match std::fs::read_to_string(&file) {
                Ok(t) => s = t,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    eprintln!("benchtime: {}: {e}", std::path::Path::new(&file).display());
                    std::process::exit(2);
                }
            }
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);
        parse_clock(&s, now).unwrap_or_else(|| {
            eprintln!("benchtime: CBB_TEST_CLOCK {s:?} is neither a duration nor an RFC 3339 time");
            std::process::exit(2);
        })
    })
}

#[cfg(not(feature = "benchtime"))]
pub fn clock_offset_ms() -> i64 {
    0
}

/// The offset s gives from now (both in milliseconds since the epoch): a
/// Go duration, or an RFC 3339 time; 0 for nothing, None for neither.
#[cfg_attr(not(feature = "benchtime"), allow(dead_code))]
fn parse_clock(s: &str, now_ms: i64) -> Option<i64> {
    let s = s.trim();
    if s.is_empty() {
        return Some(0);
    }
    if let Some(d) = go_duration_ms(s) {
        return Some(d);
    }
    Some(rfc3339_ms(s)? - now_ms)
}

/// An RFC 3339 time, such as 2026-11-08T21:00:00Z or with an offset such
/// as +03:00, in milliseconds since the epoch; fractions of a second are
/// dropped.
#[cfg_attr(not(feature = "benchtime"), allow(dead_code))]
fn rfc3339_ms(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || !matches!(b[10], b'T' | b't') || b[13] != b':' || b[16] != b':' {
        return None;
    }
    let num = |r: std::ops::Range<usize>| -> Option<i64> {
        let t = s.get(r)?;
        t.bytes().all(|c| c.is_ascii_digit()).then(|| t.parse().ok())?
    };
    let (y, mo, d, h, mi, sec) = (num(0..4)?, num(5..7)?, num(8..10)?, num(11..13)?, num(14..16)?, num(17..19)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || sec > 60 {
        return None;
    }
    let mut rest = &s[19..];
    if let Some(r) = rest.strip_prefix('.') {
        let n = r.find(|c: char| !c.is_ascii_digit()).unwrap_or(r.len());
        if n == 0 {
            return None;
        }
        rest = &r[n..];
    }
    let offset = match rest {
        "Z" | "z" => 0,
        _ if rest.len() == 6 && rest.as_bytes()[3] == b':' => {
            let sign = match rest.as_bytes()[0] {
                b'+' => 1,
                b'-' => -1,
                _ => return None,
            };
            let oh: i64 = rest[1..3].parse().ok()?;
            let om: i64 = rest[4..6].parse().ok()?;
            sign * (oh * 3600 + om * 60)
        }
        _ => return None,
    };
    // Days from the civil date (Howard Hinnant's algorithm).
    let y = if mo <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (mo + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some((days * 86_400 + h * 3600 + mi * 60 + sec - offset) * 1000)
}

/// A Go duration (time.ParseDuration's units from ms to h, with a sign and
/// fractions) in milliseconds.
#[cfg_attr(not(feature = "benchtime"), allow(dead_code))]
fn go_duration_ms(s: &str) -> Option<i64> {
    let (neg, mut rest) = match s.as_bytes().first()? {
        b'-' => (true, &s[1..]),
        b'+' => (false, &s[1..]),
        _ => (false, s),
    };
    if rest == "0" {
        return Some(0);
    }
    let mut total = 0f64;
    while !rest.is_empty() {
        let n = rest.find(|c: char| !(c.is_ascii_digit() || c == '.')).unwrap_or(rest.len());
        let v: f64 = rest[..n].parse().ok()?;
        rest = &rest[n..];
        let u = rest.find(|c: char| c.is_ascii_digit() || c == '.').unwrap_or(rest.len());
        let unit = match &rest[..u] {
            "h" => 3_600_000.0,
            "m" => 60_000.0,
            "s" => 1000.0,
            "ms" => 1.0,
            "us" | "µs" => 0.001,
            "ns" => 0.000_001,
            _ => return None,
        };
        rest = &rest[u..];
        total += v * unit;
    }
    let ms = total.round() as i64;
    Some(if neg { -ms } else { ms })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_go_durations_and_times() {
        assert_eq!(parse_clock("", 5), Some(0));
        assert_eq!(parse_clock("48h", 0), Some(48 * 3_600_000));
        assert_eq!(parse_clock("-1h30m", 0), Some(-5_400_000));
        assert_eq!(parse_clock("26280h0m0s\n", 0), Some(26280 * 3_600_000));
        assert_eq!(parse_clock("1.5s", 0), Some(1500));
        assert_eq!(parse_clock("1970-01-01T00:00:00Z", 10_000), Some(-10_000));
        assert_eq!(parse_clock("tomorrow", 0), None);
        assert_eq!(parse_clock("5", 0), None);
        assert_eq!(rfc3339_ms("2026-11-08T21:00:00Z"), Some(1_794_171_600_000));
        assert_eq!(rfc3339_ms("2026-11-09T00:00:00.5+03:00"), Some(1_794_171_600_000));
        assert_eq!(rfc3339_ms("2000-02-29T00:00:00Z"), Some(951_782_400_000));
        assert_eq!(rfc3339_ms("2026-13-01T00:00:00Z"), None);
    }
}
