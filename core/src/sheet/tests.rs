// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The recovery sheet: its text and QR code read back, every refusal with
//! the reason a person is shown, and the keys checked against the group.

use alloc::string::ToString;

use super::*;
use crate::records::key::Key;

fn secret(n: u8) -> [u8; 32] {
    core::array::from_fn(|i| n.wrapping_mul(31).wrapping_add(i as u8))
}

fn recovery(s: &[u8; 32]) -> Recovery {
    use p256::elliptic_curve::sec1::ToSec1Point as _;
    let (k1, k2) = crate::records::pq::recovery_keys(s).unwrap();
    Recovery::new(Key::es256(k1.public_key().to_sec1_point(false).as_bytes().to_vec()), k2.key()).unwrap()
}

/// The text with the character at (line, index in the line) replaced.
fn with(text: &str, line: usize, at: usize, c: char) -> String {
    let mut lines: Vec<Vec<char>> = text.lines().map(|l| l.chars().filter(|c| *c != ' ').collect()).collect();
    lines[line][at] = c;
    lines.iter().map(|l| l.iter().collect::<String>()).collect::<Vec<_>>().join("\n")
}

#[test]
fn a_sheet_reads_back() {
    for n in 0..20 {
        let s = secret(n);
        let t = text(&s);
        assert_eq!(t.lines().count(), 4);
        assert!(t.lines().all(|l| l.len() == 19 && l.split(' ').all(|g| g.len() == 4)), "{t}");
        assert!(t.starts_with('1'));
        let r = read(&t).unwrap();
        assert_eq!(*r.secret, s);
        assert!(r.group.is_none());
        // One line, hyphens, lower case.
        let typed = t.replace(['\n', ' '], "-").to_lowercase();
        assert_eq!(*read(&typed).unwrap().secret, s);
    }
}

#[test]
fn a_mistyped_character_names_its_line() {
    let t = text(&secret(3));
    for line in 0..4 {
        for at in [1, 7, 13, 15] {
            let old = t.lines().nth(line).unwrap().replace(' ', "").chars().nth(at).unwrap();
            let c = if old == 'Z' { 'Y' } else { 'Z' };
            if line == 0 && at == 0 {
                continue;
            }
            assert_eq!(read(&with(&t, line, at, c)).err(), Some(Reason::Lines(1 << line)), "line {line} at {at}");
        }
    }
}

#[test]
fn swapped_groups_and_lines_are_caught() {
    let t = text(&secret(5));
    let lines: Vec<String> = t.lines().map(str::to_string).collect();
    // Two groups swapped inside line 2.
    let g: Vec<&str> = lines[1].split(' ').collect();
    let mut swapped = lines.clone();
    swapped[1] = [g[1], g[0], g[2], g[3]].join(" ");
    assert_eq!(read(&swapped.join("\n")).err(), Some(Reason::Lines(0b10)));
    // Lines 2 and 3 swapped.
    let mut swapped = lines.clone();
    swapped.swap(1, 2);
    assert_eq!(read(&swapped.join("\n")).err(), Some(Reason::Lines(0b110)));
    // A line missing.
    assert_eq!(read(&lines[..3].join("\n")).err(), Some(Reason::Length));
}

/// A mistake the line check misses (1 in 1024) is caught by the whole
/// check, which says the typing is wrong, not the group.
#[test]
fn the_whole_check_catches_what_a_line_check_misses() {
    let s = secret(7);
    let t = text(&s);
    let line: Vec<u8> = t.lines().nth(1).unwrap().replace(' ', "").into_bytes();
    let (data, check) = line.split_at(LINE_DATA);
    let found = (0..32usize * 32 * 32)
        .find_map(|n| {
            let mut d = data.to_vec();
            d[2] = ALPHABET[n / 1024];
            d[6] = ALPHABET[n / 32 % 32];
            d[9] = ALPHABET[n % 32];
            (d != data && line_check(1, &d) == check).then_some(d)
        })
        .expect("a pair of changes the line check misses");
    let mut lines: Vec<String> = t.lines().map(|l| l.replace(' ', "")).collect();
    lines[1] = String::from_utf8([found.as_slice(), check].concat()).unwrap();
    assert_eq!(read(&lines.join("\n")).err(), Some(Reason::Whole));
}

#[test]
fn versions_and_earlier_sheets() {
    let t = text(&secret(1));
    let later = with(&t, 0, 0, '2');
    assert_eq!(read(&later).err(), Some(Reason::Newer));
    assert_eq!(read("2").err(), Some(Reason::Newer));
    // 0.5's text (56 characters) and QR code.
    let earlier = crate::recovery::text(&crate::recovery::secret_key(&[9; 32]).unwrap());
    assert_eq!(read(&earlier).err(), Some(Reason::Earlier));
    assert_eq!(read("cbb://recover?g=0011223344556677&k=AA&c=BB").err(), Some(Reason::Earlier));
    assert_eq!(read("").err(), Some(Reason::NotSheet));
    assert_eq!(read("https://example.com/").err(), Some(Reason::NotSheet));
    assert_eq!(read(&"1".repeat(MAX_INPUT + 1)).err(), Some(Reason::NotSheet));
    let mut bad = t.clone();
    bad.replace_range(5..6, "*");
    assert_eq!(read(&bad).err(), Some(Reason::Damaged));
}

#[test]
fn padding_bits_must_be_zero() {
    // The secret's last character carries 1 bit of it and 4 zero bits.
    let s = secret(2);
    let t = text(&s);
    let mut data: Vec<u8> = t.lines().flat_map(|l| l.replace(' ', "").into_bytes()[..LINE_DATA].to_vec()).collect();
    let last = 1 + SECRET_CHARS - 1;
    data[last] = ALPHABET[(value(data[last]).unwrap() | 1) as usize];
    let lines: Vec<String> = data
        .chunks(LINE_DATA)
        .enumerate()
        .map(|(i, d)| String::from_utf8([d, line_check(i, d).as_slice()].concat()).unwrap())
        .collect();
    assert_eq!(read(&lines.join("\n")).err(), Some(Reason::Padding));
}

#[test]
fn the_qr_code_reads_back_and_names_its_group() {
    let s = secret(4);
    let g = GroupId::from_slice(&[6; 16]).unwrap();
    let q = qr(&s, &g);
    assert_eq!(q.len(), 4 + 1 + 77);
    assert!(q.bytes().all(|b| b.is_ascii_digit() || b.is_ascii_uppercase()), "QR alphanumeric mode");
    let r = read(&q).unwrap();
    assert_eq!((*r.secret, r.group), (s, Some(g)));
    assert_eq!(*read(&q.to_lowercase()).unwrap().secret, s);
    let mut later = q.clone();
    later.replace_range(4..5, "2");
    assert_eq!(read(&later).err(), Some(Reason::Newer));
    assert_eq!(read(&q[..q.len() - 1]).err(), Some(Reason::Length));
    // The last character carries one spare bit.
    let mut pad = q.clone().into_bytes();
    let last = pad.len() - 1;
    pad[last] = ALPHABET[(value(pad[last]).unwrap() | 1) as usize];
    assert_eq!(read(core::str::from_utf8(&pad).unwrap()).err(), Some(Reason::Padding));
}

#[test]
fn the_keys_decide_the_group() {
    let s = secret(8);
    let g = GroupId::from_slice(&[1; 16]).unwrap();
    let rec = recovery(&s);
    check(&read(&text(&s)).unwrap(), &g, &rec).unwrap();
    check(&read(&qr(&s, &g)).unwrap(), &g, &rec).unwrap();
    let other = recovery(&secret(9));
    assert_eq!(check(&read(&text(&s)).unwrap(), &g, &other).err(), Some(Reason::OtherGroup));
    assert_eq!(
        check(&read(&qr(&s, &GroupId::from_slice(&[2; 16]).unwrap())).unwrap(), &g, &rec).err(),
        Some(Reason::OtherGroup)
    );
    // Our Group ID with keys that are not ours: damaged.
    assert_eq!(check(&read(&qr(&secret(9), &g)).unwrap(), &g, &rec).err(), Some(Reason::Damaged));
}

fn reason_name(r: Reason) -> String {
    match r {
        Reason::NotSheet => "not_sheet".into(),
        Reason::Earlier => "earlier".into(),
        Reason::Newer => "newer".into(),
        Reason::Length => "length".into(),
        Reason::Damaged => "damaged".into(),
        Reason::Lines(m) => alloc::format!("lines:{m}"),
        Reason::Padding => "padding".into(),
        Reason::Whole => "whole".into(),
        Reason::OtherGroup => "other_group".into(),
    }
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

/// testdata/format/sheet.json, written apart from the core by gen.py.
#[test]
fn the_sheet_vectors() {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../testdata/format/sheet.json");
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let s = |x: &serde_json::Value, k: &str| x[k].as_str().unwrap().to_string();
    let mut rec = None;
    let mut gid = None;
    for t in v["take"].as_array().unwrap() {
        let secret: [u8; 32] = unhex(&s(t, "secret")).try_into().unwrap();
        let group = GroupId::from_slice(&unhex(&s(t, "group"))).unwrap();
        assert_eq!(text(&secret), s(t, "text"), "{}", s(t, "name"));
        assert_eq!(qr(&secret, &group), s(t, "qr"), "{}", s(t, "name"));
        assert_eq!(*read(&s(t, "text")).unwrap().secret, secret);
        let r = recovery(&secret);
        assert_eq!(r.k1.public(), unhex(&s(t, "k1")).as_slice(), "{}", s(t, "name"));
        assert_eq!(r.k2.public(), unhex(&s(t, "k2")).as_slice(), "{}", s(t, "name"));
        rec = Some(r);
        gid = Some(group);
    }
    let (rec, gid) = (rec.unwrap(), gid.unwrap());
    for t in v["read"].as_array().unwrap() {
        let r = read(&s(t, "input")).unwrap_or_else(|e| panic!("{}: {e:?}", s(t, "name")));
        assert_eq!(r.secret.to_vec(), unhex(&s(t, "secret")), "{}", s(t, "name"));
        assert_eq!(r.group.map(|g| g.0.to_vec()), t["group"].as_str().map(unhex), "{}", s(t, "name"));
    }
    for t in v["refuse"].as_array().unwrap() {
        let got = read(&s(t, "input")).err().map(reason_name);
        assert_eq!(got.as_deref(), Some(s(t, "reason").as_str()), "{}", s(t, "name"));
    }
    for t in v["check"].as_array().unwrap() {
        let got = check(&read(&s(t, "input")).unwrap(), &gid, &rec).err().map(reason_name);
        assert_eq!(got.as_deref(), Some(s(t, "reason").as_str()), "{}", s(t, "name"));
    }
}
