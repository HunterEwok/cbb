// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The content envelope: one form for every type, a secret of any type,
//! and what an older reader does with a type it does not know.

use alloc::vec;

use super::*;
use crate::format::copy::CONTENT_STEPS;

fn raw(entries: Vec<(u16, Value<'_>)>) -> Vec<u8> {
    write_content(&Value::Map(entries)).unwrap()
}

fn png() -> media::Manifest {
    media::Manifest {
        size: 3,
        parts: vec![media::Part { kind: "image/png".into(), size: 3, sha256: Some(vec![7; 32]), ..Default::default() }],
    }
}

fn files() -> media::Manifest {
    media::Manifest {
        size: 5,
        parts: vec![
            media::Part { path: "docs".into(), dir: true, ..Default::default() },
            media::Part { path: "docs/a.txt".into(), size: 5, sha256: Some(vec![1; 32]), ..Default::default() },
        ],
    }
}

#[test]
fn every_type_reads_back_padded_to_a_step() {
    let cases = [
        Content::text("hello", false),
        Content::text("hunter2", true),
        Content { kind: TYPE_MEDIA, manifest: Some(png()), text: Some("alt".into()), ..Content::default() },
        Content { kind: TYPE_FILES, manifest: Some(files()), ttl: 2, via: 1, ..Content::default() },
        Content::state(&[0xa1, 0x01, 0x02]),
    ];
    for c in cases {
        let b = c.write().unwrap();
        assert!(CONTENT_STEPS.contains(&b.len()), "{} bytes", b.len());
        assert_eq!(Content::read(&b).unwrap(), c);
    }
}

#[test]
fn any_type_may_be_a_secret() {
    for mut c in [
        Content::text("x", false),
        Content { kind: TYPE_MEDIA, manifest: Some(png()), ..Content::default() },
        Content { kind: TYPE_FILES, manifest: Some(files()), ..Content::default() },
        Content::state(&[0x01]),
    ] {
        c.flags = FLAG_SECRET;
        let back = Content::read(&c.write().unwrap()).unwrap();
        assert!(back.is_secret());
    }
}

#[test]
fn what_this_version_does_not_know_is_kept_not_written() {
    // A type of a later version: read, so the copy is passed on, but never
    // written.
    let later = Content::read(&raw(vec![(0, Value::Uint(9)), (5, Value::Text("x"))])).unwrap();
    assert!(later.unknown && !later.writable());
    assert_eq!(later.write(), None, "this version writes no content it does not know");
    // A flag of a later version.
    let flag = Content::read(&raw(vec![(0, Value::Uint(1)), (2, Value::Uint(3)), (5, Value::Text("x"))])).unwrap();
    assert!(flag.unknown && !flag.writable());
    // A critical field of a later version.
    let field = Content::read(&raw(vec![(0, Value::Uint(1)), (5, Value::Text("x")), (40, Value::Uint(1))])).unwrap();
    assert!(field.unknown && !field.writable());
    // An optional field is skipped.
    let opt = Content::read(&raw(vec![(0, Value::Uint(1)), (5, Value::Text("x")), (300, Value::Uint(1))])).unwrap();
    assert!(!opt.unknown && opt.writable());
    // A device's state is shown, never pasted.
    assert!(!Content::state(&[0x01]).writable());
}

#[test]
fn rows_and_rows_between_fields() {
    type Case<'a> = (&'a str, Vec<(u16, Value<'a>)>, Rule);
    let refused: Vec<Case<'_>> = vec![
        ("type 0", vec![(0, Value::Uint(0))], RULE_TYPE),
        ("type as text", vec![(0, Value::Text("t"))], crate::format::copy::RULE_SHAPE),
        ("flags 0 written", vec![(0, Value::Uint(1)), (2, Value::Uint(0)), (5, Value::Text("x"))], Rule::FORM_DEFAULT),
        ("ttl 5", vec![(0, Value::Uint(1)), (3, Value::Uint(5)), (5, Value::Text("x"))], RULE_TTL),
        ("via 3", vec![(0, Value::Uint(1)), (4, Value::Uint(3)), (5, Value::Text("x"))], RULE_VIA),
        ("text without text", vec![(0, Value::Uint(1))], RULE_TEXT),
        ("empty text", vec![(0, Value::Uint(1)), (5, Value::Text(""))], Rule::FORM_DEFAULT),
        ("text as bytes", vec![(0, Value::Uint(1)), (5, Value::Bytes(b"x"))], RULE_TEXT),
        ("media without a manifest", vec![(0, Value::Uint(2)), (5, Value::Text("x"))], RULE_MANIFEST),
        ("state on a text", vec![(0, Value::Uint(1)), (5, Value::Text("x")), (7, Value::Bytes(&[1]))], RULE_DATA),
        ("state without data", vec![(0, Value::Uint(4))], RULE_DATA),
        ("state not an item", vec![(0, Value::Uint(4)), (7, Value::Bytes(&[0x82, 0x01]))], RULE_DATA),
        ("state with text", vec![(0, Value::Uint(4)), (5, Value::Text("x")), (7, Value::Bytes(&[1]))], RULE_TEXT),
    ];
    for (name, entries, rule) in refused {
        assert_eq!(Content::read(&raw(entries)), Err(rule), "{name}");
    }
    let big = vec![0x40; MAX_STATE + 1];
    assert_eq!(Content::state(&big).check(), Err(RULE_DATA));
    // A manifest of files on media, and the reverse.
    assert_eq!(Content { kind: TYPE_MEDIA, manifest: Some(files()), ..Content::default() }.check(), Err(RULE_MANIFEST));
    assert_eq!(Content { kind: TYPE_FILES, manifest: Some(png()), ..Content::default() }.check(), Err(RULE_MANIFEST));
    // A manifest's own rules: a path that walks up.
    let mut up = files();
    up.parts[1].path = "../a.txt".into();
    up.parts.remove(0);
    assert_eq!(Content { kind: TYPE_FILES, manifest: Some(up), ..Content::default() }.check(), Err(RULE_MANIFEST));
    // The rules of 0.6 on names of files.
    let named = |paths: &[&str]| {
        let parts: Vec<media::Part> = paths
            .iter()
            .map(|p| media::Part { path: (*p).into(), size: 1, sha256: Some(vec![1; 32]), ..Default::default() })
            .collect();
        let m = media::Manifest { size: parts.len() as i64, parts };
        Content { kind: TYPE_FILES, manifest: Some(m), ..Content::default() }.check()
    };
    for ok in [&["a.txt", "b.txt"][..], &["caf\u{e9}.txt"], &["COM10.txt"], &["CONSOLE"], &["\u{d55c}.txt"]] {
        assert_eq!(named(ok), Ok(()), "{ok:?}");
    }
    for bad in [
        &["con"][..],
        &["NUL.txt"],
        &["com1.tar.gz"],
        &["LPT9"],
        &["COM\u{b9}.txt"],
        &["lpt\u{b3}"],
        &["COM0"],
        &["CONIN$"],
        &["conout$.log"],
        &["CON .txt"],
        &["dir/aux.c"],
        &["A.txt", "a.txt"],
        &["\u{c9}t\u{e9}.txt", "\u{e9}t\u{e9}.txt"],
        &["cafe\u{301}.txt"],
        &["\u{1112}\u{1161}\u{11ab}.txt"],
        &["\u{304b}\u{3099}.txt"],
        &["a\u{202e}txt.exe"],
        &["a\u{2066}b"],
        &["a\u{200f}b"],
        &["Readme", "readme/x"],
    ] {
        assert_eq!(named(bad), Err(RULE_MANIFEST), "{bad:?}");
    }
    // Padding that is not the one padding of its step.
    let mut b = Content::text("x", false).write().unwrap();
    let middle = b.len() / 2;
    b[middle] = 1;
    assert_eq!(Content::read(&b), Err(crate::format::copy::RULE_CONTENT_PAD));
}

#[test]
fn ttl_names_one_of_four_lifetimes() {
    let mut c = Content::text("x", true);
    assert_eq!(c.ttl_ms(), None);
    for (i, ms) in TTLS_MS.iter().enumerate() {
        c.ttl = i as u64 + 1;
        assert_eq!(c.ttl_ms(), Some(*ms));
    }
}
