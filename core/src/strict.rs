// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The strict form of signed bodies (docs/protocol.md, section 1, "Signed
//! bodies"), which every member reads alike, as Go's checkStrict.

// The parser's arithmetic is on positions in the input, each at most one or
// a few past its end, so it cannot overflow.
#![allow(clippy::arithmetic_side_effects, reason = "positions in the input cannot overflow")]

use alloc::collections::BTreeSet;
use alloc::format;
use alloc::string::String;

use crate::error::{Error, Result};

/// How deeply a signed body nests arrays and objects at most.
const MAX_DEPTH: usize = 16;

/// Checks that b is one JSON object in valid UTF-8; member names of 1 to 64
/// of a-z, 0-9 and _, without escapes, none twice in one object; no null;
/// integers only, without fraction or exponent, in the range of i64; a
/// surrogate escape only as one half of a pair. Each name in required must
/// be a member of the object.
pub fn check(b: &[u8], required: &[&str]) -> Result<()> {
    if core::str::from_utf8(b).is_err() {
        return Err(Error::msg("a signed body is not valid UTF-8"));
    }
    let mut p = Parser { b, i: 0 };
    p.space();
    if p.peek() != Some(b'{') {
        return Err(Error::msg("a signed body is not a JSON object"));
    }
    let names = p.object(0).map_err(|e| Error::msg(format!("a signed body: {e}")))?;
    p.space();
    if p.i != b.len() {
        return Err(Error::msg("a signed body has more after its object"));
    }
    for n in required {
        if !names.contains(*n) {
            return Err(Error::msg(format!("a signed body has no {n}")));
        }
    }
    Ok(())
}

/// Checks that every number in b, outside its strings, is an integer as
/// check takes it: never "-0", a fraction or an exponent. Readers differ on
/// those (serde_json takes "-0" for a float, Go for 0), so the member
/// protocol's frames pass this first, members a reader does not know
/// included. It only scans: whether b is JSON is for the decoder.
pub fn integers_only(b: &[u8]) -> Result<()> {
    let mut i = 0;
    while let Some(&c) = b.get(i) {
        match c {
            b'"' => {
                i += 1;
                while let Some(&s) = b.get(i).filter(|s| **s != b'"') {
                    i += if s == b'\\' { 2 } else { 1 };
                }
                i += 1;
            }
            b'-' | b'0'..=b'9' => {
                let mut p = Parser { b, i };
                p.integer().map_err(Error::msg)?;
                i = p.i;
            }
            _ => i += 1,
        }
    }
    Ok(())
}

/// Checks that b is a signed body in the strict form and in its canonical
/// form (docs/protocol.md, Conventions, "Signed bodies"): exactly
/// the bytes canonicalize gives for what it holds, as Go's
/// strict.CheckCanonical.
pub fn check_canonical(b: &[u8], required: &[&str]) -> Result<()> {
    check(b, required)?;
    if canonicalize(b)? != b {
        return Err(Error::msg("a signed body is not in its canonical form"));
    }
    Ok(())
}

/// Returns the canonical form of b, a body in the strict form: no
/// whitespace, the members of every object in bytewise order of their
/// names, and in strings only the escapes \", \\ and \u00xx (lower-case
/// hex) for a character below U+0020.
pub fn canonicalize(b: &[u8]) -> Result<alloc::vec::Vec<u8>> {
    check(b, &[])?;
    let v: serde_json::Value = serde_json::from_slice(b).map_err(|_| Error::msg("a signed body does not decode"))?;
    let mut out = alloc::vec::Vec::with_capacity(b.len());
    write_canonical(&mut out, &v);
    Ok(out)
}

/// Writes v in the canonical form; serde_json's maps are sorted by name.
pub(crate) fn write_canonical(out: &mut alloc::vec::Vec<u8>, v: &serde_json::Value) {
    use serde_json::Value;
    match v {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(n) => out.extend_from_slice(format!("{n}").as_bytes()),
        Value::String(s) => write_string(out, s),
        Value::Array(a) => {
            out.push(b'[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_canonical(out, x);
            }
            out.push(b']');
        }
        Value::Object(m) => {
            out.push(b'{');
            for (i, (k, x)) in m.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_string(out, k);
                out.push(b':');
                write_canonical(out, x);
            }
            out.push(b'}');
        }
    }
}

/// The lowercase hex digit of the low four bits of n.
fn hex_digit(n: u8) -> u8 {
    b"0123456789abcdef".get(usize::from(n & 15)).copied().unwrap_or(b'0')
}

fn write_string(out: &mut alloc::vec::Vec<u8>, s: &str) {
    out.push(b'"');
    for &c in s.as_bytes() {
        match c {
            b'"' | b'\\' => out.extend_from_slice(&[b'\\', c]),
            0..=0x1f => out.extend_from_slice(&[b'\\', b'u', b'0', b'0', hex_digit(c >> 4), hex_digit(c & 15)]),
            _ => out.push(c),
        }
    }
    out.push(b'"');
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
}

type Step<T = ()> = core::result::Result<T, &'static str>;

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }

    fn space(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.i += 1;
        }
    }

    fn value(&mut self, depth: usize) -> Step {
        self.space();
        match self.peek() {
            None => Err("it ends early"),
            Some(b'{' | b'[') if depth >= MAX_DEPTH => Err("it nests too deeply"),
            Some(b'{') => self.object(depth + 1).map(|_| ()),
            Some(b'[') => self.array(depth + 1),
            Some(b'"') => self.string(),
            Some(b't') => self.literal(b"true"),
            Some(b'f') => self.literal(b"false"),
            Some(b'n') => Err("it has a null"),
            Some(b'-' | b'0'..=b'9') => self.integer(),
            Some(_) => Err("an unexpected character"),
        }
    }

    fn object(&mut self, depth: usize) -> Step<BTreeSet<String>> {
        self.i += 1; // {
        let mut names = BTreeSet::new();
        self.space();
        if self.peek() == Some(b'}') {
            self.i += 1;
            return Ok(names);
        }
        loop {
            self.space();
            let name = self.name()?;
            if !names.insert(name) {
                return Err("a member is there twice");
            }
            self.space();
            if self.peek() != Some(b':') {
                return Err("a member has no value");
            }
            self.i += 1;
            self.value(depth)?;
            self.space();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b'}') => {
                    self.i += 1;
                    return Ok(names);
                }
                Some(_) => return Err("an unexpected character in an object"),
                None => return Err("it ends early"),
            }
        }
    }

    /// A member name: 1 to 64 of a-z, 0-9 and _ in quotes.
    fn name(&mut self) -> Step<String> {
        if self.peek() != Some(b'"') {
            return Err("a member has no name");
        }
        let start = self.i + 1;
        self.i = start;
        loop {
            match self.peek() {
                None => return Err("it ends early"),
                Some(b'"') => break,
                Some(b'a'..=b'z' | b'0'..=b'9' | b'_') => self.i += 1,
                Some(_) => return Err("a member name is not of a-z, 0-9 and _"),
            }
        }
        let name = self.b.get(start..self.i).ok_or("it ends early")?;
        self.i += 1;
        if name.is_empty() || name.len() > 64 {
            return Err("a member name is not 1 to 64 characters");
        }
        // Only ASCII got here.
        Ok(String::from(core::str::from_utf8(name).unwrap_or_default()))
    }

    fn array(&mut self, depth: usize) -> Step {
        self.i += 1; // [
        self.space();
        if self.peek() == Some(b']') {
            self.i += 1;
            return Ok(());
        }
        loop {
            self.value(depth)?;
            self.space();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b']') => {
                    self.i += 1;
                    return Ok(());
                }
                Some(_) => return Err("an unexpected character in an array"),
                None => return Err("it ends early"),
            }
        }
    }

    fn string(&mut self) -> Step {
        self.i += 1; // "
        loop {
            match self.peek() {
                None => return Err("it ends early"),
                Some(b'"') => {
                    self.i += 1;
                    return Ok(());
                }
                Some(c) if c < 0x20 => return Err("a string holds a control character"),
                Some(b'\\') => {}
                Some(_) => {
                    self.i += 1;
                    continue;
                }
            }
            self.i += 1;
            match self.peek() {
                None => return Err("it ends early"),
                Some(b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't') => self.i += 1,
                Some(b'u') => {
                    let r = self.hex4()?;
                    if (0xd800..0xdc00).contains(&r) {
                        if self.b.get(self.i) != Some(&b'\\') || self.b.get(self.i + 1) != Some(&b'u') {
                            return Err("a string has half a surrogate pair");
                        }
                        self.i += 1;
                        if !(0xdc00..=0xdfff).contains(&self.hex4()?) {
                            return Err("a string has half a surrogate pair");
                        }
                    } else if (0xdc00..=0xdfff).contains(&r) {
                        return Err("a string has half a surrogate pair");
                    }
                }
                Some(_) => return Err("a string has an unknown escape"),
            }
        }
    }

    /// The u and four hex digits of a \u escape.
    fn hex4(&mut self) -> Step<u32> {
        let digits = self.b.get(self.i + 1..self.i + 5).ok_or("it ends early")?;
        let mut v = 0;
        for &c in digits {
            v = v * 16 + (c as char).to_digit(16).ok_or("a string has a wrong \\u escape")?;
        }
        self.i += 5;
        Ok(v)
    }

    fn literal(&mut self, s: &[u8]) -> Step {
        if !self.b.get(self.i..).is_some_and(|rest| rest.starts_with(s)) {
            return Err("an unknown literal");
        }
        self.i += s.len();
        Ok(())
    }

    /// -?[1-9][0-9]*|0, in the range of i64; "-0" is refused (serde_json
    /// reads it as a float, other readers as 0).
    fn integer(&mut self) -> Step {
        let start = self.i;
        if self.peek() == Some(b'-') {
            self.i += 1;
        }
        let digits = self.i;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.i += 1;
        }
        if self.i == digits {
            return Err("a number has no digits");
        }
        let zero = self.b.get(digits) == Some(&b'0');
        if zero && self.i > digits + 1 {
            return Err("a number has a leading zero");
        }
        if zero && digits > start {
            return Err("a number is a negative zero");
        }
        if matches!(self.peek(), Some(b'.' | b'e' | b'E')) {
            return Err("a number is not an integer");
        }
        let text = core::str::from_utf8(self.b.get(start..self.i).ok_or("a number is not valid")?)
            .map_err(|_| "a number is not valid")?;
        text.parse::<i64>().map(|_| ()).map_err(|_| "a number is out of range")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical() {
        for (input, want) in [
            (r#"{}"#, r#"{}"#),
            (r#"{"b":1,"a":2}"#, r#"{"a":2,"b":1}"#),
            (r#" { "a" : [ 1 , true , false , "x" ] } "#, r#"{"a":[1,true,false,"x"]}"#),
            (r#"{"a":"\/\b\f\n\r\t"}"#, r#"{"a":"/\u0008\u000c\u000a\u000d\u0009"}"#),
            (r#"{"a":"\u00e9\u20ac\ud83d\ude00"}"#, "{\"a\":\"\u{e9}\u{20ac}\u{1F600}\"}"),
            (r#"{"a":"\u001F\"\\"}"#, r#"{"a":"\u001f\"\\"}"#),
            (r#"{"a":{"z":0,"y":-1},"_":"","0":1}"#, r#"{"0":1,"_":"","a":{"y":-1,"z":0}}"#),
            (r#"{"ab":1,"a":2,"b":3}"#, r#"{"a":2,"ab":1,"b":3}"#),
            (r#"{"a":[{"c":1,"b":2},[]]}"#, r#"{"a":[{"b":2,"c":1},[]]}"#),
        ] {
            let got = canonicalize(input.as_bytes()).unwrap();
            assert_eq!(core::str::from_utf8(&got).unwrap(), want, "{input}");
            assert!(check_canonical(&got, &[]).is_ok(), "{want}");
            assert_eq!(check_canonical(input.as_bytes(), &[]).is_ok(), input == want, "{input}");
        }
        for input in [
            r#"{"b":1,"a":2}"#,
            r#"{"a":1,"a":2}"#,
            r#"{ "a":1}"#,
            r#"{"a":[1, 2]}"#,
            r#"{"a":"\/"}"#,
            r#"{"a":"\n"}"#,
            r#"{"a":"\u0041"}"#,
            r#"{"a":"\u001F"}"#,
            r#"{"a":"\u00e9"}"#,
            "{\"a\":1}\n",
            r#"{"a":null}"#,
            r#"{"a":1.0}"#,
        ] {
            assert!(check_canonical(input.as_bytes(), &[]).is_err(), "{input} is taken");
        }
    }
}
