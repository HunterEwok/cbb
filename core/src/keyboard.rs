// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Typing a text as a USB or Bluetooth keyboard (docs/roadmap.md, item 25):
//! the keys of a layout and the HID boot keyboard's reports that press
//! them.
//!
//! A keyboard sends the position of a key, not a character: the host's
//! layout turns the position into one. So the board needs the layout that
//! is active on the host, and a character that layout cannot type is
//! refused rather than typed as something else. There is no key for "type
//! U+xxxx" that works on a TV, a console or a BIOS.

use alloc::vec::Vec;

/// Shift, of the modifier bits in a report's first byte.
pub const LEFT_SHIFT: u8 = 0x02;

/// The usages of the keys a text needs besides its characters.
pub const ENTER: u8 = 0x28;
pub const TAB: u8 = 0x2b;
pub const SPACE: u8 = 0x2c;

/// A key of the HID keyboard page and the modifiers held with it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Key {
    pub usage: u8,
    pub modifiers: u8,
}

impl Key {
    const fn plain(usage: u8) -> Key {
        Key { usage, modifiers: 0 }
    }

    const fn shift(usage: u8) -> Key {
        Key { usage, modifiers: LEFT_SHIFT }
    }

    /// The boot keyboard's report that holds this key down: the
    /// modifiers, a reserved byte and up to six keys.
    pub fn report(self) -> [u8; 8] {
        [self.modifiers, 0, self.usage, 0, 0, 0, 0, 0]
    }
}

/// The report with every key up.
pub const RELEASE: [u8; 8] = [0; 8];

/// The HID boot keyboard's report descriptor (HID 1.11, appendix B.1):
/// eight modifier bits, a reserved byte, five LEDs and six keys; the USB
/// keyboard and the Bluetooth LE keyboard's report map.
pub const DESCRIPTOR: [u8; 63] = [
    0x05, 0x01, // usage page: generic desktop
    0x09, 0x06, // usage: keyboard
    0xa1, 0x01, // collection: application
    0x05, 0x07, //   usage page: keyboard
    0x19, 0xe0, //   usage minimum: left control
    0x29, 0xe7, //   usage maximum: right GUI
    0x15, 0x00, //   logical minimum: 0
    0x25, 0x01, //   logical maximum: 1
    0x75, 0x01, //   report size: 1
    0x95, 0x08, //   report count: 8
    0x81, 0x02, //   input: the modifiers
    0x95, 0x01, //   report count: 1
    0x75, 0x08, //   report size: 8
    0x81, 0x01, //   input: the reserved byte
    0x95, 0x05, //   report count: 5
    0x75, 0x01, //   report size: 1
    0x05, 0x08, //   usage page: LEDs
    0x19, 0x01, //   usage minimum: num lock
    0x29, 0x05, //   usage maximum: kana
    0x91, 0x02, //   output: the LEDs
    0x95, 0x01, //   report count: 1
    0x75, 0x03, //   report size: 3
    0x91, 0x01, //   output: padding
    0x95, 0x06, //   report count: 6
    0x75, 0x08, //   report size: 8
    0x15, 0x00, //   logical minimum: 0
    0x25, 0x65, //   logical maximum: 101
    0x05, 0x07, //   usage page: keyboard
    0x19, 0x00, //   usage minimum: 0
    0x29, 0x65, //   usage maximum: 101
    0x81, 0x00, //   input: the keys
    0xc0, // end collection
];

/// A layout active on the host, by the name a user sets it with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Layout {
    /// English (US), the default of most TVs and computers.
    Us,
    /// Russian (the JCUKEN layout), as Windows, macOS's "Russian - PC" and XKB's ru
    /// have it.
    Ru,
}

impl Layout {
    pub const ALL: [Layout; 2] = [Layout::Us, Layout::Ru];

    pub fn name(self) -> &'static str {
        match self {
            Layout::Us => "us",
            Layout::Ru => "ru",
        }
    }

    pub fn from_name(name: &str) -> Option<Layout> {
        Layout::ALL.into_iter().find(|l| l.name().eq_ignore_ascii_case(name))
    }

    /// The key that types c, if this layout has one. A new line presses
    /// Enter and a tab Tab; a carriage return types nothing (see reports).
    pub fn key(self, c: char) -> Option<Key> {
        match c {
            '\n' => return Some(Key::plain(ENTER)),
            '\t' => return Some(Key::plain(TAB)),
            ' ' => return Some(Key::plain(SPACE)),
            _ => {}
        }
        match self {
            Layout::Us => us(c),
            Layout::Ru => ru(c),
        }
    }

    /// The characters of text, each once and in the order they first come,
    /// that this layout cannot type.
    pub fn untypeable(self, text: &str) -> Vec<char> {
        let mut out = Vec::new();
        for c in text.chars() {
            if c != '\r' && self.key(c).is_none() && !out.contains(&c) {
                out.push(c);
            }
        }
        out
    }

    /// The reports that type text: each key down and then all keys up, so
    /// that the same key twice in a row is two presses. A carriage return
    /// types nothing, so a CRLF line end is one Enter. None when the
    /// layout cannot type a character of it (untypeable says which).
    pub fn reports(self, text: &str) -> Option<Vec<[u8; 8]>> {
        let mut out = Vec::with_capacity(text.len().saturating_mul(2));
        for c in text.chars() {
            if c == '\r' {
                continue;
            }
            out.push(self.key(c)?.report());
            out.push(RELEASE);
        }
        Some(out)
    }
}

/// The digits' row and the keys right of it, which most layouts share.
fn digit(c: char) -> Option<Key> {
    Some(Key::plain(match c {
        // The ranges below keep the sums within a byte.
        '1'..='9' => 0x1e_u8.wrapping_add((c as u8).wrapping_sub(b'1')),
        '0' => 0x27,
        '-' => 0x2d,
        '=' => 0x2e,
        _ => return None,
    }))
}

fn us(c: char) -> Option<Key> {
    if let Some(k) = digit(c) {
        return Some(k);
    }
    Some(match c {
        'a'..='z' => Key::plain(0x04_u8.wrapping_add((c as u8).wrapping_sub(b'a'))),
        'A'..='Z' => Key::shift(0x04_u8.wrapping_add((c as u8).wrapping_sub(b'A'))),
        '!' => Key::shift(0x1e),
        '@' => Key::shift(0x1f),
        '#' => Key::shift(0x20),
        '$' => Key::shift(0x21),
        '%' => Key::shift(0x22),
        '^' => Key::shift(0x23),
        '&' => Key::shift(0x24),
        '*' => Key::shift(0x25),
        '(' => Key::shift(0x26),
        ')' => Key::shift(0x27),
        '_' => Key::shift(0x2d),
        '+' => Key::shift(0x2e),
        '[' => Key::plain(0x2f),
        '{' => Key::shift(0x2f),
        ']' => Key::plain(0x30),
        '}' => Key::shift(0x30),
        '\\' => Key::plain(0x31),
        '|' => Key::shift(0x31),
        ';' => Key::plain(0x33),
        ':' => Key::shift(0x33),
        '\'' => Key::plain(0x34),
        '"' => Key::shift(0x34),
        '`' => Key::plain(0x35),
        '~' => Key::shift(0x35),
        ',' => Key::plain(0x36),
        '<' => Key::shift(0x36),
        '.' => Key::plain(0x37),
        '>' => Key::shift(0x37),
        '/' => Key::plain(0x38),
        '?' => Key::shift(0x38),
        _ => return None,
    })
}

/// The Russian letters on the keys of the US letters q to /, in the US
/// keys' order: the row of q, of a and of z.
const RU_LETTERS: [(char, u8); 33] = [
    ('\u{0439}', 0x14), // short i
    ('\u{0446}', 0x1a), // tse
    ('\u{0443}', 0x08), // u
    ('\u{043a}', 0x15), // ka
    ('\u{0435}', 0x17), // ie
    ('\u{043d}', 0x1c), // en
    ('\u{0433}', 0x18), // ghe
    ('\u{0448}', 0x0c), // sha
    ('\u{0449}', 0x12), // shcha
    ('\u{0437}', 0x13), // ze
    ('\u{0445}', 0x2f), // ha
    ('\u{044a}', 0x30), // hard sign
    ('\u{0444}', 0x04), // ef
    ('\u{044b}', 0x16), // yeru
    ('\u{0432}', 0x07), // ve
    ('\u{0430}', 0x09), // a
    ('\u{043f}', 0x0a), // pe
    ('\u{0440}', 0x0b), // er
    ('\u{043e}', 0x0d), // o
    ('\u{043b}', 0x0e), // el
    ('\u{0434}', 0x0f), // de
    ('\u{0436}', 0x33), // zhe
    ('\u{044d}', 0x34), // e
    ('\u{044f}', 0x1d), // ya
    ('\u{0447}', 0x1b), // che
    ('\u{0441}', 0x06), // es
    ('\u{043c}', 0x19), // em
    ('\u{0438}', 0x05), // i
    ('\u{0442}', 0x11), // te
    ('\u{044c}', 0x10), // soft sign
    ('\u{0431}', 0x36), // be
    ('\u{044e}', 0x37), // yu
    ('\u{0451}', 0x35), // io
];

fn ru(c: char) -> Option<Key> {
    if let Some(k) = digit(c) {
        return Some(k);
    }
    if let Some(&(_, u)) = RU_LETTERS.iter().find(|&&(l, _)| l == c) {
        return Some(Key::plain(u));
    }
    // A capital: the small letter's key with Shift.
    let mut lower = c.to_lowercase();
    if let (Some(l), None) = (lower.next(), lower.next()) {
        if let Some(&(_, u)) = RU_LETTERS.iter().find(|&&(r, _)| r == l && l != c) {
            return Some(Key::shift(u));
        }
    }
    Some(match c {
        '!' => Key::shift(0x1e),
        '"' => Key::shift(0x1f),
        '\u{2116}' => Key::shift(0x20), // the numero sign
        ';' => Key::shift(0x21),
        '%' => Key::shift(0x22),
        ':' => Key::shift(0x23),
        '?' => Key::shift(0x24),
        '*' => Key::shift(0x25),
        '(' => Key::shift(0x26),
        ')' => Key::shift(0x27),
        '_' => Key::shift(0x2d),
        '+' => Key::shift(0x2e),
        '\\' => Key::plain(0x31),
        '/' => Key::shift(0x31),
        '.' => Key::plain(0x38),
        ',' => Key::shift(0x38),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn us_keys() {
        assert_eq!(Layout::Us.key('a'), Some(Key::plain(0x04)));
        assert_eq!(Layout::Us.key('Z'), Some(Key::shift(0x1d)));
        assert_eq!(Layout::Us.key('1'), Some(Key::plain(0x1e)));
        assert_eq!(Layout::Us.key('0'), Some(Key::plain(0x27)));
        assert_eq!(Layout::Us.key('@'), Some(Key::shift(0x1f)));
        assert_eq!(Layout::Us.key('?'), Some(Key::shift(0x38)));
        assert_eq!(Layout::Us.key('\n'), Some(Key::plain(ENTER)));
        assert_eq!(Layout::Us.key('\u{0439}'), None);
        // Every printable ASCII character has a key.
        for c in ' '..='~' {
            assert!(Layout::Us.key(c).is_some(), "{c:?}");
        }
    }

    #[test]
    fn ru_keys() {
        // Short i, capital short i, io and capital io; the numero sign.
        assert_eq!(Layout::Ru.key('\u{0439}'), Some(Key::plain(0x14)));
        assert_eq!(Layout::Ru.key('\u{0419}'), Some(Key::shift(0x14)));
        assert_eq!(Layout::Ru.key('\u{0451}'), Some(Key::plain(0x35)));
        assert_eq!(Layout::Ru.key('\u{0401}'), Some(Key::shift(0x35)));
        assert_eq!(Layout::Ru.key('.'), Some(Key::plain(0x38)));
        assert_eq!(Layout::Ru.key(','), Some(Key::shift(0x38)));
        assert_eq!(Layout::Ru.key('\u{2116}'), Some(Key::shift(0x20)));
        assert_eq!(Layout::Ru.key('a'), None);
        // All 33 letters, small (U+0430 to U+044F and U+0451) and capital
        // (U+0410 to U+042F and U+0401), on 33 different keys.
        let small = ('\u{0430}'..='\u{044f}').chain(['\u{0451}']);
        let mut usages: Vec<u8> = small.map(|c| Layout::Ru.key(c).unwrap().usage).collect();
        for c in ('\u{0410}'..='\u{042f}').chain(['\u{0401}']) {
            assert_eq!(Layout::Ru.key(c).unwrap().modifiers, LEFT_SHIFT, "{c}");
        }
        usages.sort();
        usages.dedup();
        assert_eq!(usages.len(), 33);
    }

    #[test]
    fn reports() {
        let r = Layout::Us.reports("aA\r\n").unwrap();
        assert_eq!(
            r,
            [
                [0, 0, 0x04, 0, 0, 0, 0, 0],
                RELEASE,
                [LEFT_SHIFT, 0, 0x04, 0, 0, 0, 0, 0],
                RELEASE,
                [0, 0, ENTER, 0, 0, 0, 0, 0],
                RELEASE
            ]
        );
        // "privet" and "Privet, mir!" (hello, world) in Cyrillic.
        assert_eq!(Layout::Us.reports("\u{043f}\u{0440}\u{0438}\u{0432}\u{0435}\u{0442}"), None);
        assert_eq!(
            Layout::Ru
                .reports("\u{041f}\u{0440}\u{0438}\u{0432}\u{0435}\u{0442}, \u{043c}\u{0438}\u{0440}!")
                .unwrap()
                .len(),
            24
        );
    }

    #[test]
    fn untypeable() {
        // "dom" (house) in Cyrillic.
        assert_eq!(Layout::Ru.untypeable("Wi-Fi: \u{0434}\u{043e}\u{043c}"), ['W', 'i', 'F']);
        assert_eq!(Layout::Us.untypeable("ok\r\n"), []);
        assert_eq!(Layout::Us.untypeable("€ and €"), ['€']);
    }

    /// testdata/interop/keyboard.json, which the Android kit's Keyboard
    /// is checked against, so that the phone and the Nano type alike:
    /// every layout's key for each candidate character, and the reports of
    /// a few texts. CBB_UPDATE_VECTORS=1 writes it again.
    #[test]
    fn vectors() {
        use serde_json::{Value, json};
        let candidates: alloc::string::String = ['\n', '\t', '\r']
            .into_iter()
            .chain(' '..='~')
            .chain('\u{0400}'..='\u{045f}')
            .chain(['\u{2116}', '\u{20ac}', '\u{00e9}'])
            .collect();
        let mut layouts = serde_json::Map::new();
        for l in Layout::ALL {
            let keys: serde_json::Map<_, _> = candidates
                .chars()
                .filter_map(|c| l.key(c).map(|k| (c.to_string(), json!([k.modifiers, k.usage]))))
                .collect();
            layouts.insert(l.name().into(), Value::Object(keys));
        }
        let hex = |r: &[u8; 8]| r.iter().map(|b| alloc::format!("{b:02x}")).collect::<alloc::string::String>();
        let texts: Vec<Value> = [
            (Layout::Us, "aA\r\n"),
            (Layout::Us, "Wi-Fi: home 42!"),
            (Layout::Us, "\u{043f}\u{0440}\u{0438}\u{0432}\u{0435}\u{0442}"),
            (Layout::Ru, "\u{041f}\u{0440}\u{0438}\u{0432}\u{0435}\u{0442}, \u{043c}\u{0438}\u{0440}!"),
            (Layout::Ru, "Wi-Fi: \u{0434}\u{043e}\u{043c}"),
            (Layout::Us, "\u{20ac} and \u{20ac}"),
        ]
        .into_iter()
        .map(|(l, t)| {
            let mut o = json!({"layout": l.name(), "text": t});
            match l.reports(t) {
                Some(r) => o["reports"] = r.iter().map(hex).collect(),
                None => o["untypeable"] = l.untypeable(t).iter().map(|c| c.to_string()).collect(),
            }
            o
        })
        .collect();
        let want = json!({"candidates": candidates, "layouts": layouts, "texts": texts});
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../testdata/interop/keyboard.json");
        if std::env::var("CBB_UPDATE_VECTORS").as_deref() == Ok("1") {
            // ASCII only, as the repository's text is outside the apps' translations.
            let mut out = alloc::string::String::new();
            for c in serde_json::to_string_pretty(&want).unwrap().chars() {
                if c.is_ascii() {
                    out.push(c);
                } else {
                    out.push_str(&alloc::format!("\\u{:04x}", c as u32));
                }
            }
            out.push('\n');
            std::fs::write(&path, out).unwrap();
        }
        let got: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(
            got,
            want,
            "{} is out of date: CBB_UPDATE_VECTORS=1 cargo test -p cbb-core keyboard",
            path.display()
        );
    }

    #[test]
    fn names() {
        for l in Layout::ALL {
            assert_eq!(Layout::from_name(l.name()), Some(l));
        }
        assert_eq!(Layout::from_name("RU"), Some(Layout::Ru));
        assert_eq!(Layout::from_name("de"), None);
    }
}
