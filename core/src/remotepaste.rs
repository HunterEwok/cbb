// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The text of a remote paste as it may go in (docs/design.md, "Remote
//! paste"): one rule for `cbb` and the phones' apps, so that a paste of
//! nothing but control characters is refused everywhere alike.

use alloc::string::String;
use alloc::vec::Vec;

use crate::error::{Error, Result};

/// The text as it may go in: newlines and tabs, without other control
/// characters and without terminal escape sequences, so that a paste cannot
/// move a terminal's cursor or run what the user does not see. CR LF and a
/// lone CR become LF.
pub fn clean(text: &str) -> String {
    let c: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut rest: &[char] = &c;
    while let Some((&ch, after)) = rest.split_first() {
        let n = match ch {
            '\r' => {
                out.push('\n');
                if after.first() == Some(&'\n') { 2 } else { 1 }
            }
            '\u{1b}' => escape_len(rest),
            '\u{9b}' => csi_len(after).saturating_add(1),
            '\n' | '\t' => {
                out.push(ch);
                1
            }
            ch if ch < ' ' || ('\u{7f}'..'\u{a0}').contains(&ch) => 1,
            ch => {
                out.push(ch);
                1
            }
        };
        rest = rest.get(n..).unwrap_or(&[]);
    }
    out
}

/// The length of the escape sequence at the start of s, which starts with
/// ESC: CSI up to its final byte, OSC, DCS and the like up to BEL or ESC \,
/// or ESC and one character.
fn escape_len(s: &[char]) -> usize {
    let tail = s.get(2..).unwrap_or(&[]);
    match s.get(1) {
        None => s.len(),
        Some('[') => csi_len(tail).saturating_add(2),
        Some(']' | 'P' | 'X' | '^' | '_') => {
            for (i, ch) in tail.iter().enumerate() {
                if *ch == '\u{7}' {
                    return i.saturating_add(3);
                }
                if *ch == '\u{1b}' && tail.get(i.saturating_add(1)) == Some(&'\\') {
                    return i.saturating_add(4);
                }
            }
            s.len()
        }
        Some(_) => 2,
    }
}

/// The length of a CSI sequence's parameters and final byte.
fn csi_len(s: &[char]) -> usize {
    for (i, &c) in s.iter().enumerate() {
        if ('@'..='~').contains(&c) {
            return i.saturating_add(1);
        }
        if !(' '..='~').contains(&c) {
            return i;
        }
    }
    s.len()
}

/// The text cleaned for a paste ([`clean`]), or the error a person reads
/// when nothing is left of it.
pub fn to_paste(text: &str) -> Result<String> {
    let t = clean(text);
    if t.is_empty() {
        return Err(Error::msg("nothing to paste: the text is empty or only control characters"));
    }
    Ok(t)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cleans_as_the_full_member() {
        // The cases of internal/remotepaste's TestClean.
        for (input, want) in [
            ("ls -l\n", "ls -l\n"),
            ("a\tb\r\nc\rd", "a\tb\nc\nd"),
            ("Grüße, 世界 🙂", "Grüße, 世界 🙂"),
            ("red \x1b[31mtext\x1b[0m", "red text"),
            ("title \x1b]0;pwned\x07ok", "title ok"),
            ("osc \x1b]8;;x\x1b\\link", "osc link"),
            ("csi \u{9b}2Jclear", "csi clear"),
            ("bell\x07 nul\0 del\x7f", "bell nul del"),
            ("esc at the end \x1b", "esc at the end "),
            ("keypad \x1b=on", "keypad on"),
        ] {
            assert_eq!(clean(input), want, "{input:?}");
        }
    }

    #[test]
    fn nothing_left_is_refused() {
        assert!(to_paste("\x1b[2J\x07").unwrap_err().to_string().contains("only control characters"));
        assert!(to_paste("").is_err());
        assert_eq!(to_paste("ok\r\n").unwrap(), "ok\n");
    }
}
