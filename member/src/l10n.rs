// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The command line in the user's language (docs/roadmap.md, item 49): the
//! language comes from the locale (`LANGUAGE`, `LC_ALL`, `LC_MESSAGES`,
//! `LANG`, as gettext reads them), and English where the project has no
//! translation. The translations are `member/l10n/<language>.json`, each an
//! object from the English text to the translated one; a text is written
//! with `tr!`, whose `{}` take the arguments in order and `{0}`, `{1}` by
//! their place, so that a translation may put them in another order.
//!
//! Only what the command line says to its user is translated; the service's
//! log and the errors the service sends stay in English.

use std::collections::HashMap;
use std::fmt::Display;
use std::sync::OnceLock;

/// The languages of the project besides English, with their translations.
const CATALOGS: &[(&str, &str)] = &[
    ("zh", include_str!("../l10n/zh.json")),
    ("es", include_str!("../l10n/es.json")),
    ("ru", include_str!("../l10n/ru.json")),
    ("ar", include_str!("../l10n/ar.json")),
    ("sw", include_str!("../l10n/sw.json")),
    ("he", include_str!("../l10n/he.json")),
    ("hi", include_str!("../l10n/hi.json")),
];

/// The languages of the catalogs, besides English.
#[cfg_attr(not(any(target_os = "macos", target_os = "linux")), allow(dead_code))]
pub const LANGS: [&str; 7] = ["zh", "es", "ru", "ar", "sw", "he", "hi"];

/// The text in the user's language, or the English one as it is.
macro_rules! tr {
    ($s:literal) => {
        $crate::l10n::text($s)
    };
    ($s:literal, $($a:expr),+ $(,)?) => {
        $crate::l10n::fill($crate::l10n::text($s), &[$(&$a as &dyn ::std::fmt::Display),+])
    };
}

/// The language of the locale the variables give, in their order of
/// precedence: one of the catalogs' or "en". `LANGUAGE` is a list, and C
/// and POSIX mean English.
pub fn pick(vars: &[Option<String>]) -> &'static str {
    for v in vars.iter().flatten() {
        if v.is_empty() {
            continue;
        }
        for entry in v.split(':') {
            let code = entry.split(['_', '.', '@', '-']).next().unwrap_or("").to_ascii_lowercase();
            if code == "c" || code == "posix" || code == "en" {
                return "en";
            }
            if let Some((c, _)) = CATALOGS.iter().find(|(c, _)| *c == code) {
                return c;
            }
        }
        // The first variable set decides, as in gettext; a language the
        // project has no words for is English.
        return "en";
    }
    "en"
}

/// The user's language, read once.
fn lang() -> &'static str {
    // Tests compare the English texts, whatever the developer's locale.
    if cfg!(test) {
        return "en";
    }
    static LANG: OnceLock<&'static str> = OnceLock::new();
    LANG.get_or_init(|| {
        let var = |k: &str| std::env::var(k).ok();
        // LANGUAGE counts only when the locale is not C, as in gettext.
        let locale = [var("LC_ALL"), var("LC_MESSAGES"), var("LANG")];
        let c = pick(&locale) == "en"
            && locale.iter().flatten().find(|v| !v.is_empty()).is_none_or(|v| v == "C" || v == "POSIX");
        if c {
            return "en";
        }
        let mut all = vec![var("LANGUAGE")];
        all.extend(locale);
        pick(&all)
    })
}

/// The translation of an English text into the language, if there is one.
pub fn lookup(lang: &str, english: &str) -> Option<&'static str> {
    static TABLES: OnceLock<HashMap<&'static str, HashMap<String, String>>> = OnceLock::new();
    let tables = TABLES.get_or_init(|| {
        CATALOGS
            .iter()
            .map(|(c, json)| (*c, serde_json::from_str::<HashMap<String, String>>(json).unwrap_or_default()))
            .collect()
    });
    tables.get(lang)?.get(english).map(String::as_str).filter(|t| !t.is_empty())
}

/// The text in the user's language.
pub fn text(english: &'static str) -> &'static str {
    match lang() {
        "en" => english,
        l => lookup(l, english).unwrap_or(english),
    }
}

/// The text with its `{}` (in order) and `{N}` (by place) replaced by the
/// arguments; `{{` and `}}` are braces.
pub fn fill(template: &str, args: &[&dyn Display]) -> String {
    let mut out = String::with_capacity(template.len() + 16 * args.len());
    let mut next = 0;
    let mut chars = template.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '{' if chars.peek() == Some(&'{') => {
                chars.next();
                out.push('{');
            }
            '}' if chars.peek() == Some(&'}') => {
                chars.next();
                out.push('}');
            }
            '{' => {
                let mut index = String::new();
                for d in chars.by_ref() {
                    if d == '}' {
                        break;
                    }
                    index.push(d);
                }
                let i = if index.is_empty() {
                    next += 1;
                    next - 1
                } else {
                    index.parse().unwrap_or(usize::MAX)
                };
                if let Some(a) = args.get(i) {
                    out.push_str(&a.to_string());
                }
            }
            c => out.push(c),
        }
    }
    out
}

/// The arguments a text takes: its `{}` and `{N}`, by place.
#[cfg(test)]
fn places(template: &str) -> Vec<usize> {
    let mut out = Vec::new();
    let mut next = 0;
    let mut rest = template.replace("{{", "").replace("}}", "");
    while let Some(start) = rest.find('{') {
        let end = rest[start..].find('}').map_or(rest.len(), |e| start + e);
        let index = &rest[start + 1..end];
        out.push(if index.is_empty() {
            next += 1;
            next - 1
        } else {
            index.parse().unwrap_or(usize::MAX)
        });
        rest = rest[(end + 1).min(rest.len())..].to_string();
    }
    out.sort_unstable();
    out
}

#[cfg(test)]
mod tests {
    use super::{CATALOGS, fill, lookup, pick, places};
    use std::collections::{BTreeSet, HashMap};

    fn s(v: &str) -> Option<String> {
        Some(v.to_string())
    }

    /// The first variable set decides; a list and the parts after the
    /// language are read; C and an unknown language are English.
    #[test]
    fn picks_the_language() {
        assert_eq!(pick(&[None, s("ru_RU.UTF-8")]), "ru");
        assert_eq!(pick(&[s(""), s("he_IL")]), "he");
        assert_eq!(pick(&[s("sw:ru"), s("ru_RU.UTF-8")]), "sw");
        assert_eq!(pick(&[s("fr_FR.UTF-8"), s("ru_RU")]), "en");
        assert_eq!(pick(&[s("C.UTF-8"), s("zh_CN")]), "en");
        assert_eq!(pick(&[s("zh-Hans")]), "zh");
        assert_eq!(pick(&[None, None]), "en");
    }

    /// The arguments go in order, or by their place.
    #[test]
    fn fills_the_arguments() {
        assert_eq!(fill("Joined the group {} as {}.", &[&"ab", &"cd"]), "Joined the group ab as cd.");
        assert_eq!(fill("{1}: {0}", &[&"a", &2]), "2: a");
        assert_eq!(fill("{{}} {}", &[&"x"]), "{} x");
        assert_eq!(fill("no {}", &[]), "no ");
    }

    /// The English texts the sources give tr!, as Rust reads their string
    /// literals.
    fn english() -> BTreeSet<String> {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut out = BTreeSet::new();
        let mut files: Vec<_> = std::fs::read_dir(&dir).unwrap().flatten().map(|e| e.path()).collect();
        files.retain(|p| p.extension().is_some_and(|e| e == "rs") && !p.ends_with("l10n.rs"));
        for f in files {
            let src = std::fs::read_to_string(&f).unwrap();
            let mut rest = src.as_str();
            while let Some(i) = rest.find("tr!(") {
                let word = i > 0 && rest[..i].ends_with(|c: char| c.is_alphanumeric() || c == '_');
                rest = &rest[i + 4..];
                let at = rest.len() - rest.trim_start().len();
                if word || !rest[at..].starts_with('"') {
                    continue;
                }
                rest = &rest[at + 1..];
                let mut text = String::new();
                let mut chars = rest.char_indices();
                while let Some((j, c)) = chars.next() {
                    match c {
                        '"' => {
                            rest = &rest[j..];
                            break;
                        }
                        '\\' => match chars.next().map(|(_, c)| c) {
                            Some('n') => text.push('\n'),
                            Some('t') => text.push('\t'),
                            Some('"') => text.push('"'),
                            Some('\\') => text.push('\\'),
                            // A line continuation skips the newline and
                            // the next line's leading spaces.
                            Some('\n') => {
                                let skip = chars.clone().take_while(|(_, c)| c.is_whitespace()).count();
                                for _ in 0..skip {
                                    chars.next();
                                }
                            }
                            c => panic!("{}: an escape tr! texts do not use: {c:?}", f.display()),
                        },
                        c => text.push(c),
                    }
                }
                out.insert(text);
            }
        }
        assert!(out.len() > 20, "found only {} texts", out.len());
        out
    }

    /// Every catalog translates every text, takes the same arguments, and
    /// holds nothing else.
    #[test]
    fn catalogs_are_complete() {
        let english = english();
        for (lang, json) in CATALOGS {
            let table: HashMap<String, String> = serde_json::from_str(json).unwrap();
            for e in &english {
                let t = lookup(lang, e).unwrap_or_else(|| panic!("{lang}: no translation of {e:?}"));
                assert_eq!(places(t), places(e), "{lang}: the arguments of {e:?}");
                assert_eq!(t.ends_with('\n'), e.ends_with('\n'), "{lang}: the end of {e:?}");
            }
            for k in table.keys() {
                assert!(english.contains(k), "{lang}: {k:?} is no text of the sources");
            }
        }
    }
}
