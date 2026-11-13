// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The test hooks (feature `testhooks`, never a release's): the variables
//! that change whom cbb trusts or what time it is, which the end-to-end
//! tests set. They are read here only; a release build reads none of them,
//! and `cbb version` and the service's first log line say when a build has
//! them. The crate's own unit tests (cfg(test), which no shipped binary is
//! built with) read them too.

use std::ffi::OsString;

/// Whether this build reads the test hooks.
pub const ENABLED: bool = cfg!(feature = "testhooks");

/// The variables only a build with the test hooks reads. Every other
/// variable cbb reads is listed in UNGATED (tests below), so that a new one
/// is put on one side or the other.
pub const VARS: &[&str] = &["CBB_TEST_AHEAD_FILE", "CBB_RELEASE_ROOTS", "CBB_HELPER", "CBB_TEST_LISTS_MIRROR"];

/// The value of the test hook `name`, one of VARS; None in a build without
/// the test hooks, whatever the environment holds.
pub fn var_os(name: &str) -> Option<OsString> {
    debug_assert!(VARS.contains(&name), "{name} is not a test hook");
    if cfg!(any(test, feature = "testhooks")) { std::env::var_os(name) } else { None }
}

/// What `cbb version` and the service's first log line say of the hooks:
/// nothing in a release build.
pub fn note() -> Option<String> {
    if !ENABLED {
        return None;
    }
    let set: Vec<&str> = VARS.iter().copied().filter(|v| var_os(v).is_some()).collect();
    Some(if set.is_empty() {
        "test hooks build: reads the test variables; never install it".into()
    } else {
        format!("test hooks build: reads the test variables ({} set); never install it", set.join(", "))
    })
}

#[cfg(test)]
mod tests {
    /// The CBB_ variables cbb reads outside the hooks: where it dials, how
    /// often, its folders and its switches, none of which changes whom it
    /// trusts or its clock.
    const UNGATED: &[&str] = &[
        "CBB_TEST_RESOLVE",
        "CBB_TEST_DEAD_UDP",
        "CBB_TEST_ELSEWHERE",
        "CBB_TEST_FALLBACK",
        "CBB_TEST_RENEW_EVERY",
        "CBB_TEST_STATUS_EVERY",
        "CBB_TEST_REFETCH_EVERY",
        "CBB_TEST_ACTIONS",
        "CBB_TEST_SCALE",
        "CBB_TEST_CLOCK",
        "CBB_TEST_CLOCK_FILE",
        "CBB_TEST_XHTTP_CA",
    ];

    /// Every "CBB_TEST_..." name in the sources is a hook read here or one
    /// of UNGATED, and the hooks' names appear nowhere else as a string.
    #[test]
    fn every_test_variable_is_listed() {
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = vec![src];
        let mut seen = std::collections::BTreeSet::new();
        while let Some(p) = files.pop() {
            if p.is_dir() {
                files.extend(std::fs::read_dir(&p).unwrap().map(|e| e.unwrap().path()));
                continue;
            }
            if p.extension().is_none_or(|e| e != "rs") || p.ends_with("testhooks.rs") {
                continue;
            }
            let text = std::fs::read_to_string(&p).unwrap();
            let prefix = format!("\"{}_TEST_", "CBB");
            for (i, _) in text.match_indices(&prefix) {
                let name: String = text[i + 1..]
                    .chars()
                    .take_while(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == '_')
                    .collect();
                seen.insert(name.clone());
                assert!(
                    UNGATED.contains(&name.as_str()) || super::VARS.contains(&name.as_str()),
                    "{}: {name} is neither a test hook nor listed as ungated",
                    p.display()
                );
            }
            if let Some(what) = named_outside_the_gate(&text) {
                panic!("{}: names {what} outside a call of testhooks::var_os", p.display());
            }
        }
        assert!(seen.contains("CBB_TEST_RESOLVE"), "{seen:?}");
    }

    /// What in text names a hook other than as the argument of
    /// testhooks::var_os: however the environment is read (std::env::var,
    /// env::var_os after a use, a constant), the name is then a string
    /// somewhere else; one put together (concat!, format!) leaves its two
    /// pieces as strings; one taken from the list leaves the list's name.
    fn named_outside_the_gate(text: &str) -> Option<String> {
        if text.contains("testhooks::VARS") || text.contains("VARS[") {
            return Some("the list of hooks".into());
        }
        // The gated reads taken out, nothing of a hook's name may be left.
        let mut rest = text.to_string();
        for v in super::VARS {
            rest = rest.replace(&format!("testhooks::var_os(\"{v}\")"), "");
        }
        for v in super::VARS {
            if rest.contains(&format!("\"{v}\"")) {
                return Some(v.to_string());
            }
            // Split anywhere after "CBB_", each piece a literal of its own
            // or beside a format's {} (concat!, format! either way round).
            for k in 4..v.len() - 1 {
                let (head, tail) = v.split_at(k);
                let head_there = rest.contains(&format!("\"{head}\"")) || rest.contains(&format!("\"{head}{{"));
                let tail_there = rest.contains(&format!("\"{tail}\"")) || rest.contains(&format!("}}{tail}\""));
                if head_there && tail_there {
                    return Some(format!("{v} put together"));
                }
            }
        }
        None
    }

    #[test]
    fn a_hook_read_any_other_way_is_told() {
        let v = super::VARS[1];
        let (head, tail) = v.split_at(8);
        for read in [
            format!("std::env::var_os(\"{v}\")"),
            format!("std::env::var(\"{v}\")"),
            format!("use std::env; env::var_os(\"{v}\")"),
            format!("const R: &str = \"{v}\"; std::env::var(R)"),
            format!("crate::testhooks::var_os(\"{v}\"); std::env::var(\"{v}\")"),
            format!("std::env::var(concat!(\"{head}\", \"{tail}\"))"),
            format!("std::env::var(format!(\"{head}{{}}\", \"{tail}\"))"),
            format!("std::env::var(format!(\"{{}}{tail}\", \"{head}\"))"),
            "std::env::var(crate::testhooks::VARS[1])".to_string(),
            "use crate::testhooks::VARS; std::env::var(VARS[1])".to_string(),
        ] {
            assert!(named_outside_the_gate(&read).is_some(), "{read}");
        }
        assert_eq!(named_outside_the_gate(&format!("crate::testhooks::var_os(\"{v}\")")), None);
        assert_eq!(named_outside_the_gate(&format!("testhooks::var_os(\"{v}\")")), None);
    }

    #[test]
    fn a_release_build_says_nothing() {
        assert_eq!(super::note().is_none(), !super::ENABLED);
    }
}
