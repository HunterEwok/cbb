// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The registry of bounds against the code and the vectors: every bound is
//! reached, every refusal is in a vector, every public number of the format
//! modules is a bound or exempted, and bounds.json is the table.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use super::*;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            sources(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

fn vectors() -> Vec<(String, serde_json::Value, String)> {
    let dir = root().join("../testdata/format");
    let mut out = Vec::new();
    for e in std::fs::read_dir(&dir).unwrap() {
        let p = e.unwrap().path();
        let name = p.file_name().unwrap().to_string_lossy().to_string();
        if !name.ends_with(".json") || name == "bounds.json" {
            continue;
        }
        let text = std::fs::read_to_string(&p).unwrap();
        out.push((name, serde_json::from_str(&text).unwrap(), text));
    }
    out
}

fn has_name(v: &serde_json::Value, name: &str) -> bool {
    match v {
        serde_json::Value::Object(m) => {
            m.get("name").and_then(|n| n.as_str()) == Some(name) || m.values().any(|x| has_name(x, name))
        }
        serde_json::Value::Array(a) => a.iter().any(|x| has_name(x, name)),
        _ => false,
    }
}

#[test]
fn every_bound_is_reached() {
    let mut files = Vec::new();
    sources(&root().join("src"), &mut files);
    let code: String = files.iter().map(|p| std::fs::read_to_string(p).unwrap()).collect();
    let vecs = vectors();
    let mut missing = Vec::new();
    let mut gaps = Vec::new();
    for b in BOUNDS {
        assert!(!b.reached.is_empty(), "{} names nothing that reaches it", b.name);
        if b.reached == ["gap"] {
            gaps.push(b.name);
            continue;
        }
        for r in b.reached {
            let found = match r.strip_prefix("vec:") {
                Some(v) => {
                    let (file, name) = v.split_once(':').unwrap();
                    vecs.iter().any(|(f, j, _)| f == file && has_name(j, name))
                }
                None => code.contains(&format!("fn {r}()")),
            };
            if !found {
                missing.push(format!("{}: {r}", b.name));
            }
        }
    }
    assert!(missing.is_empty(), "not found:\n{}", missing.join("\n"));
    // The gaps stay listed until a test or a vector reaches them.
    assert_eq!(gaps, UNREACHED, "the bounds no test reaches yet");
}

#[test]
fn every_refusal_is_in_the_vectors() {
    let vecs = vectors();
    let missing: Vec<String> = BOUNDS
        .iter()
        .filter(|b| !b.refusal.is_empty() && b.class != Class::Reader)
        .filter(|b| !vecs.iter().any(|(_, _, t)| t.contains(&format!("\"{}\"", b.refusal))))
        .map(|b| format!("{}: {}", b.name, b.refusal))
        .collect();
    assert_eq!(missing, UNVECTORED, "the refusals of the format no vector shows yet");
}

/// The modules of the 0.6 format whose public numbers are bounds or
/// exempted.
const MODULES: &[&str] = &[
    "format",
    "records",
    "commands",
    "join",
    "copies",
    "blind",
    "content",
    "beacon.rs",
    "sheet.rs",
    "sheet",
    "store.rs",
    "seal.rs",
    "slhdsa.rs",
    "keystore",
    "alpn.rs",
    "media.rs",
    "bounds.rs",
];

#[test]
fn every_number_of_the_format_is_a_bound_or_exempted() {
    let src = root().join("src");
    let mut files = Vec::new();
    for m in MODULES {
        let p = src.join(m);
        if p.is_dir() {
            sources(&p, &mut files);
        } else {
            files.push(p);
        }
    }
    let types = ["usize", "u64", "u32", "u16", "u8", "i64"];
    let names: BTreeSet<&str> = BOUNDS.iter().map(|b| b.name).collect();
    assert_eq!(names.len(), BOUNDS.len(), "a bound is named twice");
    let mut loose = Vec::new();
    for f in files {
        let rel = f.strip_prefix(&src).unwrap().to_string_lossy().replace('\\', "/");
        if rel.contains("tests") || rel.contains("/test") {
            continue;
        }
        let module = rel.trim_end_matches(".rs").trim_end_matches("/mod").replace('/', "::");
        for line in std::fs::read_to_string(&f).unwrap().lines() {
            let Some(rest) = line.strip_prefix("pub const ") else { continue };
            let Some((name, rest)) = rest.split_once(": ") else { continue };
            if !types.iter().any(|t| rest.starts_with(&format!("{t} ="))) {
                continue;
            }
            let full = format!("{module}::{name}");
            let exempt =
                EXEMPT.iter().any(|(p, _)| if p.contains("::") { full.starts_with(p) } else { name.starts_with(p) });
            if !names.contains(full.as_str()) && !exempt {
                loose.push(full);
            }
        }
    }
    assert!(loose.is_empty(), "neither a bound nor exempted:\n{}", loose.join("\n"));
}

fn table() -> serde_json::Value {
    let rows: Vec<serde_json::Value> = BOUNDS
        .iter()
        .map(|b| {
            serde_json::json!({
                "name": b.name, "value": b.value, "class": b.class.name(),
                "widest": b.widest, "refusal": b.refusal, "reached": b.reached,
            })
        })
        .collect();
    serde_json::json!({
        "note": "written by the core's bounds test (CBB_WRITE_BOUNDS=1) from core/src/bounds.rs; gen.py and the Go check compare their numbers with it",
        "bounds": rows,
    })
}

#[test]
fn bounds_json_is_the_table() {
    let path = root().join("../testdata/format/bounds.json");
    let want = serde_json::to_string_pretty(&table()).unwrap() + "\n";
    if std::env::var_os("CBB_WRITE_BOUNDS").is_some() {
        std::fs::write(&path, &want).unwrap();
    }
    let got = std::fs::read_to_string(&path).unwrap_or_default();
    assert!(got == want, "testdata/format/bounds.json is not the table: run the test with CBB_WRITE_BOUNDS=1");
}

#[test]
fn the_list_field_holds_the_widest_list() {
    use crate::format::cbor::Value;
    let id = [7u8; 32];
    let ids: Vec<Value> = (0..crate::records::LIST_MAX).map(|_| Value::Bytes(&id)).collect();
    let n = Value::Array(ids).encode().len();
    assert!(n <= LIST_FIELD, "{n}");
    assert!(LIST_FIELD - n <= 4, "{n}");
}

/// A manifest at its bounds, as every reader checks it
/// (`media::Manifest::validate`, refused as `content/manifest`).
#[test]
fn a_manifest_at_its_bounds() {
    use crate::media::{MAX_NAME, MAX_PARTS, MAX_PATH, MAX_PATHS, MAX_TYPES, Manifest, Part};
    let file = |path: String| Part { path, size: 1, sha256: Some(vec![9; 32]), ..Part::default() };
    let files =
        |paths: Vec<String>| Manifest { size: paths.len() as i64, parts: paths.into_iter().map(file).collect() };
    let names = |n: usize| (0..n).map(|i| format!("f{i}")).collect::<Vec<_>>();
    assert!(files(names(MAX_PARTS)).validate().is_ok());
    assert!(files(names(MAX_PARTS + 1)).validate().is_err());
    // A name of MAX_NAME bytes, 255 characters of three bytes.
    let name = "\u{4e00}".repeat(MAX_NAME / 3);
    assert_eq!(name.len(), MAX_NAME);
    assert!(files(vec![name.clone()]).validate().is_ok());
    assert!(files(vec![name + "a"]).validate().is_err());
    // A path of MAX_PATH bytes, in names of 99 bytes and a last one.
    let path = |n: usize| {
        let mut p = String::new();
        while p.len() + 100 < n {
            p.push_str(&"d".repeat(99));
            p.push('/');
        }
        let rest = n - p.len();
        p.push_str(&"e".repeat(rest));
        assert_eq!(p.len(), n);
        p
    };
    assert!(files(vec![path(MAX_PATH)]).validate().is_ok());
    assert!(files(vec![path(MAX_PATH + 1)]).validate().is_err());
    // All the paths together: MAX_PATHS bytes, then one more.
    let each = MAX_PATHS / 128;
    let spread = |extra: usize| -> Vec<String> {
        (0..128)
            .map(|i| {
                let tail = format!("/{i:03}");
                let mut p = path(each + if i == 0 { extra } else { 0 } - tail.len());
                p.push_str(&tail);
                p
            })
            .collect()
    };
    assert_eq!(spread(0).iter().map(String::len).sum::<usize>(), MAX_PATHS);
    assert!(files(spread(0)).validate().is_ok());
    assert!(files(spread(1)).validate().is_err());
    // Clipboard data: one part per type, at most MAX_TYPES of them.
    let types = |n: usize| Manifest {
        size: n as i64,
        parts: (0..n)
            .map(|i| Part { kind: format!("image/x{i}"), size: 1, sha256: Some(vec![9; 32]), ..Part::default() })
            .collect(),
    };
    let err = types(MAX_TYPES + 1).validate().unwrap_err().to_string();
    assert!(err.contains("types"), "{err}");
    assert!(!types(MAX_TYPES).validate().unwrap_err().to_string().contains("more than"));
}

/// The registry as the table of docs/protocol.md's "Bounds" (between its
/// markers).
fn protocol_table() -> String {
    let cell = |s: &str| s.replace('|', "\\|").replace('\n', " ");
    let mut t = String::from("| Bound | Value | Class | Widest case | Refused as |\n|---|---|---|---|---|\n");
    for b in BOUNDS {
        let refusal = if b.refusal.is_empty() { String::new() } else { format!("`{}`", b.refusal) };
        t.push_str(&format!(
            "| `{}` | {} | {} | {} | {} |\n",
            b.name,
            b.value,
            b.class.name(),
            cell(b.widest),
            refusal
        ));
    }
    t
}

/// docs/protocol.md states the bounds as the registry has them: its table
/// is the registry's, and every bound it names in its text (a registry
/// name in backquotes, as `records::MAX_SEEN`) is in the registry, with
/// the registry's value where a number in parentheses follows it.
#[test]
fn protocol_md_states_the_bounds() {
    const BEGIN: &str = "<!-- bounds:begin -->\n";
    const END: &str = "<!-- bounds:end -->";
    let path = root().join("../docs/protocol.md");
    let doc = std::fs::read_to_string(&path).unwrap();
    let (Some(a), Some(z)) = (doc.find(BEGIN), doc.find(END)) else { panic!("docs/protocol.md has no bounds markers") };
    let start = a + BEGIN.len();
    let want = protocol_table();
    if std::env::var_os("CBB_WRITE_BOUNDS").is_some() && doc[start..z] != want {
        std::fs::write(&path, format!("{}{}{}", &doc[..start], want, &doc[z..])).unwrap();
    }
    let doc = std::fs::read_to_string(&path).unwrap();
    let start = doc.find(BEGIN).unwrap() + BEGIN.len();
    let z = doc.find(END).unwrap();
    assert!(doc[start..z] == want, "docs/protocol.md's bounds table is not the registry: run with CBB_WRITE_BOUNDS=1");
    // The text outside the table.
    let text = format!("{}{}", &doc[..start], &doc[z..]);
    let value: std::collections::BTreeMap<&str, u64> = BOUNDS.iter().map(|b| (b.name, b.value)).collect();
    let mut wrong = Vec::new();
    for (i, piece) in text.split('`').enumerate().skip(1).step_by(2) {
        let looks = piece.contains("::")
            && piece.rsplit("::").next().is_some_and(|last| {
                last.starts_with(|c: char| c.is_ascii_uppercase())
                    && last.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
            })
            && piece.split("::").all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'));
        if !looks {
            continue;
        }
        let Some(&v) = value.get(piece) else {
            wrong.push(format!("`{piece}` is not in the registry"));
            continue;
        };
        // What follows the closing backquote: " (1 024)" or " (1024)".
        let after = text.split('`').nth(i + 1).unwrap_or_default();
        if let Some(rest) = after.strip_prefix(" (") {
            let digits: String =
                rest.chars().take_while(|c| c.is_ascii_digit() || *c == ' ').filter(char::is_ascii_digit).collect();
            let closed = rest.trim_start_matches(|c: char| c.is_ascii_digit() || c == ' ').starts_with(')');
            if !digits.is_empty() && closed && digits.parse::<u64>().ok() != Some(v) {
                wrong.push(format!("`{piece}` ({digits}) is {v} in the registry"));
            }
        }
    }
    assert!(wrong.is_empty(), "docs/protocol.md: {wrong:#?}");
}
