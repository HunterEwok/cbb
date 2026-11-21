// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! SLH-DSA-SHA2-128s against NIST's known answers
//! (testdata/slhdsa/acvp-sha2-128s.json): key generation from the three
//! seeds, deterministic signing, and verification, with the cases the Go
//! check (testdata/format/check, circl) reads too; the same changed inputs
//! go to both, each must refuse them; and the stack a verify needs.

use cbb_core::records::pq::{self, PqKey, VERIFY_STACK};
use serde_json::Value;

fn vectors() -> Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../testdata/slhdsa/acvp-sha2-128s.json");
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn unhex(v: &Value) -> Vec<u8> {
    let s = v.as_str().unwrap();
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn seed(b: &[u8]) -> [u8; 16] {
    b.try_into().unwrap()
}

#[test]
fn keys_come_of_their_seeds_as_nist_says() {
    let v = vectors();
    for t in v["keygen"].as_array().unwrap() {
        let k =
            PqKey::from_seeds(&seed(&unhex(&t["sk_seed"])), &seed(&unhex(&t["sk_prf"])), &seed(&unhex(&t["pk_seed"])));
        assert_eq!(k.public(), unhex(&t["pk"]), "tc {}", t["tc"]);
        assert_eq!(&unhex(&t["sk"])[32..], &k.public()[..], "tc {}", t["tc"]);
    }
}

#[test]
fn signatures_are_nists_and_verify() {
    let v = vectors();
    for t in v["siggen"].as_array().unwrap() {
        let sk = unhex(&t["sk"]);
        let k = PqKey::from_seeds(&seed(&sk[..16]), &seed(&sk[16..32]), &seed(&sk[32..48]));
        assert_eq!(k.public(), unhex(&t["pk"]), "tc {}", t["tc"]);
        let (msg, ctx) = (unhex(&t["message"]), unhex(&t["context"]));
        let sig = k.sign(&msg, &ctx).unwrap();
        assert_eq!(sig, unhex(&t["signature"]), "tc {}", t["tc"]);
        assert!(cbb_core::slhdsa::verify(&k.public(), &msg, &sig, &ctx), "tc {}", t["tc"]);
    }
}

#[test]
fn verification_answers_as_nist_says() {
    let v = vectors();
    let cases = v["sigver"].as_array().unwrap();
    assert!(cases.iter().any(|t| t["valid"] == true) && cases.iter().any(|t| t["valid"] == false));
    for t in cases {
        let got = cbb_core::slhdsa::verify(
            &unhex(&t["pk"]),
            &unhex(&t["message"]),
            &unhex(&t["signature"]),
            &unhex(&t["context"]),
        );
        assert_eq!(got, t["valid"].as_bool().unwrap(), "tc {} {}", t["tc"], t["reason"]);
    }
}

/// A changed input: its name, key, message, signature and context.
pub type Changed = (String, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

/// The changed inputs, built by the same rule in the Go check: a bit
/// flipped in the key (first and last byte), the message (first and last
/// byte), the signature (R, the first FORS byte, the last byte); the
/// signature a byte short and a byte long; the key a byte short; the
/// context a byte longer. Every one is refused, the unchanged one taken.
pub fn changed(pk: &[u8], msg: &[u8], sig: &[u8], ctx: &[u8]) -> Vec<Changed> {
    let flip = |b: &[u8], i: usize, bit: u8| {
        let mut b = b.to_vec();
        b[i] ^= 1 << bit;
        b
    };
    let mut out = Vec::new();
    let mut push =
        |name: &str, p: Vec<u8>, m: Vec<u8>, s: Vec<u8>, c: Vec<u8>| out.push((name.to_string(), p, m, s, c));
    push("key first bit", flip(pk, 0, 0), msg.to_vec(), sig.to_vec(), ctx.to_vec());
    push("key last bit", flip(pk, pk.len() - 1, 7), msg.to_vec(), sig.to_vec(), ctx.to_vec());
    if !msg.is_empty() {
        push("message first bit", pk.to_vec(), flip(msg, 0, 0), sig.to_vec(), ctx.to_vec());
        push("message last bit", pk.to_vec(), flip(msg, msg.len() - 1, 7), sig.to_vec(), ctx.to_vec());
    }
    push("signature R", pk.to_vec(), msg.to_vec(), flip(sig, 0, 0), ctx.to_vec());
    push("signature FORS", pk.to_vec(), msg.to_vec(), flip(sig, 16, 3), ctx.to_vec());
    push("signature last bit", pk.to_vec(), msg.to_vec(), flip(sig, sig.len() - 1, 7), ctx.to_vec());
    push("signature a byte short", pk.to_vec(), msg.to_vec(), sig[..sig.len() - 1].to_vec(), ctx.to_vec());
    let mut long = sig.to_vec();
    long.push(0);
    push("signature a byte long", pk.to_vec(), msg.to_vec(), long, ctx.to_vec());
    push("key a byte short", pk[..pk.len() - 1].to_vec(), msg.to_vec(), sig.to_vec(), ctx.to_vec());
    let mut c = ctx.to_vec();
    c.push(0x5a);
    push("context a byte longer", pk.to_vec(), msg.to_vec(), sig.to_vec(), c);
    out
}

#[test]
fn every_changed_input_is_refused() {
    let v = vectors();
    let valid =
        v["sigver"].as_array().unwrap().iter().filter(|t| t["valid"] == true).chain(v["siggen"].as_array().unwrap());
    let mut n = 0;
    for t in valid {
        let (pk, msg, sig, ctx) = (unhex(&t["pk"]), unhex(&t["message"]), unhex(&t["signature"]), unhex(&t["context"]));
        assert!(cbb_core::slhdsa::verify(&pk, &msg, &sig, &ctx), "tc {}", t["tc"]);
        for (name, p, m, s, c) in changed(&pk, &msg, &sig, &ctx) {
            assert!(!cbb_core::slhdsa::verify(&p, &m, &s, &c), "tc {} {name}", t["tc"]);
            n += 1;
        }
    }
    assert!(n >= 90, "{n}");
}

/// The two halves of a recovery key come of one secret, each under its own
/// label: other secrets give other keys, the same secret the same.
#[test]
fn the_recovery_secret_makes_both_halves() {
    let (a1, a2) = pq::recovery_keys(&[1; 32]).unwrap();
    let (b1, b2) = pq::recovery_keys(&[1; 32]).unwrap();
    let (c1, c2) = pq::recovery_keys(&[2; 32]).unwrap();
    assert_eq!(a1.to_bytes(), b1.to_bytes());
    assert_eq!(a2.public(), b2.public());
    assert_ne!(a1.to_bytes(), c1.to_bytes());
    assert_ne!(a2.public(), c2.public());
    let sig = a2.sign(b"m", pq::CONTEXT_RECORD).unwrap();
    assert!(pq::verify(&a2.key(), b"m", &sig, pq::CONTEXT_RECORD));
    assert!(!pq::verify(&a2.key(), b"m", &sig, pq::CONTEXT_FETCH));
}

/// One head's verify fits VERIFY_STACK, and does not fit half of it: the
/// number is within a factor two of what it needs. Each size runs in a
/// child process, since running out of stack ends the process. The number
/// is the optimized build's (the generic code is built at the core's own
/// level, many times larger without optimization), so this runs with
/// `cargo test --release`.
#[test]
#[cfg_attr(debug_assertions, ignore = "the stack of the optimized build: run with cargo test --release")]
fn the_stack_a_verify_needs() {
    if let Ok(n) = std::env::var("VERIFY_STACK_CHILD") {
        let n: usize = n.parse().unwrap();
        let v = vectors();
        let t = v["siggen"][0].clone();
        let ok = std::thread::Builder::new()
            .stack_size(n)
            .spawn(move || {
                cbb_core::slhdsa::verify(
                    &unhex(&t["pk"]),
                    &unhex(&t["message"]),
                    &unhex(&t["signature"]),
                    &unhex(&t["context"]),
                )
            })
            .unwrap()
            .join()
            .unwrap();
        assert!(ok);
        return;
    }
    let run = |n: usize| {
        std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "the_stack_a_verify_needs", "--nocapture", "--test-threads=1"])
            .env("VERIFY_STACK_CHILD", n.to_string())
            .output()
            .unwrap()
            .status
            .success()
    };
    assert!(run(VERIFY_STACK), "a verify does not fit {VERIFY_STACK} bytes of stack");
    assert!(!run(VERIFY_STACK / 2), "a verify fits half of {VERIFY_STACK}: the number is too large");
}
