// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The recovery key's hash-based second signature (SLH-DSA-SHA2-128s):
//! verify of any bytes as key, message, signature and context never
//! panics, and a valid signature changed in any byte no longer verifies.

#![no_main]
use std::sync::OnceLock;

use cbb_core::records::pq::{self, PqKey, CONTEXT_RECORD};
use cbb_core::slhdsa;

struct Valid {
    public: Vec<u8>,
    msg: Vec<u8>,
    sig: Vec<u8>,
}

fn valid() -> &'static Valid {
    static V: OnceLock<Valid> = OnceLock::new();
    V.get_or_init(|| {
        let k = PqKey::from_seeds(&[1; 16], &[2; 16], &[3; 16]);
        let msg = b"a recovery head".to_vec();
        let sig = k.sign(&msg, CONTEXT_RECORD).expect("sign");
        let public = k.public();
        assert!(slhdsa::verify(&public, &msg, &sig, CONTEXT_RECORD), "a fresh signature does not verify");
        Valid { public, msg, sig }
    })
}

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else { return };
    if mode & 1 == 0 {
        // Raw bytes: key, context, signature, message.
        let take = |b: &[u8], n: usize| -> (Vec<u8>, usize) {
            let n = n.min(b.len());
            (b[..n].to_vec(), n)
        };
        let klen = if mode & 2 == 0 { slhdsa::PUBLIC_SIZE } else { usize::from(mode >> 2) };
        let (public, a) = take(rest, klen);
        let rest = &rest[a..];
        let clen = rest.first().map_or(0, |c| usize::from(*c));
        let rest = rest.get(1..).unwrap_or(&[]);
        let (ctx, b) = take(rest, clen);
        let rest = &rest[b..];
        let (mut sig, c) = take(rest, slhdsa::SIG_SIZE);
        let msg = &rest[c..];
        if mode & 4 != 0 {
            sig.resize(slhdsa::SIG_SIZE, 0);
        }
        let _ = slhdsa::verify(&public, msg, &sig, &ctx);
        let _ = slhdsa::from_spki(rest);
        let k = cbb_core::records::Key::new(if mode & 8 != 0 { cbb_core::records::key::ALG_SLH_DSA } else { 1 }, public.clone());
        let _ = pq::verify(&k, msg, &sig, &ctx);
    } else {
        // A valid signature with bytes changed: it verifies only unchanged.
        let v = valid();
        let (mut public, mut msg, mut sig) = (v.public.clone(), v.msg.clone(), v.sig.clone());
        let mut changed = false;
        for c in rest.chunks_exact(4) {
            let at = usize::from(u16::from_le_bytes([c[0], c[1]]));
            let x = c[2];
            if x == 0 {
                continue;
            }
            match c[3] % 3 {
                0 => {
                    let i = at % public.len();
                    public[i] ^= x;
                }
                1 => {
                    let i = at % msg.len();
                    msg[i] ^= x;
                }
                _ => {
                    let i = at % sig.len();
                    sig[i] ^= x;
                }
            }
            changed = true;
        }
        let ok = slhdsa::verify(&public, &msg, &sig, CONTEXT_RECORD);
        if changed && (public != v.public || msg != v.msg || sig != v.sig) {
            assert!(!ok, "a changed signature, key or message verifies");
        } else {
            assert!(ok, "the valid signature does not verify");
        }
        // The same signature under another context never verifies.
        assert!(!slhdsa::verify(&v.public, &v.msg, &v.sig, pq::CONTEXT_FETCH), "a record signature verifies as a fetch proof");
    }
});
