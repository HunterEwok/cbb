// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Translated to Rust from internal/third_party/cpace/cpace_test.go; see
// README.md.

use super::*;

/// Decodes a hexadecimal string, ignoring spaces and newlines.
fn unhex(s: &str) -> Vec<u8> {
    let s: String = s.split_whitespace().collect();
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|c| format!("{c:02x}")).collect()
}

fn arr(b: &[u8]) -> [u8; 32] {
    b.try_into().unwrap()
}

// Test vectors from draft-irtf-cfrg-cpace-21, Appendix B.1, for CPace using
// group X25519 and hash SHA-512.
const TV_PRS: &str = "Password";
const TV_CI: &str = "\x0bA_initiator\x0bB_responder";
const TV_SID: &str = "7e4b4791d6a8ef019b936c79fb7f2c57";

const TV_GEN_STRING: &str = "
    0843506163653235350850617373776f72646d000000000000000000
    00000000000000000000000000000000000000000000000000000000
    00000000000000000000000000000000000000000000000000000000
    00000000000000000000000000000000000000000000000000000000
    00000000000000000000000000000000180b415f696e69746961746f
    720b425f726573706f6e646572107e4b4791d6a8ef019b936c79fb7f
    2c57";
const TV_GEN_HASH: &str = "03998087bdb1a2617bbe25ef5a7c18cd4f84f902328701790958755ee4aed1d3";
const TV_GEN: &str = "d04bf6d41f6a289632a2e929fa29bebd51092512a7829fdde7d314b62f05a73f";

const TV_ADA: &str = "ADa";
const TV_YA: &str = "21b4f4bd9e64ed355c3eb676a28ebedaf6d8f17bdc365995b319097153044080";
const TV_MA: &str = "1d13c89278cdadd826f6d8d7f887701430f8380ddc17611cdd6dc989ce0c9f32";

const TV_ADB: &str = "ADb";
const TV_YB: &str = "848b0779ff415f0af4ea14df9dd1d3c29ac41d836c7808896c4eba19c51ac40a";
const TV_MB: &str = "248cccf6d5cdc3646f0ad593f9e6cef4e69d4945f8372e623512ecea32185623";

const TV_K: &str = "5b067effbdc0b2a0e1d907b21ebb25cfedb96a852179a847c37e43ee71322c6b";

const TV_TRANSCRIPT_IR: &str = "
    201d13c89278cdadd826f6d8d7f887701430f8380ddc17611cdd6dc9
    89ce0c9f320341446120248cccf6d5cdc3646f0ad593f9e6cef4e69d
    4945f8372e623512ecea3218562303414462";
const TV_ISK_INPUT: &str = "
    0c43506163653235355f49534b107e4b4791d6a8ef019b936c79fb7f
    2c57205b067effbdc0b2a0e1d907b21ebb25cfedb96a852179a847c3
    7e43ee71322c6b201d13c89278cdadd826f6d8d7f887701430f8380d
    dc17611cdd6dc989ce0c9f320341446120248cccf6d5cdc3646f0ad5
    93f9e6cef4e69d4945f8372e623512ecea3218562303414462";
const TV_ISK_IR: &str = "
    6e19b875f7a561d6b3ca3dbb9ef42ac55de3e717881018204b8922b4
    d5e53bb2aa82c300bea7b65d2b671da71922ddf6472301b79bc270ad
    fa8bf413285f2263";
const TV_SID_OUTPUT_IR: &str = "
    cbc73f62589bbc96ab6a95ec2363df621e93bc3b0cea83ba6b9571d0
    05fa8f5d2d08f7165622777fa484c02a9e6b20a84ee2dbebae8c53be
    757dcfc0eebdeb5f";

const TV_TRANSCRIPT_OC: &str = "
    6f6320248cccf6d5cdc3646f0ad593f9e6cef4e69d4945f8372e6235
    12ecea3218562303414462201d13c89278cdadd826f6d8d7f8877014
    30f8380ddc17611cdd6dc989ce0c9f3203414461";
const TV_ISK_SY: &str = "
    eef745e2f6e7ae2b1a1e53da340e777167a07fe150436648c51fb199
    c11f3cbabfc683a2b48e1af5881940dc398d375c95e6b4ae9948a45b
    8770de0656382be4";
const TV_SID_OUTPUT_OC: &str = "
    3a504e9c7f1f7fa7314861e2c487d13f28566f3043f0ca760d22c491
    1aca0dd8b1f12a7ad0862eb92d08a76120140412ae6b8322e99d75cf
    1d20d8cfde2b40fe";

/// The prepend_len test vectors from draft-irtf-cfrg-cpace-21, Appendix
/// A.1.2.
#[test]
fn prepend_len_vectors() {
    let r127: Vec<u8> = (0..127u8).collect();
    let mut r128 = r127.clone();
    r128.push(127);
    let tests: [(&[u8], String); 4] = [
        (b"", "00".into()),
        (b"1234", "0431323334".into()),
        (&r127, format!("7f{}", hex(&r127))),
        (&r128, format!("8001{}", hex(&r128))),
    ];
    for (input, out) in tests {
        assert_eq!(hex(&prepend_len(Vec::new(), input)), out);
    }
}

/// The lv_cat test vector from draft-irtf-cfrg-cpace-21, Appendix A.1.4.
#[test]
fn lv_cat_vector() {
    let out = lv_cat(Vec::new(), &[b"1234", b"5", b"", b"678"]);
    assert_eq!(hex(&out), "043132333401350003363738");
}

/// The o_cat test vectors from draft-irtf-cfrg-cpace-21, Appendix A.3.3.
#[test]
fn o_cat_vectors() {
    assert_eq!(hex(&o_cat(Vec::new(), b"ABCD", b"BCD")), "6f6342434441424344");
    assert_eq!(hex(&o_cat(Vec::new(), b"BCD", b"ABCDE")), "6f634243444142434445");
}

fn state(role: Role) -> State {
    State { role, sid: vec![], ad: vec![], msg: [0; 32], priv_key: None, sid_output: None, tag: None, peer_tag: None }
}

/// The transcript_ir and transcript_oc test vectors from
/// draft-irtf-cfrg-cpace-21, Appendix A.3.5 and A.3.7.
#[test]
fn transcript_vectors() {
    let tests = [
        (Role::Initiator, "123", "PartyA", "234", "PartyB", "03313233065061727479410332333406506172747942"),
        (Role::Initiator, "3456", "PartyA", "2345", "PartyB", "043334353606506172747941043233343506506172747942"),
        (Role::Symmetric, "123", "PartyA", "234", "PartyB", "6f6303323334065061727479420331323306506172747941"),
        (Role::Symmetric, "3456", "PartyA", "2345", "PartyB", "6f63043334353606506172747941043233343506506172747942"),
    ];
    for (role, ya, ada, yb, adb, out) in tests {
        let got = state(role).transcript(Vec::new(), ya.as_bytes(), ada.as_bytes(), yb.as_bytes(), adb.as_bytes());
        assert_eq!(hex(&got), out, "{role:?} {ya} {yb}");
    }
}

/// The calculate_generator test vectors from draft-irtf-cfrg-cpace-21,
/// Appendix B.1.1.
#[test]
fn generator_vectors() {
    let (prs, ci, sid) = (TV_PRS.as_bytes(), TV_CI.as_bytes(), unhex(TV_SID));
    assert_eq!(generator_string(prs, ci, &sid), unhex(TV_GEN_STRING));
    assert_eq!(hex(&generator(prs, ci, &sid)), TV_GEN);

    // The hash of the generator string is mapped to the curve by Elligator 2.
    let r = field::from_bytes(&arr(&unhex(TV_GEN_HASH)));
    assert_eq!(hex(&field::elligator2(&r)), TV_GEN);
}

/// The full protocol test vectors from draft-irtf-cfrg-cpace-21, Appendix
/// B.1.2 to B.1.7.
#[test]
fn protocol_vectors() {
    let tests = [
        (Role::Initiator, Role::Responder, TV_ISK_IR, TV_SID_OUTPUT_IR),
        (Role::Symmetric, Role::Symmetric, TV_ISK_SY, TV_SID_OUTPUT_OC),
    ];
    let sid = unhex(TV_SID);
    for (ra, rb, isk, sid_output) in tests {
        let cfg = |role, ad: &'static str| Config {
            role,
            password: TV_PRS.as_bytes(),
            channel_id: TV_CI.as_bytes(),
            session_id: &sid,
            ad: ad.as_bytes(),
        };
        let (mut a, ma) = start_with(&cfg(ra, TV_ADA), arr(&unhex(TV_YA))).unwrap();
        assert_eq!(hex(&ma), TV_MA);
        let (mut b, mb) = start_with(&cfg(rb, TV_ADB), arr(&unhex(TV_YB))).unwrap();
        assert_eq!(hex(&mb), TV_MB);
        assert!(a.session_id().is_none());

        let isk_a = a.finish(&mb, TV_ADB.as_bytes()).unwrap();
        let isk_b = b.finish(&ma, TV_ADA.as_bytes()).unwrap();
        assert_eq!(isk_a, unhex(isk), "{ra:?}");
        assert_eq!(isk_a, isk_b);
        assert_eq!(a.session_id().unwrap(), unhex(sid_output));
        assert_eq!(b.session_id().unwrap(), unhex(sid_output));

        // The exchange cannot be finished twice: the secret scalar must not
        // be reused.
        assert!(a.finish(&mb, TV_ADB.as_bytes()).is_err());
    }
}

/// Returns G.scalar_mult_vfy(y, u), or None if it is the neutral element.
fn scalar_mult_vfy(y: &[u8], u: &[u8]) -> Option<Vec<u8>> {
    let k = StaticSecret::from(arr(y)).diffie_hellman(&PublicKey::from(arr(u))).to_bytes();
    (k != [0; 32]).then(|| k.to_vec())
}

/// The test vector for the secret point K from draft-irtf-cfrg-cpace-21,
/// Appendix B.1.4, and the input hashed to derive the session key from
/// Appendix B.1.5.
#[test]
fn secret_point_vectors() {
    let k = scalar_mult_vfy(&unhex(TV_YA), &unhex(TV_MB)).unwrap();
    assert_eq!(hex(&k), TV_K);
    assert_eq!(hex(&scalar_mult_vfy(&unhex(TV_YB), &unhex(TV_MA)).unwrap()), TV_K);

    let s = state(Role::Initiator);
    let b = lv_cat(Vec::new(), &[DSI_ISK, &unhex(TV_SID), &k]);
    let b = s.transcript(b, &unhex(TV_MA), TV_ADA.as_bytes(), &unhex(TV_MB), TV_ADB.as_bytes());
    assert_eq!(b, unhex(TV_ISK_INPUT));
    let want = unhex(TV_TRANSCRIPT_IR);
    assert_eq!(b[b.len() - want.len()..], want[..]);

    let s = state(Role::Symmetric);
    let b = s.transcript(Vec::new(), &unhex(TV_MA), TV_ADA.as_bytes(), &unhex(TV_MB), TV_ADB.as_bytes());
    assert_eq!(b, unhex(TV_TRANSCRIPT_OC));
}

/// The scalar_mult_vfy test vectors for low order points from
/// draft-irtf-cfrg-cpace-21, Appendix B.1.10: the values without a result
/// must make a party receiving them abort, the others are accepted.
#[test]
fn low_order_vectors() {
    let s = unhex("af46e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449aff");
    let tests = [
        ("0000000000000000000000000000000000000000000000000000000000000000", ""),
        ("0100000000000000000000000000000000000000000000000000000000000000", ""),
        ("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", ""),
        ("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800", ""),
        ("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157", ""),
        ("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", ""),
        (
            "daffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "d8e2c776bbacd510d09fd9278b7edcd25fc5ae9adfba3b6e040e8d3b71b21806",
        ),
        ("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", ""),
        (
            "dbffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "c85c655ebe8be44ba9c0ffde69f2fe10194458d137f09bbff725ce58803cdb38",
        ),
        (
            "d9ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "db64dafa9b8fdd136914e61461935fe92aa372cb056314e1231bc4ec12417456",
        ),
        (
            "cdeb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b880",
            "e062dcd5376d58297be2618c7498f55baa07d7e03184e8aada20bca28888bf7a",
        ),
        (
            "4c9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f11d7",
            "993c6ad11c4c29da9a56f7691fd0ff8d732e49de6250b6c2e80003ff4629a175",
        ),
    ];
    for (u, q) in tests {
        let got = scalar_mult_vfy(&s, &unhex(u));
        assert_eq!(got.map(|k| hex(&k)).unwrap_or_default(), q, "u = {u}");

        // A party receiving a low order point must abort.
        let cfg =
            Config { role: Role::Initiator, password: TV_PRS.as_bytes(), channel_id: b"", session_id: b"", ad: b"" };
        let (mut st, _) = start(&cfg).unwrap();
        assert_eq!(st.finish(&unhex(u), b"").is_ok(), !q.is_empty(), "u = {u}");
    }
}

/// A party rejects its own message relayed back to it.
#[test]
fn reflect() {
    for role in [Role::Initiator, Role::Responder, Role::Symmetric] {
        let cfg = Config { role, password: b"password", channel_id: b"ci", session_id: b"sid", ad: b"same" };
        let (mut st, msg) = start(&cfg).unwrap();
        assert!(st.finish(&msg, b"same").is_err(), "{role:?}");
    }
}

/// Parties that derived the same key confirm each other; others do not.
#[test]
fn confirm() {
    let parties = |roles: [Role; 2], password_b: &[u8]| {
        let ca = Config {
            role: roles[0],
            password: b"password",
            channel_id: b"client\x00server",
            session_id: b"session",
            ad: b"a",
        };
        let cb = Config {
            role: roles[1],
            password: password_b,
            channel_id: b"client\x00server",
            session_id: b"session",
            ad: b"b",
        };
        let (mut a, ma) = start(&ca).unwrap();
        let (mut b, mb) = start(&cb).unwrap();
        a.finish(&mb, b"b").unwrap();
        b.finish(&ma, b"a").unwrap();
        (a, b)
    };
    for roles in [[Role::Initiator, Role::Responder], [Role::Symmetric, Role::Symmetric]] {
        let (a, b) = parties(roles, b"password");
        a.verify(&b.tag().unwrap()).unwrap();
        b.verify(&a.tag().unwrap()).unwrap();
        // The two tags cover different messages, so they differ.
        assert_ne!(a.tag(), b.tag());
        assert_eq!(a.tag().unwrap().len(), 64);
        // A truncated tag is rejected.
        assert!(a.verify(&b.tag().unwrap()[..63]).is_err());

        let (a, b) = parties(roles, b"Password");
        assert!(a.verify(&b.tag().unwrap()).is_err());
        assert!(b.verify(&a.tag().unwrap()).is_err());
    }

    // Neither tag is available before the exchange is finished.
    let cfg = Config { role: Role::Initiator, password: b"password", channel_id: b"", session_id: b"", ad: b"" };
    let (a, _) = start(&cfg).unwrap();
    assert!(a.tag().is_none());
    assert!(a.verify(&[0; 64]).is_err());
}
