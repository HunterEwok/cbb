// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The readers of network input, for the cargo fuzz targets in fuzz/ (the
//! feature `fuzzing`): each reads one body and checks what holds of every
//! body it takes.

/// A record's body: one it takes is in the strict form.
pub fn record_body(data: &[u8]) {
    if crate::authority::Body::parse(data).is_ok() {
        assert!(
            crate::strict::check(data, &["v", "alg", "type", "signer", "time_ms", "group", "seq"]).is_ok(),
            "took a record not in the strict form"
        );
    }
}

/// A command's body: one it takes is in the strict form.
pub fn command(data: &[u8]) {
    if crate::command::Command::parse(data).is_ok() {
        assert!(
            crate::strict::check(data, &["v", "type", "group", "by", "to", "id", "time_ms", "expires_ms"]).is_ok(),
            "took a command not in the strict form"
        );
    }
}

/// A server credential's body.
pub fn credential(data: &[u8]) {
    let _ = crate::credential::Body::parse(data);
}

/// The files of a release: keys.json, release.json and a channel's file.
pub fn release(data: &[u8]) {
    let _ = crate::release::decode_keys(data);
    let _ = crate::release::decode_release(data);
    let _ = crate::release::decode_channel(data);
}

/// A member protocol frame's payload, a manifest, a sealed copy and the
/// content inside one: a content it takes encodes to the same bytes.
pub fn wire(data: &[u8]) {
    let _ = crate::media::Manifest::parse(data);
    let _ = crate::wire::decode(data);
    let _ = serde_json::from_slice::<crate::copy::Sealed>(data).map(|s| s.validate());
    if let Ok(c) = crate::copy::Content::decode(data) {
        assert_eq!(c.encode().ok().as_deref(), Some(data), "took a content that does not encode back");
    }
}

/// The core's entry point (docs/core-api.md): any bytes get one answer, a
/// JSON object of this ABI with either `ok` or an `error` whose code is
/// one of the listed ones, and the same request gets the same answer.
pub fn api(data: &[u8]) {
    let answer = crate::api::call(data);
    let v: serde_json::Value = serde_json::from_slice(&answer).expect("the answer is not JSON");
    let o = v.as_object().expect("the answer is not an object");
    assert_eq!(o.get("abi").and_then(serde_json::Value::as_u64), Some(u64::from(crate::api::ABI)), "the answer's abi");
    match (o.get("ok"), o.get("error")) {
        (Some(_), None) => {}
        (None, Some(e)) => {
            let code = e.get("code").and_then(serde_json::Value::as_u64).expect("an error without a code");
            assert!(matches!(code, 1..=4 | 10..=17), "an error with the unknown code {code}");
            assert!(
                e.get("name").and_then(serde_json::Value::as_str).is_some_and(|n| !n.is_empty()),
                "an error without a name"
            );
        }
        _ => panic!("an answer with both ok and error, or neither"),
    }
    assert_eq!(crate::api::call(data), answer, "the same request got another answer");
}
