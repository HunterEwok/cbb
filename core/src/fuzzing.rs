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

/// VLESS and XHTTP's answers from the forwarder (src/vless.rs), in pieces
/// whose sizes the first byte picks: an HTTP head, a chunked body, the
/// framed download and a stream's. Whatever the pieces, the framed packets
/// read back are those that the framing of the same packets gives in one go.
pub fn vless(data: &[u8]) {
    use crate::vless::{Chunked, Down, frame, parse_head};
    let Some((&step, data)) = data.split_first() else { return };
    let step = usize::from(step).max(1);
    let _ = parse_head(data);
    let mut chunked = Chunked::default();
    let mut body = Vec::new();
    let (mut down, mut whole, mut stream) = (Down::default(), Down::default(), Down::stream());
    let mut got = Vec::new();
    let mut broke = false;
    for piece in data.chunks(step) {
        let _ = chunked.push(piece, &mut body);
        let _ = stream.push(piece);
        match down.push(piece) {
            Ok(p) => got.extend(p),
            Err(_) => {
                broke = true;
                break;
            }
        }
    }
    // The same bytes at once give the same packets, unless the pieces
    // broke the reader first (a packet held past its limit).
    if !broke && let Ok(all) = whole.push(data) {
        assert_eq!(got, all, "the packets depend on how the bytes came");
    }
    // Packets framed and read back are themselves.
    let packets: Vec<&[u8]> = data.chunks(step.saturating_mul(3)).collect();
    let mut wire = alloc::vec![0u8, 0u8];
    for p in &packets {
        wire.extend(frame(p).expect("a piece under 64 KiB"));
    }
    let mut back = Down::default();
    let read: Vec<Vec<u8>> = wire.chunks(step).flat_map(|c| back.push(c).expect("framed packets read")).collect();
    assert_eq!(read, packets, "framed packets did not read back");
}

/// Message 67 before its tag is checked: any bytes are read as a pairing
/// frame after the confirm and their Welcome opened under a fixed ISK. No
/// bytes panic, and none pass the tag (the fuzzer cannot forge
/// HMAC-SHA-512), so nothing past the frame's walk is ever read of them.
pub fn welcome_message(data: &[u8]) {
    let Ok(m) = crate::join::read_pairing(data, true) else { return };
    if m.t != crate::join::T_WELCOME {
        return;
    }
    let body = data.get(4..).unwrap_or_default();
    assert!(crate::join::welcome::open(body, &[7; 64]).is_err(), "a Welcome passed a tag nobody made");
}
