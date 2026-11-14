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

/// The recovery sheet's text or QR code, as typed or scanned: no input
/// panics, and one it takes is written again (`text`, and `qr` when it
/// named its group) and reads back as the same secret and group.
pub fn sheet(data: &[u8]) {
    let Ok(input) = core::str::from_utf8(data) else { return };
    let Ok(read) = crate::sheet::read(input) else { return };
    let again = crate::sheet::read(&crate::sheet::text(&read.secret)).expect("a sheet written again does not read");
    assert_eq!(*again.secret, *read.secret, "the sheet's text gives another secret");
    if let Some(group) = read.group {
        let qr = crate::sheet::read(&crate::sheet::qr(&read.secret, &group)).expect("a QR written again does not read");
        assert_eq!((*qr.secret, qr.group), (*read.secret, Some(group)), "the QR gives another secret or group");
    }
}

/// The hardware key's object (5FC121) as a card gives it back: no bytes
/// panic; an object that reads is cbb's of this version, and opening it
/// with any answer of the card either fails or gives 32 bytes, never a
/// panic (the fuzzer cannot forge the AEAD's tag, so it fails).
pub fn yubikey_object(data: &[u8]) {
    let read = crate::sheet::yubikey::read(data);
    if read.is_ok() {
        assert!(crate::sheet::yubikey::is_ours(data), "read an object that is not ours");
    }
    let card = data.get(..65).unwrap_or_default();
    let z = [7u8; 32];
    if let Ok(secret) = crate::sheet::yubikey::open(&z, card, data) {
        panic!("an object nobody sealed opened to {} bytes", secret.len());
    }
}

/// The Welcome's assembly from message 67 and its `records` parts, in any
/// order, repeated or cut. Input: 2 bytes of the Welcome's length, the
/// Welcome (field 3 of message 67), then frames, each 1 byte of seconds
/// since the one before and 3 bytes of length. No input panics; a part
/// taken counts one down and keeps the parts' bytes within their ceiling;
/// nothing is taken once none is due or once late; `finish` gives the
/// Welcome only when every part came, after exactly the parts announced and
/// with the Welcome's own records kept; and the same parts in the other order give the same
/// records and lists.
pub fn welcome_parts(data: &[u8]) {
    use crate::join::welcome::{Assembly, MAX_PARTS_BYTES, Welcome};
    let Some((head, rest)) = data.split_first_chunk::<2>() else { return };
    let n = usize::from(u16::from_be_bytes(*head));
    let Some((body, mut rest)) = (rest.len() >= n).then(|| rest.split_at(n)) else { return };
    let Ok(welcome) = Welcome::decode(body) else { return };
    let mut frames: Vec<(u64, &[u8])> = Vec::new();
    while let Some((h, tail)) = rest.split_first_chunk::<4>() {
        let len = usize::from(h[1]) << 16 | usize::from(h[2]) << 8 | usize::from(h[3]);
        let Some(frame) = tail.get(..len) else { break };
        frames.push((u64::from(h[0]).saturating_mul(1000), frame));
        rest = tail.get(len..).unwrap_or_default();
    }
    let run = |order: &mut dyn Iterator<Item = &(u64, &[u8])>| -> Option<Welcome> {
        let mut a = Assembly::new(welcome.clone(), 0).ok()?;
        let (mut now, mut bytes, mut taken) = (0u64, 0usize, 0u64);
        for (step, frame) in order {
            now = now.saturating_add(*step);
            let (due, late) = (a.due(), a.late(now));
            match a.take(frame, now) {
                Ok(()) => {
                    assert!(due > 0 && !late, "a part taken when none was due or late");
                    assert_eq!(a.due(), due.saturating_sub(1), "a part taken did not count one down");
                    bytes = bytes.saturating_add(frame.len());
                    taken = taken.saturating_add(1);
                    assert!(bytes <= MAX_PARTS_BYTES, "the parts passed their bytes");
                }
                Err(_) => assert_eq!(a.due(), due, "a refused part changed what is due"),
            }
            if a.due() == 0 {
                break;
            }
        }
        let due = a.due();
        let w = a.finish();
        assert_eq!(w.is_ok(), due == 0, "finish with parts still due");
        let w = w.ok()?;
        assert_eq!(taken, welcome.parts, "finish after another number of parts than announced");
        assert!(w.records.len() >= welcome.records.len() && w.lists.len() >= welcome.lists.len(), "parts lost records");
        Some(w)
    };
    let forward = run(&mut frames.iter());
    let backward = run(&mut frames.iter().rev());
    if let (Some(f), Some(b)) = (forward, backward)
        && frames.len() as u64 == welcome.parts
    {
        let ids = |w: &Welcome| {
            let mut v: Vec<_> = w.records.iter().map(crate::records::Record::id).collect();
            v.sort();
            let mut l = w.lists.clone();
            l.sort();
            (v, l)
        };
        assert_eq!(ids(&f), ids(&b), "the parts in the other order give another Welcome");
    }
}

/// Message 67's Welcome as a later version may write it (fields this
/// version does not know, the digest and parts beside them): no bytes
/// panic, and a Welcome that reads is written again in one form that reads
/// back as itself.
pub fn welcome_fields(data: &[u8]) {
    let Ok(w) = crate::join::welcome::Welcome::decode(data) else { return };
    let again = w.encode();
    let back = crate::join::welcome::Welcome::decode(&again).expect("a Welcome written again does not read");
    assert_eq!(back.encode(), again, "a Welcome written again changes");
}
