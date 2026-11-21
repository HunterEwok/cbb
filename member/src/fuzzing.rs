// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The service's readers of what reaches it from outside its own code, for
//! the cargo fuzz targets in fuzz/ (the feature `fuzzing`): each reads one
//! input and checks what holds of every input it takes.

use crate::control::{self, Reader};

/// The control socket's messages, which cbb-helper's channel uses too: each
/// one read is within the limits, and written again it reads back the same.
pub fn control(data: &[u8]) {
    let mut r = Reader::new(data);
    for _ in 0..64 {
        let Ok(Some(m)) = r.read() else { return };
        assert!(m.payload.len() == m.header.len, "a payload of another length than its header says");
        let _ = control::needs_admin(&m.header);
        let mut wire = Vec::new();
        if control::write(&mut wire, &m).is_ok() {
            let again = Reader::new(wire.as_slice()).read().expect("a message written reads").expect("not the end");
            assert_eq!(again.payload, m.payload, "the payload changed on the way back");
            assert_eq!(
                serde_json::to_value(&again.header).ok(),
                serde_json::to_value(&m.header).ok(),
                "the header changed on the way back"
            );
        }
    }
}

/// The frames from the ZX Spectrum Next's driver on the Pi's UART and the
/// text in its character set, in pieces whose sizes the first byte picks:
/// the frames do not depend on how the bytes came, and each frame encoded
/// decodes to itself.
#[cfg(unix)]
pub fn next_frames(data: &[u8]) {
    use crate::nextlink::frame::{Decoder, encode};
    let Some((&step, data)) = data.split_first() else { return };
    let step = usize::from(step).max(1);
    let mut d = Decoder::new();
    let got: Vec<_> = data.chunks(step).flat_map(|c| d.push(c)).collect();
    assert_eq!(got, Decoder::new().push(data), "the frames depend on how the bytes came");
    for f in &got {
        assert_eq!(Decoder::new().push(&encode(f.kind, &f.data)), vec![f.clone()], "a frame did not read back");
    }
    let text = crate::next::from_spectrum(data);
    let _ = crate::next::to_spectrum(&text);
}

/// The relay's messages of 0.6 (`cbb-relay/3`, t 90 to 99), as both ends
/// read them: frames one after another as the relay reads a registration
/// and a request, each body also as the device reads a challenge, a
/// welcome and a note. A registration or a note read and written again
/// reads back the same, and every frame written is on the format's grid.
#[cfg(feature = "tunnel")]
pub fn relay_wire(data: &[u8]) {
    use crate::relay::v3;
    use crate::relayd::wire3::{self, MAX_FRAME, Register};
    let mut r = data;
    for _ in 0..16 {
        let Ok((_, body)) = wire3::read(&mut r, MAX_FRAME) else { break };
        if let Ok(reg) = Register::read(&body) {
            let f = reg.write();
            let again = Register::read(&f[4..]).expect("a registration written reads");
            assert_eq!(
                (again.key, again.proof, &again.root),
                (reg.key, reg.proof, &reg.root),
                "the registration changed"
            );
            assert!(again.credentials.len() <= reg.credentials.len(), "credentials grew on the way back");
        }
        if let Ok(q) = wire3::request(&body) {
            let n = [q.watch, !q.dial.is_empty(), !q.answer.is_empty()].iter().filter(|x| **x).count();
            assert!(n <= 1, "a request of two kinds");
        }
        let _ = v3::challenge(&body);
        let _ = v3::welcome(&body);
        if let Ok(n) = v3::note(&body) {
            let srv = crate::relayd::wire::Note {
                online: n.online.clone(),
                call: n.call.clone(),
                ticket: n.ticket.clone(),
                ok: n.ok,
                error: n.error.clone(),
            };
            if let Some(f) = wire3::note(&srv) {
                assert!(v3::length(f[..4].try_into().expect("a head"), MAX_FRAME).is_ok(), "a note off the grid");
                let back = v3::note(&f[4..]).expect("a note written reads");
                assert_eq!(back.ok, n.ok, "the note changed");
                assert_eq!(back.call, n.call, "the note changed");
            }
        }
    }
}

#[cfg(all(test, feature = "tunnel"))]
mod tests {
    use crate::relayd::wire::Note;
    use crate::relayd::wire3::{self, Register};

    /// The relay's frames of every kind, one after another, then the
    /// same with bytes flipped, cut short and random: the fuzz target's
    /// promises hold on all of them.
    #[test]
    fn the_relay_wire_target_holds_on_its_seeds() {
        let b64 = |b: &[u8]| base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b);
        let mut all = Vec::new();
        for f in [
            wire3::challenge(&[5; 32], true),
            wire3::challenge(&[5; 32], false),
            Register { key: [7; 32], proof: [6; 32], credentials: vec![vec![0xa0]], root: Some(vec![4; 65]) }.write(),
            wire3::registered(&[9; 32], &[8; 32], "fd00::5"),
            wire3::error("not listed"),
            wire3::note(&Note { online: Some(vec![b64(&[3; 32])]), ..Note::default() }).unwrap(),
            wire3::note(&Note { call: b64(&[3; 32]), ticket: b64(&[4; 16]), ..Note::default() }).unwrap(),
            wire3::note(&Note { ok: true, ..Note::default() }).unwrap(),
        ] {
            super::relay_wire(&f);
            all.extend_from_slice(&f);
        }
        super::relay_wire(&all);
        let mut x = 0x9e37_79b9_u32;
        for i in 0..2000 {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            let mut m = all.clone();
            let at = (x as usize) % m.len();
            m[at] ^= (x >> 8) as u8 | 1;
            m.truncate(m.len() - i % 64);
            super::relay_wire(&m);
            super::relay_wire(&x.to_be_bytes().repeat(i % 32 + 1));
        }
    }
}
