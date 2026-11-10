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
