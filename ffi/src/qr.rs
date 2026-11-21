// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Reading QR codes from the camera's frames, for an app whose system has
//! no reader of its own (the Aurora app, which scans a device's join code):
//! the app hands a frame's luminance, one byte a pixel, and gets the texts
//! of the codes in it.

use cbb_core::error::{Error, Result};
use serde::Serialize;

use crate::join::answer;

/// The largest frame side it takes, in pixels.
const MAX_SIDE: usize = 4096;

#[derive(Serialize)]
struct ReadAnswer {
    texts: Vec<String>,
}

/// What a frame of that size refuses with.
fn bad_size() -> Error {
    Error::msg("the frame's size does not match its bytes")
}

/// The number of bytes a frame of width by height pixels, rows stride
/// bytes apart, takes: `stride * (height - 1) + width`; None when the
/// sides are out of range or the length overflows what a slice can hold,
/// before any slice is made of the caller's pointer.
pub fn frame_len(width: usize, height: usize, stride: usize) -> Option<usize> {
    if width == 0 || height == 0 || width > MAX_SIDE || height > MAX_SIDE || stride < width {
        return None;
    }
    let n = stride.checked_mul(height.checked_sub(1)?)?.checked_add(width)?;
    (n <= isize::MAX as usize).then_some(n)
}

/// The answer to a frame whose size `frame_len` refuses.
pub fn refused() -> Vec<u8> {
    answer::<ReadAnswer>(Err(bad_size()))
}

/// The texts of the QR codes in a grey image of width by height pixels,
/// row by row, stride bytes apart.
pub fn read(gray: &[u8], width: usize, height: usize, stride: usize) -> Vec<u8> {
    answer((|| -> Result<ReadAnswer> {
        if frame_len(width, height, stride).is_none_or(|n| n > gray.len()) {
            return Err(bad_size());
        }
        let mut img = rqrr::PreparedImage::prepare_from_greyscale(width, height, |x, y| {
            y.checked_mul(stride).and_then(|r| r.checked_add(x)).and_then(|i| gray.get(i)).copied().unwrap_or(255)
        });
        let texts = img.detect_grids().into_iter().filter_map(|g| g.decode().ok().map(|(_, text)| text)).collect();
        Ok(ReadAnswer { texts })
    })())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_a_join_code() {
        let text = cbb_core::pair::join_qr(
            "246802",
            &["192.168.1.20:8767".into()],
            "qFnj7Uv+CE/WNnna2IEmMaLbkA6tHcKf0VijTRzekKA=",
        );
        let code = qrcode::QrCode::new(text.as_bytes()).unwrap();
        let w = code.width();
        // Four pixels a module and a quiet zone of four modules.
        let (scale, quiet) = (4, 4);
        let side = (w + 2 * quiet) * scale;
        let colors = code.to_colors();
        let mut gray = vec![255u8; side * side];
        for (i, c) in colors.iter().enumerate() {
            if *c == qrcode::Color::Dark {
                let (mx, my) = (i % w + quiet, i / w + quiet);
                for dy in 0..scale {
                    for dx in 0..scale {
                        gray[(my * scale + dy) * side + mx * scale + dx] = 0;
                    }
                }
            }
        }
        let got: serde_json::Value = serde_json::from_slice(&read(&gray, side, side, side)).unwrap();
        assert_eq!(got["ok"]["texts"][0], text.as_str());
        let bad: serde_json::Value = serde_json::from_slice(&read(&gray, side, side + 1, side)).unwrap();
        assert!(bad["error"].is_object());
    }

    #[test]
    fn a_frame_size_that_overflows_is_refused_before_its_bytes() {
        assert_eq!(frame_len(4, 3, 5), Some(14));
        assert_eq!(frame_len(0, 3, 5), None);
        assert_eq!(frame_len(4, 0, 5), None);
        assert_eq!(frame_len(5, 3, 4), None);
        assert_eq!(frame_len(MAX_SIDE + 1, 3, MAX_SIDE + 1), None);
        assert_eq!(frame_len(4, MAX_SIDE + 1, 4), None);
        assert_eq!(frame_len(4, 3, usize::MAX), None);
        assert_eq!(frame_len(4, 2, isize::MAX as usize), None);
        let got: serde_json::Value = serde_json::from_slice(&refused()).unwrap();
        assert!(got["error"].is_object(), "{got}");
    }
}
