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

/// The texts of the QR codes in a grey image of width by height pixels,
/// row by row, stride bytes apart.
pub fn read(gray: &[u8], width: usize, height: usize, stride: usize) -> Vec<u8> {
    answer((|| -> Result<ReadAnswer> {
        let needed = stride.checked_mul(height.saturating_sub(1)).and_then(|n| n.checked_add(width));
        if width == 0
            || height == 0
            || width > MAX_SIDE
            || height > MAX_SIDE
            || stride < width
            || needed.is_none_or(|n| n > gray.len())
        {
            return Err(Error::msg("the frame's size does not match its bytes"));
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
}
