// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The group's latest image for the ZX Spectrum Next's Layer 2 (`cbb next
//! image`, member/README.md, "ZX Spectrum Next"): a PNG or JPEG fitted to the
//! screen, in 256 colours at 320×256 or 16 at 640×256, whichever shows it
//! closer, from the Next's 512 (three bits a channel), with Floyd–Steinberg
//! dithering. The pixels are in Layer 2's own order, a column of 256 bytes
//! after another, so the Next copies them into its banks as they come.

use std::io::Cursor;

use crate::error::{Error, Result};

/// The screen's height in both modes.
pub const HEIGHT: usize = 256;
/// The bytes of a frame's pixels, in both modes.
pub const PIXEL_BYTES: usize = 320 * HEIGHT;
/// The largest image this decodes, on a side.
const MAX_SIDE: usize = 16384;
/// The largest image file it takes.
pub const MAX_FILE: usize = 48 << 20;

/// Layer 2's two modes for an image.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// 320×256, a byte a pixel, 256 colours.
    Lo,
    /// 640×256, half a byte a pixel (the left one in the high half), 16
    /// colours; its pixels are half as wide.
    Hi,
}

impl Mode {
    fn width(self) -> usize {
        match self {
            Mode::Lo => 320,
            Mode::Hi => 640,
        }
    }
    fn colours(self) -> usize {
        match self {
            Mode::Lo => 256,
            Mode::Hi => 16,
        }
    }
    /// The letter in the frame's header line.
    pub fn letter(self) -> char {
        match self {
            Mode::Lo => 'L',
            Mode::Hi => 'H',
        }
    }
}

/// An image in 8-bit RGB, row after row.
pub struct Rgb {
    pub width: usize,
    pub height: usize,
    pub pixels: Vec<[u8; 3]>,
}

/// A frame for Layer 2: its pixels in Layer 2's order and its palette, a
/// 9-bit colour (RRRGGGBBB) an entry, darkest first.
pub struct Frame {
    pub mode: Mode,
    pub pixels: Vec<u8>,
    pub palette: Vec<u16>,
}

impl Frame {
    /// The bytes the Next takes: the pixels, then two bytes a palette entry
    /// as Next register 0x44 takes them (RRRGGGBB, then the low bit of blue).
    pub fn bytes(&self) -> Vec<u8> {
        let mut b = self.pixels.clone();
        for &c in &self.palette {
            b.push((c >> 1) as u8);
            b.push((c & 1) as u8);
        }
        b
    }
}

/// Decodes a PNG or a JPEG by its MIME type; transparent parts go on black.
pub fn decode(kind: &str, data: &[u8]) -> Result<Rgb> {
    let img = match kind {
        "image/png" => decode_png(data)?,
        "image/jpeg" => decode_jpeg(data)?,
        _ => return Err(Error::msg(format!("the Next shows PNG and JPEG images, not {kind}"))),
    };
    if img.width == 0 || img.height == 0 {
        return Err(Error::msg("the image is empty"));
    }
    Ok(img)
}

fn decode_png(data: &[u8]) -> Result<Rgb> {
    let mut d = png::Decoder::new(Cursor::new(data));
    d.set_transformations(png::Transformations::normalize_to_color8());
    let mut r = d.read_info().map_err(|e| Error::with("the PNG image is damaged", e))?;
    let (w, h) = (r.info().width as usize, r.info().height as usize);
    if w > MAX_SIDE || h > MAX_SIDE {
        return Err(Error::msg(format!("the image is too large ({w}×{h})")));
    }
    let size = r.output_buffer_size().ok_or_else(|| Error::msg("the PNG image is too large"))?;
    let mut buf = vec![0; size];
    let info = r.next_frame(&mut buf).map_err(|e| Error::with("the PNG image is damaged", e))?;
    let (ct, _) = r.output_color_type();
    let n = match ct {
        png::ColorType::Grayscale => 1,
        png::ColorType::GrayscaleAlpha => 2,
        png::ColorType::Rgb => 3,
        png::ColorType::Rgba => 4,
        png::ColorType::Indexed => return Err(Error::msg("the PNG image's palette did not expand")),
    };
    let line = info.line_size;
    let mut pixels = Vec::with_capacity(w * h);
    for y in 0..h {
        let row = &buf[y * line..];
        for x in 0..w {
            let p = &row[x * n..x * n + n];
            let (c, a) = match n {
                1 => ([p[0]; 3], 255),
                2 => ([p[0]; 3], p[1]),
                3 => ([p[0], p[1], p[2]], 255),
                _ => ([p[0], p[1], p[2]], p[3]),
            };
            pixels.push(c.map(|v| (v as u16 * a as u16 / 255) as u8));
        }
    }
    Ok(Rgb { width: w, height: h, pixels })
}

fn decode_jpeg(data: &[u8]) -> Result<Rgb> {
    use zune_jpeg::zune_core::colorspace::ColorSpace;
    use zune_jpeg::zune_core::options::DecoderOptions;
    let opts = DecoderOptions::default()
        .set_max_width(MAX_SIDE)
        .set_max_height(MAX_SIDE)
        .jpeg_set_out_colorspace(ColorSpace::RGB);
    let mut d = zune_jpeg::JpegDecoder::new_with_options(Cursor::new(data), opts);
    let buf = d.decode().map_err(|e| Error::msg(format!("the JPEG image is damaged: {e:?}")))?;
    let (w, h) = d.dimensions().ok_or_else(|| Error::msg("the JPEG image is damaged"))?;
    if buf.len() < w * h * 3 {
        return Err(Error::msg("the JPEG image is damaged"));
    }
    let pixels = buf.chunks_exact(3).take(w * h).map(|p| [p[0], p[1], p[2]]).collect();
    Ok(Rgb { width: w, height: h, pixels })
}

/// The frame of an image: in mode, or with None in the mode that shows it
/// closer.
pub fn convert(img: &Rgb, mode: Option<Mode>) -> Frame {
    let mode = mode.unwrap_or_else(|| best_mode(img));
    let (px, w) = (fit(img, mode), mode.width());
    let palette = quantize(&px, mode.colours());
    let idx = dither(&px, w, &palette);
    let mut pixels = vec![0; PIXEL_BYTES];
    for y in 0..HEIGHT {
        for x in 0..w {
            let i = idx[y * w + x];
            match mode {
                Mode::Lo => pixels[x * HEIGHT + y] = i,
                Mode::Hi => pixels[(x / 2) * HEIGHT + y] |= if x % 2 == 0 { i << 4 } else { i },
            }
        }
    }
    Frame { mode, pixels, palette }
}

/// The finer pixels for an image of a few flat colours, a screenshot of
/// text, say, where 16 of the Next's colours cover nearly all of it; 256
/// colours for the rest, photographs above all.
fn best_mode(img: &Rgb) -> Mode {
    let px = fit(img, Mode::Hi);
    let mut hist = [0u32; 512];
    for &p in &px {
        hist[snap(p) as usize] += 1;
    }
    hist.sort_unstable_by(|a, b| b.cmp(a));
    let top: u64 = hist[..16].iter().map(|&n| n as u64).sum();
    if top * 100 >= px.len() as u64 * 97 { Mode::Hi } else { Mode::Lo }
}

/// The image scaled to fit the screen of mode, its proportions kept (a
/// pixel of 640×256 is half as wide as it is high), centred on black.
fn fit(img: &Rgb, mode: Mode) -> Vec<[u8; 3]> {
    let w = mode.width();
    // In 320×256's pixels, which the Next shows about square.
    let s = (320.0 / img.width as f64).min(HEIGHT as f64 / img.height as f64);
    let cols = ((img.width as f64 * s * (w / 320) as f64).round() as usize).clamp(1, w);
    let rows = ((img.height as f64 * s).round() as usize).clamp(1, HEIGHT);
    let (x0, y0) = ((w - cols) / 2, (HEIGHT - rows) / 2);
    let wx = weights(img.width, cols);
    let wy = weights(img.height, rows);
    // Rows first: each output row from the source rows it covers.
    let mut out = vec![[0u8; 3]; w * HEIGHT];
    let mut acc = vec![[0f32; 3]; img.width];
    for (r, taps) in wy.iter().enumerate() {
        acc.iter_mut().for_each(|a| *a = [0.0; 3]);
        for &(sy, f) in taps {
            let row = &img.pixels[sy * img.width..(sy + 1) * img.width];
            for (a, p) in acc.iter_mut().zip(row) {
                for c in 0..3 {
                    a[c] += p[c] as f32 * f;
                }
            }
        }
        for (cx, taps) in wx.iter().enumerate() {
            let mut v = [0f32; 3];
            for &(sx, f) in taps {
                for c in 0..3 {
                    v[c] += acc[sx][c] * f;
                }
            }
            out[(y0 + r) * w + x0 + cx] = v.map(|c| c.round().clamp(0.0, 255.0) as u8);
        }
    }
    out
}

/// For each of n output samples, the source samples of 0..len it takes
/// and their weights: the area it covers when it shrinks, a linear blend
/// of two when it grows.
fn weights(len: usize, n: usize) -> Vec<Vec<(usize, f32)>> {
    let scale = len as f64 / n as f64;
    (0..n)
        .map(|i| {
            if scale > 1.0 {
                let (a, b) = (i as f64 * scale, (i + 1) as f64 * scale);
                let mut taps = Vec::new();
                let mut s = a.floor() as usize;
                while (s as f64) < b && s < len {
                    let cover = (b.min(s as f64 + 1.0) - a.max(s as f64)) / scale;
                    if cover > 0.0 {
                        taps.push((s, cover as f32));
                    }
                    s += 1;
                }
                taps
            } else {
                let c = ((i as f64 + 0.5) * scale - 0.5).clamp(0.0, (len - 1) as f64);
                let s = c.floor() as usize;
                let f = (c - s as f64) as f32;
                if s + 1 < len && f > 0.0 { vec![(s, 1.0 - f), (s + 1, f)] } else { vec![(s, 1.0)] }
            }
        })
        .collect()
}

/// A 9-bit colour as 8-bit RGB, as the Next's video shows it.
fn colour(c: u16) -> [u8; 3] {
    let v = |n: u16| ((n & 7) * 255 / 7) as u8;
    [v(c >> 6), v(c >> 3), v(c)]
}

/// The nearest 9-bit colour to an 8-bit one, except Layer 2's default
/// transparent colour (0xE3 in RRRGGGBB, a magenta), which would let the
/// screen under it show through.
fn snap(c: [u8; 3]) -> u16 {
    let t = |v: u8| ((v as u16 * 7 + 127) / 255).min(7);
    let (r, mut g, b) = (t(c[0]), t(c[1]), t(c[2]));
    if r == 7 && g == 0 && b >= 6 {
        g = 1;
    }
    r << 6 | g << 3 | b
}

fn dist(a: [u8; 3], b: [u8; 3]) -> u32 {
    // Weighted for the eye, as a cheap approximation.
    let d = |i: usize| (a[i] as i32 - b[i] as i32).pow(2) as u32;
    2 * d(0) + 4 * d(1) + 3 * d(2)
}

fn luma(c: u16) -> u32 {
    let [r, g, b] = colour(c);
    299 * r as u32 + 587 * g as u32 + 114 * b as u32
}

/// Up to n colours of the Next's 512 for pixels: a median cut over a
/// histogram of 15-bit colours, its boxes' means snapped to 9 bits, a few
/// rounds of k-means; sorted darkest first, so the Next can show the
/// pixels in grey while the palette is still on its way.
fn quantize(pixels: &[[u8; 3]], n: usize) -> Vec<u16> {
    let mut hist = vec![0u32; 1 << 15];
    for p in pixels {
        hist[key(*p)] += 1;
    }
    let bins: Vec<([u8; 3], u32)> =
        hist.iter().enumerate().filter(|(_, c)| **c > 0).map(|(k, &c)| (unkey(k), c)).collect();
    let mut pal: Vec<u16> = median_cut(&bins, n).into_iter().map(snap).collect();
    pal.sort_unstable();
    pal.dedup();
    for _ in 0..4 {
        let mut sum = vec![[0u64; 4]; pal.len()];
        let near = Nearest::new(&pal);
        for &(c, w) in &bins {
            let s = &mut sum[near.get(c) as usize];
            for i in 0..3 {
                s[i] += c[i] as u64 * w as u64;
            }
            s[3] += w as u64;
        }
        let mut next: Vec<u16> = sum
            .iter()
            .zip(&pal)
            .map(|(s, &old)| if s[3] == 0 { old } else { snap([0, 1, 2].map(|i| (s[i] / s[3]) as u8)) })
            .collect();
        next.sort_unstable();
        next.dedup();
        if next == pal {
            break;
        }
        pal = next;
    }
    // Pixels between the Next's colours dither between the corners around
    // them, so the free entries go to the corners most pixels need.
    if pal.len() < n {
        let mut score = vec![0u64; 512];
        for &(c, w) in &bins {
            let lo = c.map(|v| v as u16 * 7 / 255);
            for corner in 0..8 {
                let v: [u16; 3] = [0, 1, 2].map(|i| (lo[i] + (corner >> i & 1)).min(7));
                score[snap(v.map(|x| (x * 255 / 7) as u8)) as usize] += w as u64;
            }
        }
        let mut order: Vec<u16> = (0..512).filter(|&c| score[c as usize] > 0).collect();
        order.sort_by_key(|&c| std::cmp::Reverse(score[c as usize]));
        for c in order {
            if pal.len() == n {
                break;
            }
            if !pal.contains(&c) {
                pal.push(c);
            }
        }
    }
    pal.sort_by_key(|&c| (luma(c), c));
    pal
}

fn key(c: [u8; 3]) -> usize {
    (c[0] as usize >> 3) << 10 | (c[1] as usize >> 3) << 5 | c[2] as usize >> 3
}

fn unkey(k: usize) -> [u8; 3] {
    [(k >> 10) & 31, (k >> 5) & 31, k & 31].map(|v| (v << 3 | v >> 2) as u8)
}

/// Splits the weighted colours into up to n boxes, each time the one with
/// the widest channel times its weight, and gives each box's mean.
fn median_cut(bins: &[([u8; 3], u32)], n: usize) -> Vec<[u8; 3]> {
    let mut boxes: Vec<Vec<([u8; 3], u32)>> = vec![bins.to_vec()];
    while boxes.len() < n {
        let Some((i, ch)) = boxes
            .iter()
            .enumerate()
            .filter(|(_, b)| b.len() > 1)
            .map(|(i, b)| {
                let (ch, range) = widest(b);
                let w: u64 = b.iter().map(|x| x.1 as u64).sum();
                (i, ch, range as u64 * (w as f64).sqrt() as u64)
            })
            .max_by_key(|x| x.2)
            .map(|(i, ch, _)| (i, ch))
        else {
            break;
        };
        let mut b = boxes.swap_remove(i);
        b.sort_unstable_by_key(|x| x.0[ch]);
        let total: u64 = b.iter().map(|x| x.1 as u64).sum();
        let (mut acc, mut cut) = (0u64, 1);
        for (j, x) in b.iter().enumerate() {
            acc += x.1 as u64;
            if acc * 2 >= total {
                cut = (j + 1).clamp(1, b.len() - 1);
                break;
            }
        }
        let rest = b.split_off(cut);
        boxes.push(b);
        boxes.push(rest);
    }
    boxes
        .iter()
        .map(|b| {
            let mut s = [0u64; 4];
            for &(c, w) in b {
                for i in 0..3 {
                    s[i] += c[i] as u64 * w as u64;
                }
                s[3] += w as u64;
            }
            [0, 1, 2].map(|i| (s[i] / s[3].max(1)) as u8)
        })
        .collect()
}

fn widest(b: &[([u8; 3], u32)]) -> (usize, u8) {
    (0..3)
        .map(|ch| {
            let (lo, hi) = b.iter().fold((255u8, 0u8), |(lo, hi), x| (lo.min(x.0[ch]), hi.max(x.0[ch])));
            (ch, hi - lo)
        })
        .max_by_key(|x| x.1)
        .unwrap_or((0, 0))
}

/// The nearest palette entry to a colour, remembered for each 15-bit
/// colour.
struct Nearest<'a> {
    pal: Vec<[u8; 3]>,
    cache: std::cell::RefCell<Vec<u16>>,
    _p: std::marker::PhantomData<&'a ()>,
}

impl Nearest<'_> {
    fn new(pal: &[u16]) -> Nearest<'static> {
        Nearest {
            pal: pal.iter().map(|&c| colour(c)).collect(),
            cache: std::cell::RefCell::new(vec![u16::MAX; 1 << 15]),
            _p: std::marker::PhantomData,
        }
    }

    fn get(&self, c: [u8; 3]) -> u8 {
        let k = key(c);
        let mut cache = self.cache.borrow_mut();
        if cache[k] == u16::MAX {
            let q = unkey(k);
            let best = (0..self.pal.len()).min_by_key(|&i| dist(q, self.pal[i])).unwrap_or(0);
            cache[k] = best as u16;
        }
        cache[k] as u8
    }
}

/// Floyd–Steinberg dithering to the palette, along each row and back
/// along the next.
fn dither(pixels: &[[u8; 3]], w: usize, pal: &[u16]) -> Vec<u8> {
    let near = Nearest::new(pal);
    let cols: Vec<[i32; 3]> = pal.iter().map(|&c| colour(c).map(|v| v as i32)).collect();
    let mut err = vec![[0i32; 3]; 2 * (w + 2)];
    let mut out = vec![0u8; pixels.len()];
    for y in 0..HEIGHT {
        let (cur, next) = err.split_at_mut(w + 2);
        let (cur, next) = if y % 2 == 0 { (cur, next) } else { (next, cur) };
        next.iter_mut().for_each(|e| *e = [0; 3]);
        let back = y % 2 == 1;
        for i in 0..w {
            let x = if back { w - 1 - i } else { i };
            let p = pixels[y * w + x];
            // Errors in sixteenths.
            let e = cur[x + 1];
            let v = [0, 1, 2].map(|c| (p[c] as i32 + e[c] / 16).clamp(0, 255));
            let n = near.get(v.map(|c| c as u8));
            out[y * w + x] = n;
            let q = [0, 1, 2].map(|c| v[c] - cols[n as usize][c]);
            let (ahead, behind) = if back { (x, x + 2) } else { (x + 2, x) };
            for c in 0..3 {
                cur[ahead][c] += q[c] * 7;
                next[behind][c] += q[c] * 3;
                next[x + 1][c] += q[c] * 5;
                next[ahead][c] += q[c];
            }
        }
        cur.iter_mut().for_each(|e| *e = [0; 3]);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn solid(w: usize, h: usize, f: impl Fn(usize, usize) -> [u8; 3]) -> Rgb {
        let pixels = (0..h).flat_map(|y| (0..w).map(move |x| (x, y))).map(|(x, y)| f(x, y)).collect();
        Rgb { width: w, height: h, pixels }
    }

    #[test]
    fn colours_snap_to_nine_bits() {
        assert_eq!(snap([0, 0, 0]), 0);
        assert_eq!(snap([255, 255, 255]), 0x1FF);
        assert_eq!(colour(0x1FF), [255, 255, 255]);
        // Layer 2's transparent magenta is never in a palette.
        assert_eq!(snap([255, 0, 255]), 7 << 6 | 1 << 3 | 7);
        for c in 0..512u16 {
            assert_ne!(snap(colour(c)) >> 1, 0xE3, "{c:03o}");
        }
    }

    #[test]
    fn a_frame_is_in_layer_2_order() {
        // A red left half and a blue right half, 320×256: column x at x * 256.
        let img = solid(320, 256, |x, _| if x < 160 { [255, 0, 0] } else { [0, 0, 255] });
        let f = convert(&img, Some(Mode::Lo));
        assert_eq!(f.pixels.len(), PIXEL_BYTES);
        let (red, blue) = (snap([255, 0, 0]), snap([0, 0, 255]));
        assert_eq!(f.palette[f.pixels[0] as usize], red);
        assert_eq!(f.palette[f.pixels[159 * 256 + 255] as usize], red);
        assert_eq!(f.palette[f.pixels[160 * 256] as usize], blue);
        let b = f.bytes();
        assert_eq!(b.len(), PIXEL_BYTES + 2 * f.palette.len());
        // Darkest first: blue before red.
        assert!(f.palette.iter().position(|&c| c == blue) < f.palette.iter().position(|&c| c == red));
    }

    #[test]
    fn hi_packs_two_pixels_a_byte() {
        // Stripes a pixel wide at 640×256: white, black, white...
        let img = solid(640, 512, |x, _| if x % 2 == 0 { [255; 3] } else { [0; 3] });
        let f = convert(&img, Some(Mode::Hi));
        assert!(f.palette.len() <= 16);
        let b = f.pixels[100 * 256 + 10];
        assert_eq!(f.palette[(b >> 4) as usize], 0x1FF);
        assert_eq!(f.palette[(b & 15) as usize], 0);
    }

    #[test]
    fn a_screenshot_of_few_colours_takes_hi_and_a_photo_lo() {
        let stripes = solid(1280, 512, |x, _| if x % 4 < 2 { [255; 3] } else { [0, 0, 128] });
        assert_eq!(best_mode(&stripes), Mode::Hi);
        let photo = solid(400, 300, |x, y| [(x * 255 / 399) as u8, (y * 255 / 299) as u8, ((x + y) % 256) as u8]);
        assert_eq!(best_mode(&photo), Mode::Lo);
    }

    #[test]
    fn fits_with_its_proportions_on_black() {
        // A tall white image: black on the left and right, white in the middle.
        let img = solid(100, 400, |_, _| [255; 3]);
        let px = fit(&img, Mode::Lo);
        assert_eq!(px[128 * 320], [0; 3]);
        assert_eq!(px[128 * 320 + 160], [255; 3]);
        assert_eq!(px[128 * 320 + 319], [0; 3]);
    }

    #[test]
    fn dithering_keeps_the_mean() {
        // A mid grey between two of the Next's greys comes out as a mix.
        let img = solid(320, 256, |_, _| [128; 3]);
        let px = fit(&img, Mode::Lo);
        let pal = vec![0, 0x1FF];
        let idx = dither(&px, 320, &pal);
        let white = idx.iter().filter(|&&i| i == 1).count();
        let share = white as f64 / idx.len() as f64;
        assert!((share - 0.5).abs() < 0.02, "{share}");
    }

    /// What the Next would show, as a PNG at 640×512, for a look by eye:
    /// `CBB_IMAGE=in.jpg CBB_PREVIEW=out.png cargo test preview -- --ignored`.
    #[test]
    #[ignore]
    fn preview() {
        let input = std::env::var("CBB_IMAGE").unwrap();
        let data = std::fs::read(&input).unwrap();
        let kind = if input.ends_with(".png") { "image/png" } else { "image/jpeg" };
        let f = convert(&decode(kind, &data).unwrap(), None);
        let mut rgb = Vec::with_capacity(640 * 512 * 3);
        for y in 0..512 {
            for x in 0..640 {
                let i = match f.mode {
                    Mode::Lo => f.pixels[(x / 2) * HEIGHT + y / 2],
                    Mode::Hi => {
                        let b = f.pixels[(x / 2) * HEIGHT + y / 2];
                        if x % 2 == 0 { b >> 4 } else { b & 15 }
                    }
                };
                rgb.extend_from_slice(&colour(f.palette[i as usize]));
            }
        }
        let out = std::fs::File::create(std::env::var("CBB_PREVIEW").unwrap()).unwrap();
        let mut e = png::Encoder::new(out, 640, 512);
        e.set_color(png::ColorType::Rgb);
        e.set_depth(png::BitDepth::Eight);
        e.write_header().unwrap().write_image_data(&rgb).unwrap();
        eprintln!("{:?}, {} colours", f.mode, f.palette.len());
    }

    #[test]
    fn decodes_png_and_jpeg() {
        let mut png_bytes = Vec::new();
        {
            let mut e = png::Encoder::new(&mut png_bytes, 2, 1);
            e.set_color(png::ColorType::Rgba);
            e.set_depth(png::BitDepth::Eight);
            let mut w = e.write_header().unwrap();
            w.write_image_data(&[255, 0, 0, 255, 0, 255, 0, 0]).unwrap();
        }
        let img = decode("image/png", &png_bytes).unwrap();
        assert_eq!((img.width, img.height), (2, 1));
        // Transparent goes on black.
        assert_eq!(img.pixels, vec![[255, 0, 0], [0, 0, 0]]);
        assert!(decode("image/heic", &png_bytes).is_err());
        assert!(decode("image/jpeg", b"not a jpeg").is_err());
        assert!(decode("image/png", b"not a png").is_err());
    }
}
