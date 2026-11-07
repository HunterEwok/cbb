// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The part of ring's AEAD API that GotaTun's WireGuard uses, on RustCrypto's
//! ChaCha20-Poly1305, which the lite member's TLS uses too. ring has C and
//! assembly, which would need a C cross compiler for each target; with this,
//! the lite member stays all Rust and links with rust-lld (.cargo/config.toml).
//! Only ChaCha20-Poly1305 with a 12-byte nonce is here, the one AEAD of WireGuard.

#![no_std]

pub mod error {
    /// An error with no details, as ring's.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Unspecified;

    impl core::fmt::Display for Unspecified {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.write_str("ring::error::Unspecified")
        }
    }

    impl core::error::Error for Unspecified {}
}

pub mod aead {
    use chacha20poly1305::ChaCha20Poly1305;
    use chacha20poly1305::aead::{AeadInOut, KeyInit};

    use crate::error::Unspecified;

    pub const NONCE_LEN: usize = 12;
    const TAG_LEN: usize = 16;

    /// An AEAD algorithm; only ChaCha20-Poly1305 is here.
    #[derive(Debug, PartialEq, Eq)]
    pub struct Algorithm(());

    pub static CHACHA20_POLY1305: Algorithm = Algorithm(());

    pub struct UnboundKey(ChaCha20Poly1305);

    impl UnboundKey {
        pub fn new(_: &'static Algorithm, key: &[u8]) -> Result<Self, Unspecified> {
            ChaCha20Poly1305::new_from_slice(key).map(UnboundKey).map_err(|_| Unspecified)
        }
    }

    pub struct LessSafeKey(ChaCha20Poly1305);

    impl LessSafeKey {
        pub fn new(key: UnboundKey) -> Self {
            LessSafeKey(key.0)
        }

        /// Encrypts in_out in place and returns the tag.
        pub fn seal_in_place_separate_tag<A: AsRef<[u8]>>(
            &self,
            nonce: Nonce,
            aad: Aad<A>,
            in_out: &mut [u8],
        ) -> Result<Tag, Unspecified> {
            let tag = self
                .0
                .encrypt_inout_detached((&nonce.0).into(), aad.0.as_ref(), in_out.into())
                .map_err(|_| Unspecified)?;
            Ok(Tag(tag.into()))
        }

        /// Checks the tag at the end of in_out and decrypts the rest in
        /// place, which it returns; on a wrong tag in_out is not decrypted.
        pub fn open_in_place<'a, A: AsRef<[u8]>>(
            &self,
            nonce: Nonce,
            aad: Aad<A>,
            in_out: &'a mut [u8],
        ) -> Result<&'a mut [u8], Unspecified> {
            let n = in_out.len().checked_sub(TAG_LEN).ok_or(Unspecified)?;
            let (data, tag) = in_out.split_at_mut(n);
            let tag = chacha20poly1305::Tag::try_from(&*tag).map_err(|_| Unspecified)?;
            self.0
                .decrypt_inout_detached((&nonce.0).into(), aad.0.as_ref(), data.into(), &tag)
                .map_err(|_| Unspecified)?;
            Ok(data)
        }
    }

    pub struct Nonce([u8; NONCE_LEN]);

    impl Nonce {
        pub fn assume_unique_for_key(n: [u8; NONCE_LEN]) -> Self {
            Nonce(n)
        }
    }

    pub struct Aad<A>(A);

    impl<A> Aad<A> {
        pub fn from(aad: A) -> Self {
            Aad(aad)
        }
    }

    pub struct Tag([u8; TAG_LEN]);

    impl AsRef<[u8]> for Tag {
        fn as_ref(&self) -> &[u8] {
            &self.0
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        // RFC 8439, section 2.8.2.
        #[test]
        fn rfc8439() {
            let key: [u8; 32] = core::array::from_fn(|i| 0x80 + i as u8);
            let nonce = [0x07, 0, 0, 0, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47];
            let aad = [0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7];
            let plain = *b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
            let k = LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, &key).unwrap());
            let mut buf = [0u8; 114 + 16];
            buf[..114].copy_from_slice(&plain);
            let tag = k
                .seal_in_place_separate_tag(Nonce::assume_unique_for_key(nonce), Aad::from(&aad), &mut buf[..114])
                .unwrap();
            assert_eq!(&buf[..4], &[0xd3, 0x1a, 0x8d, 0x34]);
            assert_eq!(
                tag.as_ref(),
                &[0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91]
            );
            buf[114..].copy_from_slice(tag.as_ref());
            let mut bad = buf;
            bad[0] ^= 1;
            assert!(k.open_in_place(Nonce::assume_unique_for_key(nonce), Aad::from(&aad), &mut bad).is_err());
            let opened = k.open_in_place(Nonce::assume_unique_for_key(nonce), Aad::from(&aad), &mut buf).unwrap();
            assert_eq!(opened, &plain[..]);
            assert!(UnboundKey::new(&CHACHA20_POLY1305, &key[..31]).is_err());
        }
    }
}
