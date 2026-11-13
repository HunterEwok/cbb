// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! This device's place in a group: its device ID, its key, its member
//! certificate, the admin CA that issued it, the group CA and the later
//! roots. A member in Rust holds no CA keys, like a Mac (docs/protocol.md,
//! section 2).
//!
//! The identity file has the format of the Go member's identity.json,
//! without the parts only an admin holds; where it is kept is the
//! program's business.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use p256::ecdsa::SigningKey;
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use serde::{Deserialize, Serialize};

use crate::certs::{self, Cert, DeviceId, b64};
use crate::error::{Context, Error, Result, Wrap};

const FILE_VERSION: u32 = 1;

/// A device's identity in its group. It is not changed once made; renewal
/// returns a new one.
#[derive(Clone)]
pub struct Identity {
    pub id: DeviceId,
    /// The device key, PKCS #8; empty when external holds it.
    pub key: Vec<u8>,
    /// The device key when the core does not hold it, such as the Aurora
    /// app's key in OP-TEE: the member's TLS and its copies' signatures go
    /// through it.
    pub external: Option<Arc<dyn ExternalKey>>,
    /// The member certificate, from a root or from issuer.
    pub cert: Cert,
    /// The admin CA that issued cert, when an admin did rather than a root.
    pub issuer: Option<Cert>,
    /// The group's first root, which names the group for good.
    pub group_ca: Cert,
    /// The roots that took a phone group over from group_ca, in order; the
    /// last is the current root.
    pub roots: Vec<Cert>,
}

impl Drop for Identity {
    /// The device key does not outlive the identity in memory.
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.key);
    }
}

/// Makes a new P-256 key, PKCS #8.
pub fn new_key() -> Result<Vec<u8>> {
    let key = loop {
        let mut b = [0u8; 32];
        getrandom::fill(&mut b).map_err(|_| Error::msg("cannot make a key: the system has no randomness"))?;
        // Almost every 32 bytes are a valid scalar.
        if let Ok(k) = SigningKey::from_slice(&b) {
            break k;
        }
    };
    let doc = key.to_pkcs8_der().map_err(|e| Error::msg(format!("cannot encode the new key ({e})")))?;
    Ok(doc.as_bytes().to_vec())
}

/// Reads a PKCS #8 P-256 key.
pub fn signing_key(pkcs8: &[u8]) -> Result<SigningKey> {
    SigningKey::from_pkcs8_der(pkcs8).map_err(|e| Error::msg(format!("the device key is not a P-256 key ({e})")))
}

/// Signs data with a PKCS #8 P-256 key: ECDSA with SHA-256, DER, as a
/// member signs its copies (docs/protocol.md, section 4, "Sealing").
pub fn sign(pkcs8: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    use p256::ecdsa::signature::Signer as _;
    let sig: p256::ecdsa::Signature = signing_key(pkcs8)?.sign(data);
    Ok(sig.to_der().as_bytes().to_vec())
}

/// A device key the core does not hold, such as a phone's key in its secure
/// hardware: its public key and a way to sign with it. A joiner with one
/// signs its pairing certificate and its TLS handshake through it.
pub trait ExternalKey: Send + Sync {
    /// The public key, SEC1 uncompressed (65 bytes).
    fn public(&self) -> Vec<u8>;
    /// ECDSA P-256 over a SHA-256 digest, DER.
    fn sign_digest(&self, digest: &[u8; 32]) -> Result<Vec<u8>>;
    /// ECDSA P-256 over data, DER: by default over its SHA-256 digest; a
    /// key whose holder must see what it signs, such as a watch's admin key
    /// (docs/protocol.md, section 10, "Watches"), takes the data itself.
    fn sign_data(&self, data: &[u8]) -> Result<Vec<u8>> {
        self.sign_digest(&certs::sha256(data))
    }
    /// Where the identity file keeps the key, for a key that the machine's
    /// hardware holds; None for a key the file cannot name, such as a
    /// phone app's.
    fn held(&self) -> Option<HeldKey> {
        None
    }
}

/// A key the core holds as PKCS #8 behind the [`ExternalKey`] interface,
/// such as a computer root's group CA key in its identity file: code that
/// signs with an external key signs with it too.
pub struct FileKey(SigningKey);

impl FileKey {
    /// Reads a PKCS #8 P-256 key.
    pub fn new(pkcs8: &[u8]) -> Result<FileKey> {
        Ok(FileKey(signing_key(pkcs8)?))
    }
}

impl ExternalKey for FileKey {
    fn public(&self) -> Vec<u8> {
        self.0.verifying_key().to_sec1_point(false).as_bytes().to_vec()
    }

    fn sign_digest(&self, digest: &[u8; 32]) -> Result<Vec<u8>> {
        use p256::ecdsa::signature::hazmat::PrehashSigner as _;
        let sig: p256::ecdsa::Signature =
            self.0.sign_prehash(digest).map_err(|_| Error::msg("cannot sign with the key"))?;
        Ok(sig.to_der().as_bytes().to_vec())
    }
}

/// A device key that the identity file keeps as a blob only the machine's
/// hardware loads, as the Go member's identity.json does: a TPM's
/// (`key_tpm`, kept as its JSON) or a Mac's Secure Enclave's (`key_se`).
/// cbb-helper opens it (docs/design.md, "The service and its helper").
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HeldKey {
    Tpm(serde_json::Value),
    SecureEnclave(Vec<u8>),
}

/// Opens a key the identity file keeps as a [`HeldKey`].
pub type OpenHeld<'a> = &'a dyn Fn(&HeldKey) -> Result<Arc<dyn ExternalKey>>;

/// Signs data with an external key: SHA-256, then the key, and checks the
/// signature it gave, so that a broken key fails here and not in the peer.
pub fn sign_external(key: &dyn ExternalKey, data: &[u8]) -> Result<Vec<u8>> {
    use p256::ecdsa::signature::hazmat::PrehashVerifier as _;
    let digest = certs::sha256(data);
    let sig = key.sign_data(data)?;
    let public = p256::ecdsa::VerifyingKey::from_sec1_bytes(&key.public())
        .map_err(|_| Error::msg("the device key is not a P-256 key"))?;
    let parsed =
        p256::ecdsa::Signature::from_der(&sig).map_err(|_| Error::msg("the device key's signature is not DER"))?;
    public.verify_prehash(&digest, &parsed).map_err(|_| Error::msg("the device key's signature does not verify"))?;
    Ok(sig)
}

/// Returns the uncompressed public key of a PKCS #8 P-256 key.
pub fn public_key(pkcs8: &[u8]) -> Result<Vec<u8>> {
    Ok(signing_key(pkcs8)?.verifying_key().to_sec1_point(false).as_bytes().to_vec())
}

impl Identity {
    /// The current root: the last of roots, or the group CA.
    pub fn root(&self) -> &Cert {
        self.roots.last().unwrap_or(&self.group_ca)
    }

    /// Every root the group had, the group CA first.
    pub fn trusted(&self) -> Vec<Cert> {
        let mut out = vec![self.group_ca.clone()];
        out.extend(self.roots.iter().cloned());
        out
    }

    /// The group tag.
    pub fn tag(&self) -> String {
        certs::tag(&self.group_ca)
    }

    /// The certificates this member presents: its own, and its issuer when
    /// an admin CA issued it.
    pub fn chain(&self) -> Vec<Vec<u8>> {
        let mut out = vec![self.cert.der.clone()];
        if let Some(i) = &self.issuer {
            out.push(i.der.clone());
        }
        out
    }

    /// Checks that the parts belong together: the certificate names this
    /// device and its key and comes from a root of the group, or from an
    /// admin CA under one. It does not check expiry.
    pub fn check(&self) -> Result<()> {
        match &self.external {
            Some(k) => self.check_key(&k.public()),
            None => self.check_key(&public_key(&self.key)?),
        }
    }

    /// Signs data with the device key, wherever it is: ECDSA with SHA-256,
    /// DER, as a member signs its copies.
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        match &self.external {
            Some(k) => sign_external(&**k, data),
            None => sign(&self.key, data),
        }
    }

    /// Checks the parts as check does, for the public key key (SEC1,
    /// uncompressed): for a device whose key is kept outside the core
    /// ([`ExternalKey`]), whose identity has no key of its own.
    pub fn check_key(&self, key: &[u8]) -> Result<()> {
        DeviceId::parse(self.id.as_str())?;
        certs::check_ca(&self.group_ca, "group CA", 1)?;
        if !self.roots.is_empty() && self.group_ca.path_len != Some(1) {
            return Err(Error::msg("only a group whose root is a phone has later roots"));
        }
        for r in &self.roots {
            certs::check_root(r)?;
        }
        let mut issuers = self.trusted();
        if let Some(issuer) = &self.issuer {
            if !issuers.iter().any(|root| certs::check_admin_ca(issuer, root).is_ok()) {
                return Err(Error::msg("the issuer is not an admin CA of the group"));
            }
            issuers = vec![issuer.clone()];
        }
        if self.cert.is_ca {
            return Err(Error::msg("the member certificate is a CA"));
        }
        if !issuers.iter().any(|i| self.cert.signed_by(i)) {
            return Err(Error::msg("the member certificate is not from its CA"));
        }
        if self.cert.public_key() != key {
            return Err(Error::msg("the member certificate does not match the device key"));
        }
        if certs::device_of(&self.cert).ok().as_ref() != Some(&self.id) {
            return Err(Error::msg(format!("the member certificate does not name the device {}", self.id)));
        }
        if !self.cert.server_auth || !self.cert.client_auth {
            return Err(Error::msg("the member certificate is not for client and server use"));
        }
        Ok(())
    }

    /// Returns the identity with a member certificate that an admin renewed
    /// for it: from the issuer of the current one or a root, or, when
    /// issuer is given, from that admin CA under a root. It must name this
    /// device and its key and end later than the current one, unless the
    /// current root took the group over from the root of the current one.
    pub fn with_cert_from(&self, der: &[u8], issuer: Option<&[u8]>) -> Result<Identity> {
        let next = self.with_cert_any_end(der, issuer)?;
        // A certificate from a root that took the group over replaces one
        // from an earlier root (or an admin CA under it) instead of renewing
        // it, so it may be issued in the same second.
        let root = self.root();
        let replaced = next.cert.signed_by(root)
            && match &self.issuer {
                // The admin's own key may be the new root's (the Aurora app).
                Some(i) => !i.signed_by(root),
                None => !self.cert.signed_by(root),
            };
        if !replaced && next.cert.not_after <= self.cert.not_after {
            return Err(Error::msg("the renewed certificate does not end later than the current one"));
        }
        Ok(next)
    }

    /// Returns the identity with the member certificate that the root an
    /// admin's takeover made issued it, as Go's TakenOver: it may end when
    /// the current one does, as one issued in the same second.
    pub fn with_cert_of_takeover(&self, der: &[u8]) -> Result<Identity> {
        let mut next = self.with_cert_any_end(der, None)?;
        next.issuer = None;
        next.check()?;
        Ok(next)
    }

    /// Returns the identity with a member certificate issued again for it,
    /// as with_cert_from checks it, whatever its end: the one from a new
    /// admin CA may be issued in the same second as the current one.
    pub fn with_cert_any_end(&self, der: &[u8], issuer: Option<&[u8]>) -> Result<Identity> {
        let mut next = self.clone();
        next.cert = Cert::parse(der).wrap("the renewed certificate")?;
        if let Some(i) = issuer {
            next.issuer = Some(Cert::parse(i).wrap("the renewed certificate's issuer")?);
        } else if next.cert.signed_by(self.root()) {
            // The current root issued it, even when an admin CA for the same
            // key issued the current one, as on the Aurora app after a
            // takeover, whose admin key became the root's.
            next.issuer = None;
        }
        if let Err(e) = next.check() {
            if self.issuer.is_none() || issuer.is_some() {
                return Err(e);
            }
            // A root renewed a certificate that an admin CA had issued.
            next.issuer = None;
            if next.check().is_err() {
                return Err(e);
            }
        }
        Ok(next)
    }

    /// The identity file's contents, in the format of Go's identity.json.
    pub fn to_file(&self) -> Result<Vec<u8>> {
        let held = match &self.external {
            None => None,
            Some(k) => Some(
                k.held()
                    .ok_or_else(|| Error::msg("an identity whose key is kept outside the core has no identity file"))?,
            ),
        };
        self.check()?;
        let f = File {
            v: FILE_VERSION,
            device: self.id.to_string(),
            key: self.key.clone(),
            key_tpm: match &held {
                Some(HeldKey::Tpm(b)) => Some(b.clone()),
                _ => None,
            },
            key_se: match &held {
                Some(HeldKey::SecureEnclave(b)) => Some(b.clone()),
                _ => None,
            },
            cert: self.cert.der.clone(),
            issuer: self.issuer.as_ref().map(|c| c.der.clone()),
            group_ca: self.group_ca.der.clone(),
            roots: self.roots.iter().map(|c| c.der.clone()).collect(),
        };
        let mut data = serde_json::to_vec_pretty(&f).context("cannot encode the identity")?;
        data.push(b'\n');
        Ok(data)
    }

    /// Reads and checks an identity file's contents.
    pub fn from_file(data: &[u8]) -> Result<Identity> {
        Identity::from_file_with(data, &|_| {
            Err(Error::msg(
                "this device's key is in the TPM or the Secure Enclave, which only cbb-helper opens, and there is no cbb-helper beside cbb",
            ))
        })
    }

    /// Reads and checks an identity file's contents, opening a key that
    /// the machine's hardware holds with open.
    pub fn from_file_with(data: &[u8], open: OpenHeld) -> Result<Identity> {
        parse(data, open)
    }
}

fn parse(data: &[u8], open: OpenHeld) -> Result<Identity> {
    let f: File = serde_json::from_slice(data).context("not an identity file")?;
    if f.v != FILE_VERSION {
        return Err(Error::msg(format!("unknown identity file version {}", f.v)));
    }
    let held = match (f.key_tpm, f.key_se) {
        (Some(b), None) if f.key.is_empty() => Some(HeldKey::Tpm(b)),
        (None, Some(b)) if f.key.is_empty() => Some(HeldKey::SecureEnclave(b)),
        (None, None) => None,
        _ => return Err(Error::msg("the identity file keeps its device key in more than one place")),
    };
    let external = held.as_ref().map(open).transpose()?;
    let id = Identity {
        id: DeviceId::parse(&f.device)?,
        key: f.key,
        external,
        cert: Cert::parse(&f.cert)?,
        issuer: f.issuer.as_deref().map(Cert::parse).transpose()?,
        group_ca: Cert::parse(&f.group_ca)?,
        roots: f.roots.iter().map(|d| Cert::parse(d)).collect::<Result<_>>()?,
    };
    id.check()?;
    Ok(id)
}

#[derive(Serialize, Deserialize)]
struct File {
    v: u32,
    device: String,
    #[serde(with = "b64", default, skip_serializing_if = "Vec::is_empty")]
    key: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    key_tpm: Option<serde_json::Value>,
    #[serde(with = "b64::opt", default, skip_serializing_if = "Option::is_none")]
    key_se: Option<Vec<u8>>,
    #[serde(with = "b64")]
    cert: Vec<u8>,
    #[serde(with = "b64::opt", default, skip_serializing_if = "Option::is_none")]
    issuer: Option<Vec<u8>>,
    #[serde(with = "b64")]
    group_ca: Vec<u8>,
    #[serde(with = "b64::list", default, skip_serializing_if = "Vec::is_empty")]
    roots: Vec<Vec<u8>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::issue;

    const NOW: i64 = 1_800_000_000;

    fn signer(pkcs8: &[u8]) -> impl FnMut(&[u8]) -> Result<Vec<u8>> + '_ {
        move |b: &[u8]| sign(pkcs8, b)
    }

    /// A group with a root, an admin CA under it and a device whose
    /// certificate the root issued.
    struct Group {
        root_key: Vec<u8>,
        root: Cert,
        admin_key: Vec<u8>,
        admin: Cert,
        device: DeviceId,
        key: Vec<u8>,
    }

    fn group() -> Group {
        let root_key = new_key().unwrap();
        let root = Cert::parse(&issue::root_ca(&public_key(&root_key).unwrap(), NOW, &mut signer(&root_key)).unwrap())
            .unwrap();
        let device = DeviceId::random();
        let admin_key = new_key().unwrap();
        let admin = Cert::parse(
            &issue::admin_ca(&device, &public_key(&admin_key).unwrap(), &root, NOW, &mut signer(&root_key)).unwrap(),
        )
        .unwrap();
        Group { root_key, root, admin_key, admin, device, key: new_key().unwrap() }
    }

    impl Group {
        fn cert(&self, by: &Cert, by_key: &[u8], point: &[u8], now: i64) -> Vec<u8> {
            issue::member(&self.device, point, by, now, &mut signer(by_key)).unwrap()
        }

        fn identity(&self) -> Identity {
            let point = public_key(&self.key).unwrap();
            Identity {
                id: self.device.clone(),
                key: self.key.clone(),
                external: None,
                cert: Cert::parse(&self.cert(&self.root, &self.root_key, &point, NOW)).unwrap(),
                issuer: None,
                group_ca: self.root.clone(),
                roots: vec![],
            }
        }
    }

    /// A key the hardware holds, played by a key in memory.
    struct Held(FileKey, HeldKey);

    impl ExternalKey for Held {
        fn public(&self) -> Vec<u8> {
            self.0.public()
        }
        fn sign_digest(&self, digest: &[u8; 32]) -> Result<Vec<u8>> {
            self.0.sign_digest(digest)
        }
        fn held(&self) -> Option<HeldKey> {
            Some(self.1.clone())
        }
    }

    /// A key that signs wrongly in the way its name says.
    struct Broken(&'static str, FileKey);

    impl ExternalKey for Broken {
        fn public(&self) -> Vec<u8> {
            match self.0 {
                "not p-256" => vec![4; 10],
                _ => self.1.public(),
            }
        }
        fn sign_digest(&self, digest: &[u8; 32]) -> Result<Vec<u8>> {
            match self.0 {
                "not der" => Ok(vec![1, 2, 3]),
                "another key" => FileKey::new(&new_key().unwrap())?.sign_digest(digest),
                _ => self.1.sign_digest(digest),
            }
        }
    }

    #[test]
    fn a_file_key_identity_round_trips() {
        let g = group();
        let id = g.identity();
        id.check().unwrap();
        assert_eq!(id.root().der, g.root.der);
        assert_eq!(id.trusted().len(), 1);
        assert_eq!(id.tag(), certs::tag(&g.root));
        assert_eq!(id.chain(), vec![id.cert.der.clone()]);

        let file = id.to_file().unwrap();
        assert!(file.ends_with(b"\n"));
        let back = Identity::from_file(&file).unwrap();
        assert_eq!((back.id.as_str(), &back.key, &back.cert.der), (id.id.as_str(), &id.key, &id.cert.der));
        let sig = back.sign(b"copy").unwrap();
        let point = public_key(&g.key).unwrap();
        let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&point).unwrap();
        use p256::ecdsa::signature::Verifier as _;
        vk.verify(b"copy", &p256::ecdsa::Signature::from_der(&sig).unwrap()).unwrap();
    }

    #[test]
    fn a_held_key_is_named_in_the_file_and_opened_by_the_caller() {
        let g = group();
        for held in [HeldKey::Tpm(serde_json::json!({"blob": "AAEC"})), HeldKey::SecureEnclave(vec![9, 8, 7])] {
            let mut id = g.identity();
            id.key = Vec::new();
            id.external = Some(Arc::new(Held(FileKey::new(&g.key).unwrap(), held.clone())));
            id.check().unwrap();
            let file = id.to_file().unwrap();
            let text = core::str::from_utf8(&file).unwrap();
            assert_eq!(text.contains("key_tpm"), matches!(held, HeldKey::Tpm(_)), "{text}");
            assert_eq!(text.contains("key_se"), matches!(held, HeldKey::SecureEnclave(_)), "{text}");
            assert!(!text.contains("\"key\""), "{text}");
            let e = Identity::from_file(&file).err().unwrap();
            assert!(e.to_string().contains("cbb-helper"), "{e}");
            let key = g.key.clone();
            let want = held.clone();
            let back = Identity::from_file_with(&file, &move |h| {
                assert_eq!(h, &want);
                Ok(Arc::new(FileKey::new(&key)?) as Arc<dyn ExternalKey>)
            })
            .unwrap();
            back.check().unwrap();
            assert!(back.sign(b"x").is_ok());
        }
        // A key the file cannot name, such as a phone app's.
        let mut id = g.identity();
        id.key = Vec::new();
        id.external = Some(Arc::new(FileKey::new(&g.key).unwrap()));
        assert!(id.to_file().err().unwrap().to_string().contains("no identity file"));
    }

    #[test]
    fn bad_files_are_refused() {
        let g = group();
        let file: serde_json::Value = serde_json::from_slice(&g.identity().to_file().unwrap()).unwrap();
        let with = |k: &str, v: serde_json::Value| {
            let mut f = file.clone();
            f[k] = v;
            serde_json::to_vec(&f).unwrap()
        };
        for (name, data, want) in [
            ("not json", b"{".to_vec(), "not an identity file"),
            ("another version", with("v", 2.into()), "unknown identity file version"),
            ("a file key and a TPM's", with("key_tpm", serde_json::json!({})), "more than one place"),
            ("a bad device", with("device", "x".into()), ""),
            ("a cert of another key", with("key", serde_json::Value::String(b64e(&new_key().unwrap()))), "match"),
        ] {
            let e = Identity::from_file(&data).err().unwrap_or_else(|| panic!("{name}: taken"));
            assert!(e.to_string().contains(want), "{name}: {e}");
        }
        let mut f = file.clone();
        f.as_object_mut().unwrap().remove("key");
        f["key_tpm"] = serde_json::json!({});
        f["key_se"] = "AAAA".into();
        assert!(Identity::from_file(&serde_json::to_vec(&f).unwrap()).is_err());
    }

    fn b64e(b: &[u8]) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(b)
    }

    #[test]
    fn identities_that_do_not_hold_together() {
        let g = group();
        let point = public_key(&g.key).unwrap();
        let check = |f: &dyn Fn(&mut Identity)| {
            let mut id = g.identity();
            f(&mut id);
            id.check().err().map(|e| e.to_string()).unwrap_or_default()
        };
        assert_eq!(check(&|_| {}), "");
        assert!(check(&|id| id.key = new_key().unwrap()).contains("does not match the device key"));
        assert!(check(&|id| id.id = DeviceId::random()).contains("does not name the device"));
        let stranger = group();
        assert!(
            check(&|id| id.cert = Cert::parse(&stranger.cert(&stranger.root, &stranger.root_key, &point, NOW)).unwrap())
                .contains("not from its CA")
        );
        // A certificate an admin CA issued, with and without that CA.
        let by_admin = Cert::parse(&g.cert(&g.admin, &g.admin_key, &point, NOW)).unwrap();
        assert_eq!(
            check(&|id| {
                id.cert = by_admin.clone();
                id.issuer = Some(g.admin.clone());
            }),
            ""
        );
        assert!(check(&|id| id.cert = by_admin.clone()).contains("not from its CA"));
        assert!(check(&|id| id.issuer = Some(stranger.admin.clone())).contains("not an admin CA"));
        assert!(check(&|id| id.cert = g.admin.clone()).contains("is a CA"));
        let mut id = g.identity();
        id.issuer = Some(g.admin.clone());
        id.cert = by_admin.clone();
        assert_eq!(id.chain().len(), 2);
    }

    #[test]
    fn renewed_certificates() {
        let g = group();
        let id = g.identity();
        let point = public_key(&g.key).unwrap();
        // Two years from now ends later than two years from a minute ago.
        let later = g.cert(&g.root, &g.root_key, &point, NOW + 60);
        let next = id.with_cert_from(&later, None).unwrap();
        assert_eq!(next.cert.der, later);
        let same = g.cert(&g.root, &g.root_key, &point, NOW);
        assert!(id.with_cert_from(&same, None).err().unwrap().to_string().contains("does not end later"));
        assert!(id.with_cert_from(b"junk", None).is_err());
        let other = g.cert(&g.root, &g.root_key, &public_key(&new_key().unwrap()).unwrap(), NOW + 60);
        assert!(id.with_cert_from(&other, None).is_err());

        // From an admin CA, named with it; then back to the root.
        let by_admin = g.cert(&g.admin, &g.admin_key, &point, NOW + 120);
        let admin_issued = id.with_cert_from(&by_admin, Some(&g.admin.der)).unwrap();
        assert_eq!(admin_issued.issuer.as_ref().map(|c| c.der.clone()), Some(g.admin.der.clone()));
        assert!(id.with_cert_from(&by_admin, Some(b"junk")).is_err());
        assert!(id.with_cert_from(&by_admin, None).is_err());
        let from_root = g.cert(&g.root, &g.root_key, &point, NOW + 180);
        let back = admin_issued.with_cert_from(&from_root, None).unwrap();
        assert!(back.issuer.is_none());
        // A takeover's certificate may end when the current one does.
        let taken = id.with_cert_of_takeover(&same).unwrap();
        assert!(taken.issuer.is_none());
        assert!(id.with_cert_of_takeover(&other).is_err());
    }

    #[test]
    fn external_keys_that_sign_wrongly() {
        let key = new_key().unwrap();
        let good = FileKey::new(&key).unwrap();
        assert_eq!(good.public(), public_key(&key).unwrap());
        assert!(good.held().is_none());
        sign_external(&good, b"x").unwrap();
        for (name, want) in
            [("not p-256", "not a P-256 key"), ("not der", "not DER"), ("another key", "does not verify")]
        {
            let e = sign_external(&Broken(name, FileKey::new(&key).unwrap()), b"x").unwrap_err();
            assert!(e.to_string().contains(want), "{name}: {e}");
        }
        assert!(FileKey::new(b"junk").is_err());
        assert!(signing_key(b"junk").unwrap_err().to_string().contains("not a P-256 key"));
        assert!(sign(b"junk", b"x").is_err());
        assert!(public_key(b"junk").is_err());
    }
}
