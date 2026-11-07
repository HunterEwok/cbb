// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! This device's place in a group: its device ID, its key, its member
//! certificate, the admin CA that issued it, the group CA and the later
//! roots. A lite member holds no CA keys, like a Mac (docs/protocol.md,
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
    let sig = key.sign_digest(&digest)?;
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
    /// device and its key and end later than the current one.
    pub fn with_cert_from(&self, der: &[u8], issuer: Option<&[u8]>) -> Result<Identity> {
        let mut next = self.clone();
        next.cert = Cert::parse(der).wrap("the renewed certificate")?;
        if let Some(i) = issuer {
            next.issuer = Some(Cert::parse(i).wrap("the renewed certificate's issuer")?);
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
        if next.cert.not_after <= self.cert.not_after {
            return Err(Error::msg("the renewed certificate does not end later than the current one"));
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
