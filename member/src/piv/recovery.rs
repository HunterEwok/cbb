// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The 0.6 recovery secret on a YubiKey 5: the card's commands around the
//! bytes of `cbb_core::sheet::yubikey`. The card makes a P-256 key in PIV's
//! retired slot 95 (PIN and touch every time), and the secret, sealed to
//! that key, goes in the data object 5FC121, which reads only after the PIN.
//!
//! Nothing on the card is overwritten: before anything is written, the
//! firmware must be a YubiKey 5's from 5.3 (GET VERSION, and GET METADATA
//! to see that slot 95 is empty), slot 95 must hold no key and 5FC121 no
//! value. Every refusal comes before the first write; 0.6 has no
//! overwrite, reset or delete. A card that holds cbb's object is opened,
//! never sealed again. The management key, which GENERATE and PUT DATA
//! need, is used as the card keeps it: a PIN-protected one read from
//! PRINTED (5FC109), a changed one asked of the person; a PIN-derived one
//! is refused. The factory default is publicly known, so with it anyone
//! holding the card could write over cbb's slot and object without the
//! PIN: `inspect` tells it before anything is written, and `seal` replaces
//! it, only when the person agreed, by a random key of the same kind kept
//! PIN-protected (Yubico's PIN-protected mode: the key in PRINTED, the flag
//! in ADMIN DATA). That is the one step in which cbb changes the
//! management key; without consent the card is sealed as it is, and the
//! warning goes back to the caller.
//!
//! Sources: Yubico's "PIV data objects", "The PIV PIN, PUK, and management
//! key", "PIV PIN-only mode" (docs.yubico.com, YubiKey SDK user's manual)
//! and "Yubico extensions" (developers.yubico.com/PIV), read 2026-11-14.

// The command line and the service call these with wave 5, when the 0.6
// groups replace 0.5's; until then only the tests do.
#![cfg_attr(not(test), allow(dead_code))]

use cbb_core::secret::Zeroizing;
use cbb_core::sheet::yubikey::{self as yk, Reason};

use super::{Card, command, read_tlv, refused, tlv, verify};
use crate::error::{Error, Result};

/// The firmware that cbb asks for: GET METADATA came with 5.3.
pub const MIN_FIRMWARE: (u8, u8) = (5, 3);

pub const FIRMWARE: &str = "cbb keeps the recovery key on a YubiKey 5 with firmware 5.3 or later";
pub const TAKEN: &str = "this YubiKey already holds something in the place cbb uses";
pub const HOLDS_ONE: &str = "this YubiKey already holds a recovery key: cbb opens it and never seals it again; to start over, use another YubiKey";
pub const NONE: &str = "this YubiKey holds no recovery key of cbb";
pub const PIN_DERIVED: &str = "set a PIN-protected management key in YubiKey Manager first";
pub const KEY_TRIES: &str = "three wrong management keys: cbb stops here";
/// What the caller shows when the card still has the factory management
/// key, before asking whether cbb may replace it.
pub const DEFAULT_KEY: &str = "this YubiKey still has its factory management key, which anyone can look up: whoever holds the card could erase or overwrite the recovery key on it without the PIN. cbb can replace it with a random key that the PIN protects; your other uses of the card that need the management key will then ask for the PIN";
/// What the caller shows beside the sheet: the two copies back each other.
pub const DUPLICATES: &str = "the YubiKey and the recovery sheet hold the same recovery key: if one is lost or spoiled, the other still recovers the group; keep both, in different places";
pub const PRINTED_TAKEN: &str = "this YubiKey's place for a PIN-protected management key holds something else: cbb leaves its management key as it is";
pub const NOT_AS_ASKED: &str =
    "the YubiKey did not make the key as cbb asks (the PIN and a touch every time): nothing more is written to it";

/// The PIV algorithm of an ECC P-256 key.
const ALG_P256: u8 = 0x11;
/// The management key's algorithms.
const ALG_3DES: u8 = 0x03;
const ALG_AES128: u8 = 0x08;
const ALG_AES192: u8 = 0x0a;
const ALG_AES256: u8 = 0x0c;
/// The management key's slot.
const SLOT_MGMT: u8 = 0x9b;
/// The default management key, of either algorithm.
const FACTORY_KEY: [u8; 24] = [1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8];
/// Yubico's ADMIN DATA and PRINTED objects.
const ADMIN_DATA: [u8; 3] = [0x5f, 0xff, 0x00];
const PRINTED: [u8; 3] = [0x5f, 0xc1, 0x09];
/// PIN policy "always" and touch policy "always" (Yubico's tags AA, AB).
const PIN_ALWAYS: u8 = 0x03;
const TOUCH_ALWAYS: u8 = 0x02;
/// GET METADATA's origin of a key made on the card.
const ORIGIN_GENERATED: u8 = 0x01;

fn version(c: &mut dyn Card) -> Result<(u8, u8, u8)> {
    match command(c, 0xfd, 0x00, 0x00, &[])? {
        (v, 0x9000) if v.len() == 3 => Ok((v[0], v[1], v[2])),
        _ => Err(Error::msg(FIRMWARE)),
    }
}

/// What GET METADATA tells of a slot.
#[derive(Debug, Default, PartialEq, Eq)]
struct Metadata {
    algorithm: u8,
    policy: Option<(u8, u8)>,
    origin: Option<u8>,
    point: Option<Vec<u8>>,
    default: Option<bool>,
}

/// GET METADATA of slot; None if it holds no key.
fn metadata(c: &mut dyn Card, slot: u8) -> Result<Option<Metadata>> {
    let data = match command(c, 0xf7, 0x00, slot, &[])? {
        (_, 0x6a82) => return Ok(None),
        (d, 0x9000) => d,
        (_, sw) => return Err(refused(sw)),
    };
    let bad = || Error::msg("the YubiKey's metadata does not parse");
    let mut m = Metadata::default();
    let mut rest = data.as_slice();
    while let Some(&tag) = rest.first() {
        let (v, r) = read_tlv(rest, tag).ok_or_else(bad)?;
        match (tag, v) {
            (0x01, [a]) => m.algorithm = *a,
            (0x02, [p, t]) => m.policy = Some((*p, *t)),
            (0x03, [o]) => m.origin = Some(*o),
            (0x04, _) => m.point = Some(read_tlv(v, 0x86).ok_or_else(bad)?.0.to_vec()),
            (0x05, [d]) => m.default = Some(*d == 1),
            _ => {}
        }
        rest = r;
    }
    Ok(Some(m))
}

/// GET DATA of an object: its value inside tag 53, None if it is absent.
fn get_data(c: &mut dyn Card, object: &[u8; 3]) -> Result<Option<Vec<u8>>> {
    let data = match command(c, 0xcb, 0x3f, 0xff, &tlv(0x5c, object))? {
        (_, 0x6a82) => return Ok(None),
        (_, 0x6982) => return Err(Error::msg("the YubiKey wants its PIN first")),
        (d, 0x9000) => d,
        (_, sw) => return Err(refused(sw)),
    };
    match read_tlv(&data, 0x53) {
        Some((v, [])) => Ok(Some(v.to_vec())),
        _ => Err(Error::msg("the YubiKey's data object does not parse")),
    }
}

/// The checks before sealing: a YubiKey 5 from 5.3, slot 95 empty, the PIN,
/// 5FC121 absent. Each refusal comes before any write.
fn may_seal(c: &mut dyn Card, pin: &str) -> Result<()> {
    super::select(c)?;
    let (major, minor, _) = version(c)?;
    if (major, minor) < MIN_FIRMWARE {
        return Err(Error::msg(FIRMWARE));
    }
    let key = metadata(c, yk::SLOT)?;
    verify(c, pin)?;
    match get_data(c, &yk::OBJECT)? {
        Some(v) if yk::is_ours(&v) && key.is_some() => Err(Error::msg(HOLDS_ONE)),
        Some(_) => Err(Error::msg(TAKEN)),
        None if key.is_some() => Err(Error::msg(TAKEN)),
        None => Ok(()),
    }
}

/// How the card keeps its management key, from GET METADATA of 9B and
/// ADMIN DATA.
enum Management {
    Default(u8),
    Protected(u8),
    Changed(u8),
}

fn management(c: &mut dyn Card) -> Result<Management> {
    let m = metadata(c, SLOT_MGMT)?.ok_or_else(|| Error::msg("the YubiKey has no management key"))?;
    let alg = m.algorithm;
    if m.default == Some(true) {
        return Ok(Management::Default(alg));
    }
    // ADMIN DATA: 53 { 80 { 81 flags, 82 salt (PIN-derived), ... } }.
    let Some(admin) = get_data(c, &ADMIN_DATA)? else { return Ok(Management::Changed(alg)) };
    let bad = || Error::msg("the YubiKey's admin data does not parse");
    let (mut inner, _) = read_tlv(&admin, 0x80).ok_or_else(bad)?;
    let mut protected = false;
    while let Some(&tag) = inner.first() {
        let (v, r) = read_tlv(inner, tag).ok_or_else(bad)?;
        match tag {
            0x81 => protected = v.first().is_some_and(|f| f & 0x02 != 0),
            0x82 => return Err(Error::msg(PIN_DERIVED)),
            _ => {}
        }
        inner = r;
    }
    Ok(if protected { Management::Protected(alg) } else { Management::Changed(alg) })
}

/// The PIN-protected management key from PRINTED: 53 { 88 { 89 key } }.
fn protected_key(c: &mut dyn Card) -> Result<Zeroizing<Vec<u8>>> {
    let bad = || Error::msg("the YubiKey's protected management key does not parse");
    let printed = Zeroizing::new(get_data(c, &PRINTED)?.ok_or_else(bad)?);
    let (inner, _) = read_tlv(&printed, 0x88).ok_or_else(bad)?;
    let (key, _) = read_tlv(inner, 0x89).ok_or_else(bad)?;
    Ok(Zeroizing::new(key.to_vec()))
}

fn block(alg: u8) -> Option<usize> {
    match alg {
        ALG_3DES => Some(8),
        ALG_AES128 | ALG_AES192 | ALG_AES256 => Some(16),
        _ => None,
    }
}

/// One block through the management key's cipher.
fn cipher(alg: u8, key: &[u8], b: &[u8], encrypt: bool) -> Option<Vec<u8>> {
    use aes::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
    fn run<C: KeyInit + BlockCipherEncrypt + BlockCipherDecrypt>(
        key: &[u8],
        b: &[u8],
        encrypt: bool,
    ) -> Option<Vec<u8>> {
        let c = C::new_from_slice(key).ok()?;
        let mut blk = aes::cipher::Block::<C>::try_from(b).ok()?;
        if encrypt {
            c.encrypt_block(&mut blk);
        } else {
            c.decrypt_block(&mut blk);
        }
        Some(blk.to_vec())
    }
    match (alg, key.len()) {
        (ALG_3DES, 24) => run::<des::TdesEde3>(key, b, encrypt),
        (ALG_AES128, 16) => run::<aes::Aes128>(key, b, encrypt),
        (ALG_AES192, 24) => run::<aes::Aes192>(key, b, encrypt),
        (ALG_AES256, 32) => run::<aes::Aes256>(key, b, encrypt),
        _ => None,
    }
}

/// Mutual authentication with the management key; Ok(false) when the card
/// turns the key down.
fn authenticate(c: &mut dyn Card, alg: u8, key: &[u8]) -> Result<bool> {
    let n = block(alg).ok_or_else(|| Error::msg("the YubiKey's management key is of an unknown kind"))?;
    let bad = || Error::msg("the YubiKey's challenge does not parse");
    let witness = match command(c, 0x87, alg, SLOT_MGMT, &tlv(0x7c, &tlv(0x80, &[])))? {
        (d, 0x9000) => d,
        (_, sw) => return Err(refused(sw)),
    };
    let (outer, _) = read_tlv(&witness, 0x7c).ok_or_else(bad)?;
    let (w, _) = read_tlv(outer, 0x80).ok_or_else(bad)?;
    if w.len() != n {
        return Err(bad());
    }
    let Some(opened) = cipher(alg, key, w, false) else { return Ok(false) };
    let mut challenge = vec![0u8; n];
    getrandom::fill(&mut challenge).map_err(|e| Error::msg(format!("no randomness: {e}")))?;
    let body = [tlv(0x80, &opened), tlv(0x81, &challenge)].concat();
    let answer = match command(c, 0x87, alg, SLOT_MGMT, &tlv(0x7c, &body))? {
        (d, 0x9000) => d,
        (_, 0x6982) => return Ok(false),
        (_, sw) => return Err(refused(sw)),
    };
    let (outer, _) = read_tlv(&answer, 0x7c).ok_or_else(bad)?;
    let (r, _) = read_tlv(outer, 0x82).ok_or_else(bad)?;
    Ok(cipher(alg, key, &challenge, true).is_some_and(|want| want == r))
}

/// Authenticates with the management key as the card keeps it; ask gives
/// a changed key, typed by the person, for try 1, 2 or 3, None if they
/// give up. Returns the key's algorithm when it is still the default.
fn unlock(c: &mut dyn Card, ask: &mut dyn FnMut(u8) -> Option<Zeroizing<Vec<u8>>>) -> Result<Option<u8>> {
    match management(c)? {
        Management::Default(alg) => match authenticate(c, alg, &FACTORY_KEY)? {
            true => Ok(Some(alg)),
            false => Err(Error::msg("the YubiKey turned down its default management key")),
        },
        Management::Protected(alg) => {
            let key = protected_key(c)?;
            match authenticate(c, alg, &key)? {
                true => Ok(None),
                false => Err(Error::msg("the YubiKey turned down its PIN-protected management key")),
            }
        }
        Management::Changed(alg) => {
            for n in 1..=3 {
                let Some(key) = ask(n) else { return Err(Error::msg("no management key given")) };
                if authenticate(c, alg, &key)? {
                    return Ok(None);
                }
            }
            Err(Error::msg(KEY_TRIES))
        }
    }
}

/// The point of GENERATE's answer: 7F49 { 86 point }.
fn new_point(b: &[u8]) -> Option<Vec<u8>> {
    // The two-byte tag 7F49 read as a one-byte tag in its place.
    let rest = b.strip_prefix(&[0x7f][..])?;
    let (v, _) = read_tlv(rest, 0x49)?;
    read_tlv(v, 0x86).map(|(p, _)| p.to_vec())
}

/// What the card is like before sealing (`inspect`).
#[derive(Debug, PartialEq, Eq)]
pub struct Inspected {
    /// The card still has the factory management key: the caller shows
    /// `DEFAULT_KEY` and asks whether cbb may replace it.
    pub default_key: bool,
}

/// The checks of sealing, and how the card keeps its management key, with
/// nothing written: the caller runs it first, shows `DEFAULT_KEY` when
/// the key is the default and passes the person's answer to `seal`.
pub fn inspect(c: &mut dyn Card, pin: &str) -> Result<Inspected> {
    may_seal(c, pin)?;
    Ok(Inspected { default_key: matches!(management(c)?, Management::Default(_)) })
}

/// What sealing did.
#[derive(Debug, PartialEq, Eq)]
pub struct Sealed {
    /// The card's management key is still the factory one: the person did
    /// not agree to replace it, or cbb could not (`warning`). The caller
    /// shows the warning.
    pub default_key: bool,
    /// cbb replaced the factory key with a PIN-protected random one.
    pub replaced: bool,
    /// What the caller shows after sealing, when the card keeps its
    /// factory key: `DEFAULT_KEY`, or `PRINTED_TAKEN` when cbb would have
    /// replaced it but the card's place for it holds something else.
    pub warning: Option<&'static str>,
}

/// SET MANAGEMENT KEY (Yubico's INS FF), no touch: the algorithm, then 9B
/// and the new key.
fn set_management_key(c: &mut dyn Card, alg: u8, key: &[u8]) -> Result<()> {
    let len = u8::try_from(key.len()).map_err(|_| Error::msg("a management key is at most 32 bytes"))?;
    let data = [&[alg, SLOT_MGMT, len][..], key].concat();
    match command(c, 0xff, 0xff, 0xff, &data)? {
        (_, 0x9000) => Ok(()),
        (_, sw) => Err(refused(sw)),
    }
}

fn put_data(c: &mut dyn Card, object: &[u8; 3], value: &[u8]) -> Result<()> {
    let put = [tlv(0x5c, object), tlv(0x53, value)].concat();
    match command(c, 0xdb, 0x3f, 0xff, &put)? {
        (_, 0x9000) => Ok(()),
        (_, sw) => Err(refused(sw)),
    }
}

/// ADMIN DATA with the flag "the management key is PIN-protected" set and
/// every other field kept: 53 { 80 { 81 flags, ... } }.
fn admin_data_protected(old: Option<&[u8]>) -> Result<Vec<u8>> {
    let bad = || Error::msg("the YubiKey's admin data does not parse");
    let mut fields: Vec<(u8, Vec<u8>)> = Vec::new();
    if let Some(old) = old {
        let (mut inner, _) = read_tlv(old, 0x80).ok_or_else(bad)?;
        while let Some(&tag) = inner.first() {
            let (v, r) = read_tlv(inner, tag).ok_or_else(bad)?;
            fields.push((tag, v.to_vec()));
            inner = r;
        }
    }
    match fields.iter_mut().find(|(t, _)| *t == 0x81) {
        Some((_, v)) if !v.is_empty() => v[0] |= 0x02,
        Some((_, v)) => *v = vec![0x02],
        None => fields.insert(0, (0x81, vec![0x02])),
    }
    let inner: Vec<u8> = fields.iter().flat_map(|(t, v)| tlv(*t, v)).collect();
    Ok(tlv(0x80, &inner))
}

/// Replaces the factory management key by a random key of the same kind,
/// kept PIN-protected, while the card is authenticated with the factory
/// key and the PIN verified. The writes go in the order that leaves the
/// card usable if one fails: PRINTED with the new key, then ADMIN DATA's
/// flag, then the key itself. Until the last write the card still answers
/// to its factory key, which GET METADATA reports, so the key cbb reads
/// from PRINTED is used only after the card took it; the last write is
/// one command. Afterwards cbb authenticates again with the new key.
/// Returns false, with nothing written, when PRINTED holds anything but a
/// PIN-protected key of an earlier try.
fn protect(c: &mut dyn Card, alg: u8) -> Result<bool> {
    if let Some(old) = get_data(c, &PRINTED)? {
        let ours = read_tlv(&old, 0x88)
            .and_then(|(v, _)| read_tlv(v, 0x89))
            .is_some_and(|(k, _)| block(alg).is_some() && !k.is_empty());
        if !ours {
            return Ok(false);
        }
    }
    let admin = get_data(c, &ADMIN_DATA)?;
    if let Some(a) = admin.as_deref() {
        // A PIN-derived key's salt: not a card cbb sets up.
        let (mut inner, _) = read_tlv(a, 0x80).ok_or_else(|| Error::msg("the YubiKey's admin data does not parse"))?;
        while let Some(&tag) = inner.first() {
            let Some((_, r)) = read_tlv(inner, tag) else { break };
            if tag == 0x82 {
                return Ok(false);
            }
            inner = r;
        }
    }
    let len = match alg {
        ALG_3DES | ALG_AES192 => 24,
        ALG_AES128 => 16,
        ALG_AES256 => 32,
        _ => return Ok(false),
    };
    let mut key = Zeroizing::new(vec![0u8; len]);
    getrandom::fill(key.as_mut_slice()).map_err(|e| Error::msg(format!("no randomness: {e}")))?;
    let printed = Zeroizing::new(tlv(0x88, &tlv(0x89, &key)));
    put_data(c, &PRINTED, &printed)?;
    put_data(c, &ADMIN_DATA, &admin_data_protected(admin.as_deref())?)?;
    set_management_key(c, alg, &key)?;
    if !authenticate(c, alg, &key)? {
        return Err(Error::msg("the YubiKey turned down the management key cbb just gave it"));
    }
    Ok(true)
}

/// Seals secret onto a YubiKey: the checks, the management key (replaced
/// first when it is the factory one and replace_default says the person
/// agreed), then GENERATE in slot 95 (checked by GET METADATA), then PUT
/// DATA of 5FC121, read back.
pub fn seal(
    c: &mut dyn Card,
    pin: &str,
    secret: &[u8; 32],
    ask: &mut dyn FnMut(u8) -> Option<Zeroizing<Vec<u8>>>,
    replace_default: bool,
) -> Result<Sealed> {
    may_seal(c, pin)?;
    let mut out = Sealed { default_key: false, replaced: false, warning: None };
    if let Some(alg) = unlock(c, ask)? {
        if replace_default && protect(c, alg)? {
            out.replaced = true;
        } else {
            out.default_key = true;
            out.warning = Some(if replace_default { PRINTED_TAKEN } else { DEFAULT_KEY });
        }
    }
    // The first write of the recovery key: the card's key.
    let spec = tlv(0xac, &[tlv(0x80, &[ALG_P256]), tlv(0xaa, &[PIN_ALWAYS]), tlv(0xab, &[TOUCH_ALWAYS])].concat());
    let made = match command(c, 0x47, 0x00, yk::SLOT, &spec)? {
        (d, 0x9000) => d,
        (_, sw) => return Err(refused(sw)),
    };
    let point = new_point(&made).ok_or_else(|| Error::msg("the YubiKey's new key does not parse"))?;
    let m = metadata(c, yk::SLOT)?.ok_or_else(|| Error::msg(NOT_AS_ASKED))?;
    if m.algorithm != ALG_P256
        || m.origin != Some(ORIGIN_GENERATED)
        || m.policy != Some((PIN_ALWAYS, TOUCH_ALWAYS))
        || m.point.as_deref() != Some(point.as_slice())
    {
        return Err(Error::msg(NOT_AS_ASKED));
    }
    let mut e = Zeroizing::new([0u8; 32]);
    let e = loop {
        getrandom::fill(e.as_mut()).map_err(|err| Error::msg(format!("no randomness: {err}")))?;
        if let Ok(k) = p256::SecretKey::from_slice(e.as_ref()) {
            break k;
        }
    };
    let object = yk::seal(secret, &point, &e).map_err(|r| Error::msg(r.message()))?;
    drop(e);
    put_data(c, &yk::OBJECT, &object)?;
    if get_data(c, &yk::OBJECT)?.as_deref() != Some(object.as_slice()) {
        return Err(Error::msg("the YubiKey does not read back what cbb wrote"));
    }
    Ok(out)
}

/// Opens the secret on a YubiKey: its key in slot 95 must be one cbb asked
/// for, 5FC121 cbb's object of a version this program reads; the card does
/// ECDH after the PIN and a touch. The caller checks the secret against
/// the group (`yubikey::check`), uses it for one signing and drops it.
pub fn open(c: &mut dyn Card, pin: &str) -> Result<Zeroizing<[u8; 32]>> {
    super::select(c)?;
    let (major, minor, _) = version(c)?;
    if (major, minor) < MIN_FIRMWARE {
        return Err(Error::msg(FIRMWARE));
    }
    let key = metadata(c, yk::SLOT)?;
    verify(c, pin)?;
    let object = get_data(c, &yk::OBJECT)?;
    let (key, object) = match (key, object) {
        (_, None) => return Err(Error::msg(NONE)),
        (None, Some(_)) => return Err(Error::msg(TAKEN)),
        (Some(k), Some(o)) => (k, o),
    };
    let sealed = yk::read(&object).map_err(|r| match r {
        Reason::NotCbb => Error::msg(TAKEN),
        r => Error::msg(r.message()),
    })?;
    let point = match key {
        Metadata {
            algorithm: ALG_P256,
            origin: Some(ORIGIN_GENERATED),
            policy: Some((PIN_ALWAYS, TOUCH_ALWAYS)),
            point: Some(p),
            ..
        } => p,
        _ => return Err(Error::msg(TAKEN)),
    };
    let input = tlv(0x7c, &[tlv(0x82, &[]), tlv(0x85, sealed.e)].concat());
    let data = match command(c, 0x87, ALG_P256, yk::SLOT, &input)? {
        (_, 0x6982) => return Err(Error::msg("the YubiKey wants its PIN first")),
        (d, 0x9000) => Zeroizing::new(d),
        (_, sw) => return Err(refused(sw)),
    };
    let bad = || Error::msg("the YubiKey's answer does not parse");
    let (outer, _) = read_tlv(&data, 0x7c).ok_or_else(bad)?;
    let (z, _) = read_tlv(outer, 0x82).ok_or_else(bad)?;
    let z: Zeroizing<[u8; 32]> = Zeroizing::new(z.try_into().map_err(|_| bad())?);
    yk::open(&z, &point, &object).map_err(|r| Error::msg(r.message()))
}

#[cfg(test)]
mod tests;
