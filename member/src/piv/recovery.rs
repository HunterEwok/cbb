// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The 0.6 recovery secret on a YubiKey 5: the card's commands around the
//! bytes of `cbb_core::sheet::yubikey`. The card makes a P-256 key (PIN and
//! touch every time) in the first empty retired slot, searched from 95
//! down to 82, and the secret, sealed to that key, goes in that slot's own
//! certificate object, inside cbb's container certificate, whose CN names
//! the group: a device finds the group's slot without the PIN.
//!
//! Nothing on the card is overwritten: a slot that holds a key or a
//! certificate is never touched, whoever put it there, and a slot with a
//! key but no cbb certificate stays taken. Before anything is written, the
//! firmware must be a YubiKey 5's from 5.3 (GET VERSION; GET METADATA tells
//! an empty slot) and the card must hold no recovery key of this group.
//! Every refusal comes before the first write; 0.6 has no overwrite,
//! reset or delete. The management key, which GENERATE and PUT DATA need,
//! is used as the card keeps it and never changed: a PIN-protected one
//! read from PRINTED (5FC109), the factory one as it is, a changed one
//! asked of the person; a PIN-derived one is refused.
//!
//! Sources: Yubico's "PIV data objects", "The PIV PIN, PUK, and management
//! key", "PIV PIN-only mode" (docs.yubico.com, YubiKey SDK user's manual)
//! and "Yubico extensions" (developers.yubico.com/PIV), read 2026-11-14.

// The recovery opens a card (`open_one`); a computer seals none in 0.6:
// the root phone does, through the phones' core (ffi's `cbb_piv`).

use cbb_core::secret::Zeroizing;
use cbb_core::sheet::yubikey as yk;

use super::{Card, command, read_tlv, refused, tlv, verify};
use crate::error::{Error, Result};

/// The firmware that cbb asks for: GET METADATA came with 5.3.
pub const MIN_FIRMWARE: (u8, u8) = (5, 3);

pub const FIRMWARE: &str = "cbb keeps the recovery key on a YubiKey 5 with firmware 5.3 or later";
pub const HOLDS_ONE: &str =
    "this YubiKey already holds this group's recovery key: cbb opens it and never seals it again";
pub const NONE: &str = "this YubiKey holds no recovery key of cbb";
pub const TWO_SLOTS: &str = "this YubiKey holds two recovery keys for this group: cbb does not choose between them";
pub const GROUPS: &str =
    "this YubiKey holds the recovery keys of more than one group: open it on a device of the group";
pub const PIN_DERIVED: &str = "set a PIN-protected management key in YubiKey Manager first";
pub const KEY_TRIES: &str = "three wrong management keys: cbb stops here";
/// What the caller shows beside the sheet: the two copies back each other.
pub const DUPLICATES: &str = "the YubiKey and the recovery sheet hold the same recovery key: if one is lost or spoiled, the other still recovers the group; keep both, in different places";
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
        // YubiKey firmware 5.x answers 6A88 (referenced data not found) for
        // an empty slot; 6A82 is kept for cards that answer as for a file.
        (_, 0x6a82 | 0x6a88) => return Ok(None),
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
/// give up. Returns whether it is the factory key, which cbb uses as it
/// is (the owner's choice, docs/decisions.md D-127).
fn unlock(c: &mut dyn Card, ask: &mut dyn FnMut(u8) -> Option<Zeroizing<Vec<u8>>>) -> Result<bool> {
    match management(c)? {
        Management::Default(alg) => match authenticate(c, alg, &super::factory_management_key())? {
            true => Ok(true),
            false => Err(Error::msg("the YubiKey turned down its default management key")),
        },
        Management::Protected(alg) => {
            let key = protected_key(c)?;
            match authenticate(c, alg, &key)? {
                true => Ok(false),
                false => Err(Error::msg("the YubiKey turned down its PIN-protected management key")),
            }
        }
        Management::Changed(alg) => {
            for n in 1..=3 {
                let Some(key) = ask(n) else { return Err(Error::msg("no management key given")) };
                if authenticate(c, alg, &key)? {
                    return Ok(false);
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

/// What a slot's certificate object holds: None when it is empty, else
/// cbb's container when it reads as one.
fn slot_object(c: &mut dyn Card, slot: u8) -> Result<Option<Option<yk::Container>>> {
    // The certificate objects read without the PIN.
    let Some(v) = get_data(c, &super::cert_object(slot))? else { return Ok(None) };
    Ok(Some(read_tlv(&v, 0x70).and_then(|(der, _)| yk::read_container(der))))
}

/// The card's retired slots as cbb sees them, from 95 down to 82.
struct Scan {
    /// The slots with cbb's container, of the group when one was named.
    ours: Vec<(u8, yk::Container)>,
    /// The first slot with neither a key nor a certificate.
    free: Option<u8>,
}

/// Reads the 14 retired slots' certificate objects and metadata, without
/// the PIN. A slot is free only when it holds neither a certificate nor a
/// key; a key without cbb's certificate keeps its slot taken forever.
fn scan(c: &mut dyn Card, tag: Option<&str>) -> Result<Scan> {
    let mut out = Scan { ours: Vec::new(), free: None };
    for slot in (super::FIRST_SLOT..=super::LAST_SLOT).rev() {
        match slot_object(c, slot)? {
            Some(Some(container)) => {
                if tag.is_none_or(|t| container.tag == t) {
                    out.ours.push((slot, container));
                }
            }
            Some(None) => {}
            None => {
                if out.free.is_none() && metadata(c, slot)?.is_none() {
                    out.free = Some(slot);
                }
            }
        }
    }
    Ok(out)
}

/// The checks before the PIN: the PIV application and firmware 5.3.
fn ready(c: &mut dyn Card) -> Result<()> {
    super::select(c)?;
    let (major, minor, _) = version(c)?;
    if (major, minor) < MIN_FIRMWARE {
        return Err(Error::msg(FIRMWARE));
    }
    Ok(())
}

/// What sealing did.
#[derive(Debug, PartialEq, Eq)]
pub struct Sealed {
    /// The retired slot that holds the key and its container.
    pub slot: u8,
    /// The card kept its factory management key, as cbb leaves it.
    pub default_key: bool,
}

/// Seals secret onto a YubiKey for the group of tag (`yubikey::TAG_LEN`
/// hex digits): the checks (none of this group's recovery keys there, an
/// empty slot), the PIN, the management key as the card keeps it, then
/// GENERATE in the slot (checked by GET METADATA), the seal, and last the
/// container in the slot's certificate object, read back.
pub fn seal(
    c: &mut dyn Card,
    pin: &str,
    secret: &[u8; 32],
    tag: &str,
    ask: &mut dyn FnMut(u8) -> Option<Zeroizing<Vec<u8>>>,
) -> Result<Sealed> {
    if !yk::is_tag(tag) {
        return Err(Error::msg("the group's tag is not 16 hex digits"));
    }
    ready(c)?;
    let found = scan(c, Some(tag))?;
    if !found.ours.is_empty() {
        return Err(Error::msg(HOLDS_ONE));
    }
    let slot = found.free.ok_or_else(|| Error::msg(super::NO_FREE_SLOT))?;
    verify(c, pin)?;
    let default_key = unlock(c, ask)?;
    // The first write: the card's key.
    let spec = tlv(0xac, &[tlv(0x80, &[ALG_P256]), tlv(0xaa, &[PIN_ALWAYS]), tlv(0xab, &[TOUCH_ALWAYS])].concat());
    let made = match command(c, 0x47, 0x00, slot, &spec)? {
        (d, 0x9000) => d,
        (_, sw) => return Err(refused(sw)),
    };
    let point = new_point(&made).ok_or_else(|| Error::msg("the YubiKey's new key does not parse"))?;
    let m = metadata(c, slot)?.ok_or_else(|| Error::msg(NOT_AS_ASKED))?;
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
    let cert = yk::container(tag, &point, &object).map_err(|e| Error::msg(e.to_string()))?;
    // The last write: the container, which names the slot as cbb's.
    super::put_certificate(c, slot, &cert)?;
    match slot_object(c, slot)? {
        Some(Some(back)) if back.tag == tag && back.point == point && back.object == object => {}
        _ => return Err(Error::msg("the YubiKey does not read back what cbb wrote")),
    }
    Ok(Sealed { slot, default_key })
}

/// Opens the secret on the one YubiKey PC/SC finds with cbb's recovery key
/// (`open`), of any group: the card is chosen before the PIN, so that a
/// wrong card costs no PIN attempt.
pub fn open_one(pin: &str) -> Result<Zeroizing<[u8; 32]>> {
    open_one_of(pin, None)
}

/// `open_one` for the group of tag, or any group with None.
pub fn open_one_of(pin: &str, tag: Option<&str>) -> Result<Zeroizing<[u8; 32]>> {
    open_among(super::cards()?, pin, tag)
}

/// `open_one_of` among cards.
fn open_among(cards: Vec<Box<dyn Card>>, pin: &str, tag: Option<&str>) -> Result<Zeroizing<[u8; 32]>> {
    let mut found = Vec::new();
    let mut last = super::NO_CARD;
    for mut c in cards {
        if ready(c.as_mut()).is_err() {
            continue;
        }
        last = NONE;
        if scan(c.as_mut(), tag).is_ok_and(|s| !s.ours.is_empty()) {
            found.push(c);
        }
    }
    match found.len() {
        0 => Err(Error::msg(last)),
        1 => open(found[0].as_mut(), pin, tag),
        _ => Err(Error::msg(super::TWO_CARDS)),
    }
}

/// Opens the secret on a YubiKey: the slot whose container names the group
/// of tag (or the one container, with None) is found without the PIN; its
/// key must be one cbb asked for, the point the container names; the card
/// does ECDH after the PIN and a touch. The caller checks the secret
/// against the group (`yubikey::check`), uses it for one signing and drops
/// it.
pub fn open(c: &mut dyn Card, pin: &str, tag: Option<&str>) -> Result<Zeroizing<[u8; 32]>> {
    ready(c)?;
    let mut found = scan(c, tag)?;
    let (slot, container) = match found.ours.len() {
        0 => return Err(Error::msg(NONE)),
        1 => found.ours.remove(0),
        // Several of one group, or of several groups when none was named.
        _ if found.ours.iter().all(|(_, c)| c.tag == found.ours[0].1.tag) => return Err(Error::msg(TWO_SLOTS)),
        _ => return Err(Error::msg(GROUPS)),
    };
    let sealed = yk::read(&container.object).map_err(|r| Error::msg(r.message()))?;
    match metadata(c, slot)? {
        Some(Metadata {
            algorithm: ALG_P256,
            origin: Some(ORIGIN_GENERATED),
            policy: Some((PIN_ALWAYS, TOUCH_ALWAYS)),
            point: Some(p),
            ..
        }) if p == container.point => {}
        _ => return Err(Error::msg(NOT_AS_ASKED)),
    }
    verify(c, pin)?;
    let input = tlv(0x7c, &[tlv(0x82, &[]), tlv(0x85, sealed.e)].concat());
    let data = match command(c, 0x87, ALG_P256, slot, &input)? {
        (_, 0x6982) => return Err(Error::msg("the YubiKey wants its PIN first")),
        (d, 0x9000) => Zeroizing::new(d),
        (_, sw) => return Err(refused(sw)),
    };
    let bad = || Error::msg("the YubiKey's answer does not parse");
    let (outer, _) = read_tlv(&data, 0x7c).ok_or_else(bad)?;
    let (z, _) = read_tlv(outer, 0x82).ok_or_else(bad)?;
    let z: Zeroizing<[u8; 32]> = Zeroizing::new(z.try_into().map_err(|_| bad())?);
    yk::open(&z, &container.point, &container.object).map_err(|r| Error::msg(r.message()))
}

#[cfg(test)]
pub(crate) mod tests;
