// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The hello of a member connection of 0.6 (format section 9.3,
//! `cbb_core::msg::member::HELLO`): what a member says of itself when the
//! connection opens. Everything in it is shown or asks for something; what
//! a device may do comes from its records. The set digest and the count
//! are the exchange's (link.rs); this is the rest.

use cbb_core::format::cbor::Value;

/// The hello's own fields, as one side writes them and the other reads
/// them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Hello {
    pub caps: u64,
    pub os: u64,
    pub name: String,
    pub wall_ms: u64,
    /// The sender's current copy, as its bytes (a copy of format section
    /// 10), for the copies' reader.
    pub current: Option<Vec<u8>>,
    /// 1 shared, 2 own.
    pub mode: u64,
    pub muted: bool,
    pub muted_for_ms: u64,
    pub device: Device,
    pub key_store: u64,
    pub actions: Vec<String>,
    pub release_seq: u64,
    pub release_keys_seq: u64,
    pub entries_seq: u64,
    pub entries_keys_seq: u64,
    /// Bit 1: it serves blobs.
    pub features: u64,
    pub keys_epoch: u64,
}

/// The hello's `device` map (field 13).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Device {
    pub form: u64,
    pub os_version: String,
    pub version: String,
    pub mac: Option<[u8; 6]>,
    pub archive: String,
}

/// Bit 1 of `features`: the device serves blobs.
pub const FEATURE_MEDIA: u64 = 1;

impl Hello {
    /// The fields above the exchange's, for `link::hello_with`: only those
    /// set, in order.
    pub fn fields(&self) -> Vec<(u16, Value<'_>)> {
        let mut f = Vec::new();
        let uint = |f: &mut Vec<(u16, Value<'_>)>, n: u16, v: u64| {
            if v != 0 {
                f.push((n, Value::Uint(v)));
            }
        };
        uint(&mut f, 2, self.caps);
        uint(&mut f, 3, self.os);
        if !self.name.is_empty() {
            f.push((4, Value::Text(&self.name)));
        }
        uint(&mut f, 5, self.wall_ms);
        if let Some(c) = self.current.as_deref().and_then(|b| cbb_core::format::cbor::decode(b).ok()) {
            f.push((6, c));
        }
        // 7 and 8 are the exchange's.
        uint(&mut f, 10, self.mode);
        if self.muted {
            f.push((11, Value::Uint(1)));
            uint(&mut f, 12, self.muted_for_ms);
        }
        let d = self.device.fields();
        if !d.is_empty() {
            f.push((13, Value::Map(d)));
        }
        uint(&mut f, 14, self.key_store);
        if !self.actions.is_empty() {
            f.push((15, Value::Array(self.actions.iter().map(|a| Value::Text(a)).collect())));
        }
        uint(&mut f, 16, self.release_seq);
        uint(&mut f, 17, self.release_keys_seq);
        uint(&mut f, 18, self.entries_seq);
        uint(&mut f, 19, self.entries_keys_seq);
        uint(&mut f, 20, self.features);
        uint(&mut f, 21, self.keys_epoch);
        f
    }

    /// Reads a hello as the core's reader gave it (`msg::read_noted`):
    /// a field out of this version's range is already left out there.
    pub fn read(v: &Value<'_>) -> Hello {
        let uint = |n: u16| v.get(n).and_then(Value::as_uint).unwrap_or(0);
        let text = |v: Option<&Value<'_>>| v.and_then(Value::as_text).unwrap_or_default().to_string();
        let d = v.get(13);
        Hello {
            caps: uint(2),
            os: uint(3),
            name: text(v.get(4)),
            wall_ms: uint(5),
            current: v.get(6).map(Value::encode),
            mode: uint(10),
            muted: uint(11) == 1,
            muted_for_ms: uint(12),
            device: Device {
                form: d.and_then(|d| d.get(1)).and_then(Value::as_uint).unwrap_or(0),
                os_version: text(d.and_then(|d| d.get(2))),
                version: text(d.and_then(|d| d.get(3))),
                mac: d.and_then(|d| d.get(4)).and_then(Value::as_bytes).and_then(|b| b.try_into().ok()),
                archive: text(d.and_then(|d| d.get(5))),
            },
            key_store: uint(14),
            actions: v
                .get(15)
                .and_then(Value::as_array)
                .unwrap_or(&[])
                .iter()
                .filter_map(|a| a.as_text().map(str::to_string))
                .collect(),
            release_seq: uint(16),
            release_keys_seq: uint(17),
            entries_seq: uint(18),
            entries_keys_seq: uint(19),
            features: uint(20),
            keys_epoch: uint(21),
        }
    }
}

impl Device {
    fn fields(&self) -> Vec<(u16, Value<'_>)> {
        let mut f = Vec::new();
        if self.form != 0 {
            f.push((1, Value::Uint(self.form)));
        }
        if !self.os_version.is_empty() {
            f.push((2, Value::Text(&self.os_version)));
        }
        if !self.version.is_empty() {
            f.push((3, Value::Text(&self.version)));
        }
        if let Some(m) = &self.mac {
            f.push((4, Value::Bytes(m)));
        }
        if !self.archive.is_empty() {
            f.push((5, Value::Text(&self.archive)));
        }
        f
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_hello_reads_back_as_written_and_checks() {
        let h = Hello {
            caps: 3,
            os: 2,
            name: "laptop".into(),
            wall_ms: 1_700_000_000_000,
            mode: 1,
            muted: true,
            muted_for_ms: 60_000,
            device: Device {
                form: 1,
                os_version: "14.1".into(),
                version: "0.6.0".into(),
                mac: Some([2, 0, 0, 0, 0, 1]),
                archive: "linux-x64".into(),
            },
            key_store: 2,
            actions: vec!["lock".into()],
            release_seq: 4,
            features: FEATURE_MEDIA,
            keys_epoch: 9,
            ..Hello::default()
        };
        let (k1, k2) = cbb_core::records::pq::recovery_keys(&[1; 32]).unwrap();
        let point = |k: &p256::SecretKey| {
            p256::ecdsa::SigningKey::from(k).verifying_key().to_sec1_point(false).as_bytes().to_vec()
        };
        let root = p256::SecretKey::from_slice(&[2; 32]).unwrap();
        let set = cbb_core::records::RecordSet::new(
            cbb_core::records::Key::es256(point(&root)),
            cbb_core::records::Recovery::new(
                cbb_core::records::Key::es256(point(&k1)),
                cbb_core::records::Key::new(cbb_core::records::key::ALG_SLH_DSA, k2.public()),
            )
            .unwrap(),
        );
        let frame = crate::link::hello_with(&set, h.fields());
        let msg = &frame[4..];
        assert_eq!(cbb_core::msg::check(msg), Ok(cbb_core::msg::member::T_HELLO));
        let (_, v, dropped) = cbb_core::msg::read_noted(msg).unwrap();
        assert!(dropped.is_empty());
        assert_eq!(Hello::read(&v), h);
        // The least hello: the digest alone.
        let least = crate::link::hello(&set);
        let (_, v, _) = cbb_core::msg::read_noted(&least[4..]).unwrap();
        assert_eq!(Hello::read(&v), Hello::default());
    }
}
