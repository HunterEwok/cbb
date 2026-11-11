// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The promise of the format's readers for the fuzz target `format` and the
//! property tests: whatever bytes they take have exactly one form, so
//! writing what was read gives the same bytes back; and no input makes them
//! panic.

use alloc::vec::Vec;

use super::cbor::{self, Value};
use super::{container, copy, envelope, frame, grant, print};

/// Feeds data to every reader of the format and checks the promise of each.
pub fn one_form(data: &[u8]) {
    if let Ok(v) = cbor::decode(data) {
        assert_eq!(v.encode(), data, "took an item that does not encode back");
        let _ = print::diag(&v);
        let _ = print::describe(print::Kind::Record, &v);
        let _ = print::describe(print::Kind::Message, &v);
        if let Ok(e) = envelope::Envelope::from_value(&v) {
            assert_eq!(envelope::write(e.body, e.sig, e.sig2), data, "took an envelope that does not write back");
            assert_eq!(e.map.encode(), e.body, "took a body that does not encode back");
            let _ = e.verify(&[0x04; 65], super::sig::LABEL_RECORD);
        }
        if let Ok(k) = super::Key::from_value(&v) {
            let _ = k.check();
            assert_eq!(k.encode(), data, "took a key that does not encode back");
        }
        let _ = copy::Copy::from_value(&v).map(|c| c.verify(&[0x04; 65]));
        let _ = grant::read(&v, &[0x04; 65]);
        let _ = grant::copy_sender(&v, &super::DeviceId([0; 16]));
    }
    if let Ok(m) = frame::message(data) {
        let entries: Vec<(u16, Value<'_>)> =
            m.map.as_map().unwrap_or(&[]).iter().filter(|(k, _)| *k != frame::FIELD_PAD).cloned().collect();
        let f = frame::write(&Value::Map(entries));
        assert_eq!(f.get(4..), Some(data), "took a message whose frame is another");
    }
    let _ = frame::read(data, frame::LIMIT_MEMBER);
    if let Ok(c) = copy::read_content(data) {
        let entries: Vec<(u16, Value<'_>)> =
            c.as_map().unwrap_or(&[]).iter().filter(|(k, _)| *k != 1).cloned().collect();
        assert_eq!(
            copy::write_content(&Value::Map(entries)).as_deref(),
            Some(data),
            "took a content padded another way"
        );
    }
    if let Ok(point) = container::read(data) {
        // The TBS follows a SEQUENCE head of 3 bytes (30 81 LL) or 4.
        let at: usize = if data.get(1) == Some(&0x81) { 3 } else { 4 };
        assert_eq!(
            container::build(&point).get(3..3 + container::TBS_LEN),
            data.get(at..at.saturating_add(container::TBS_LEN)),
            "took a container whose TBS is another"
        );
    }
}
