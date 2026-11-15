// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

use cbb_core::records::{Kind, Record, RecordSet};

/// Architecture 2026-11-14 (both candidates, same words): a device that
/// was removed, and whose removal a checkpoint dropped, never counts again
/// from records signed before the removal. "Dropped": a counting
/// checkpoint's head covers the removal's signer at or past its seq and
/// keeps not the removal. "Before": the admission's time_ms is not past the
/// removal's (the generators sign on one rising clock).
pub fn drop_oracle(m: &RecordSet, st: &cbb_core::records::State, who: &str) {
    if std::env::var_os("FZ_NO_DROP_ORACLE").is_some() {
        return;
    }
    let held: Vec<&Record> = m.in_dependency_order();
    let cps: Vec<&&Record> =
        held.iter().filter(|r| st.counting.contains(&r.id()) && matches!(r.body().kind, Kind::Checkpoint { .. })).collect();
    if cps.is_empty() {
        return;
    }
    for r in &held {
        let Kind::Revoke(rm) = &r.body().kind else { continue };
        if st.counting.contains(&r.id()) {
            continue;
        }
        let b = r.body();
        let dropped = cps.iter().any(|c| match &c.body().kind {
            Kind::Checkpoint { heads, keep, .. } => {
                heads.iter().any(|h| h.key == b.signer && h.seq >= b.seq) && !keep.contains(&r.id())
            }
            _ => false,
        });
        if !dropped {
            continue;
        }
        for key in &rm.keys {
            if st.device_by_key(key).is_none() {
                continue;
            }
            let admissions: Vec<&&Record> = held
                .iter()
                .filter(|x| st.counting.contains(&x.id()) && matches!(&x.body().kind, Kind::Device(d) if d.key.hash() == *key))
                .collect();
            if admissions.iter().any(|x| x.body().time_ms > b.time_ms) {
                continue;
            }
            panic!(
                "drops: {who}: a removed device whose removal a checkpoint dropped counts again from records signed before the removal ({} admissions)",
                admissions.len()
            );
        }
    }
}
