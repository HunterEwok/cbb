// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! A simulator case (seed 1326): the new root's writer, restored from its
//! saved set, writes a checkpoint that settles a record of the change's
//! first group and keeps an admin's acknowledgement. A set restored from
//! the writer's own records, and a fresh member fed what the writer gives,
//! must still count the change: before the fix they waited for good, as
//! the acknowledgement's signer was named only by records set aside for
//! the waiting root. The writer's saved records are in
//! testdata/records-case1326.

use super::*;

const SAVED: [&[u8]; 12] = [
    include_bytes!("../../../../testdata/records-case1326/r000"),
    include_bytes!("../../../../testdata/records-case1326/r001"),
    include_bytes!("../../../../testdata/records-case1326/r002"),
    include_bytes!("../../../../testdata/records-case1326/r003"),
    include_bytes!("../../../../testdata/records-case1326/r004"),
    include_bytes!("../../../../testdata/records-case1326/r005"),
    include_bytes!("../../../../testdata/records-case1326/r006"),
    include_bytes!("../../../../testdata/records-case1326/r007"),
    include_bytes!("../../../../testdata/records-case1326/r008"),
    include_bytes!("../../../../testdata/records-case1326/r009"),
    include_bytes!("../../../../testdata/records-case1326/r010"),
    include_bytes!("../../../../testdata/records-case1326/r011"),
];
const LIST: &[u8] = include_bytes!("../../../../testdata/records-case1326/l000");

fn saved() -> RecordSet {
    let recs: Vec<Record> = SAVED.iter().map(|b| Record::decode(b).unwrap()).collect();
    let recovery = Recovery { k1: k("sim1326/recovery").key, k2: crate::testkit::rk2().key() };
    RecordSet::restore(k("sim1326/root").key, recovery, &recs, &[LIST.to_vec()])
}

/// The writer's checkpoint leaves a closed set: restored, and fed to a
/// fresh member through `for_peer`, it counts the change as the writer
/// does; a member that only receives the checkpoint ends the same.
#[test]
fn a_checkpoint_after_a_change_leaves_a_closed_set() {
    let mut writer = saved();
    let st = writer.state();
    assert_eq!((st.roots.len(), st.counting.len()), (2, 12));
    crate::testkit::closed(&writer);
    let mut member = writer.clone();
    let cp = writer.write_checkpoint(&st, &k("sim1326/root1"), 1_793_007_461_220).unwrap();
    writer.insert(cp.clone()).unwrap();
    let live = writer.state();
    assert_eq!(live.roots.len(), 2);
    assert!(live.counting.contains(&cp.id()));
    crate::testkit::closed(&writer);
    // Every device of the group, fed only what the writer gives it.
    for d in &live.devices {
        let peer = d.key.hash();
        let given: Vec<Record> = writer.for_peer(&live, &peer).into_iter().cloned().collect();
        let lists: Vec<Vec<u8>> = writer.lists_for_peer(&live, &peer).into_iter().map(<[u8]>::to_vec).collect();
        let fresh = RecordSet::restore(writer.root().clone(), writer.recovery().clone(), &given, &lists);
        assert_eq!(fresh.state(), live, "{}", d.name);
    }
    // A member that receives the checkpoint.
    member.insert(cp).unwrap();
    assert_eq!(member.state(), live);
    crate::testkit::closed(&member);
}
