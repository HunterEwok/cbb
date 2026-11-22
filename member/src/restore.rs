// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Restoring a group on a new phone with the group's recovery key, read
//! from the QR code of its sheet (docs/protocol.md, section 10, "The
//! recovery key"), for an app whose keys the core does not hold (the Aurora
//! app's in OP-TEE). The recovery key issues the phone a member certificate
//! under its own admin CA; a member of the group that browsing finds by the
//! sheet's tag takes it on a connection that carries records only and sends
//! the group's first root in its hello. The phone checks the records before
//! it signs anything, then starts its member with that certificate and
//! claims the group for a new root of its own with the recovery key
//! (cbb_member_manage's `recover` with the sheet). The claim waits the
//! group's delay, unless the root cancels it; the app's takeover then makes
//! the phone the root. As the Swift kit's Restore.
