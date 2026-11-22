// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// The phone's place in its group once it joined: its device ID, the
// group's ID and its role (member.json in the app's data folder). The
// member keeps the group's set itself (group.cbor), and the key stays in
// the key store.
#pragma once

#include "errors.h"

#include <QString>

struct Membership
{
    QString device;
    // The group's ID in hex (docs/apps.md, "Screens").
    QString group;
    bool root = false; // the phone made the group or changed its root, and holds the root key
    bool admin = false; // the group's records make this phone an admin, as the member's devices say
    // The saved group was made before 0.6, which this version no longer
    // runs (D-126): the app offers only to leave it.
    bool before06 = false;

    bool isNull() const { return device.isEmpty() && !before06; }
    bool isAdmin() const { return root || admin; }

    // The group's tag: the first 8 bytes of the group ID in hex; empty
    // when the phone is in no group of 0.6.
    QString groupTag() const { return group.left(16); }

    // The saved membership, a null one when the phone is in no group, or
    // one with before06 set for a group made before 0.6.
    static Membership load(Failure *failure);
    // Saves member.json, written whole.
    bool save(Failure *failure) const;
    // Leaves the group on this phone: deletes every file the member keeps
    // of it, then member.json.
    static bool remove(Failure *failure);

    // The app's data directory, where the member keeps its files too.
    static QString directory();
};
