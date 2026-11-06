// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// The phone's place in its group once it joined: its device ID, its member
// certificate with the admin CA that issued it, the group CA and the later
// roots (member.json), and the group's records (records.json, the core's
// records file), in the app's data folder. The key stays in the key store.
#pragma once

#include "errors.h"

#include <QByteArray>
#include <QJsonObject>
#include <QList>
#include <QString>

struct Membership
{
    QString device;
    QByteArray cert;
    QByteArray issuer; // empty when a root issued cert
    QByteArray groupCa;
    QList<QByteArray> roots;
    QByteArray records; // the records file

    bool isNull() const { return device.isEmpty(); }

    // The group's tag: the first 8 bytes of the group CA's SHA-256, in hex;
    // empty when the phone is in no group.
    QString groupTag() const;

    // From the core's answer of a join (lite/ffi's cbb_join_feed, joined).
    static Membership fromJoined(const QJsonObject &joined);

    // The saved membership, or a null one when the phone is in no group.
    static Membership load(Failure *failure);
    // Saves it: the records first, then member.json, each written whole.
    bool save(Failure *failure) const;
};

// The phone's secret for sealed messages (32 random bytes, seal.key in the
// app's data folder), made the first time.
QByteArray sealSecret(Failure *failure);
