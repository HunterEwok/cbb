// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// This phone as a remote paste target (docs/design.md, "Remote paste"), as
// Android's PasteReceiver: a paste command an admin signed is typed on the
// device the phone's Bluetooth keyboard is connected to, once this phone's
// user turned remote paste on. Aurora lets no app put keys into another
// app, so the keyboard is the one way in. It keeps the switches, the limits
// per sender and the log of the last pastes (never their text).
#pragma once

#include <QDateTime>
#include <QHash>
#include <QJsonObject>
#include <QList>
#include <QObject>
#include <QString>
#include <QVariantList>

class BleKeyboard;
class Member;

class PasteReceiver : public QObject
{
    Q_OBJECT
    // The switches only the phone's own user turns on: on lets the group's
    // admins paste, enter lets a paste press Enter (and hold line breaks).
    Q_PROPERTY(bool on READ on WRITE setOn NOTIFY settingsChanged)
    Q_PROPERTY(bool enter READ enter WRITE setEnter NOTIFY settingsChanged)
    // The last pastes, newest first: maps with time (QDateTime), by, name,
    // bytes, enter, status, reason and unverified.
    Q_PROPERTY(QVariantList log READ log NOTIFY logChanged)

public:
    static const int logSize = 100;
    static const int everyMs = 1000;
    static const int burst = 30;

    PasteReceiver(Member *member, BleKeyboard *keyboard, QObject *parent = nullptr);

    bool on() const;
    void setOn(bool on);
    bool enter() const;
    void setEnter(bool on);
    QVariantList log() const;

    // Deletes the log, which names the group's devices, as when the phone
    // leaves its group.
    void forgetLog();

    // Whether sender may paste at nowMs (at most one a second and burst a
    // minute); counts the paste if so.
    bool allow(const QString &sender, qint64 nowMs);

signals:
    void settingsChanged();
    void logChanged();
    // A paste went in, for a notification: name is the sender's.
    void pasted(const QString &name);

private:
    void carryOut(const QJsonObject &checked);
    void keep(const QJsonObject &entry);

    Member *m_member;
    BleKeyboard *m_keyboard;
    QHash<QString, QList<qint64>> m_sent;
};
