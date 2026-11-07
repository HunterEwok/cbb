// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// The phone as a member of its group: the lite member's node in the app's
// process (lite/ffi's cbb_member_*, docs/core-api.md), with the key in the
// key store. It dials the members it finds, puts what they send into the
// clipboard, and sends what the user copied when the app comes to the
// front or the user asks (Aurora lets no app read the clipboard in the
// background).
#pragma once

#include "membership.h"

#include <QByteArray>
#include <QDateTime>
#include <QList>
#include <QObject>
#include <QString>
#include <QStringList>
#include <QTimer>
#include <QVariantList>

struct cbb_member;

class Member : public QObject
{
    Q_OBJECT
    Q_PROPERTY(bool running READ running NOTIFY changed)
    Q_PROPERTY(QStringList peers READ peers NOTIFY changed)
    // Every device of the group, as cbb_member_devices lists it: maps with
    // device, name, role, os, admin, root, frozen, online, self and listed.
    Q_PROPERTY(QVariantList devices READ devices NOTIFY devicesChanged)
    Q_PROPERTY(QString last READ last NOTIFY changed)
    Q_PROPERTY(QString error READ error NOTIFY changed)
    // The quick switch (design.md, "Muting a device"): the group's copies
    // stay out of the clipboard, until pausedUntil or, when it is invalid,
    // until the user turns them on again.
    Q_PROPERTY(bool paused READ paused NOTIFY changed)
    Q_PROPERTY(QDateTime pausedUntil READ pausedUntil NOTIFY changed)
    // An admin muted the phone: its copies stay its own, until mutedUntil
    // or, when it is invalid, until an admin unmutes it.
    Q_PROPERTY(bool muted READ muted NOTIFY changed)
    Q_PROPERTY(QDateTime mutedUntil READ mutedUntil NOTIFY changed)

public:
    explicit Member(QObject *parent = nullptr);
    ~Member() override;

    bool running() const { return m_member != nullptr; }
    // The names of the members connected now.
    QStringList peers() const { return m_peers; }
    QVariantList devices() const { return m_devices; }
    // What the clipboard got or sent last, shortened, for the main page.
    QString last() const { return m_last; }
    QString error() const { return m_error; }
    bool paused() const { return m_paused; }
    QDateTime pausedUntil() const { return m_pausedUntil; }
    bool muted() const { return m_muted; }
    QDateTime mutedUntil() const { return m_mutedUntil; }

    // Starts the member of membership as the phone named name.
    void start(const Membership &membership, const QString &name, const QByteArray &publicKey, const QString &os,
               const QString &osVersion);
    void stop();

    // Sends the clipboard's text when it is new: neither what the group
    // sent last nor what the phone sent last.
    Q_INVOKABLE void sendClipboard();

    // Keeps the group's copies out of the clipboard for minutes (0 for
    // until resume), or takes them again; the phone's own still go out.
    Q_INVOKABLE void pause(int minutes);
    Q_INVOKABLE void resume();

signals:
    void changed();
    void devicesChanged();
    // An admin renewed the member certificate, or a takeover made a new
    // root: the phone keeps them in member.json.
    void identityChanged(const QByteArray &cert, const QByteArray &issuer, const QList<QByteArray> &roots);

private:
    Q_INVOKABLE void event(const QByteArray &json);
    void write(const QString &text, bool secret, qint64 ttlMs);
    void pollPeers();
    void pollDevices();
    void setLast(const QString &text, bool secret);
    // Reads the pause and the mute from the core's answer, or asks for it.
    void readMuted(const QJsonObject &state);
    void pollMuted();

    cbb_member *m_member = nullptr;
    QTimer m_peerTimer;
    QStringList m_peers;
    QVariantList m_devices;
    QString m_last;
    QString m_error;
    // The clipboard's text as the group last set it or the phone last sent it.
    QString m_known;
    bool m_paused = false;
    QDateTime m_pausedUntil;
    bool m_muted = false;
    QDateTime m_mutedUntil;
};
