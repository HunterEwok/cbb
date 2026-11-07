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
#include <QObject>
#include <QString>
#include <QStringList>
#include <QTimer>

struct cbb_member;

class Member : public QObject
{
    Q_OBJECT
    Q_PROPERTY(bool running READ running NOTIFY changed)
    Q_PROPERTY(QStringList peers READ peers NOTIFY changed)
    Q_PROPERTY(QString last READ last NOTIFY changed)
    Q_PROPERTY(QString error READ error NOTIFY changed)

public:
    explicit Member(QObject *parent = nullptr);
    ~Member() override;

    bool running() const { return m_member != nullptr; }
    // The names of the members connected now.
    QStringList peers() const { return m_peers; }
    // What the clipboard got or sent last, shortened, for the main page.
    QString last() const { return m_last; }
    QString error() const { return m_error; }

    // Starts the member of membership as the phone named name.
    void start(const Membership &membership, const QString &name, const QByteArray &publicKey, const QString &os,
               const QString &osVersion);
    void stop();

    // Sends the clipboard's text when it is new: neither what the group
    // sent last nor what the phone sent last.
    Q_INVOKABLE void sendClipboard();

signals:
    void changed();

private:
    Q_INVOKABLE void event(const QByteArray &json);
    void write(const QString &text, bool secret, qint64 ttlMs);
    void pollPeers();
    void setLast(const QString &text, bool secret);

    cbb_member *m_member = nullptr;
    QTimer m_peerTimer;
    QStringList m_peers;
    QString m_last;
    QString m_error;
    // The clipboard's text as the group last set it or the phone last sent it.
    QString m_known;
};
