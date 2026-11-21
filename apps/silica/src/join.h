// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Joining a group of 0.6 from afar by a remote invitation (docs/protocol.md,
// section 12), through ffi's cbb_joiner_* with the invitation's text: the
// phone dials the hub through the invitation's guest tunnel and shows its
// fingerprint, which the inviting admin compares; once admitted, the set is
// kept where the member then starts, and the member reaches the hub through
// that tunnel until the hub's offer comes. A phone joins at home by a
// pairing window's QR code (pairing06.h).
#pragma once

#include "errors.h"

#include <QObject>
#include <QString>
#include <QTimer>

struct cbb_joiner;

class Join : public QObject
{
    Q_OBJECT
    Q_PROPERTY(QString state READ state NOTIFY changed)
    Q_PROPERTY(QString error READ error NOTIFY changed)
    Q_PROPERTY(QString fingerprint READ fingerprint NOTIFY changed)
    Q_PROPERTY(bool byInvite READ byInvite NOTIFY changed)

public:
    explicit Join(QObject *parent = nullptr);
    ~Join() override;

    // idle, dialing (until the hub answered through the guest tunnel),
    // joining (waiting for the inviting admin), joined or failed.
    QString state() const { return m_state; }
    QString error() const { return m_error; }
    // The words the phone shows while it joins by an invitation, which the
    // inviting admin compares.
    QString fingerprint() const { return m_fingerprint; }
    bool byInvite() const { return !m_invite.isEmpty(); }
    // The invitation the phone joins by.
    QString invite() const { return m_invite; }

    // Joins by a remote invitation's text, which the user accepted, as the
    // phone named name with system os and the member key's public point,
    // keeping the set in dir.
    void startInvite(const QString &invite, const QString &dir, const QString &name, const QString &os, const QByteArray &publicKey);
    Q_INVOKABLE void stop();
    // Ends the join with f shown on the page.
    void fail(const Failure &f);

signals:
    void changed();
    // The phone joined the group (its ID in hex) as the device device; the
    // set is in dir.
    void joined(const QString &group, const QString &device);

private:
    void poll();
    void free();
    void setState(const QString &state);

    cbb_joiner *m_joiner = nullptr;
    QTimer m_poll;
    quint64 m_version = 0;
    bool m_answered = false;
    QString m_state = QStringLiteral("idle");
    QString m_error;
    QString m_invite;
    QString m_fingerprint;
};
