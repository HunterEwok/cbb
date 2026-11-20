// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Joining a group by a remote invitation (docs/protocol.md, section 12): the
// core (ffi's cbb_join_*) starts the invitation's guest tunnel, the phone
// dials its loopback port, and the inviting admin admits the phone by the
// fingerprint it shows; the core runs the pairing inside its own TLS,
// signing with the key in the key store. This class only moves the bytes.
// Joining at home is the pairing window's (pairing06.h).
#pragma once

#include "membership.h"

#include <QByteArray>
#include <QObject>
#include <QPointer>
#include <QString>
#include <QStringList>

class QTcpSocket;
struct cbb_join;

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

    // idle, dialing, joining (the invitation's hub answered), joined or
    // failed.
    QString state() const { return m_state; }
    QString error() const { return m_error; }
    // The words the phone shows while it joins by an invitation, which the
    // inviting admin compares.
    QString fingerprint() const { return m_fingerprint; }
    bool byInvite() const { return !m_invite.isEmpty(); }
    // The invitation the phone joins by, until it joined.
    QString invite() const { return m_invite; }

    // Joins by a remote invitation's text, which the user accepted, as a
    // phone named name with system os ("aurora" or "sailfish") and the
    // key's public point.
    void startInvite(const QString &name, const QString &os, const QByteArray &publicKey, const QString &invite);
    Q_INVOKABLE void stop();
    // Ends the join with f shown on the page.
    void fail(const Failure &f);

signals:
    void changed();
    // The phone joined; membership is saved.
    void joined(const Membership &membership);

private:
    void dialInvite();
    void inviteAttemptEnded();
    void feed(const QByteArray &data);
    void setState(const QString &state);

    cbb_join *m_join = nullptr;
    QPointer<QTcpSocket> m_conn;
    QByteArray m_publicKey;
    QString m_state = QStringLiteral("idle");
    QString m_error;
    QString m_fingerprint;
    QString m_invite;
    quint16 m_invitePort = 0;
    int m_inviteAttempts = 0;
};
