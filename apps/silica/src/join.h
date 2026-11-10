// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Joining a group by the phone's QR code (docs/protocol.md, section 6, "The
// joiner listens"): the phone listens on the member port and shows the QR
// code, the group's phone or computer scans it and dials in, and the core
// (ffi's cbb_join_*) runs the pairing inside its own TLS, signing with
// the key in the key store. Or by a remote invitation (section 12): the
// core starts the invitation's guest tunnel, the phone dials its loopback
// port, and the inviting admin admits the phone by the fingerprint it
// shows. This class only moves the bytes.
#pragma once

#include "membership.h"

#include <QByteArray>
#include <QObject>
#include <QPointer>
#include <QString>
#include <QStringList>

class QTcpServer;
class QTcpSocket;
struct cbb_join;

class Join : public QObject
{
    Q_OBJECT
    Q_PROPERTY(QString state READ state NOTIFY changed)
    Q_PROPERTY(QString code READ code NOTIFY changed)
    Q_PROPERTY(QStringList modules READ modules NOTIFY changed)
    Q_PROPERTY(QString qr READ qr NOTIFY changed)
    Q_PROPERTY(QString error READ error NOTIFY changed)
    Q_PROPERTY(QString fingerprint READ fingerprint NOTIFY changed)
    Q_PROPERTY(bool byInvite READ byInvite NOTIFY changed)

public:
    // The member port, which the QR code names.
    static const quint16 port = 8764;

    explicit Join(QObject *parent = nullptr);
    ~Join() override;

    // idle, listening, dialing (by an invitation), joining (a device
    // dialed in, or the invitation's hub answered), joined or failed.
    QString state() const { return m_state; }
    QString code() const { return m_code; }
    // The QR code's rows, '1' for a dark module.
    QStringList modules() const { return m_modules; }
    QString qr() const { return m_qr; }
    QString error() const { return m_error; }
    // The words the phone shows while it joins by an invitation, which the
    // inviting admin compares.
    QString fingerprint() const { return m_fingerprint; }
    bool byInvite() const { return !m_invite.isEmpty(); }
    // The invitation the phone joins by, until it joined.
    QString invite() const { return m_invite; }

    // Starts listening as a phone named name with system os ("aurora" or
    // "sailfish") and the key's public point; with adminKey, the admin
    // key's, it asks to be an admin, which only the group's root admits.
    void start(const QString &name, const QString &os, const QByteArray &publicKey, const QByteArray &adminKey = QByteArray());
    // Joins by a remote invitation's text, which the user accepted.
    void startInvite(const QString &name, const QString &os, const QByteArray &publicKey, const QString &invite);
    Q_INVOKABLE void stop();
    // Ends the join with f shown on the page.
    void fail(const Failure &f);

signals:
    void changed();
    // The phone joined; membership is saved.
    void joined(const Membership &membership);

private:
    void accept();
    void dialInvite();
    void inviteAttemptEnded();
    void feed(const QByteArray &data);
    void setState(const QString &state);

    cbb_join *m_join = nullptr;
    QTcpServer *m_server = nullptr;
    QPointer<QTcpSocket> m_conn;
    QByteArray m_publicKey;
    bool m_admin = false;
    int m_wrongCodes = 0;
    QString m_state = QStringLiteral("idle");
    QString m_code;
    QStringList m_modules;
    QString m_qr;
    QString m_error;
    QString m_fingerprint;
    QString m_invite;
    quint16 m_invitePort = 0;
    int m_inviteAttempts = 0;
};
