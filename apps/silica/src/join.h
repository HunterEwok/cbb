// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Joining a group by the phone's QR code (docs/protocol.md, section 6, "The
// joiner listens"): the phone listens on the member port and shows the QR
// code, the group's phone or computer scans it and dials in, and the core
// (ffi's cbb_join_*) runs the pairing inside its own TLS, signing with
// the key in the key store. This class only moves the bytes.
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

public:
    // The member port, which the QR code names.
    static const quint16 port = 8764;

    explicit Join(QObject *parent = nullptr);
    ~Join() override;

    // idle, listening, joining (a device dialed in), joined or failed.
    QString state() const { return m_state; }
    QString code() const { return m_code; }
    // The QR code's rows, '1' for a dark module.
    QStringList modules() const { return m_modules; }
    QString qr() const { return m_qr; }
    QString error() const { return m_error; }

    // Starts listening as a phone named name with system os ("aurora" or
    // "sailfish") and the key's public point; with adminKey, the admin
    // key's, it asks to be an admin, which only the group's root admits.
    void start(const QString &name, const QString &os, const QByteArray &publicKey, const QByteArray &adminKey = QByteArray());
    Q_INVOKABLE void stop();
    // Ends the join with f shown on the page.
    void fail(const Failure &f);

signals:
    void changed();
    // The phone joined; membership is saved.
    void joined(const Membership &membership);

private:
    void accept();
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
};
