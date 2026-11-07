// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Adding a device to the group by its QR code, as an admin phone
// (docs/protocol.md, section 6, "The joiner listens"): the camera's frames
// go to the core's QR reader (ffi's cbb_qr_read), and once it finds a
// join code the phone dials the device and the core (cbb_admit_*) runs the
// pairing inside its own TLS, issuing the device's certificate with the
// admin key in the key store and sending its record to the group. This
// class moves the bytes and tries the code's addresses in turn.
#pragma once

#include "errors.h"

#include <QByteArray>
#include <QObject>
#include <QPointer>
#include <QString>
#include <QStringList>
#include <QVariant>

class QTcpSocket;
struct cbb_admit;
struct cbb_member;

class Admit : public QObject
{
    Q_OBJECT
    Q_PROPERTY(QString state READ state NOTIFY changed)
    Q_PROPERTY(QString device READ device NOTIFY changed)
    Q_PROPERTY(QString error READ error NOTIFY changed)
    Q_PROPERTY(QString hint READ hint NOTIFY changed)

public:
    explicit Admit(QObject *parent = nullptr);
    ~Admit() override;

    // scanning (waiting for a code), preparing (finding the admin key),
    // dialing, admitting, admitted (the device is in the group), confirmed
    // (it said it stored its identity) or failed.
    QString state() const { return m_state; }
    // The name of the device being added, once its description came.
    QString device() const { return m_device; }
    QString error() const { return m_error; }
    // What the last frame showed that is no join code, for the camera page.
    QString hint() const { return m_hint; }

    // Back to scanning, ending any admission.
    Q_INVOKABLE void reset();
    // Reads a camera frame (a QImage from grabToImage); returns the join
    // code it found, if any.
    Q_INVOKABLE QString scan(const QVariant &frame);
    // Starts with a join code: the app finds the admin key, then calls
    // admit.
    void admit(const QString &qr, cbb_member *member, const QByteArray &publicKey, const QByteArray &adminCa, bool makeAdmin);
    void setPreparing();
    void fail(const Failure &f);

signals:
    void changed();

private:
    void dialNext();
    void feed(const QByteArray &data);
    void handle(const QJsonObject &step);
    void setState(const QString &state);
    void close();

    cbb_admit *m_admit = nullptr;
    QPointer<QTcpSocket> m_conn;
    QStringList m_addrs;
    QString m_lastError;
    QString m_state = QStringLiteral("scanning");
    QString m_device;
    QString m_error;
    QString m_hint;
};
