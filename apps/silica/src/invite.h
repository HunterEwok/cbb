// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// A remote invitation (docs/protocol.md, section 12), both sides of it on
// this phone. As an admin: the core (ffi's cbb_invite_*) opens the
// invitation's guest tunnel on this phone when it is the group's hub, else
// through a hub of the group it reaches, and runs the pairing window; the
// page shows the invitation's QR code, and asks the user about each device
// that uses it by the fingerprint the device shows. As a phone without a
// group: reads an invitation the user scanned or pasted, for the page that
// accepts or declines it.
#pragma once

#include "errors.h"

#include <QByteArray>
#include <QObject>
#include <QString>
#include <QStringList>
#include <QTimer>
#include <QVariant>
#include <QVariantMap>

struct cbb_invite;
struct cbb_member;

class Invite : public QObject
{
    Q_OBJECT
    Q_PROPERTY(QString state READ state NOTIFY changed)
    Q_PROPERTY(QString text READ text NOTIFY changed)
    Q_PROPERTY(QStringList modules READ modules NOTIFY changed)
    Q_PROPERTY(double expiresMs READ expiresMs NOTIFY changed)
    Q_PROPERTY(QString joiningName READ joiningName NOTIFY changed)
    Q_PROPERTY(QString joiningOs READ joiningOs NOTIFY changed)
    Q_PROPERTY(QString fingerprint READ fingerprint NOTIFY changed)
    Q_PROPERTY(QString joined READ joined NOTIFY changed)
    Q_PROPERTY(QString error READ error NOTIFY changed)

public:
    explicit Invite(QObject *parent = nullptr);
    ~Invite() override;

    // idle, preparing (finding the admin key), opening (waiting for the
    // hub), open, joining (the user is asked), done or failed.
    QString state() const { return m_state; }
    // The invitation's text, cbb://invite#..., and its QR code's rows.
    QString text() const { return m_text; }
    QStringList modules() const { return m_modules; }
    // When it expires, Unix milliseconds.
    double expiresMs() const { return m_expiresMs; }
    // The device that used it, while the user is asked.
    QString joiningName() const { return m_joiningName; }
    QString joiningOs() const { return m_joiningOs; }
    QString fingerprint() const { return m_fingerprint; }
    // The name of the device that joined by it.
    QString joined() const { return m_joined; }
    QString error() const { return m_error; }

    void setPreparing();
    // Opens it with the admin key's public point and admin CA (empty on
    // the root), for seconds; the hub's answer is waited for off the GUI
    // thread.
    void open(cbb_member *member, const QByteArray &publicKey, const QByteArray &adminCa, int seconds);
    // The user's answer about the device that used it.
    Q_INVOKABLE void answer(bool yes);
    // Ends it, or forgets how the last one ended.
    Q_INVOKABLE void cancel();
    void fail(const Failure &f);

    // Reads what the user scanned or pasted as an invitation: {"group",
    // "hub", "expiresMs"} for the page that accepts or declines it, or
    // {"error"} with the message to show.
    Q_INVOKABLE QVariantMap read(const QString &text) const;
    // Reads a camera frame (a QImage from grabToImage); returns the
    // invitation's text it found, if any.
    Q_INVOKABLE QString scan(const QVariant &frame) const;

signals:
    void changed();

private:
    void poll();
    void setState(const QString &state);
    void close();

    cbb_invite *m_invite = nullptr;
    QTimer m_poll;
    quint64 m_version = 0;
    QString m_state = QStringLiteral("idle");
    QString m_text;
    QStringList m_modules;
    double m_expiresMs = 0;
    QString m_joiningName;
    QString m_joiningOs;
    QString m_fingerprint;
    QString m_joined;
    QString m_error;
};
