// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Pairing in a group of 0.6 (docs/apps.md, "Screens"; docs/protocol.md,
// section 3). PairWindow: an admin phone opens its member's pairing window
// (ffi's cbb_window_*), shows its QR code and announces it by mDNS; the code
// a dialing device shows waits for the person's "they match". Joiner: a
// phone without a group finds the one window announced at home (or dials
// the QR code's text the person pasted) through ffi's cbb_joiner_*, shows
// the same code, and keeps the group's set where its member then starts.
// The core runs the pairing; these classes only poll it.
#pragma once

#include "errors.h"

#include <QByteArray>
#include <QObject>
#include <QString>
#include <QStringList>
#include <QTimer>

struct cbb_member;
struct cbb_window;
struct cbb_joiner;

class PairWindow : public QObject
{
    Q_OBJECT
    Q_PROPERTY(QString state READ state NOTIFY changed)
    Q_PROPERTY(QString qr READ qr NOTIFY changed)
    Q_PROPERTY(QStringList modules READ modules NOTIFY changed)
    Q_PROPERTY(QString joiningName READ joiningName NOTIFY changed)
    Q_PROPERTY(QString code READ code NOTIFY changed)
    Q_PROPERTY(QString joined READ joined NOTIFY changed)
    Q_PROPERTY(QString error READ error NOTIFY changed)

public:
    explicit PairWindow(QObject *parent = nullptr);
    ~PairWindow() override;

    // idle, preparing (finding the admin key), open, joining (the person
    // is asked), done (a device joined; the window stays open for the
    // next), closed (its time is up) or failed.
    QString state() const { return m_state; }
    QString qr() const { return m_qr; }
    // The QR code's rows, '1' for a dark module.
    QStringList modules() const { return m_modules; }
    // The device that dialed and the code both screens show, while the
    // person is asked.
    QString joiningName() const { return m_joiningName; }
    QString code() const { return m_code; }
    // The name of the last device that joined.
    QString joined() const { return m_joined; }
    QString error() const { return m_error; }

    void setPreparing();
    // Opens the window on member, whose port listens, with the admitting
    // key's public point (the admin or root key, which signs off the GUI
    // thread's way through Core::signAdminDigest).
    void open(cbb_member *member, const QByteArray &publicKey);
    // The person's answer about the code.
    Q_INVOKABLE void answer(bool yes);
    // Closes it, or forgets how the last one ended.
    Q_INVOKABLE void close();
    void fail(const Failure &f);

signals:
    void changed();
    // A device joined; the app looks at its devices again.
    void admitted();

private:
    void poll();
    void free();
    void setState(const QString &state);

    cbb_window *m_window = nullptr;
    QTimer m_poll;
    quint64 m_version = 0;
    QString m_state = QStringLiteral("idle");
    QString m_qr;
    QStringList m_modules;
    QString m_joiningName;
    QString m_code;
    QString m_joined;
    QString m_error;
};

class Joiner : public QObject
{
    Q_OBJECT
    Q_PROPERTY(QString state READ state NOTIFY changed)
    Q_PROPERTY(QString memberName READ memberName NOTIFY changed)
    Q_PROPERTY(QString code READ code NOTIFY changed)
    Q_PROPERTY(QString error READ error NOTIFY changed)

public:
    explicit Joiner(QObject *parent = nullptr);
    ~Joiner() override;

    // idle, dialing, joining (the person is asked), done or failed.
    QString state() const { return m_state; }
    // The member that admits the phone, and the code both screens show.
    QString memberName() const { return m_memberName; }
    QString code() const { return m_code; }
    QString error() const { return m_error; }

    // Joins as the phone named name with system os and the member key's
    // public point, keeping the set in dir; qr is a window's QR code text,
    // or empty to find the one window announced at home.
    void start(const QString &dir, const QString &qr, const QString &name, const QString &os, const QByteArray &publicKey);
    Q_INVOKABLE void answer(bool yes);
    Q_INVOKABLE void stop();
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
    QString m_state = QStringLiteral("idle");
    QString m_memberName;
    QString m_code;
    QString m_error;
};
