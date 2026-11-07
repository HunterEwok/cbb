// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// The phone as a member of its group: the lite member's node in the app's
// process (ffi's cbb_member_*, docs/core-api.md), with the key in the
// key store. It dials the members it finds, puts what they send into the
// clipboard, and sends what the user copied when the app comes to the
// front or the user asks (Aurora lets no app read the clipboard in the
// background).
#pragma once

#include "membership.h"

#include <QByteArray>
#include <QDateTime>
#include <QImage>
#include <QJsonObject>
#include <QJsonValue>
#include <QList>
#include <QObject>
#include <QString>
#include <QStringList>
#include <QTimer>
#include <QVariantList>

struct cbb_member;
class QThread;

class Member : public QObject
{
    Q_OBJECT
    Q_PROPERTY(bool running READ running NOTIFY changed)
    Q_PROPERTY(QStringList peers READ peers NOTIFY changed)
    // Every device of the group, as the member's devices op lists it: maps with
    // device, name, role, os, admin, root, frozen, online, self and listed.
    Q_PROPERTY(QVariantList devices READ devices NOTIFY devicesChanged)
    // What the group's records stop and what ends it (docs/core-api.md, the
    // member's alerts): maps with kind, names, devices, records, left_ms, count.
    Q_PROPERTY(QVariantList alerts READ alerts NOTIFY devicesChanged)
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
    // Images or files of the group's copy are coming to the phone.
    Q_PROPERTY(bool fetching READ fetching NOTIFY changed)
    // Sync away from home (docs/protocol.md, section 11): on or off; where it
    // stands: "off", "waiting" (no hub's offer yet), "home", "connecting" or
    // "connected"; the hub's name, and what went wrong last, shown as
    // Errors::shown shows it.
    Q_PROPERTY(bool awayOn READ awayOn NOTIFY awayChanged)
    Q_PROPERTY(QString awayStatus READ awayStatus NOTIFY awayChanged)
    Q_PROPERTY(QString awayHub READ awayHub NOTIFY awayChanged)
    Q_PROPERTY(QString awayError READ awayError NOTIFY awayChanged)

public:
    explicit Member(QObject *parent = nullptr);
    ~Member() override;

    bool running() const { return m_member != nullptr; }
    // The core's member, for adding a device (Admit); null when stopped.
    cbb_member *handle() const { return m_member; }
    // The names of the members connected now.
    QStringList peers() const { return m_peers; }
    QVariantList devices() const { return m_devices; }
    QVariantList alerts() const { return m_alerts; }
    // What the clipboard got or sent last, shortened, for the main page.
    QString last() const { return m_last; }
    QString error() const { return m_error; }
    bool paused() const { return m_paused; }
    QDateTime pausedUntil() const { return m_pausedUntil; }
    bool muted() const { return m_muted; }
    QDateTime mutedUntil() const { return m_mutedUntil; }
    bool fetching() const { return m_fetch != nullptr; }
    bool awayOn() const { return m_awayOn; }
    QString awayStatus() const { return m_awayStatus; }
    QString awayHub() const { return m_awayHub; }
    QString awayError() const { return m_awayError; }

    // Starts the member of membership as the phone named name.
    void start(const Membership &membership, const QString &name, const QByteArray &publicKey, const QString &os,
               const QString &osVersion);
    void stop();

    // The one button (docs/design.md, "The one button"): a copy from
    // another device that waits for the phone comes to it; otherwise what
    // the phone copied goes to the group (sendClipboard).
    Q_INVOKABLE void button();
    // Sends the clipboard's text or image when the core's rule says so:
    // neither the group's copy nor what this phone sent or took last.
    Q_INVOKABLE void sendClipboard();
    // Sends a text shared to the app, as a copy of this phone.
    Q_INVOKABLE void sendText(const QString &text);
    // Sends images or files shared to the app (absolute paths), up to
    // maxSendBytes together.
    Q_INVOKABLE void sendFiles(const QStringList &paths);

    // Keeps the group's copies out of the clipboard for minutes (0 for
    // until resume), or takes them again; the phone's own still go out.
    Q_INVOKABLE void pause(int minutes);
    Q_INVOKABLE void resume();

    // Turns sync away from home on, with new tunnel keys that the hellos
    // offer the group's hubs, or off, forgetting them.
    Q_INVOKABLE void setAway(bool on);

signals:
    void changed();
    void devicesChanged();
    void awayChanged();
    // An admin renewed the member certificate, or a takeover made a new
    // root: the phone keeps them in member.json.
    void identityChanged(const QByteArray &cert, const QByteArray &issuer, const QList<QByteArray> &roots);
    // The images or files of a copy are in folder, for a notification.
    void saved(const QString &folder, int count);

public:
    // Brings the devices up to date now, as after an admin's change.
    void pollDevices();

private:
    Q_INVOKABLE void event(const QByteArray &json);
    void write(const QString &text, bool secret, qint64 ttlMs);
    void pollPeers();
    void setLast(const QString &text, bool secret);
    // Takes the group's copy (as the core's copy JSON): a text into the
    // clipboard, images or files fetched into Downloads, one image into the
    // clipboard too; then tells the core it took it.
    void take(const QJsonObject &copy);
    void sendImage(const QImage &image);
    // The key the core's rule compares an image by: its PNG's SHA-256.
    static QString imageKey(const QByteArray &png);
    // Reads the pause and the mute from the core's answer, or asks for it.
    void readMuted(const QJsonObject &state);
    void pollMuted();
    // Reads where sync away from home stands from the core's answer.
    void readAway(const QJsonValue &away);
    void pollAway();

    cbb_member *m_member = nullptr;
    QTimer m_peerTimer;
    QStringList m_peers;
    QVariantList m_devices;
    QVariantList m_alerts;
    QString m_last;
    QString m_error;
    // The clipboard's text as the group last set it or the phone last sent it.
    QString m_known;
    // The key of the image this phone put into the clipboard from the
    // group: read back, it is encoded anew, so the core cannot tell it.
    QString m_tookImage;
    QThread *m_fetch = nullptr;
    bool m_paused = false;
    QDateTime m_pausedUntil;
    bool m_muted = false;
    QDateTime m_mutedUntil;
    bool m_awayOn = false;
    QString m_awayStatus = QStringLiteral("off");
    QString m_awayHub;
    QString m_awayError;
    // The core's last error message, so that each is shown and logged once.
    QString m_awayFailure;
};
