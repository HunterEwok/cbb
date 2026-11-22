// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// The phone as a member of its group: the Rust member's node in the app's
// process (ffi's cbb_member_*, docs/core-api.md), with the key in the
// key store. It dials the members it finds, puts what they send into the
// clipboard, and sends what the user copied when the app comes to the
// front or the user asks (Aurora lets no app read the clipboard in the
// background).
#pragma once

#include "membership.h"

#include <QByteArray>
#include <QDateTime>
#include <QHash>
#include <QImage>
#include <QJsonObject>
#include <QJsonValue>
#include <QList>
#include <QObject>
#include <QString>
#include <QStringList>
#include <QTimer>
#include <QVariantList>
#include <QVariantMap>

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
    // Why the phone does not sync (cbb_core::why, docs/apps.md "Why it does
    // not sync"): maps with code, level, until_ms, device, devices, value and
    // detail, the reason that stops the most first.
    Q_PROPERTY(QVariantList why READ why NOTIFY devicesChanged)
    // The group as its records stand (the member's group op,
    // docs/core-api.md): root_device, key_level, stop, halted and the rest.
    Q_PROPERTY(QVariantMap groupState READ groupState NOTIFY devicesChanged)
    // The member's notices about the group (docs/apps.md, "Notices"): maps
    // with id, kind, args and dismissable.
    Q_PROPERTY(QVariantList notices READ notices NOTIFY devicesChanged)
    // The group's main device changed (docs/apps.md, "Changing the main
    // device"), until the person saw it: from and to, the devices' names,
    // and seq; empty when none.
    Q_PROPERTY(QVariantMap rootChanged READ rootChanged NOTIFY devicesChanged)
    Q_PROPERTY(QString last READ last NOTIFY changed)
    // The last copy that came from another device (D-128): from which
    // device, and its text, empty for a secret; lastFrom is empty when there
    // is none to show.
    Q_PROPERTY(QString lastFrom READ lastFrom NOTIFY changed)
    Q_PROPERTY(QString lastText READ lastText NOTIFY changed)
    Q_PROPERTY(QString error READ error NOTIFY changed)
    // Sync turned off (design.md, "Sync on and off"): the clipboard is the
    // phone's own, until pausedUntil or, when it is invalid, until the user
    // turns sync on again.
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
    // The core's member, for a pairing window or an invitation; null when stopped.
    cbb_member *handle() const { return m_member; }
    // The names of the members connected now.
    QStringList peers() const { return m_peers; }
    QVariantList devices() const { return m_devices; }
    // The member's recent log lines, oldest first, for a bug report.
    QStringList recentLog() const { return m_recentLog; }
    QVariantList why() const { return m_why; }
    QVariantMap groupState() const { return m_groupState; }
    QVariantList notices() const { return m_notices; }
    QVariantMap rootChanged() const { return m_rootChanged; }
    // What the clipboard got or sent last, shortened, for the main page.
    QString last() const { return m_last; }
    QString lastFrom() const { return m_lastFrom; }
    QString lastText() const { return m_lastText; }
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

    // Opens the member port at home, which a pairing window of 0.6 needs
    // (the member's listen op); a second call keeps it open.
    bool listen(Failure *failure);

    // The app's opening (docs/design.md, "The one button", D-128), which
    // swaps nothing: a clipboard changed since the app last saw it goes to
    // the group, unless it is the group's copy or what this phone sent or
    // took last; otherwise the phone takes the group's copy.
    Q_INVOKABLE void opened();
    // Copy on the main page's last received line: the group's copy into
    // the clipboard, if it is still the group's latest.
    Q_INVOKABLE void copyReceived();
    // Sends a text shared to the app, as a copy of this phone.
    Q_INVOKABLE void sendText(const QString &text);
    // Sends images or files shared to the app (absolute paths), up to
    // maxSendBytes together.
    Q_INVOKABLE void sendFiles(const QStringList &paths);
    // Makes a copy of images or files for a remote paste, as sendFiles
    // would send them, and returns its event ID, or none with failure set.
    QString copyFiles(const QStringList &paths, Failure *failure);

    // Keeps the group's copies out of the clipboard for minutes (0 for
    // until resume), or takes them again; the phone's own still go out.
    Q_INVOKABLE void pause(int minutes);
    Q_INVOKABLE void resume();

    // Turns sync away from home on, with new tunnel keys that the hellos
    // offer the group's hubs, or off, forgetting them.
    Q_INVOKABLE void setAway(bool on);
    // Hides a notice that may be hidden, until something about it changes.
    Q_INVOKABLE void dismissNotice(const QString &id);
    // The person saw that the group's main device changed.
    Q_INVOKABLE void rootChangeSeen();

signals:
    void changed();
    void devicesChanged();
    void awayChanged();
    // The images or files of a copy are in folder, for a notification.
    void saved(const QString &folder, int count);
    // A paste or paste-off command an admin signed for this phone, checked
    // and opened (the member's check_command answer, with the event's
    // token): the receiver carries it out and answers.
    void commandArrived(const QJsonObject &checked);
    // Something in the member broke (docs/core-api.md, "Panics"): details
    // say what and where. The app shows it and starts the member again.
    void panicked(const QString &details);

public:
    // Brings the devices up to date now, as after an admin's change.
    void pollDevices();
    // The device tiles as the member keeps them (docs/apps.md, "What the
    // member shows"), with the user's change op applied and kept first
    // (null for none): {tiles, online, others, custom}; empty with failure
    // set when there is no member or the change does not fit.
    QJsonObject view(const QJsonValue &op, Failure *failure) const;
    // Answers the command of the token: done, refused or failed, and why
    // (in English: the sender's log shows it).
    void answer(double token, const QString &status, const QString &reason);

private:
    Q_INVOKABLE void event(const QByteArray &json);
    void write(const QString &text, bool secret, qint64 ttlMs);
    // A command for the phone itself (docs/protocol.md, section 15) that
    // the node passed on: checked with the records, not carried out before
    // and signed after the member started.
    void command(double token, const QString &from, const QJsonObject &record);
    void pollPeers();
    // A device's name as the member's devices list it, else its ID.
    QString deviceName(const QString &id) const;
    void setLast(const QString &text, bool secret);
    // Takes the group's copy (as the core's copy JSON): a text into the
    // clipboard, images or files fetched into Downloads, one image into the
    // clipboard too; then tells the core it took it.
    void take(const QJsonObject &copy);
    void sendImage(const QByteArray &png, const QString &key);
    // Sends a text the clipboard held, as the opening decided.
    void sendBoardText(const QString &text);
    // Sends images or files as one copy, up to maxSendBytes together, and
    // returns its event ID, or none with failure set.
    QString copyMedia(const QStringList &paths, Failure *failure);
    // The key the core's rule compares an image by: its PNG's SHA-256.
    static QString imageKey(const QByteArray &png);
    // Reads the pause and the mute from the core's answer, or asks for it.
    void readMuted(const QJsonObject &state);
    void pollMuted();
    // Reads where sync away from home stands from the core's answer.
    void readAway(const QJsonValue &away);
    void pollAway();

    cbb_member *m_member = nullptr;
    bool m_listening = false; // the member port is open (listen)
    QTimer m_peerTimer;
    QStringList m_peers;
    // The connected devices whose hello says an admin muted them, by ID:
    // pollDevices marks them muted for their tiles.
    QStringList m_mutedPeers;
    QVariantList m_devices;
    QStringList m_recentLog;
    QVariantList m_why;
    QVariantMap m_groupState;
    QVariantList m_notices;
    QVariantMap m_rootChanged;
    QString m_last;
    QString m_error;
    // The clipboard's text as the group last set it or the phone last sent it.
    QString m_known;
    QString m_lastId, m_lastFrom, m_lastText;
    // The key of the image this phone put into the clipboard from the
    // group: read back, it is encoded anew, so the core cannot tell it.
    QString m_tookImage;
    // The ID of the group's copy that image came from.
    QString m_tookImageCopy;
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
    // The commands carried out, by ID, until they expire.
    static const int maxCommands = 4096;
    QHash<QString, qint64> m_seen;
    qint64 m_startedMs = 0;
};
