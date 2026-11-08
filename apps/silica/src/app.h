// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// What the QML pages show: the app, the core, the system and the phone's key.
#pragma once

#include "admit.h"
#include "blekeyboard.h"
#include "events.h"
#include "join.h"
#include "member.h"
#include "membership.h"
#include "pastereceiver.h"
#include "platform/osinfo.h"

#include <QJsonObject>
#include <QObject>
#include <QString>
#include <QTimer>
#include <QVariantList>

class App : public QObject
{
    Q_OBJECT
    Q_PROPERTY(QString version READ version CONSTANT)
    Q_PROPERTY(QString core READ core CONSTANT)
    Q_PROPERTY(QString system READ system CONSTANT)
    Q_PROPERTY(QString keyLevel READ keyLevel NOTIFY keyChanged)
    Q_PROPERTY(QString keyFingerprint READ keyFingerprint NOTIFY keyChanged)
    Q_PROPERTY(bool busy READ busy NOTIFY keyChanged)
    Q_PROPERTY(QString error READ error NOTIFY errorChanged)
    Q_PROPERTY(QString group READ group NOTIFY groupChanged)
    Q_PROPERTY(QString device READ device NOTIFY groupChanged)
    Q_PROPERTY(bool admin READ admin NOTIFY groupChanged)
    Q_PROPERTY(bool root READ root NOTIFY groupChanged)
    // The phone's claim to take the group over: "" without one, else
    // "pending", "competing", "disputed" or "none" (not in the records yet).
    Q_PROPERTY(QString claimState READ claimState NOTIFY claimChanged)
    // How long a pending claim still waits, in milliseconds.
    Q_PROPERTY(double claimLeftMs READ claimLeftMs NOTIFY claimChanged)
    Q_PROPERTY(Join *join READ join CONSTANT)
    Q_PROPERTY(Member *member READ member CONSTANT)
    Q_PROPERTY(Admit *admit READ admit CONSTANT)
    Q_PROPERTY(Events *events READ events CONSTANT)
    Q_PROPERTY(BleKeyboard *keyboard READ keyboard CONSTANT)
    Q_PROPERTY(PasteReceiver *paste READ paste CONSTANT)
    // Settings: the error details under each error message (Errors::
    // showDetails), the language the next start uses ("" for the
    // system's), and whether the main page shows the devices as a list.
    Q_PROPERTY(bool errorDetails READ errorDetails WRITE setErrorDetails NOTIFY settingsChanged)
    Q_PROPERTY(QString language READ language WRITE setLanguage NOTIFY settingsChanged)
    Q_PROPERTY(bool deviceList READ deviceList WRITE setDeviceList NOTIFY settingsChanged)
    // The language chosen differs from the one the app started with.
    // Bumped when the user's arrangement of the tiles changes; arranged
    // takes it so that QML asks again.
    Q_PROPERTY(int arrangement READ arrangement NOTIFY arrangementChanged)
    // Whether the user has an arrangement of their own, for "Back to the
    // group's order".
    Q_PROPERTY(bool hasArrangement READ hasArrangement NOTIFY arrangementChanged)
    Q_PROPERTY(bool languagePending READ languagePending NOTIFY settingsChanged)

public:
    explicit App(QObject *parent = nullptr);

    QString version() const;
    QString core() const { return m_core; }
    QString system() const;
    // "hardware" when the key is in OP-TEE, "none" while the phone has no key.
    QString keyLevel() const { return m_keyLevel; }
    // The first bytes of the public key's SHA-256, for the about screen.
    QString keyFingerprint() const { return m_keyFingerprint; }
    bool busy() const { return m_busy; }
    // The last error as shown (with its details when Errors::showDetails()).
    QString error() const { return m_error; }

    // The group's tag and this phone's device ID once it joined, else empty.
    QString group() const { return m_member.groupTag(); }
    QString device() const { return m_member.device; }
    // Whether the group's root made this phone an admin when it joined.
    bool admin() const { return m_member.isAdmin(); }
    bool root() const { return m_member.root; }
    QString claimState() const { return m_member.claim.isEmpty() ? QString() : m_claimState; }
    double claimLeftMs() const { return double(m_claimLeftMs); }
    Join *join() { return &m_join; }
    Member *member() { return &m_node; }
    Admit *admit() { return &m_admit; }
    Events *events() { return &m_events; }
    BleKeyboard *keyboard() { return &m_keyboard; }
    PasteReceiver *paste() { return &m_paste; }

    bool errorDetails() const;
    void setErrorDetails(bool on);
    QString language() const;
    void setLanguage(const QString &code);
    bool languagePending() const { return language() != m_startLanguage; }
    bool deviceList() const;
    // The language's name in itself (Russian's in Russian), for Settings.
    Q_INVOKABLE QString languageName(const QString &code) const;
    // Whether the user closed a tip or a card that is shown until closed
    // once (docs/apps.md, Settings: tips instead of long texts), and closing it.
    Q_INVOKABLE bool tipClosed(const QString &name) const;
    Q_INVOKABLE void closeTip(const QString &name);
    void setDeviceList(bool on);

    // Finds or makes the phone's key, off the GUI thread.
    Q_INVOKABLE void setUpKey();
    // Listens for the device that scans this phone's QR code; with admin,
    // the phone asks to be an admin and offers its admin key, made now the
    // first time, off the GUI thread.
    Q_INVOKABLE void startJoin(bool admin = false);
    // Adds the device whose join code (a cbb://join link) the camera read,
    // with the admin key, found off the GUI thread.
    // makeAdmin: the root makes a phone that asks an admin.
    Q_INVOKABLE void startAdmit(const QString &qr, bool makeAdmin = false);
    // Makes a group of the phone's own, its root key the admin key in the
    // TEE (docs/protocol.md, section 3), and starts the member as its root.
    Q_INVOKABLE void makeGroup();
    // An admin's change to a device of the group (remove, rename, thaw,
    // make_admin as the root, for a computer) or command for it (mute, unmute), signed with the admin key, or the
    // root's, off the GUI thread; managed() tells when it is done.
    // forMinutes: how long a mute lasts, 0 for until an unmute.
    Q_INVOKABLE void manage(const QString &action, const QString &device, const QString &name = QString(),
                            int forMinutes = 0);
    // The member's devices (Member::devices) in the user's order and
    // collections (docs/apps.md, "Collections and the order of the tiles";
    // cbb_core::arrange through the core's arrange call): each item is
    // {kind: "device", device} or {kind: "collection", id, name, devices};
    // this phone is first until the user moves it.
    // The arrangement forgets devices that left the group once the list is
    // whole (it holds this phone). stamp is the arrangement property.
    Q_INVOKABLE QVariantList arranged(const QVariantList &devices, int stamp);
    // Applies a change of the arrangement, an operation of the core's
    // arrange call ({op: "move", item: {device: id}, before: …}, "into",
    // "out", "new", "rename", "ungroup", "reset") on the devices arranged
    // was last given, keeps it in the settings and tells arrangementChanged.
    Q_INVOKABLE bool arrange(const QVariantMap &op);
    // Takes the group over from its lost root, the device with the ID
    // device, as an admin (cbb_core::takeover): a new root CA for the admin
    // key, kept first, and the claim, as the root handed the group to this
    // phone or else after the group's delay; the claim is then checked
    // every minute until it makes this phone the root, off the GUI thread.
    Q_INVOKABLE void takeOver(const QString &device);
    // The root's decision on an alert: voids the records it names.
    Q_INVOKABLE void resolve(const QStringList &records);
    // Leaves the group on this phone: stops the member and deletes the
    // membership. The group still lists the phone until an admin removes it.
    Q_INVOKABLE void leave();

signals:
    void keyChanged();
    void errorChanged();
    void groupChanged();
    void settingsChanged();
    // ok: the change is in the group's records or the device took the command.
    void managed(const QString &action, const QString &device, bool ok);
    void claimChanged();
    void arrangementChanged();

private:
    void show(const QString &error);
    // Starts the member once the phone has both its key and a group.
    void startMember();
    QString phoneName() const;
    // As an admin, renews the member certificates that are due, the
    // devices' connected and the phone's own, quietly: only the log says.
    void renew();
    QString phoneOs() const;
    // While the phone has a claim: where it stands, and once it took
    // effect, the phone as the group's root.
    void finishTakeover();
    int arrangement() const { return m_arrangement; }
    bool hasArrangement() const;
    // The core's arrange call on ids with op (null for none): {view, stored},
    // the stored arrangement kept in the settings; null on a refusal, shown.
    QJsonObject callArrange(const QStringList &ids, bool prune, const QJsonValue &op);
    // Keeps next as the membership, or shows why it could not.
    bool keep(const Membership &next);

    OsInfo m_os;
    QString m_core;
    QString m_keyLevel = QStringLiteral("none");
    QString m_keyFingerprint;
    QByteArray m_publicKey;
    Membership m_member;
    Join m_join;
    Member m_node;
    Admit m_admit;
    Events m_events;
    BleKeyboard m_keyboard;
    PasteReceiver m_paste{&m_node, &m_keyboard};
    bool m_busy = false;
    QTimer m_renewTimer;
    QTimer m_claimTimer;
    QString m_claimState;
    qint64 m_claimLeftMs = 0;
    QString m_error;
    QString m_startLanguage;
    int m_arrangement = 0;
    QStringList m_arrangeIds; // the devices arranged was last given
};
