// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// What the QML pages show: the app, the core, the system and the phone's key.
#pragma once

#include "join.h"
#include "member.h"
#include "membership.h"
#include "platform/osinfo.h"

#include <QObject>
#include <QString>

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
    Q_PROPERTY(Join *join READ join CONSTANT)
    Q_PROPERTY(Member *member READ member CONSTANT)

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
    Join *join() { return &m_join; }
    Member *member() { return &m_node; }

    // Finds or makes the phone's key, off the GUI thread.
    Q_INVOKABLE void setUpKey();
    // Listens for the device that scans this phone's QR code; with admin,
    // the phone asks to be an admin and offers its admin key, made now the
    // first time, off the GUI thread.
    Q_INVOKABLE void startJoin(bool admin = false);
    // Leaves the group on this phone: stops the member and deletes the
    // membership. The group still lists the phone until an admin removes it.
    Q_INVOKABLE void leave();

signals:
    void keyChanged();
    void errorChanged();
    void groupChanged();

private:
    void show(const QString &error);
    // Starts the member once the phone has both its key and a group.
    void startMember();
    QString phoneName() const;
    QString phoneOs() const;

    OsInfo m_os;
    QString m_core;
    QString m_keyLevel = QStringLiteral("none");
    QString m_keyFingerprint;
    QByteArray m_publicKey;
    Membership m_member;
    Join m_join;
    Member m_node;
    bool m_busy = false;
    QString m_error;
};
