// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// What the QML pages show: the app, the core, the system and the phone's key.
#pragma once

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

    // Finds or makes the phone's key, off the GUI thread.
    Q_INVOKABLE void setUpKey();

signals:
    void keyChanged();
    void errorChanged();

private:
    void show(const QString &error);

    OsInfo m_os;
    QString m_core;
    QString m_keyLevel = QStringLiteral("none");
    QString m_keyFingerprint;
    bool m_busy = false;
    QString m_error;
};
