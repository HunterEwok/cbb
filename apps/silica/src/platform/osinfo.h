// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// The system the app runs on, from /etc/os-release: what differs between
// Aurora's versions and Sailfish OS is decided here and nowhere else.
#pragma once

#include <QString>

struct OsInfo
{
    QString id;      // ID: "auroraos" or "sailfishos"
    QString name;    // NAME, for the about screen
    QString version; // VERSION_ID, such as "5.1.5.105"

    bool isAurora() const { return id == QLatin1String("auroraos"); }
    // Whether VERSION_ID is at least major.minor.
    bool atLeast(int major, int minor) const;

    static OsInfo current();
    // Reads the text of an os-release file.
    static OsInfo parse(const QString &text);
};
