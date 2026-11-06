// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

#include "osinfo.h"

#include <QFile>
#include <QStringList>

bool OsInfo::atLeast(int major, int minor) const
{
    const QStringList parts = version.split(QLatin1Char('.'));
    const int ma = parts.value(0).toInt(), mi = parts.value(1).toInt();
    return ma > major || (ma == major && mi >= minor);
}

OsInfo OsInfo::current()
{
    QFile f(QStringLiteral("/etc/os-release"));
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text))
        return OsInfo();
    return parse(QString::fromUtf8(f.readAll()));
}

OsInfo OsInfo::parse(const QString &text)
{
    OsInfo p;
    for (const QString &line : text.split(QLatin1Char('\n'))) {
        const int eq = line.indexOf(QLatin1Char('='));
        if (eq <= 0)
            continue;
        const QString key = line.left(eq).trimmed();
        QString value = line.mid(eq + 1).trimmed();
        if (value.size() >= 2 && (value.startsWith(QLatin1Char('"')) || value.startsWith(QLatin1Char('\''))) && value.endsWith(value.at(0)))
            value = value.mid(1, value.size() - 2);
        if (key == QLatin1String("ID"))
            p.id = value;
        else if (key == QLatin1String("NAME"))
            p.name = value;
        else if (key == QLatin1String("VERSION_ID"))
            p.version = value;
    }
    return p;
}
