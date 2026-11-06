// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

#include "errors.h"

#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QMutex>
#include <QSettings>
#include <QStandardPaths>
#include <QTextStream>
#include <QtDebug>

namespace Errors {

bool showDetails()
{
    QSettings settings;
    const QVariant set = settings.value(QStringLiteral("errors/details"));
    if (set.isValid())
        return set.toBool();
    const QByteArray env = qgetenv("CBB_ERROR_DETAILS");
    if (!env.isEmpty())
        return env != "0";
#ifdef QT_DEBUG
    return true;
#else
    return false;
#endif
}

QString shown(const Failure &f)
{
    log(QStringLiteral("error: %1%2").arg(f.message, f.details.isEmpty() ? QString() : QStringLiteral(": ") + QString(f.details).replace(QLatin1Char('\n'), QStringLiteral("; "))));
    if (!showDetails() || f.details.isEmpty())
        return f.message;
    return f.message + QStringLiteral("\n\n") + f.details;
}

void log(const QString &line)
{
    static QMutex mutex;
    QMutexLocker lock(&mutex);
    qInfo().noquote() << line;
    const QString dir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    QDir().mkpath(dir);
    QFile file(dir + QStringLiteral("/cbb.log"));
    if (file.size() > 1024 * 1024)
        file.remove();
    if (!file.open(QIODevice::Append | QIODevice::Text))
        return;
    QTextStream(&file) << QDateTime::currentDateTimeUtc().toString(Qt::ISODate) << ' ' << line << '\n';
}

} // namespace Errors
