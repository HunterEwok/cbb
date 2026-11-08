// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

#include "membership.h"

#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QSaveFile>
#include <QStandardPaths>

namespace {

const int fileVersion = 1;

QString dataDir()
{
    const QString dir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    QDir().mkpath(dir);
    return dir;
}

QByteArray b64(const QJsonValue &v)
{
    return QByteArray::fromBase64(v.toString().toLatin1());
}

QString b64(const QByteArray &b)
{
    return QString::fromLatin1(b.toBase64());
}

// Writes data to the file name in the app's data folder, whole or not at all,
// readable only by the app.
bool writeFile(const QString &name, const QByteArray &data, Failure *failure)
{
    QSaveFile f(dataDir() + QLatin1Char('/') + name);
    if (!f.open(QIODevice::WriteOnly) || f.write(data) != data.size() || !f.setPermissions(QFile::ReadOwner | QFile::WriteOwner) ||
        !f.commit()) {
        *failure = {QCoreApplication::translate("Errors", "The phone could not save the group."),
                    QStringLiteral("membership: %1: %2").arg(name, f.errorString())};
        return false;
    }
    return true;
}

} // namespace

QString Membership::groupTag() const
{
    if (groupCa.isEmpty())
        return QString();
    return QString::fromLatin1(QCryptographicHash::hash(groupCa, QCryptographicHash::Sha256).left(8).toHex());
}

Membership Membership::fromJoined(const QJsonObject &j)
{
    Membership m;
    m.device = j.value(QStringLiteral("device")).toString();
    m.cert = b64(j.value(QStringLiteral("cert")));
    m.issuer = b64(j.value(QStringLiteral("issuer")));
    m.adminCa = b64(j.value(QStringLiteral("admin_ca")));
    m.groupCa = b64(j.value(QStringLiteral("group_ca")));
    for (const QJsonValue &r : j.value(QStringLiteral("roots")).toArray())
        m.roots.append(b64(r));
    m.records = b64(j.value(QStringLiteral("records")));
    m.root = j.value(QStringLiteral("root")).toBool();
    m.claim = b64(j.value(QStringLiteral("claim")));
    return m;
}

Membership Membership::load(Failure *failure)
{
    QFile f(dataDir() + QStringLiteral("/member.json"));
    if (!f.exists())
        return Membership();
    if (!f.open(QIODevice::ReadOnly)) {
        *failure = {QCoreApplication::translate("Errors", "The phone could not read its group."), QStringLiteral("membership: member.json: %1").arg(f.errorString())};
        return Membership();
    }
    QJsonParseError parse;
    const QJsonObject o = QJsonDocument::fromJson(f.readAll(), &parse).object();
    if (o.value(QStringLiteral("v")).toInt() != fileVersion) {
        *failure = {QCoreApplication::translate("Errors", "The phone could not read its group."),
                    QStringLiteral("membership: member.json is not of version %1 (%2)").arg(fileVersion).arg(parse.errorString())};
        return Membership();
    }
    Membership m = fromJoined(o);
    QFile r(dataDir() + QStringLiteral("/records.json"));
    if (r.open(QIODevice::ReadOnly))
        m.records = r.readAll();
    return m;
}

bool Membership::save(Failure *failure) const
{
    return writeFile(QStringLiteral("records.json"), records, failure) && saveIdentity(failure);
}

bool Membership::saveIdentity(Failure *failure) const
{
    QJsonArray rs;
    for (const QByteArray &r : roots)
        rs.append(b64(r));
    QJsonObject o{
        {QStringLiteral("v"), fileVersion},
        {QStringLiteral("device"), device},
        {QStringLiteral("cert"), b64(cert)},
        {QStringLiteral("group_ca"), b64(groupCa)},
        {QStringLiteral("roots"), rs},
    };
    if (!issuer.isEmpty())
        o.insert(QStringLiteral("issuer"), b64(issuer));
    if (!adminCa.isEmpty())
        o.insert(QStringLiteral("admin_ca"), b64(adminCa));
    if (root)
        o.insert(QStringLiteral("root"), true);
    if (!claim.isEmpty())
        o.insert(QStringLiteral("claim"), b64(claim));
    return writeFile(QStringLiteral("member.json"), QJsonDocument(o).toJson(), failure);
}

bool Membership::remove(Failure *failure)
{
    for (const QString &name : {QStringLiteral("member.json"), QStringLiteral("records.json")}) {
        QFile f(dataDir() + QLatin1Char('/') + name);
        if (f.exists() && !f.remove()) {
            *failure = {QCoreApplication::translate("Errors", "The phone could not leave the group."), QStringLiteral("membership: %1: %2").arg(name, f.errorString())};
            return false;
        }
    }
    return true;
}

QString Membership::directory()
{
    return dataDir();
}

QByteArray sealSecret(Failure *failure)
{
    const QString path = dataDir() + QStringLiteral("/seal.key");
    QFile f(path);
    if (f.open(QIODevice::ReadOnly)) {
        const QByteArray s = f.readAll();
        if (s.size() == 32)
            return s;
    }
    QFile random(QStringLiteral("/dev/urandom"));
    QByteArray s;
    if (random.open(QIODevice::ReadOnly))
        s = random.read(32);
    if (s.size() != 32) {
        *failure = {QCoreApplication::translate("Errors", "The phone could not make its keys."), QStringLiteral("membership: /dev/urandom: %1").arg(random.errorString())};
        return QByteArray();
    }
    if (!writeFile(QStringLiteral("seal.key"), s, failure))
        return QByteArray();
    return s;
}
