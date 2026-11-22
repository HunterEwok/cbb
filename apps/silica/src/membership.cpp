// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

#include "membership.h"

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
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
    Membership m;
    m.device = o.value(QStringLiteral("device")).toString();
    m.group = o.value(QStringLiteral("group06")).toString();
    m.root = o.value(QStringLiteral("root")).toBool();
    m.admin = o.value(QStringLiteral("admin06")).toBool();
    // A group made before 0.6 names no group ID.
    m.before06 = m.group.isEmpty();
    return m;
}

bool Membership::save(Failure *failure) const
{
    // The names stay those of the files the phones of 0.6 wrote first.
    QJsonObject o{
        {QStringLiteral("v"), fileVersion},
        {QStringLiteral("device"), device},
        {QStringLiteral("group06"), group},
    };
    if (root)
        o.insert(QStringLiteral("root"), true);
    if (admin)
        o.insert(QStringLiteral("admin06"), true);
    return writeFile(QStringLiteral("member.json"), QJsonDocument(o).toJson(), failure);
}

// The member's files of the group, as member/src/leave.rs lists them
// (GROUP_FILES): keep the two lists alike.
static const char *const groupFiles[] = {
    "identity.json", "seal.json", "tunnel.json", "entries.json", "attest-status.json", "content", "networks.json",
    "credentials.json", "server-keys.json", "pastes.json", "actions-log.json", "mute.json", "signed.json", "before-0.6",
    "local.json", "offered.json", "keys.json", "epochs.json", "statements.json", "commands.cbor", "marks.cbor",
    "signed-records.json", "push.cbor", "push-previous.cbor", "server-credentials.cbor", "period-key", "server-secret",
    "hub-forwarders.json", "invite-guest", "records.json", "group.cbor",
};

// Leaves the group on this phone: every file the member keeps of the group
// (a directory with what it holds), then the key for sealed messages a
// group made before 0.6 kept and member.json last, so that a leave cut short still shows the group and
// can be done again.
bool Membership::remove(Failure *failure)
{
    QStringList names;
    for (const char *name : groupFiles)
        names.append(QString::fromLatin1(name));
    names << QStringLiteral("seal.key") << QStringLiteral("member.json");
    for (const QString &name : names) {
        const QString path = dataDir() + QLatin1Char('/') + name;
        const QFileInfo info(path);
        if (!info.exists() && !info.isSymLink())
            continue;
        const bool gone = info.isDir() && !info.isSymLink() ? QDir(path).removeRecursively() : QFile::remove(path);
        if (!gone) {
            *failure = {QCoreApplication::translate("Errors", "The phone could not leave the group."), QStringLiteral("membership: cannot delete %1").arg(name)};
            return false;
        }
    }
    return true;
}

QString Membership::directory()
{
    return dataDir();
}
