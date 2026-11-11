// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// The member key in a file, for Sailfish OS and Aurora 4, which give an app
// no key in a TEE: device.key in the app's data folder (admin.key for the
// admin key), readable only by the app, holding the P-256 key the core made (level 3, "file", of "Key levels"
// in docs/roadmap.md). The core signs with it, so no crypto library is linked.

#include "keystore.h"

#include "core.h"

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QMutex>
#include <QSaveFile>
#include <QStandardPaths>

namespace KeyStore {

namespace {

QString path(Which which)
{
    const QString dir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    QDir().mkpath(dir);
    return dir + (which == Which::Admin ? QStringLiteral("/admin.key") : QStringLiteral("/device.key"));
}

QString b64(const QByteArray &b)
{
    return QString::fromLatin1(b.toBase64());
}

QByteArray b64(const QJsonValue &v)
{
    return QByteArray::fromBase64(v.toString().toLatin1());
}

// The keys read once, for sign, which runs on the node's threads.
QMutex lock;
QByteArray pkcs8[2];

QByteArray &secretOf(Which which)
{
    return pkcs8[which == Which::Admin ? 1 : 0];
}

} // namespace

QString store()
{
    return QStringLiteral("file");
}

Key ensure(Which which)
{
    Key key;
    QFile f(path(which));
    if (f.exists()) {
        if (!f.open(QIODevice::ReadOnly)) {
            key.failure = {QCoreApplication::translate("Errors", "The phone could not read its key."), QStringLiteral("key: %1: %2").arg(f.fileName(), f.errorString())};
            return key;
        }
        const QJsonObject o = QJsonDocument::fromJson(f.readAll()).object();
        const QByteArray secret = b64(o.value(QStringLiteral("pkcs8")));
        key.publicKey = b64(o.value(QStringLiteral("public")));
        if (secret.isEmpty() || key.publicKey.size() != 65) {
            key.publicKey.clear();
            key.failure = {QCoreApplication::translate("Errors", "The phone's key file is damaged."), QStringLiteral("key: %1 does not read").arg(f.fileName())};
            return key;
        }
        QMutexLocker l(&lock);
        secretOf(which) = secret;
        key.state = State::Ready;
        return key;
    }
    Failure failure;
    const QJsonObject made = Core::call(QStringLiteral("new_device_key"), QJsonValue(), &failure).toObject();
    if (!failure.isNull()) {
        key.failure = failure;
        return key;
    }
    QSaveFile out(path(which));
    const QByteArray data = QJsonDocument(made).toJson(QJsonDocument::Compact);
    if (!out.open(QIODevice::WriteOnly) || out.write(data) != data.size() ||
        !out.setPermissions(QFile::ReadOwner | QFile::WriteOwner) || !out.commit()) {
        key.failure = {QCoreApplication::translate("Errors", "The phone could not save its key."), QStringLiteral("key: %1: %2").arg(out.fileName(), out.errorString())};
        return key;
    }
    QMutexLocker l(&lock);
    secretOf(which) = b64(made.value(QStringLiteral("pkcs8")));
    key.publicKey = b64(made.value(QStringLiteral("public")));
    key.created = true;
    key.state = State::Ready;
    return key;
}

QByteArray sign(const QByteArray &digest, Failure *failure, Which which, bool *)
{
    QByteArray secret;
    {
        QMutexLocker l(&lock);
        secret = secretOf(which);
    }
    if (secret.isEmpty()) {
        *failure = {QCoreApplication::translate("Errors", "The phone has no key yet."), QStringLiteral("key: sign before ensure")};
        return QByteArray();
    }
    const QJsonObject args{{QStringLiteral("pkcs8"), b64(secret)}, {QStringLiteral("digest"), b64(digest)}};
    const QJsonObject ok = Core::call(QStringLiteral("sign_digest"), args, failure).toObject();
    return b64(ok.value(QStringLiteral("sig")));
}

// A key in a file has no PIN of its own: the file is as safe as the app's
// data folder (level 3, "file").
PinStatus adminPin()
{
    PinStatus s;
    s.state = PinState::None;
    return s;
}

PinResult enterAdminPin(const QByteArray &, PinStatus *after, Failure *)
{
    after->state = PinState::None;
    return PinResult::Right;
}

PinResult changeAdminPin(const QByteArray &, const QByteArray &, PinStatus *after, Failure *)
{
    after->state = PinState::None;
    return PinResult::Right;
}

bool adminPinHeld()
{
    return true;
}

void dropAdminPin() {}

bool forget(Failure *failure)
{
    for (const Which which : {Which::Member, Which::Admin}) {
        QFile f(path(which));
        if (f.exists() && !f.remove()) {
            *failure = {QCoreApplication::translate("Errors", "The phone could not delete its key."), QStringLiteral("key: %1: %2").arg(f.fileName(), f.errorString())};
            return false;
        }
        QMutexLocker l(&lock);
        secretOf(which).clear();
    }
    return true;
}

} // namespace KeyStore
