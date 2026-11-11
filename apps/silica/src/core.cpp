// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

#include "core.h"

#include "platform/keystore.h"

#include <cbb_core.h>

#include <QCoreApplication>
#include <QJsonDocument>

#include <cstring>

namespace Core {

QJsonValue call(const QString &op, const QJsonValue &args, Failure *failure)
{
    const uint32_t got = cbb_abi();
    if (got != uint32_t(abi)) {
        *failure = {QCoreApplication::translate("Errors", "This build of CBB is broken."),
                    QStringLiteral("core: the linked core speaks ABI %1, not %2").arg(got).arg(abi)};
        return QJsonValue();
    }
    QJsonObject request{{QStringLiteral("abi"), abi}, {QStringLiteral("op"), op}};
    if (!args.isNull())
        request.insert(QStringLiteral("args"), args);
    const QByteArray bytes = QJsonDocument(request).toJson(QJsonDocument::Compact);
    size_t len = 0;
    uint8_t *answer = cbb_call(reinterpret_cast<const uint8_t *>(bytes.constData()), size_t(bytes.size()), &len);
    if (!answer) {
        *failure = {QCoreApplication::translate("Errors", "This build of CBB is broken."), QStringLiteral("core: no answer to %1").arg(op)};
        return QJsonValue();
    }
    QJsonParseError parse;
    const QJsonDocument doc = QJsonDocument::fromJson(QByteArray(reinterpret_cast<const char *>(answer), int(len)), &parse);
    cbb_free(answer, len);
    if (!doc.isObject()) {
        *failure = {QCoreApplication::translate("Errors", "This build of CBB is broken."),
                    QStringLiteral("core: the answer to %1 does not read: %2").arg(op, parse.errorString())};
        return QJsonValue();
    }
    const QJsonObject a = doc.object();
    if (a.contains(QStringLiteral("error"))) {
        const QJsonObject e = a.value(QStringLiteral("error")).toObject();
        QString details = QStringLiteral("core: %1 (%2, code %3)")
                              .arg(op, e.value(QStringLiteral("name")).toString())
                              .arg(e.value(QStringLiteral("code")).toInt());
        const QString causes = e.value(QStringLiteral("details")).toString();
        if (!causes.isEmpty())
            details += QLatin1Char('\n') + causes;
        *failure = {e.value(QStringLiteral("message")).toString(), details};
        return QJsonValue();
    }
    if (!a.contains(QStringLiteral("ok"))) {
        *failure = {QCoreApplication::translate("Errors", "This build of CBB is broken."),
                    QStringLiteral("core: the answer to %1 has neither ok nor error").arg(op)};
        return QJsonValue();
    }
    return a.value(QStringLiteral("ok"));
}

QString versionLine(Failure *failure)
{
    const QJsonObject v = call(QStringLiteral("version"), QJsonValue(), failure).toObject();
    if (!failure->isNull())
        return QString();
    const QString source = v.value(QStringLiteral("source")).toString();
    return QStringLiteral("core %1, abi %2, source %3")
        .arg(v.value(QStringLiteral("core")).toString())
        .arg(v.value(QStringLiteral("abi")).toInt())
        .arg(source.isEmpty() ? QStringLiteral("unknown") : source);
}

QJsonValue testPanic(Failure *failure)
{
    size_t len = 0;
    uint8_t *answer = cbb_test_panic(&len);
    const QJsonObject a = QJsonDocument::fromJson(QByteArray(reinterpret_cast<const char *>(answer), int(len))).object();
    if (answer)
        cbb_free(answer, len);
    const QJsonObject e = a.value(QStringLiteral("error")).toObject();
    if (e.isEmpty()) {
        *failure = {QCoreApplication::translate("Errors", "This build of CBB is broken."), QStringLiteral("core: cbb_test_panic did not answer an error")};
        return QJsonValue();
    }
    *failure = {e.value(QStringLiteral("message")).toString(),
                QStringLiteral("core: test_panic (%1, code %2)\n%3")
                    .arg(e.value(QStringLiteral("name")).toString())
                    .arg(e.value(QStringLiteral("code")).toInt())
                    .arg(e.value(QStringLiteral("details")).toString())};
    return QJsonValue(e.value(QStringLiteral("code")).toInt());
}

QJsonObject take(uint8_t *answer, size_t len, const QString &what, Failure *failure)
{
    if (!answer) {
        *failure = {QCoreApplication::translate("Errors", "This build of CBB is broken."), QStringLiteral("%1: no answer").arg(what)};
        return QJsonObject();
    }
    const QJsonObject a = QJsonDocument::fromJson(QByteArray(reinterpret_cast<const char *>(answer), int(len))).object();
    cbb_free(answer, len);
    if (a.contains(QStringLiteral("error"))) {
        const QJsonObject e = a.value(QStringLiteral("error")).toObject();
        *failure = {e.value(QStringLiteral("message")).toString(), QStringLiteral("%1: %2").arg(what, e.value(QStringLiteral("details")).toString())};
        return QJsonObject();
    }
    return a.value(QStringLiteral("ok")).toObject();
}

namespace {

int32_t signWith(KeyStore::Which which, const uint8_t *digest, uint8_t *sig, size_t *sigLen)
{
    Failure failure;
    const QByteArray der = KeyStore::sign(QByteArray(reinterpret_cast<const char *>(digest), 32), &failure, which);
    if (der.isEmpty() || der.size() > 72) {
        Errors::log(QStringLiteral("key: the key did not sign: %1 %2").arg(failure.message, failure.details));
        return 1;
    }
    std::memcpy(sig, der.constData(), size_t(der.size()));
    *sigLen = size_t(der.size());
    return 0;
}

} // namespace

int32_t signDigest(void *, const uint8_t *digest, uint8_t *sig, size_t *sigLen)
{
    return signWith(KeyStore::Which::Member, digest, sig, sigLen);
}

int32_t signAdminDigest(void *, const uint8_t *digest, uint8_t *sig, size_t *sigLen)
{
    return signWith(KeyStore::Which::Admin, digest, sig, sigLen);
}

} // namespace Core
