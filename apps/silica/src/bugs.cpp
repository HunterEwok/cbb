// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

#include "bugs.h"

#include "core.h"
#include "errors.h"

#include <QDateTime>
#include <QJsonArray>
#include <QJsonDocument>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QSettings>
#include <QUrl>

namespace {

const char stateKey[] = "bug/state";
const char url[] = "https://bug.cbb.tools/";

qint64 nowMs()
{
    return QDateTime::currentMSecsSinceEpoch();
}

} // namespace

Bugs::Bugs(QObject *parent) : QObject(parent) {}

QJsonObject Bugs::state() const
{
    return QJsonDocument::fromJson(QSettings().value(QLatin1String(stateKey)).toByteArray()).object();
}

void Bugs::keep(const QJsonValue &answer)
{
    const QJsonValue s = answer.toObject().value(QStringLiteral("state"));
    if (s.isObject())
        QSettings().setValue(QLatin1String(stateKey), QJsonDocument(s.toObject()).toJson(QJsonDocument::Compact));
}

bool Bugs::offerAlways() const
{
    return m_offer.value(QStringLiteral("offer_always")).toBool();
}

QString Bugs::fixedIn() const
{
    return m_offer.value(QStringLiteral("fixed_in")).toString();
}

QString Bugs::report() const
{
    return QString::fromUtf8(QJsonDocument(m_offer.value(QStringLiteral("report")).toObject()).toJson(QJsonDocument::Indented));
}

QString Bugs::offer(const QJsonObject &input)
{
    QJsonObject in = input;
    in.insert(QStringLiteral("now_ms"), double(nowMs()));
    Failure failure;
    const QJsonObject a =
        Core::call(QStringLiteral("bug_report"), QJsonObject{{QStringLiteral("input"), in}, {QStringLiteral("state"), state()}}, &failure)
            .toObject();
    if (!failure.isNull()) {
        Errors::log(QStringLiteral("bug: no report: %1 %2").arg(failure.message, failure.details));
        return QString();
    }
    const QString action = a.value(QStringLiteral("action")).toString();
    if (action == QStringLiteral("ask")) {
        m_offer = a;
        emit changed();
    } else if (action == QStringLiteral("send")) {
        send(a.value(QStringLiteral("fingerprint")).toString(), a.value(QStringLiteral("report")).toObject().value(QStringLiteral("version")).toString(),
             a.value(QStringLiteral("post")).toString(), a.value(QStringLiteral("url")).toString());
    }
    return action;
}

void Bugs::allow(bool always)
{
    if (m_offer.isEmpty())
        return;
    const QJsonObject o = m_offer;
    m_offer = QJsonObject();
    emit changed();
    Failure failure;
    keep(Core::call(QStringLiteral("bug_allow"), QJsonObject{{QStringLiteral("state"), state()}, {QStringLiteral("always"), always}}, &failure));
    send(o.value(QStringLiteral("fingerprint")).toString(), o.value(QStringLiteral("report")).toObject().value(QStringLiteral("version")).toString(),
         o.value(QStringLiteral("post")).toString(), o.value(QStringLiteral("url")).toString());
}

void Bugs::cancel()
{
    m_offer = QJsonObject();
    emit changed();
}

void Bugs::send(const QString &fingerprint, const QString &version, const QString &post, const QString &to)
{
    if (post.isEmpty())
        return;
    QNetworkRequest req(QUrl(to.isEmpty() ? QString::fromLatin1(url) : to));
    req.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/json"));
    QNetworkReply *reply = m_net.post(req, post.toUtf8());
    connect(reply, &QNetworkReply::finished, this, [this, reply, fingerprint, version, post]() {
        reply->deleteLater();
        const bool ok = reply->error() == QNetworkReply::NoError && reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt() == 200;
        const QString fixed = ok ? QJsonDocument::fromJson(reply->read(4096)).object().value(QStringLiteral("fixed_in")).toString() : QString();
        if (!ok)
            Errors::log(QStringLiteral("bug: the report did not go, it waits: %1").arg(reply->errorString()));
        Failure failure;
        keep(Core::call(QStringLiteral("bug_sent"),
                        QJsonObject{{QStringLiteral("state"), state()},
                                    {QStringLiteral("fingerprint"), fingerprint},
                                    {QStringLiteral("version"), version},
                                    {QStringLiteral("post"), post},
                                    {QStringLiteral("ok"), ok},
                                    {QStringLiteral("fixed_in"), fixed},
                                    {QStringLiteral("now_ms"), double(nowMs())}},
                        &failure));
    });
}

void Bugs::resend()
{
    Failure failure;
    const QJsonObject a =
        Core::call(QStringLiteral("bug_pending"), QJsonObject{{QStringLiteral("state"), state()}, {QStringLiteral("now_ms"), double(nowMs())}}, &failure)
            .toObject();
    if (!failure.isNull())
        return;
    keep(a);
    for (const QJsonValue &q : a.value(QStringLiteral("queue")).toArray()) {
        const QJsonObject o = q.toObject();
        send(o.value(QStringLiteral("fingerprint")).toString(), o.value(QStringLiteral("version")).toString(), o.value(QStringLiteral("post")).toString(),
             QString());
    }
}
