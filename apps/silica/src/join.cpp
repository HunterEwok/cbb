// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

#include "join.h"

#include "core.h"
#include "errors.h"

#include <cbb_core.h>

#include <QCoreApplication>
#include <QHostAddress>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QTcpSocket>
#include <QTimer>

namespace {

// How many times a join by an invitation dials its guest tunnel, and the
// pause between the attempts, as the other phones' apps.
const int inviteAttempts = 5;
const int inviteDialPauseMs = 2000;

QByteArray b64(const QJsonValue &v)
{
    return QByteArray::fromBase64(v.toString().toLatin1());
}

} // namespace

Join::Join(QObject *parent) : QObject(parent) {}

Join::~Join()
{
    stop();
}

void Join::startInvite(const QString &name, const QString &os, const QByteArray &publicKey, const QString &invite)
{
    stop();
    m_publicKey = publicKey;
    m_inviteAttempts = 0;
    m_error.clear();
    m_fingerprint.clear();
    m_invite = invite.trimmed();
    Failure failure;
    const QByteArray secret = sealSecret(&failure);
    if (secret.isEmpty())
        return fail(failure);
    const QJsonObject seal =
        Core::call(QStringLiteral("seal_public"), QJsonObject{{QStringLiteral("secret"), QString::fromLatin1(secret.toBase64())}}, &failure).toObject();
    if (!failure.isNull())
        return fail(failure);
    const QJsonObject req{
        {QStringLiteral("name"), name},
        {QStringLiteral("os"), os},
        {QStringLiteral("public"), QString::fromLatin1(publicKey.toBase64())},
        {QStringLiteral("seal"), seal.value(QStringLiteral("key"))},
        {QStringLiteral("invite"), m_invite},
    };
    const QByteArray bytes = QJsonDocument(req).toJson(QJsonDocument::Compact);
    uint8_t *answer = nullptr;
    size_t len = 0;
    m_join = cbb_join_new(reinterpret_cast<const uint8_t *>(bytes.constData()), size_t(bytes.size()), Core::signDigest, nullptr, &answer, &len);
    const QJsonObject made = Core::take(answer, len, QStringLiteral("join"), &failure);
    if (!m_join)
        return fail(failure.isNull() ? Failure{QCoreApplication::translate("Errors", "This build of CBB is broken."), QStringLiteral("join: no joiner")} : failure);
    m_invitePort = quint16(made.value(QStringLiteral("port")).toInt());
    m_fingerprint = made.value(QStringLiteral("fingerprint")).toString();
    if (m_invitePort == 0)
        return fail({QCoreApplication::translate("Errors", "This build of CBB is broken."), QStringLiteral("join: the invitation's tunnel has no port")});
    Errors::log(QStringLiteral("join: by an invitation, as %1, through the guest tunnel on port %2").arg(made.value(QStringLiteral("device")).toString()).arg(m_invitePort));
    setState(QStringLiteral("dialing"));
    dialInvite();
}

void Join::dialInvite()
{
    if (!m_join || m_invite.isEmpty() || m_conn)
        return;
    ++m_inviteAttempts;
    auto *s = new QTcpSocket(this);
    m_conn = s;
    connect(s, &QTcpSocket::connected, this, [this, s]() {
        if (s != m_conn || !m_join)
            return;
        size_t len = 0;
        Failure failure;
        const QJsonObject first = Core::take(cbb_join_accept(m_join, &len), len, QStringLiteral("join"), &failure);
        if (!failure.isNull())
            return fail(failure);
        s->write(b64(first.value(QStringLiteral("send"))));
    });
    connect(s, &QTcpSocket::readyRead, this, [this, s]() {
        if (s != m_conn)
            return;
        if (m_state == QStringLiteral("dialing"))
            setState(QStringLiteral("joining"));
        feed(s->readAll());
    });
    connect(s, &QTcpSocket::disconnected, this, [this, s]() {
        s->deleteLater();
        if (s == m_conn) {
            m_conn = nullptr;
            inviteAttemptEnded();
        }
    });
    connect(s, static_cast<void (QAbstractSocket::*)(QAbstractSocket::SocketError)>(&QAbstractSocket::error), this, [this, s](QAbstractSocket::SocketError) {
        if (s != m_conn)
            return;
        Errors::log(QStringLiteral("join: dialing the invitation's tunnel: %1").arg(s->errorString()));
        m_conn = nullptr;
        s->abort();
        s->deleteLater();
        inviteAttemptEnded();
    });
    s->connectToHost(QHostAddress::LocalHost, m_invitePort);
}

void Join::inviteAttemptEnded()
{
    if (!m_join || m_state == QStringLiteral("joined") || m_state == QStringLiteral("failed"))
        return;
    if (m_inviteAttempts >= inviteAttempts) {
        if (!cbb_join_answered(m_join))
            return fail({QCoreApplication::translate("Errors", "The group's hub did not answer. Check that the invitation is still valid and that the hub is on, then try again."),
                         QStringLiteral("join: the invitation's hub never answered through the tunnel")});
        return fail({QCoreApplication::translate("Errors", "The other phone's group could not be joined. Try again."),
                     QStringLiteral("join: %1 attempts through the invitation failed").arg(inviteAttempts)});
    }
    setState(QStringLiteral("dialing"));
    QTimer::singleShot(inviteDialPauseMs, this, &Join::dialInvite);
}

void Join::stop()
{
    if (m_conn)
        m_conn->abort();
    cbb_join_free(m_join);
    m_join = nullptr;
    if (m_state == QStringLiteral("dialing") || m_state == QStringLiteral("joining"))
        setState(QStringLiteral("idle"));
}

void Join::feed(const QByteArray &data)
{
    if (!m_join || !m_conn)
        return;
    size_t len = 0;
    Failure failure;
    const QJsonObject step = Core::take(cbb_join_feed(m_join, reinterpret_cast<const uint8_t *>(data.constData()), size_t(data.size()), 0, &len), len, QStringLiteral("join"), &failure);
    if (!failure.isNull())
        return fail(failure);
    m_conn->write(b64(step.value(QStringLiteral("send"))));
    const QString state = step.value(QStringLiteral("state")).toString();
    if (state == QStringLiteral("failed")) {
        const QJsonObject e = step.value(QStringLiteral("error")).toObject();
        Errors::log(QStringLiteral("join: an attempt failed: %1: %2").arg(e.value(QStringLiteral("message")).toString(), e.value(QStringLiteral("details")).toString()));
        QTcpSocket *conn = m_conn;
        m_conn = nullptr;
        conn->disconnectFromHost();
        return inviteAttemptEnded();
    }
    if (state != QStringLiteral("joined"))
        return;
    const Membership m = Membership::fromJoined(step.value(QStringLiteral("joined")).toObject());
    const bool saved = m.save(&failure);
    const QJsonObject last = Core::take(cbb_join_finish(m_join, saved ? 1 : 0, &len), len, QStringLiteral("join"), &failure);
    // Let go of the socket first: its disconnected signal, which may come
    // at once, must not count as a failed attempt.
    QTcpSocket *conn = m_conn;
    m_conn = nullptr;
    conn->write(b64(last.value(QStringLiteral("send"))));
    conn->disconnectFromHost();
    if (!saved)
        return fail(failure);
    Errors::log(QStringLiteral("join: joined the group %1 as %2%3").arg(m.groupTag(), m.device, m.isAdmin() ? QStringLiteral(", an admin") : QString()));
    stop();
    setState(QStringLiteral("joined"));
    emit joined(m);
}

void Join::fail(const Failure &f)
{
    m_error = Errors::shown(f);
    stop();
    setState(QStringLiteral("failed"));
}

void Join::setState(const QString &state)
{
    m_state = state;
    emit changed();
}
