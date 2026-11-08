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
#include <QNetworkInterface>
#include <QTcpServer>
#include <QTcpSocket>

namespace {

// How many wrong codes a listening join takes (pair::MAX_FAILURES).
const int maxWrongCodes = 3;

// Whether an address is on the home network, as mDNS would publish it:
// private IPv4, unique-local IPv6, or link-local.
bool home(const QHostAddress &a)
{
    bool v4 = false;
    const quint32 ip = a.toIPv4Address(&v4);
    if (v4)
        return (ip >> 24) == 10 || (ip >> 20) == (172u << 4 | 1) || (ip >> 16) == (192u << 8 | 168) || (ip >> 16) == (169u << 8 | 254);
    const Q_IPV6ADDR v6 = a.toIPv6Address();
    return (v6[0] & 0xfe) == 0xfc || (v6[0] == 0xfe && (v6[1] & 0xc0) == 0x80);
}

// The addresses for the QR code: this phone's private IPv4 ones, at most four.
QJsonArray qrAddresses()
{
    QJsonArray out;
    for (const QHostAddress &a : QNetworkInterface::allAddresses()) {
        if (a.isLoopback() || a.protocol() != QAbstractSocket::IPv4Protocol || !home(a) || (a.toIPv4Address() >> 16) == (169u << 8 | 254))
            continue;
        out.append(QStringLiteral("%1:%2").arg(a.toString()).arg(Join::port));
        if (out.size() == 4)
            break;
    }
    return out;
}

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

void Join::start(const QString &name, const QString &os, const QByteArray &publicKey, const QByteArray &adminKey)
{
    stop();
    m_publicKey = publicKey;
    m_admin = !adminKey.isEmpty();
    m_wrongCodes = 0;
    m_error.clear();
    Failure failure;
    const QByteArray secret = sealSecret(&failure);
    if (secret.isEmpty())
        return fail(failure);
    const QJsonObject seal =
        Core::call(QStringLiteral("seal_public"), QJsonObject{{QStringLiteral("secret"), QString::fromLatin1(secret.toBase64())}}, &failure).toObject();
    if (!failure.isNull())
        return fail(failure);
    const QJsonArray addrs = qrAddresses();
    if (addrs.isEmpty())
        return fail({QCoreApplication::translate("Errors", "Connect the phone to your home Wi-Fi to join a group."), QStringLiteral("join: no private IPv4 address")});
    QJsonObject req{
        {QStringLiteral("name"), name},
        {QStringLiteral("os"), os},
        {QStringLiteral("public"), QString::fromLatin1(publicKey.toBase64())},
        {QStringLiteral("seal"), seal.value(QStringLiteral("key"))},
        {QStringLiteral("addrs"), addrs},
    };
    if (m_admin)
        req.insert(QStringLiteral("admin_public"), QString::fromLatin1(adminKey.toBase64()));
    const QByteArray bytes = QJsonDocument(req).toJson(QJsonDocument::Compact);
    uint8_t *answer = nullptr;
    size_t len = 0;
    const auto *data = reinterpret_cast<const uint8_t *>(bytes.constData());
    m_join = m_admin ? cbb_join_new_admin(data, size_t(bytes.size()), Core::signDigest, nullptr, Core::signAdminDigest, nullptr, &answer, &len)
                     : cbb_join_new(data, size_t(bytes.size()), Core::signDigest, nullptr, &answer, &len);
    const QJsonObject made = Core::take(answer, len, QStringLiteral("join"), &failure);
    if (!m_join)
        return fail(failure.isNull() ? Failure{QCoreApplication::translate("Errors", "This build of CBB is broken."), QStringLiteral("join: no joiner")} : failure);
    m_server = new QTcpServer(this);
    if (!m_server->listen(QHostAddress::Any, port))
        return fail({QCoreApplication::translate("Errors", "The phone cannot listen for the other device."),
                     QStringLiteral("join: listen on %1: %2").arg(port).arg(m_server->errorString())});
    connect(m_server, &QTcpServer::newConnection, this, &Join::accept);
    // Announced while it listens, so that a computer of the group finds it
    // by the code typed there (docs/protocol.md, section 6).
    if (!cbb_join_announce(m_join, m_server->serverPort()))
        Errors::log(QStringLiteral("join: no mDNS announcement"));
    m_code = made.value(QStringLiteral("code")).toString();
    m_qr = made.value(QStringLiteral("qr")).toString();
    m_modules.clear();
    for (const QJsonValue &row : made.value(QStringLiteral("modules")).toArray())
        m_modules.append(row.toString());
    Errors::log(QStringLiteral("join: listening as %1 on %2").arg(made.value(QStringLiteral("device")).toString(),
                                                                   QString::fromLatin1(QJsonDocument(addrs).toJson(QJsonDocument::Compact))));
    // With the details on, the QR code's text goes to the log too, so that a
    // test can admit the phone without a camera; it holds the one-time code.
    if (Errors::showDetails())
        Errors::log(QStringLiteral("join: QR: %1").arg(m_qr));
    setState(QStringLiteral("listening"));
}

void Join::stop()
{
    if (m_conn)
        m_conn->abort();
    if (m_server) {
        m_server->close();
        m_server->deleteLater();
        m_server = nullptr;
    }
    cbb_join_free(m_join);
    m_join = nullptr;
    if (m_state == QStringLiteral("listening") || m_state == QStringLiteral("joining"))
        setState(QStringLiteral("idle"));
}

void Join::accept()
{
    while (QTcpSocket *s = m_server ? m_server->nextPendingConnection() : nullptr) {
        // One attempt at a time, and only from the home network.
        if (m_conn || !home(s->peerAddress())) {
            Errors::log(QStringLiteral("join: refused a connection from %1").arg(s->peerAddress().toString()));
            s->abort();
            s->deleteLater();
            continue;
        }
        size_t len = 0;
        Failure failure;
        Core::take(cbb_join_accept(m_join, &len), len, QStringLiteral("join"), &failure);
        if (!failure.isNull()) {
            s->abort();
            s->deleteLater();
            return fail(failure);
        }
        // The server owns the sockets it hands out and deletes them with
        // itself, which would drop the joiner's last frame still waiting to
        // be written when stop() lets the server go after a join. The join
        // owns the socket instead, and the socket deletes itself once it is
        // closed.
        s->setParent(this);
        m_conn = s;
        connect(s, &QTcpSocket::readyRead, this, [this, s]() {
            if (s == m_conn)
                feed(s->readAll());
        });
        connect(s, &QTcpSocket::disconnected, this, [this, s]() {
            s->deleteLater();
            if (s == m_conn && m_state == QStringLiteral("joining"))
                setState(QStringLiteral("listening"));
        });
        Errors::log(QStringLiteral("join: a device dialed in from %1").arg(s->peerAddress().toString()));
        setState(QStringLiteral("joining"));
        feed(QByteArray());
    }
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
        m_conn->disconnectFromHost();
        m_conn = nullptr;
        const bool wrongCode = step.value(QStringLiteral("wrong_code")).toBool();
        if (wrongCode && ++m_wrongCodes >= maxWrongCodes)
            return fail({QCoreApplication::translate("Errors", "The other device showed a wrong code three times. Start again."), QStringLiteral("join: too many wrong codes")});
        // A window that makes no admins refuses a phone that asks to be one:
        // the page says so, and keeps waiting for the root.
        if (m_admin && !wrongCode)
            m_error = Errors::shown({QCoreApplication::translate("Errors", "The other device did not admit this phone as an admin. Only the group's root makes admins: there, admit it as an admin (cbb pair -qr -admin), or join without being an admin."),
                                     QStringLiteral("join: %1: %2").arg(e.value(QStringLiteral("message")).toString(), e.value(QStringLiteral("details")).toString())});
        setState(QStringLiteral("listening"));
        return;
    }
    if (state != QStringLiteral("joined"))
        return;
    const Membership m = Membership::fromJoined(step.value(QStringLiteral("joined")).toObject());
    const bool saved = m.save(&failure);
    const QJsonObject last = Core::take(cbb_join_finish(m_join, saved ? 1 : 0, &len), len, QStringLiteral("join"), &failure);
    m_conn->write(b64(last.value(QStringLiteral("send"))));
    m_conn->disconnectFromHost();
    m_conn = nullptr;
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
