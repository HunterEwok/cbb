// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

#include "admit.h"

#include "core.h"

#include <cbb_core.h>

#include <QCoreApplication>
#include <QImage>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QTcpSocket>

namespace {

// The widest frame the reader gets; larger ones are scaled down first.
const int maxFrameSide = 1024;

QByteArray b64(const QJsonValue &v)
{
    return QByteArray::fromBase64(v.toString().toLatin1());
}

// The host and port of host:port or [v6]:port.
bool split(const QString &addr, QString *host, quint16 *port)
{
    const int colon = addr.lastIndexOf(QLatin1Char(':'));
    if (colon <= 0)
        return false;
    bool ok = false;
    *port = addr.mid(colon + 1).toUShort(&ok);
    *host = addr.left(colon);
    if (host->startsWith(QLatin1Char('[')) && host->endsWith(QLatin1Char(']')))
        *host = host->mid(1, host->size() - 2);
    return ok && *port != 0 && !host->isEmpty();
}

QString describe(const QJsonObject &e)
{
    return QStringLiteral("%1: %2").arg(e.value(QStringLiteral("message")).toString(), e.value(QStringLiteral("details")).toString());
}

} // namespace

Admit::Admit(QObject *parent) : QObject(parent) {}

Admit::~Admit()
{
    close();
}

void Admit::close()
{
    if (m_conn) {
        m_conn->disconnect(this);
        m_conn->abort();
        m_conn->deleteLater();
        m_conn = nullptr;
    }
    cbb_admit_free(m_admit);
    m_admit = nullptr;
}

void Admit::reset()
{
    close();
    m_addrs.clear();
    m_device.clear();
    m_error.clear();
    m_hint.clear();
    setState(QStringLiteral("scanning"));
}

QString Admit::scan(const QVariant &frame)
{
    if (m_state != QStringLiteral("scanning"))
        return QString();
    QImage img = frame.value<QImage>();
    if (img.isNull())
        return QString();
    if (img.width() > maxFrameSide || img.height() > maxFrameSide)
        img = img.scaled(maxFrameSide, maxFrameSide, Qt::KeepAspectRatio, Qt::FastTransformation);
    img = img.convertToFormat(QImage::Format_Grayscale8);
    size_t len = 0;
    Failure failure;
    const QJsonObject read = Core::take(cbb_qr_read(img.constBits(), size_t(img.width()), size_t(img.height()), size_t(img.bytesPerLine()), &len),
                                        len, QStringLiteral("qr"), &failure);
    if (!failure.isNull()) {
        Errors::log(QStringLiteral("admit: reading a frame: %1: %2").arg(failure.message, failure.details));
        return QString();
    }
    for (const QJsonValue &t : read.value(QStringLiteral("texts")).toArray()) {
        const QString text = t.toString().trimmed();
        if (text.startsWith(QStringLiteral("cbb://join?")))
            return text;
        const QString hint = QCoreApplication::translate("Errors", "This is not a CBB code. On the other device, choose to join a group, and scan the code it shows.");
        if (m_hint != hint) {
            m_hint = hint;
            emit changed();
        }
    }
    return QString();
}

void Admit::setPreparing()
{
    m_hint.clear();
    setState(QStringLiteral("preparing"));
}

void Admit::admit(const QString &qr, cbb_member *member, const QByteArray &publicKey, const QByteArray &adminCa, bool makeAdmin)
{
    close();
    m_error.clear();
    m_device.clear();
    if (!member)
        return fail({QCoreApplication::translate("Errors", "The phone is not connected to its group yet. Try again in a moment."), QStringLiteral("admit: no member")});
    QJsonObject req{
        {QStringLiteral("qr"), qr},
        {QStringLiteral("public"), QString::fromLatin1(publicKey.toBase64())},
        {QStringLiteral("make_admin"), makeAdmin},
    };
    if (!adminCa.isEmpty())
        req.insert(QStringLiteral("admin_ca"), QString::fromLatin1(adminCa.toBase64()));
    const QByteArray bytes = QJsonDocument(req).toJson(QJsonDocument::Compact);
    uint8_t *answer = nullptr;
    size_t len = 0;
    Failure failure;
    m_admit = cbb_admit_new(member, reinterpret_cast<const uint8_t *>(bytes.constData()), size_t(bytes.size()), Core::signAdminDigest, nullptr,
                            &answer, &len);
    const QJsonObject made = Core::take(answer, len, QStringLiteral("admit"), &failure);
    if (!m_admit)
        return fail(failure.isNull() ? Failure{QCoreApplication::translate("Errors", "This build of CBB is broken."), QStringLiteral("admit: no admission")} : failure);
    m_addrs.clear();
    for (const QJsonValue &a : made.value(QStringLiteral("addrs")).toArray())
        m_addrs.append(a.toString());
    m_lastError = QStringLiteral("no address of the code answered");
    Errors::log(QStringLiteral("admit: dialing %1").arg(m_addrs.join(QStringLiteral(", "))));
    setState(QStringLiteral("dialing"));
    dialNext();
}

void Admit::dialNext()
{
    if (m_conn) {
        m_conn->disconnect(this);
        m_conn->abort();
        m_conn->deleteLater();
        m_conn = nullptr;
    }
    QString host;
    quint16 port = 0;
    while (!m_addrs.isEmpty() && !split(m_addrs.first(), &host, &port))
        m_addrs.removeFirst();
    if (m_addrs.isEmpty())
        return fail({QCoreApplication::translate("Errors", "The phone cannot reach the other device. Check that both are on the same Wi-Fi, and that the other device still shows its code."),
                     QStringLiteral("admit: %1").arg(m_lastError)});
    const QString addr = m_addrs.takeFirst();
    auto *s = new QTcpSocket(this);
    m_conn = s;
    connect(s, &QTcpSocket::connected, this, [this, s]() {
        if (s != m_conn)
            return;
        size_t len = 0;
        Failure failure;
        const QJsonObject step = Core::take(cbb_admit_dial(m_admit, &len), len, QStringLiteral("admit"), &failure);
        if (!failure.isNull())
            return fail(failure);
        setState(QStringLiteral("admitting"));
        handle(step);
    });
    connect(s, &QTcpSocket::readyRead, this, [this, s]() {
        if (s == m_conn)
            feed(s->readAll());
    });
    connect(s, static_cast<void (QAbstractSocket::*)(QAbstractSocket::SocketError)>(&QAbstractSocket::error), this, [this, s, addr]() {
        if (s != m_conn)
            return;
        if (m_state == QStringLiteral("admitted")) {
            // The device closed after the Welcome without answering: it is
            // in the group whether or not it stored its identity.
            close();
            return;
        }
        if (m_state != QStringLiteral("dialing") && m_state != QStringLiteral("admitting"))
            return;
        m_lastError = QStringLiteral("%1: %2").arg(addr, s->errorString());
        Errors::log(QStringLiteral("admit: %1").arg(m_lastError));
        setState(QStringLiteral("dialing"));
        dialNext();
    });
    s->connectToHost(host, port);
}

void Admit::feed(const QByteArray &data)
{
    if (!m_admit || !m_conn)
        return;
    size_t len = 0;
    Failure failure;
    const QJsonObject step =
        Core::take(cbb_admit_feed(m_admit, reinterpret_cast<const uint8_t *>(data.constData()), size_t(data.size()), 0, &len), len,
                   QStringLiteral("admit"), &failure);
    if (!failure.isNull())
        return fail(failure);
    handle(step);
}

void Admit::handle(const QJsonObject &step)
{
    if (m_conn)
        m_conn->write(b64(step.value(QStringLiteral("send"))));
    const QString state = step.value(QStringLiteral("state")).toString();
    const QJsonObject e = step.value(QStringLiteral("error")).toObject();
    if (state == QStringLiteral("admitted")) {
        const QJsonObject d = step.value(QStringLiteral("device")).toObject();
        m_device = d.value(QStringLiteral("name")).toString();
        Errors::log(QStringLiteral("admit: admitted %1 (%2, %3)%4")
                        .arg(d.value(QStringLiteral("device")).toString(), d.value(QStringLiteral("os")).toString(),
                             d.value(QStringLiteral("role")).toString(), d.value(QStringLiteral("admin")).toBool() ? QStringLiteral(", an admin") : QString()));
        // The record could not go to the group: the device has its
        // certificate, and the app says what went wrong.
        if (!e.isEmpty())
            m_error = Errors::shown({QCoreApplication::translate("Errors", "The device joined, but the group did not take its record yet."), QStringLiteral("admit: %1").arg(describe(e))});
        setState(QStringLiteral("admitted"));
    } else if (state == QStringLiteral("done")) {
        const bool confirmed = step.value(QStringLiteral("confirmed")).toBool();
        Errors::log(QStringLiteral("admit: the device %1").arg(confirmed ? QStringLiteral("stored its identity") : QStringLiteral("did not confirm")));
        close();
        if (confirmed)
            setState(QStringLiteral("confirmed"));
    } else if (state == QStringLiteral("failed")) {
        const bool wrongCode = step.value(QStringLiteral("wrong_code")).toBool();
        const QString message = e.value(QStringLiteral("message")).toString() + e.value(QStringLiteral("details")).toString();
        Failure f{QCoreApplication::translate("Errors", "The other device did not join."), QStringLiteral("admit: %1").arg(describe(e))};
        if (wrongCode)
            f.message = QCoreApplication::translate("Errors", "The code did not match. Scan the code the other device shows now.");
        else if (message.contains(QStringLiteral("asks to be an admin")) || message.contains(QStringLiteral("joins only through the group's root")))
            f.message = QCoreApplication::translate("Errors", "That phone asks to be an admin. Only the group's root makes admins; on that phone, join without being an admin.");
        else if (message.contains(QStringLiteral("not the one in the QR code")))
            f.message = QCoreApplication::translate("Errors", "Another device answered at the code's address. Scan the code again.");
        fail(f);
    }
}

void Admit::fail(const Failure &f)
{
    m_error = Errors::shown(f);
    close();
    setState(QStringLiteral("failed"));
}

void Admit::setState(const QString &state)
{
    m_state = state;
    emit changed();
}
