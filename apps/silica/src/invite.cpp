// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

#include "invite.h"

#include "core.h"

#include <cbb_core.h>

#include <QCoreApplication>
#include <QDateTime>
#include <QImage>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QThread>

namespace {

// The longest side of a camera frame the QR reader gets, as Admit's.
const int maxFrameSide = 1024;

// How often the page's state is asked of the core.
const int pollMs = 300;

// Opens the invitation off the GUI thread: the core waits for the hub.
class OpenThread : public QThread
{
public:
    cbb_member *member = nullptr;
    QByteArray request;
    cbb_invite *invite = nullptr;
    QJsonObject answer;
    Failure failure;

protected:
    void run() override
    {
        uint8_t *out = nullptr;
        size_t len = 0;
        invite = cbb_invite_new(member, reinterpret_cast<const uint8_t *>(request.constData()), size_t(request.size()), Core::signAdminDigest,
                                nullptr, &out, &len);
        answer = Core::take(out, len, QStringLiteral("invite"), &failure);
    }
};

} // namespace

Invite::Invite(QObject *parent) : QObject(parent)
{
    m_poll.setInterval(pollMs);
    connect(&m_poll, &QTimer::timeout, this, &Invite::poll);
}

Invite::~Invite()
{
    close();
}

void Invite::setPreparing()
{
    close();
    m_error.clear();
    m_joined.clear();
    setState(QStringLiteral("preparing"));
}

void Invite::open(cbb_member *member, const QByteArray &publicKey, const QByteArray &adminCa, int seconds)
{
    close();
    if (!member)
        return fail({QCoreApplication::translate("Errors", "The phone is not connected to its group yet. Try again in a moment."), QStringLiteral("invite: no member")});
    QJsonObject req{
        {QStringLiteral("public"), QString::fromLatin1(publicKey.toBase64())},
        {QStringLiteral("expires"), seconds},
    };
    if (!adminCa.isEmpty())
        req.insert(QStringLiteral("admin_ca"), QString::fromLatin1(adminCa.toBase64()));
    auto *thread = new OpenThread;
    thread->member = member;
    thread->request = QJsonDocument(req).toJson(QJsonDocument::Compact);
    connect(thread, &QThread::finished, this, [this, thread]() {
        thread->deleteLater();
        if (m_state != QStringLiteral("opening")) {
            // Cancelled while it waited for the hub.
            cbb_invite_free(thread->invite);
            return;
        }
        if (!thread->invite)
            return fail(thread->failure.isNull() ? Failure{QCoreApplication::translate("Errors", "This build of CBB is broken."), QStringLiteral("invite: no invitation")}
                                                 : thread->failure);
        m_invite = thread->invite;
        m_text = thread->answer.value(QStringLiteral("invite")).toString();
        m_modules.clear();
        for (const QJsonValue &row : thread->answer.value(QStringLiteral("modules")).toArray())
            m_modules.append(row.toString());
        m_expiresMs = double(QDateTime::currentMSecsSinceEpoch()) + thread->answer.value(QStringLiteral("expires")).toDouble() * 1000;
        m_version = 0;
        Errors::log(QStringLiteral("invite: open for %1 s").arg(thread->answer.value(QStringLiteral("expires")).toDouble()));
        setState(QStringLiteral("open"));
        m_poll.start();
    });
    setState(QStringLiteral("opening"));
    thread->start();
}

void Invite::poll()
{
    if (!m_invite)
        return;
    size_t len = 0;
    Failure failure;
    const QJsonObject st = Core::take(cbb_invite_next(m_invite, m_version, 0, &len), len, QStringLiteral("invite"), &failure);
    if (!failure.isNull())
        return fail(failure);
    const quint64 version = quint64(st.value(QStringLiteral("version")).toDouble());
    if (version <= m_version)
        return;
    m_version = version;
    const QString state = st.value(QStringLiteral("state")).toString();
    const QJsonObject j = st.value(QStringLiteral("joining")).toObject();
    m_joiningName = j.value(QStringLiteral("name")).toString();
    m_joiningOs = j.value(QStringLiteral("os")).toString();
    m_fingerprint = j.value(QStringLiteral("fingerprint")).toString();
    if (state == QStringLiteral("done")) {
        m_joined = st.value(QStringLiteral("name")).toString();
        Errors::log(QStringLiteral("invite: %1 joined").arg(st.value(QStringLiteral("device")).toString()));
        close();
        return setState(QStringLiteral("done"));
    }
    if (state == QStringLiteral("failed")) {
        const QJsonObject e = st.value(QStringLiteral("error")).toObject();
        close();
        return fail({e.value(QStringLiteral("message")).toString(), QStringLiteral("invite: %1").arg(e.value(QStringLiteral("details")).toString())});
    }
    setState(state);
}

void Invite::answer(bool yes)
{
    if (m_invite)
        cbb_invite_answer(m_invite, yes ? 1 : 0);
}

void Invite::cancel()
{
    close();
    m_error.clear();
    m_joined.clear();
    setState(QStringLiteral("idle"));
}

void Invite::fail(const Failure &f)
{
    close();
    m_error = Errors::shown(f);
    setState(QStringLiteral("failed"));
}

void Invite::close()
{
    m_poll.stop();
    if (m_invite) {
        cbb_invite_free(m_invite);
        m_invite = nullptr;
    }
    m_text.clear();
    m_modules.clear();
    m_joiningName.clear();
    m_joiningOs.clear();
    m_fingerprint.clear();
}

void Invite::setState(const QString &state)
{
    m_state = state;
    emit changed();
}

QVariantMap Invite::read(const QString &text) const
{
    Failure failure;
    const QJsonObject r = Core::call(QStringLiteral("read_invite"), QJsonObject{{QStringLiteral("text"), text.trimmed()}}, &failure).toObject();
    if (!failure.isNull())
        return {{QStringLiteral("error"), Errors::shown(failure)}};
    const QJsonObject inv = r.value(QStringLiteral("invitation")).toObject();
    if (inv.isEmpty()) {
        const QJsonObject why = r.value(QStringLiteral("refused")).toObject();
        return {{QStringLiteral("error"), Errors::shown({QCoreApplication::translate("Errors", "This is not a CBB invitation."),
                                                          QStringLiteral("invite: %1").arg(why.value(QStringLiteral("message")).toString())})}};
    }
    const double expiresMs = inv.value(QStringLiteral("expires")).toDouble() * 1000;
    if (expiresMs <= double(QDateTime::currentMSecsSinceEpoch()))
        return {{QStringLiteral("error"), Errors::shown({QCoreApplication::translate("Errors", "The invitation has expired. Ask for a new one."),
                                                          QStringLiteral("invite: expired")})}};
    return {
        {QStringLiteral("group"), inv.value(QStringLiteral("group")).toString()},
        {QStringLiteral("hub"), inv.value(QStringLiteral("hub")).toString().left(12)},
        {QStringLiteral("expiresMs"), expiresMs},
    };
}

QString Invite::scan(const QVariant &frame) const
{
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
    for (const QJsonValue &t : read.value(QStringLiteral("texts")).toArray()) {
        const QString text = t.toString().trimmed();
        if (text.startsWith(QStringLiteral("cbb://invite#")))
            return text;
    }
    return QString();
}
