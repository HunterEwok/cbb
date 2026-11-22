// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

#include "join.h"

#include "core.h"

#include <cbb_core.h>

#include <QCoreApplication>
#include <QJsonDocument>
#include <QJsonObject>

namespace {

// How often the page's state is asked of the core, as the window's.
const int pollMs = 300;

} // namespace

Join::Join(QObject *parent) : QObject(parent)
{
    m_poll.setInterval(pollMs);
    connect(&m_poll, &QTimer::timeout, this, &Join::poll);
}

Join::~Join()
{
    free();
}

void Join::startInvite(const QString &invite, const QString &dir, const QString &name, const QString &os, const QByteArray &publicKey)
{
    free();
    m_error.clear();
    m_fingerprint.clear();
    m_answered = false;
    m_invite = invite.trimmed();
    const QByteArray req = QJsonDocument(QJsonObject{
                                             {QStringLiteral("dir"), dir},
                                             {QStringLiteral("qr"), QString()},
                                             {QStringLiteral("invite"), m_invite},
                                             {QStringLiteral("name"), name},
                                             {QStringLiteral("os"), os},
                                             {QStringLiteral("public"), QString::fromLatin1(publicKey.toBase64())},
                                         })
                               .toJson(QJsonDocument::Compact);
    uint8_t *answer = nullptr;
    size_t len = 0;
    Failure failure;
    m_joiner = cbb_joiner_new(reinterpret_cast<const uint8_t *>(req.constData()), size_t(req.size()), Core::signDigest, nullptr, &answer, &len);
    const QJsonObject first = Core::take(answer, len, QStringLiteral("join"), &failure);
    if (!m_joiner)
        return fail(failure.isNull() ? Failure{QCoreApplication::translate("Errors", "This build of CBB is broken."), QStringLiteral("join: no joiner")} : failure);
    m_fingerprint = first.value(QStringLiteral("fingerprint")).toString();
    m_version = 0;
    Errors::log(QStringLiteral("join: dialing the hub of the invitation"));
    setState(QStringLiteral("dialing"));
    m_poll.start();
}

void Join::poll()
{
    if (!m_joiner)
        return;
    size_t len = 0;
    Failure failure;
    const QJsonObject st = Core::take(cbb_joiner_next(m_joiner, m_version, 0, &len), len, QStringLiteral("join"), &failure);
    if (!failure.isNull())
        return fail(failure);
    const quint64 version = quint64(st.value(QStringLiteral("version")).toDouble());
    if (version <= m_version)
        return;
    m_version = version;
    m_answered = m_answered || st.value(QStringLiteral("answered")).toBool();
    const QString state = st.value(QStringLiteral("state")).toString();
    if (state == QStringLiteral("done")) {
        const QString group = st.value(QStringLiteral("group")).toString();
        const QString device = st.value(QStringLiteral("device")).toString();
        free();
        Errors::log(QStringLiteral("join: joined %1 as %2 by an invitation").arg(group.left(16), device));
        setState(QStringLiteral("joined"));
        emit joined(group, device);
        return;
    }
    if (state == QStringLiteral("failed")) {
        const QJsonObject e = st.value(QStringLiteral("error")).toObject();
        const QString details = QStringLiteral("join: %1").arg(e.value(QStringLiteral("details")).toString());
        if (!m_answered)
            return fail({QCoreApplication::translate("Errors", "The group's hub did not answer. Check that the invitation is still valid and that the hub is on, then try again."), details});
        return fail({e.value(QStringLiteral("message")).toString(), details});
    }
    setState(m_answered ? QStringLiteral("joining") : QStringLiteral("dialing"));
}

void Join::stop()
{
    free();
    m_error.clear();
    setState(QStringLiteral("idle"));
}

void Join::fail(const Failure &f)
{
    free();
    m_error = Errors::shown(f);
    setState(QStringLiteral("failed"));
}

void Join::free()
{
    m_poll.stop();
    if (m_joiner) {
        cbb_joiner_free(m_joiner);
        m_joiner = nullptr;
    }
}

void Join::setState(const QString &state)
{
    m_state = state;
    emit changed();
}
