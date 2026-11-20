// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

#include "pairing06.h"

#include "core.h"

#include <cbb_core.h>

#include <QCoreApplication>
#include <QHostAddress>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QNetworkInterface>

namespace {

// How often the page's state is asked of the core, as Invite's.
const int pollMs = 300;

// The phone's home addresses for the window's QR code, without a port (the
// core adds the member port's): private IPv4, at most four.
QJsonArray homeAddresses()
{
    QJsonArray out;
    for (const QHostAddress &a : QNetworkInterface::allAddresses()) {
        bool v4 = false;
        const quint32 ip = a.toIPv4Address(&v4);
        if (!v4 || a.isLoopback())
            continue;
        if ((ip >> 24) == 10 || (ip >> 20) == (172u << 4 | 1) || (ip >> 16) == (192u << 8 | 168))
            out.append(a.toString());
        if (out.size() == 4)
            break;
    }
    return out;
}

// The core's {"message","details"} of a failed state.
Failure failureOf(const QJsonObject &st, const QString &what)
{
    const QJsonObject e = st.value(QStringLiteral("error")).toObject();
    return {e.value(QStringLiteral("message")).toString(), QStringLiteral("%1: %2").arg(what, e.value(QStringLiteral("details")).toString())};
}

QByteArray compact(const QJsonObject &o)
{
    return QJsonDocument(o).toJson(QJsonDocument::Compact);
}

} // namespace

PairWindow::PairWindow(QObject *parent) : QObject(parent)
{
    m_poll.setInterval(pollMs);
    connect(&m_poll, &QTimer::timeout, this, &PairWindow::poll);
}

PairWindow::~PairWindow()
{
    free();
}

void PairWindow::setPreparing()
{
    free();
    m_error.clear();
    m_joined.clear();
    setState(QStringLiteral("preparing"));
}

void PairWindow::open(cbb_member *member, const QByteArray &publicKey)
{
    free();
    if (!member)
        return fail({QCoreApplication::translate("Errors", "The phone is not connected to its group yet. Try again in a moment."), QStringLiteral("window: no member")});
    const QJsonArray addrs = homeAddresses();
    if (addrs.isEmpty())
        return fail({QCoreApplication::translate("Errors", "Connect the phone to your home Wi-Fi to add a device."), QStringLiteral("window: no private IPv4 address")});
    const QByteArray req = compact(QJsonObject{
        {QStringLiteral("public"), QString::fromLatin1(publicKey.toBase64())},
        {QStringLiteral("addrs"), addrs},
        {QStringLiteral("expires"), 0},
        // Aurora has no system DNS-SD for the app: the core announces it.
        {QStringLiteral("mdns"), true},
    });
    uint8_t *answer = nullptr;
    size_t len = 0;
    Failure failure;
    m_window = cbb_window_new(member, reinterpret_cast<const uint8_t *>(req.constData()), size_t(req.size()), Core::signAdminDigest, nullptr,
                              &answer, &len);
    const QJsonObject made = Core::take(answer, len, QStringLiteral("window"), &failure);
    if (!m_window)
        return fail(failure.isNull() ? Failure{QCoreApplication::translate("Errors", "This build of CBB is broken."), QStringLiteral("window: no window")} : failure);
    m_qr = made.value(QStringLiteral("qr")).toString();
    m_modules.clear();
    for (const QJsonValue &row : made.value(QStringLiteral("modules")).toArray())
        m_modules.append(row.toString());
    m_version = 0;
    Errors::log(QStringLiteral("window: open for %1 s").arg(made.value(QStringLiteral("expires")).toDouble()));
    setState(QStringLiteral("open"));
    m_poll.start();
}

void PairWindow::poll()
{
    if (!m_window)
        return;
    size_t len = 0;
    Failure failure;
    const QJsonObject st = Core::take(cbb_window_next(m_window, m_version, 0, &len), len, QStringLiteral("window"), &failure);
    if (!failure.isNull())
        return fail(failure);
    const quint64 version = quint64(st.value(QStringLiteral("version")).toDouble());
    if (version <= m_version)
        return;
    m_version = version;
    const QString state = st.value(QStringLiteral("state")).toString();
    const QJsonObject j = st.value(QStringLiteral("joining")).toObject();
    m_joiningName = j.value(QStringLiteral("name")).toString();
    m_code = j.value(QStringLiteral("code")).toString();
    if (state == QStringLiteral("done")) {
        m_joined = st.value(QStringLiteral("name")).toString();
        m_error.clear();
        Errors::log(QStringLiteral("window: %1 joined").arg(st.value(QStringLiteral("device")).toString()));
        setState(state);
        emit admitted();
        return;
    }
    if (state == QStringLiteral("failed")) {
        // That attempt failed; the window stays open for another.
        const Failure f = failureOf(st, QStringLiteral("window"));
        m_error = Errors::shown(f);
        return setState(QStringLiteral("open"));
    }
    if (state == QStringLiteral("closed")) {
        free();
        return setState(state);
    }
    if (state == QStringLiteral("joining"))
        m_error.clear();
    setState(state);
}

void PairWindow::answer(bool yes)
{
    if (m_window)
        cbb_window_answer(m_window, yes ? 1 : 0);
}

void PairWindow::close()
{
    free();
    m_error.clear();
    m_joined.clear();
    setState(QStringLiteral("idle"));
}

void PairWindow::fail(const Failure &f)
{
    free();
    m_error = Errors::shown(f);
    setState(QStringLiteral("failed"));
}

void PairWindow::free()
{
    m_poll.stop();
    if (m_window) {
        cbb_window_free(m_window);
        m_window = nullptr;
    }
    m_qr.clear();
    m_modules.clear();
    m_joiningName.clear();
    m_code.clear();
}

void PairWindow::setState(const QString &state)
{
    m_state = state;
    emit changed();
}

Joiner::Joiner(QObject *parent) : QObject(parent)
{
    m_poll.setInterval(pollMs);
    connect(&m_poll, &QTimer::timeout, this, &Joiner::poll);
}

Joiner::~Joiner()
{
    free();
}

void Joiner::start(const QString &dir, const QString &qr, const QString &name, const QString &os, const QByteArray &publicKey)
{
    free();
    m_error.clear();
    const QByteArray req = compact(QJsonObject{
        {QStringLiteral("dir"), dir},
        {QStringLiteral("qr"), qr.trimmed()},
        {QStringLiteral("name"), name},
        {QStringLiteral("os"), os},
        {QStringLiteral("public"), QString::fromLatin1(publicKey.toBase64())},
    });
    uint8_t *answer = nullptr;
    size_t len = 0;
    Failure failure;
    m_joiner = cbb_joiner_new(reinterpret_cast<const uint8_t *>(req.constData()), size_t(req.size()), Core::signDigest, nullptr, &answer, &len);
    Core::take(answer, len, QStringLiteral("joiner"), &failure);
    if (!m_joiner)
        return fail(failure.isNull() ? Failure{QCoreApplication::translate("Errors", "This build of CBB is broken."), QStringLiteral("joiner: no joiner")} : failure);
    m_version = 0;
    Errors::log(qr.isEmpty() ? QStringLiteral("joiner: looking for a window at home") : QStringLiteral("joiner: dialing the window of the code"));
    setState(QStringLiteral("dialing"));
    m_poll.start();
}

void Joiner::poll()
{
    if (!m_joiner)
        return;
    size_t len = 0;
    Failure failure;
    const QJsonObject st = Core::take(cbb_joiner_next(m_joiner, m_version, 0, &len), len, QStringLiteral("joiner"), &failure);
    if (!failure.isNull())
        return fail(failure);
    const quint64 version = quint64(st.value(QStringLiteral("version")).toDouble());
    if (version <= m_version)
        return;
    m_version = version;
    const QString state = st.value(QStringLiteral("state")).toString();
    const QJsonObject shown = st.value(QStringLiteral("shown")).toObject();
    m_memberName = shown.value(QStringLiteral("name")).toString();
    m_code = shown.value(QStringLiteral("code")).toString();
    if (state == QStringLiteral("done")) {
        const QString group = st.value(QStringLiteral("group")).toString();
        const QString device = st.value(QStringLiteral("device")).toString();
        free();
        Errors::log(QStringLiteral("joiner: joined %1 as %2").arg(group.left(16), device));
        setState(state);
        emit joined(group, device);
        return;
    }
    if (state == QStringLiteral("failed"))
        return fail(failureOf(st, QStringLiteral("joiner")));
    setState(state);
}

void Joiner::answer(bool yes)
{
    if (m_joiner)
        cbb_joiner_answer(m_joiner, yes ? 1 : 0);
}

void Joiner::stop()
{
    free();
    m_error.clear();
    setState(QStringLiteral("idle"));
}

void Joiner::fail(const Failure &f)
{
    free();
    m_error = Errors::shown(f);
    setState(QStringLiteral("failed"));
}

void Joiner::free()
{
    m_poll.stop();
    if (m_joiner) {
        cbb_joiner_free(m_joiner);
        m_joiner = nullptr;
    }
    m_memberName.clear();
    m_code.clear();
}

void Joiner::setState(const QString &state)
{
    m_state = state;
    emit changed();
}
