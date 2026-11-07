// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

#include "member.h"

#include "core.h"
#include "errors.h"
#include "platform/keystore.h"

#include <cbb_core.h>

#include <QClipboard>
#include <QCoreApplication>
#include <QGuiApplication>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QMetaObject>

#include <atomic>

namespace {

// The member the core's threads call back. The core may call a moment after
// cbb_member_stop, so its callbacks go through this pointer, which the
// member clears first, and never through a pointer of their own.
std::atomic<Member *> current{nullptr};

// The core's event callback, on any of the member's threads: the event goes
// to the GUI thread.
void onEvent(void *, const uint8_t *json, size_t len)
{
    Member *m = current.load();
    if (!m)
        return;
    const QByteArray bytes(reinterpret_cast<const char *>(json), int(len));
    QMetaObject::invokeMethod(m, "event", Qt::QueuedConnection, Q_ARG(QByteArray, bytes));
}

QString b64(const QByteArray &b)
{
    return QString::fromLatin1(b.toBase64());
}

// How often the main page's list of connected members is brought up to date.
const int peerPollMs = 3000;

} // namespace

Member::Member(QObject *parent) : QObject(parent)
{
    m_peerTimer.setInterval(peerPollMs);
    connect(&m_peerTimer, &QTimer::timeout, this, &Member::pollPeers);
}

Member::~Member()
{
    stop();
}

void Member::start(const Membership &membership, const QString &name, const QByteArray &publicKey, const QString &os,
                   const QString &osVersion)
{
    if (m_member || membership.isNull() || publicKey.isEmpty())
        return;
    Failure failure;
    const QByteArray seal = sealSecret(&failure);
    if (seal.isEmpty()) {
        m_error = Errors::shown(failure);
        emit changed();
        return;
    }
    QJsonArray roots;
    for (const QByteArray &r : membership.roots)
        roots.append(b64(r));
    QJsonObject req{
        {QStringLiteral("dir"), Membership::directory()},
        {QStringLiteral("name"), name},
        {QStringLiteral("os"), os},
        {QStringLiteral("os_version"), osVersion},
        {QStringLiteral("key_store"), KeyStore::store()},
        {QStringLiteral("version"), QCoreApplication::applicationVersion()},
        {QStringLiteral("device"), membership.device},
        {QStringLiteral("public"), b64(publicKey)},
        {QStringLiteral("seal"), b64(seal)},
        {QStringLiteral("cert"), b64(membership.cert)},
        {QStringLiteral("group_ca"), b64(membership.groupCa)},
        {QStringLiteral("roots"), roots},
    };
    if (!membership.issuer.isEmpty())
        req.insert(QStringLiteral("issuer"), b64(membership.issuer));
    const QByteArray bytes = QJsonDocument(req).toJson(QJsonDocument::Compact);
    current.store(this);
    uint8_t *answer = nullptr;
    size_t len = 0;
    m_member = cbb_member_start(reinterpret_cast<const uint8_t *>(bytes.constData()), size_t(bytes.size()), Core::signDigest,
                                onEvent, nullptr, &answer, &len);
    Core::take(answer, len, QStringLiteral("member"), &failure);
    if (!m_member) {
        current.store(nullptr);
        m_error = Errors::shown(failure.isNull() ? Failure{QCoreApplication::translate("Errors", "This build of CBB is broken."), QStringLiteral("member: no member")} : failure);
        emit changed();
        return;
    }
    m_error.clear();
    Errors::log(QStringLiteral("member: started in the group %1").arg(membership.groupTag()));
    m_peerTimer.start();
    pollMuted();
    emit changed();
}

void Member::stop()
{
    if (!m_member)
        return;
    current.store(nullptr);
    m_peerTimer.stop();
    cbb_member_stop(m_member);
    m_member = nullptr;
    m_peers.clear();
    m_paused = m_muted = false;
    Errors::log(QStringLiteral("member: stopped"));
    emit changed();
}

void Member::sendClipboard()
{
    if (!m_member)
        return;
    const QString text = QGuiApplication::clipboard()->text();
    // A muted phone's copies stay its own; the main page says so.
    if (text.isEmpty() || text == m_known || m_muted)
        return;
    const QByteArray req = QJsonDocument(QJsonObject{{QStringLiteral("text"), text}}).toJson(QJsonDocument::Compact);
    size_t len = 0;
    Failure failure;
    Core::take(cbb_member_copy(m_member, reinterpret_cast<const uint8_t *>(req.constData()), size_t(req.size()), &len), len,
               QStringLiteral("member"), &failure);
    if (!failure.isNull()) {
        m_error = Errors::shown(failure);
        emit changed();
        return;
    }
    m_known = text;
    m_error.clear();
    setLast(text, false);
}

void Member::event(const QByteArray &json)
{
    const QJsonObject e = QJsonDocument::fromJson(json).object();
    const QString type = e.value(QStringLiteral("type")).toString();
    if (type == QStringLiteral("log")) {
        Errors::log(e.value(QStringLiteral("line")).toString());
    } else if (type == QStringLiteral("write")) {
        write(e.value(QStringLiteral("text")).toString(), e.value(QStringLiteral("kind")).toString() == QStringLiteral("secret"),
              qint64(e.value(QStringLiteral("ttl_ms")).toDouble()));
    } else if (type == QStringLiteral("identity")) {
        QList<QByteArray> roots;
        for (const QJsonValue &r : e.value(QStringLiteral("roots")).toArray())
            roots.append(QByteArray::fromBase64(r.toString().toLatin1()));
        emit identityChanged(QByteArray::fromBase64(e.value(QStringLiteral("cert")).toString().toLatin1()),
                             QByteArray::fromBase64(e.value(QStringLiteral("issuer")).toString().toLatin1()), roots);
    } else if (type == QStringLiteral("mute")) {
        pollMuted();
    }
}

void Member::pause(int minutes)
{
    if (!m_member)
        return;
    const QByteArray req = QJsonDocument(QJsonObject{{QStringLiteral("pause"), true},
                                                     {QStringLiteral("for_ms"), double(qint64(minutes) * 60 * 1000)}})
                               .toJson(QJsonDocument::Compact);
    size_t len = 0;
    Failure failure;
    const QJsonObject a = Core::take(cbb_member_pause(m_member, reinterpret_cast<const uint8_t *>(req.constData()),
                                                      size_t(req.size()), &len),
                                     len, QStringLiteral("member"), &failure);
    if (!failure.isNull()) {
        m_error = Errors::shown(failure);
        emit changed();
        return;
    }
    Errors::log(minutes > 0 ? QStringLiteral("member: takes no copies from the group for %1 min").arg(minutes)
                            : QStringLiteral("member: takes no copies from the group until turned on"));
    readMuted(a);
}

void Member::resume()
{
    if (!m_member)
        return;
    const QByteArray req = QJsonDocument(QJsonObject{{QStringLiteral("pause"), false}}).toJson(QJsonDocument::Compact);
    size_t len = 0;
    Failure failure;
    const QJsonObject a = Core::take(cbb_member_pause(m_member, reinterpret_cast<const uint8_t *>(req.constData()),
                                                      size_t(req.size()), &len),
                                     len, QStringLiteral("member"), &failure);
    if (!failure.isNull()) {
        m_error = Errors::shown(failure);
        emit changed();
        return;
    }
    Errors::log(QStringLiteral("member: takes the group's copies again"));
    readMuted(a);
}

void Member::pollMuted()
{
    if (!m_member)
        return;
    size_t len = 0;
    Failure failure;
    const QJsonObject a = Core::take(cbb_member_muted(m_member, &len), len, QStringLiteral("member"), &failure);
    if (failure.isNull())
        readMuted(a);
}

void Member::readMuted(const QJsonObject &a)
{
    // The core gives what is left, 0 for until it is lifted.
    const auto until = [](const QJsonValue &ms) {
        const qint64 left = qint64(ms.toDouble());
        return left > 0 ? QDateTime::currentDateTime().addMSecs(left) : QDateTime();
    };
    const bool paused = a.value(QStringLiteral("paused")).toBool();
    const bool muted = a.value(QStringLiteral("muted")).toBool();
    const QDateTime pausedUntil = paused ? until(a.value(QStringLiteral("paused_ms"))) : QDateTime();
    const QDateTime mutedUntil = muted ? until(a.value(QStringLiteral("muted_ms"))) : QDateTime();
    // Within a few seconds the same end: the poll's own drift.
    const auto same = [](const QDateTime &x, const QDateTime &y) {
        return x.isValid() == y.isValid() && (!x.isValid() || qAbs(x.secsTo(y)) < 5);
    };
    if (paused == m_paused && muted == m_muted && same(pausedUntil, m_pausedUntil) && same(mutedUntil, m_mutedUntil))
        return;
    m_paused = paused;
    m_muted = muted;
    m_pausedUntil = pausedUntil;
    m_mutedUntil = mutedUntil;
    emit changed();
}

void Member::write(const QString &text, bool secret, qint64 ttlMs)
{
    QClipboard *board = QGuiApplication::clipboard();
    board->setText(text);
    m_known = text;
    setLast(text, secret);
    // A secret leaves the clipboard when its time is up, unless something
    // else replaced it meanwhile.
    if (secret && ttlMs > 0) {
        QTimer::singleShot(int(qMin<qint64>(ttlMs, 24 * 3600 * 1000)), this, [text]() {
            QClipboard *b = QGuiApplication::clipboard();
            if (b->text() == text)
                b->clear();
        });
    }
}

void Member::pollPeers()
{
    if (!m_member)
        return;
    size_t len = 0;
    Failure failure;
    const QJsonObject a = Core::take(cbb_member_peers(m_member, &len), len, QStringLiteral("member"), &failure);
    QStringList names;
    for (const QJsonValue &p : a.value(QStringLiteral("peers")).toArray()) {
        const QJsonObject o = p.toObject();
        const QString name = o.value(QStringLiteral("name")).toString();
        names.append(name.isEmpty() ? o.value(QStringLiteral("device")).toString().left(8) : name);
    }
    if (names != m_peers) {
        m_peers = names;
        emit changed();
    }
    // A pause or a mute that ran out ends on its own.
    pollMuted();
}

void Member::setLast(const QString &text, bool secret)
{
    if (secret) {
        m_last = tr("A secret");
    } else {
        QString t = text.simplified();
        if (t.size() > 60)
            t = t.left(59) + QChar(0x2026);
        m_last = t;
    }
    emit changed();
}
