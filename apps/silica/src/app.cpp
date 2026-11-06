// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

#include "app.h"

#include "core.h"
#include "errors.h"
#include "platform/keystore.h"

#include <QCoreApplication>
#include <QCryptographicHash>
#include <QSysInfo>
#include <QThread>

namespace {

// Runs KeyStore::ensure in a thread of its own and hands the key back.
class KeyThread : public QThread
{
public:
    KeyStore::Key key;

protected:
    void run() override { key = KeyStore::ensure(); }
};

} // namespace

App::App(QObject *parent) : QObject(parent), m_os(OsInfo::current())
{
    Failure failure;
    m_core = Core::versionLine(&failure);
    if (!failure.isNull())
        show(Errors::shown(failure));
    Errors::log(QStringLiteral("start: CBB %1, %2, %3").arg(version(), m_core.isEmpty() ? QStringLiteral("no core") : m_core, system()));
    failure = Failure();
    m_member = Membership::load(&failure);
    if (!failure.isNull())
        show(Errors::shown(failure));
    else if (!m_member.isNull())
        Errors::log(QStringLiteral("group: %1 as %2").arg(m_member.groupTag(), m_member.device));
    connect(&m_join, &Join::joined, this, [this](const Membership &m) {
        m_member = m;
        emit groupChanged();
        startMember();
    });
}

QString App::version() const
{
    return QCoreApplication::applicationVersion();
}

QString App::system() const
{
    if (m_os.id.isEmpty())
        return QStringLiteral("unknown");
    return QStringLiteral("%1 %2").arg(m_os.name.isEmpty() ? m_os.id : m_os.name, m_os.version);
}

void App::setUpKey()
{
    if (m_busy)
        return;
    m_busy = true;
    emit keyChanged();
    auto *thread = new KeyThread;
    connect(thread, &QThread::finished, this, [this, thread]() {
        const KeyStore::Key key = thread->key;
        thread->deleteLater();
        m_busy = false;
        if (key.state == KeyStore::State::Ready) {
            m_keyLevel = QStringLiteral("hardware");
            m_publicKey = key.publicKey;
            m_keyFingerprint = QString::fromLatin1(QCryptographicHash::hash(key.publicKey, QCryptographicHash::Sha256).left(8).toHex());
            Errors::log(QStringLiteral("key: %1 hardware key %2").arg(key.created ? QStringLiteral("made") : QStringLiteral("found"), m_keyFingerprint));
            show(QString());
            startMember();
        } else {
            // Without OP-TEE the phone keeps its key in a file, level 3,
            // which comes with the group's features.
            m_keyLevel = QStringLiteral("none");
            m_keyFingerprint.clear();
            show(Errors::shown(key.failure));
        }
        emit keyChanged();
    });
    thread->start();
}

void App::startJoin()
{
    if (m_publicKey.isEmpty()) {
        show(Errors::shown({QStringLiteral("The phone has no key yet."), QStringLiteral("join: no key")}));
        return;
    }
    m_join.start(phoneName(), m_publicKey);
}

void App::leave()
{
    m_node.stop();
    Failure failure;
    if (!Membership::remove(&failure)) {
        show(Errors::shown(failure));
        return;
    }
    Errors::log(QStringLiteral("group: left %1").arg(m_member.groupTag()));
    m_member = Membership();
    show(QString());
    emit groupChanged();
}

void App::startMember()
{
    if (m_member.isNull() || m_publicKey.isEmpty() || m_node.running())
        return;
    m_node.start(m_member, phoneName(), m_publicKey, m_os.isAurora() ? QStringLiteral("aurora") : QStringLiteral("sailfish"),
                 system());
}

QString App::phoneName() const
{
    QString name = QSysInfo::machineHostName();
    if (name.isEmpty() || name.toUtf8().size() > 64)
        name = m_os.isAurora() ? QStringLiteral("Aurora OS phone") : QStringLiteral("Sailfish OS phone");
    return name;
}

void App::show(const QString &error)
{
    if (m_error == error)
        return;
    m_error = error;
    emit errorChanged();
}
