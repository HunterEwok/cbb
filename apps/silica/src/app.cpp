// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

#include "app.h"

#include "core.h"
#include "errors.h"
#include "platform/keystore.h"

#include <QCoreApplication>
#include <QCryptographicHash>
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
            m_keyFingerprint = QString::fromLatin1(QCryptographicHash::hash(key.publicKey, QCryptographicHash::Sha256).left(8).toHex());
            Errors::log(QStringLiteral("key: %1 hardware key %2").arg(key.created ? QStringLiteral("made") : QStringLiteral("found"), m_keyFingerprint));
            show(QString());
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

void App::show(const QString &error)
{
    if (m_error == error)
        return;
    m_error = error;
    emit errorChanged();
}
