// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

#include "app.h"

#include "core.h"
#include "errors.h"
#include "platform/keystore.h"

#include <QCoreApplication>
#include <QCryptographicHash>
#include <QLocale>
#include <QSettings>
#include <QSysInfo>
#include <QThread>

namespace {

// Runs KeyStore::ensure in a thread of its own and hands the key back.
class KeyThread : public QThread
{
public:
    explicit KeyThread(KeyStore::Which which = KeyStore::Which::Member) : m_which(which) {}
    KeyStore::Key key;

protected:
    void run() override { key = KeyStore::ensure(m_which); }

private:
    KeyStore::Which m_which;
};

} // namespace

App::App(QObject *parent) : QObject(parent), m_os(OsInfo::current()), m_startLanguage(language())
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
    connect(&m_node, &Member::identityChanged, this,
            [this](const QByteArray &cert, const QByteArray &issuer, const QList<QByteArray> &roots) {
                if (m_member.isNull())
                    return;
                Membership next = m_member;
                next.cert = cert;
                next.issuer = issuer;
                next.roots = roots;
                Failure f;
                if (!next.saveIdentity(&f)) {
                    // The member runs on with it; the next start loads the
                    // old one, which an admin renews again.
                    show(Errors::shown(f));
                    return;
                }
                m_member = next;
                Errors::log(QStringLiteral("group: kept a new member certificate or root"));
            });
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
            m_keyLevel = KeyStore::store();
            m_publicKey = key.publicKey;
            m_keyFingerprint = QString::fromLatin1(QCryptographicHash::hash(key.publicKey, QCryptographicHash::Sha256).left(8).toHex());
            Errors::log(QStringLiteral("key: %1 %2 key %3").arg(key.created ? QStringLiteral("made") : QStringLiteral("found"), m_keyLevel, m_keyFingerprint));
            show(QString());
            startMember();
        } else {
            // Aurora 5 without OP-TEE (the emulator) has no key: its file
            // key at level 3 needs the user's consent, which comes later.
            m_keyLevel = QStringLiteral("none");
            m_keyFingerprint.clear();
            show(Errors::shown(key.failure));
        }
        emit keyChanged();
    });
    thread->start();
}

void App::startJoin(bool admin)
{
    if (m_publicKey.isEmpty()) {
        show(Errors::shown({QCoreApplication::translate("Errors", "The phone has no key yet."), QStringLiteral("join: no key")}));
        return;
    }
    if (!admin) {
        m_join.start(phoneName(), phoneOs(), m_publicKey);
        return;
    }
    if (m_busy)
        return;
    m_busy = true;
    emit keyChanged();
    auto *thread = new KeyThread(KeyStore::Which::Admin);
    connect(thread, &QThread::finished, this, [this, thread]() {
        const KeyStore::Key key = thread->key;
        thread->deleteLater();
        m_busy = false;
        emit keyChanged();
        if (key.state != KeyStore::State::Ready) {
            m_join.fail(key.failure);
            return;
        }
        Errors::log(QStringLiteral("key: %1 the admin key").arg(key.created ? QStringLiteral("made") : QStringLiteral("found")));
        m_join.start(phoneName(), phoneOs(), m_publicKey, key.publicKey);
    });
    thread->start();
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
    m_node.start(m_member, phoneName(), m_publicKey, phoneOs(), system());
}

QString App::phoneOs() const
{
    return m_os.isAurora() ? QStringLiteral("aurora") : QStringLiteral("sailfish");
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

bool App::errorDetails() const
{
    return Errors::showDetails();
}

void App::setErrorDetails(bool on)
{
    if (on == errorDetails())
        return;
    QSettings().setValue(QStringLiteral("errors/details"), on);
    Errors::log(QStringLiteral("settings: error details %1").arg(on ? QStringLiteral("on") : QStringLiteral("off")));
    emit settingsChanged();
}

QString App::language() const
{
    return QSettings().value(QStringLiteral("ui/language")).toString();
}

void App::setLanguage(const QString &code)
{
    if (code == language())
        return;
    QSettings settings;
    if (code.isEmpty())
        settings.remove(QStringLiteral("ui/language"));
    else
        settings.setValue(QStringLiteral("ui/language"), code);
    emit settingsChanged();
}

bool App::deviceList() const
{
    return QSettings().value(QStringLiteral("ui/devices")).toString() == QStringLiteral("list");
}

void App::setDeviceList(bool on)
{
    if (on == deviceList())
        return;
    QSettings().setValue(QStringLiteral("ui/devices"), on ? QStringLiteral("list") : QStringLiteral("tiles"));
    emit settingsChanged();
}

QString App::languageName(const QString &code) const
{
    const QString name = QLocale(code).nativeLanguageName();
    return name.isEmpty() ? code : name.left(1).toUpper() + name.mid(1);
}
