// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

#include "app.h"

#include "core.h"
#include "errors.h"
#include "platform/keystore.h"

#include <cbb_core.h>

#include <QCoreApplication>
#include <QCryptographicHash>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLocale>
#include <QSettings>
#include <QSysInfo>
#include <QThread>

namespace {

// How often an admin looks for member certificates due for renewal, and
// how long after the member starts it looks first.
const int renewEveryMs = 6 * 3600 * 1000;
const int renewFirstMs = 60 * 1000;

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

// Makes a group off the GUI thread: finds the admin key, which stands as
// the group's root key, then has the core make the group, which signs
// with it three times in the TEE.
class GroupThread : public QThread
{
public:
    QJsonObject request; // without root_public, which the key gives
    QJsonObject group;   // the core's answer, with a join's fields
    Failure failure;

protected:
    void run() override
    {
        const KeyStore::Key key = KeyStore::ensure(KeyStore::Which::Admin);
        if (key.state != KeyStore::State::Ready) {
            failure = key.failure;
            return;
        }
        request.insert(QStringLiteral("root_public"), QString::fromLatin1(key.publicKey.toBase64()));
        const QByteArray bytes = QJsonDocument(request).toJson(QJsonDocument::Compact);
        size_t len = 0;
        group = Core::take(cbb_group_new(reinterpret_cast<const uint8_t *>(bytes.constData()), size_t(bytes.size()),
                                         Core::signAdminDigest, nullptr, &len),
                           len, QStringLiteral("group"), &failure);
    }
};

// Signs an admin's change or command off the GUI thread: finds the admin
// key, then has the member sign with it in the TEE; a command waits for the
// device's answer.
class ManageThread : public QThread
{
public:
    cbb_member *member = nullptr;
    QJsonObject request; // without public, which the key gives
    QJsonObject answer;
    Failure failure;

protected:
    void run() override
    {
        const KeyStore::Key key = KeyStore::ensure(KeyStore::Which::Admin);
        if (key.state != KeyStore::State::Ready) {
            failure = key.failure;
            return;
        }
        request.insert(QStringLiteral("public"), QString::fromLatin1(key.publicKey.toBase64()));
        const QByteArray bytes = QJsonDocument(request).toJson(QJsonDocument::Compact);
        size_t len = 0;
        const QJsonObject a = answer =
            Core::take(cbb_member_manage(member, reinterpret_cast<const uint8_t *>(bytes.constData()), size_t(bytes.size()),
                                         Core::signAdminDigest, nullptr, &len),
                       len, QStringLiteral("manage"), &failure);
        // A command the device refused answers with its reason.
        const QJsonObject result = a.value(QStringLiteral("result")).toObject();
        const QString status = result.value(QStringLiteral("status")).toString();
        if (failure.isNull() && !result.isEmpty() && status != QStringLiteral("done")) {
            failure = Failure{QCoreApplication::translate("Errors", "The device did not take the command."),
                              QStringLiteral("manage: %1: %2").arg(status, result.value(QStringLiteral("reason")).toString())};
        }
    }
};

// Runs KeyStore::forget in a thread of its own.
class ForgetThread : public QThread
{
public:
    bool ok = false;
    Failure failure;

protected:
    void run() override { ok = KeyStore::forget(&failure); }
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
    connect(&m_node, &Member::devicesChanged, this, [this]() { m_events.observe(m_node.devices()); });
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
    // Renewals are due months ahead, so a look every few hours, and one
    // a minute after the member starts, once it reached its peers, is plenty.
    m_renewTimer.setInterval(renewEveryMs);
    connect(&m_renewTimer, &QTimer::timeout, this, &App::renew);
    connect(&m_node, &Member::changed, this, [this]() {
        if (m_node.running() && !m_renewTimer.isActive()) {
            m_renewTimer.start();
            QTimer::singleShot(renewFirstMs, this, &App::renew);
        } else if (!m_node.running()) {
            m_renewTimer.stop();
        }
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

void App::startAdmit(const QString &qr, bool makeAdmin)
{
    if (!m_member.isAdmin()) {
        m_admit.fail({QCoreApplication::translate("Errors", "Only an admin of the group adds devices."), QStringLiteral("admit: not an admin")});
        return;
    }
    if (m_busy)
        return;
    m_busy = true;
    emit keyChanged();
    m_admit.setPreparing();
    auto *thread = new KeyThread(KeyStore::Which::Admin);
    connect(thread, &QThread::finished, this, [this, thread, qr, makeAdmin]() {
        const KeyStore::Key key = thread->key;
        thread->deleteLater();
        m_busy = false;
        emit keyChanged();
        if (key.state != KeyStore::State::Ready) {
            m_admit.fail(key.failure);
            return;
        }
        m_admit.admit(qr, m_node.handle(), key.publicKey, m_member.adminCa, makeAdmin && m_member.root);
    });
    thread->start();
}

void App::resolve(const QStringList &records)
{
    manage(QStringLiteral("resolve"), QString(), records.join(QLatin1Char(',')));
}

void App::manage(const QString &action, const QString &device, const QString &name, int forMinutes)
{
    if (!m_member.isAdmin() || !m_node.handle()) {
        show(Errors::shown({QCoreApplication::translate("Errors", "Only an admin of the group changes its devices."),
                            QStringLiteral("manage: not an admin or no member")}));
        emit managed(action, device, false);
        return;
    }
    if (m_busy)
        return;
    m_busy = true;
    emit keyChanged();
    auto *thread = new ManageThread;
    thread->member = m_node.handle();
    thread->request = QJsonObject{
        {QStringLiteral("action"), action},
        {QStringLiteral("device"), device},
        {QStringLiteral("name"), name},
        {QStringLiteral("for_ms"), double(qint64(forMinutes) * 60 * 1000)},
    };
    // A resolve's records come joined in name, as QML hands them.
    if (action == QStringLiteral("resolve"))
        thread->request.insert(QStringLiteral("records"), QJsonArray::fromStringList(name.split(QLatin1Char(','), QString::SkipEmptyParts)));
    if (!m_member.adminCa.isEmpty() && !m_member.root)
        thread->request.insert(QStringLiteral("admin_ca"), QString::fromLatin1(m_member.adminCa.toBase64()));
    connect(thread, &QThread::finished, this, [this, thread, action, device]() {
        const Failure failure = thread->failure;
        thread->deleteLater();
        m_busy = false;
        emit keyChanged();
        if (!failure.isNull()) {
            show(Errors::shown(failure));
            emit managed(action, device, false);
            return;
        }
        Errors::log(QStringLiteral("manage: %1 %2").arg(action, device));
        show(QString());
        m_node.pollDevices();
        emit managed(action, device, true);
    });
    thread->start();
}

void App::renew()
{
    if (m_busy || !m_member.isAdmin() || !m_node.running())
        return;
    m_busy = true;
    emit keyChanged();
    auto *thread = new ManageThread;
    thread->member = m_node.handle();
    thread->request = QJsonObject{{QStringLiteral("action"), QStringLiteral("renew")}};
    if (!m_member.adminCa.isEmpty() && !m_member.root)
        thread->request.insert(QStringLiteral("admin_ca"), QString::fromLatin1(m_member.adminCa.toBase64()));
    connect(thread, &QThread::finished, this, [this, thread]() {
        const Failure failure = thread->failure;
        const int renewed = thread->answer.value(QStringLiteral("renewed")).toInt();
        thread->deleteLater();
        m_busy = false;
        emit keyChanged();
        if (!failure.isNull())
            Errors::log(QStringLiteral("renew: %1 (%2)").arg(failure.message, failure.details));
        else if (renewed > 0)
            Errors::log(QStringLiteral("renew: renewed %1 member certificates").arg(renewed));
    });
    thread->start();
}

void App::makeGroup()
{
    if (m_busy || !m_member.isNull())
        return;
    if (m_publicKey.isEmpty()) {
        show(Errors::shown({QCoreApplication::translate("Errors", "The phone has no key yet."), QStringLiteral("group: no key")}));
        return;
    }
    Failure failure;
    const QByteArray secret = sealSecret(&failure);
    const QJsonObject seal = secret.isEmpty() ? QJsonObject()
        : Core::call(QStringLiteral("seal_public"), QJsonObject{{QStringLiteral("secret"), QString::fromLatin1(secret.toBase64())}}, &failure).toObject();
    if (!failure.isNull()) {
        show(Errors::shown(failure));
        return;
    }
    m_busy = true;
    emit keyChanged();
    auto *thread = new GroupThread;
    thread->request = QJsonObject{
        {QStringLiteral("name"), phoneName()},
        {QStringLiteral("os"), phoneOs()},
        {QStringLiteral("store"), KeyStore::store()},
        {QStringLiteral("public"), QString::fromLatin1(m_publicKey.toBase64())},
        {QStringLiteral("seal"), seal.value(QStringLiteral("key"))},
    };
    connect(thread, &QThread::finished, this, [this, thread]() {
        const QJsonObject group = thread->group;
        Failure failure = thread->failure;
        thread->deleteLater();
        m_busy = false;
        emit keyChanged();
        if (!failure.isNull()) {
            show(Errors::shown(failure));
            return;
        }
        Membership m = Membership::fromJoined(group);
        m.root = true;
        if (m.isNull() || !m.save(&failure)) {
            show(Errors::shown(failure.isNull() ? Failure{QCoreApplication::translate("Errors", "The phone could not save the group."), QStringLiteral("group: no device in the answer")} : failure));
            return;
        }
        Errors::log(QStringLiteral("group: made %1 as its root").arg(m.groupTag()));
        m_member = m;
        show(QString());
        emit groupChanged();
        startMember();
    });
    thread->start();
}

void App::leave()
{
    if (m_busy)
        return;
    m_node.stop();
    Failure failure;
    if (!Membership::remove(&failure)) {
        show(Errors::shown(failure));
        return;
    }
    Errors::log(QStringLiteral("group: left %1").arg(m_member.groupTag()));
    m_member = Membership();
    m_events.forget();
    show(QString());
    emit groupChanged();

    // The keys go too (D-83): a phone that joined again with its old member
    // key would share it with its old device record, and removing that
    // record revokes the key, so the new one would go with it. The next key
    // is made right after, for the next join.
    m_publicKey.clear();
    m_keyFingerprint.clear();
    m_busy = true;
    emit keyChanged();
    auto *thread = new ForgetThread;
    connect(thread, &QThread::finished, this, [this, thread]() {
        const Failure failure = thread->failure;
        const bool ok = thread->ok;
        thread->deleteLater();
        m_busy = false;
        if (!ok) {
            emit keyChanged();
            show(Errors::shown(failure));
            return;
        }
        Errors::log(QStringLiteral("key: deleted the member and admin keys"));
        setUpKey();
    });
    thread->start();
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
