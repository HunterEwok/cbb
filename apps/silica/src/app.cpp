// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

#include "app.h"

#include "core.h"
#include "errors.h"
#include "platform/keystore.h"

#include <cbb_core.h>

#include <QCoreApplication>
#include <QCryptographicHash>
#include <QGuiApplication>
#include <QHash>
#include <QImage>
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
// A waiting claim is looked at every minute, and first once the member
// had time to reach its peers.
const int claimEveryMs = 60 * 1000;
const int claimFirstMs = 10 * 1000;
// Camera frames are scaled down to this before the core reads their codes.
const int maxSheetFrameSide = 1024;

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
    Core::AdminSign sign;

protected:
    void run() override
    {
        const KeyStore::Key key = KeyStore::ensure(KeyStore::Which::Admin);
        if (key.state != KeyStore::State::Ready) {
            sign.pinNeeded = key.pinNeeded;
            failure = key.failure;
            return;
        }
        request.insert(QStringLiteral("root_public"), QString::fromLatin1(key.publicKey.toBase64()));
        const QByteArray bytes = QJsonDocument(request).toJson(QJsonDocument::Compact);
        size_t len = 0;
        group = Core::take(cbb_group_new(reinterpret_cast<const uint8_t *>(bytes.constData()), size_t(bytes.size()),
                                         Core::signAdminDigest, &sign, &len),
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
    // An action to try when the request's is refused, as a claim tries
    // take_over when the root handed the group to nobody.
    QString fallback;
    QString refused; // why the request's own action was refused, for the log
    QJsonObject answer;
    Failure failure;
    Core::AdminSign sign; // whether the admin key waited for its PIN

protected:
    void run() override
    {
        const KeyStore::Key key = KeyStore::ensure(KeyStore::Which::Admin);
        if (key.state != KeyStore::State::Ready) {
            sign.pinNeeded = key.pinNeeded;
            failure = key.failure;
            return;
        }
        request.insert(QStringLiteral("public"), QString::fromLatin1(key.publicKey.toBase64()));
        QJsonObject a = answer = call();
        if (!failure.isNull() && !fallback.isEmpty()) {
            refused = failure.details;
            failure = Failure();
            request.insert(QStringLiteral("action"), fallback);
            a = answer = call();
        }
        // A command the device refused answers with its reason.
        const QJsonObject result = a.value(QStringLiteral("result")).toObject();
        const QString status = result.value(QStringLiteral("status")).toString();
        if (failure.isNull() && !result.isEmpty() && status != QStringLiteral("done")) {
            failure = Failure{QCoreApplication::translate("Errors", "The device did not take the command."),
                              QStringLiteral("manage: %1: %2").arg(status, result.value(QStringLiteral("reason")).toString())};
        }
    }

private:
    QJsonObject call()
    {
        const QByteArray bytes = QJsonDocument(request).toJson(QJsonDocument::Compact);
        size_t len = 0;
        return Core::take(cbb_member_manage(member, reinterpret_cast<const uint8_t *>(bytes.constData()), size_t(bytes.size()),
                                            Core::signAdminDigest, &sign, &len),
                          len, QStringLiteral("manage"), &failure);
    }
};

// Asks the key store about the admin PIN, or hands it one, off the GUI
// thread: the TEE takes a few hundred milliseconds.
class PinThread : public QThread
{
public:
    enum Job { Status, Enter, Change };
    Job job = Status;
    QByteArray old, pin;
    KeyStore::PinResult result = KeyStore::PinResult::Failed;
    KeyStore::PinStatus status;
    Failure failure;

    ~PinThread() override
    {
        old.fill('\0');
        pin.fill('\0');
    }

protected:
    void run() override
    {
        switch (job) {
        case Status:
            status = KeyStore::adminPin();
            break;
        case Enter:
            result = KeyStore::enterAdminPin(pin, &status, &failure);
            break;
        case Change:
            result = KeyStore::changeAdminPin(old, pin, &status, &failure);
            break;
        }
    }
};

QString pinStateName(KeyStore::PinState state)
{
    switch (state) {
    case KeyStore::PinState::None: return QStringLiteral("none");
    case KeyStore::PinState::NotSet: return QStringLiteral("not_set");
    case KeyStore::PinState::Set: return QStringLiteral("set");
    case KeyStore::PinState::Locked: return QStringLiteral("locked");
    case KeyStore::PinState::Failed: break;
    }
    return QStringLiteral("unknown");
}

// Restores a group from its recovery sheet off the GUI thread: the core
// browses for a member of the group, takes its records on a connection
// that carries records only and checks them, the member key signing this
// phone's side of the handshake in the TEE.
class RestoreThread : public QThread
{
public:
    QJsonObject request;
    QJsonObject answer; // a join's fields
    Failure failure;

protected:
    void run() override
    {
        const QByteArray bytes = QJsonDocument(request).toJson(QJsonDocument::Compact);
        size_t len = 0;
        answer = Core::take(cbb_restore(reinterpret_cast<const uint8_t *>(bytes.constData()), size_t(bytes.size()),
                                        Core::signDigest, nullptr, &len),
                            len, QStringLiteral("restore"), &failure);
    }
};

// What the user reads when restoring failed: the core's refusals it knows
// said in the user's language, the core's own words kept in the details.
Failure restoreFailure(const Failure &f)
{
    const QString d = f.message + QLatin1Char(' ') + f.details;
    QString shown;
    if (d.contains(QStringLiteral("scan the QR code of the recovery sheet")))
        shown = QCoreApplication::translate("Errors", "Scan the QR code of the recovery sheet: on a new phone the typed key is not enough.");
    else if (d.contains(QStringLiteral("not the group's recovery key now")))
        shown = QCoreApplication::translate("Errors", "This is not the group's recovery key now: the root removed it or made a new one.");
    else if (d.contains(QStringLiteral("no device of the group was found")))
        shown = QCoreApplication::translate("Errors", "No device of the group was found on this network. Turn on a phone or a computer of the group and try again.");
    else if (d.contains(QStringLiteral("not a cbb recovery sheet")))
        shown = QCoreApplication::translate("Errors", "This is not a CBB recovery sheet.");
    else
        shown = QCoreApplication::translate("Errors", "The phone could not restore the group.");
    return {shown, QStringLiteral("%1 (%2)").arg(f.details, f.message)};
}

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
        // A claim to take the group over is looked at every minute while
        // the member runs, and once soon after it starts.
        if (m_node.running() && !m_member.claim.isEmpty() && !m_claimTimer.isActive()) {
            m_claimTimer.start();
            QTimer::singleShot(claimFirstMs, this, &App::finishTakeover);
        } else if (!m_node.running()) {
            m_claimTimer.stop();
        }
    });
    m_claimTimer.setInterval(claimEveryMs);
    connect(&m_claimTimer, &QTimer::timeout, this, &App::finishTakeover);
    // The admin token stays logged in only while the app is on the screen,
    // and is logged out once unused for five minutes, which adminPinHeld
    // checks.
    auto *pinCheck = new QTimer(this);
    connect(pinCheck, &QTimer::timeout, this, [] { KeyStore::adminPinHeld(); });
    pinCheck->start(30 * 1000);
    connect(qGuiApp, &QGuiApplication::applicationStateChanged, this, [](Qt::ApplicationState state) {
        if (state != Qt::ApplicationActive)
            KeyStore::dropAdminPin();
    });
    connect(&m_join, &Join::joined, this, [this](const Membership &m) {
        m_member = m;
        emit groupChanged();
        startMember();
        // Joined from afar: sync away from home goes on, and the member
        // offers its tunnel key to the hub through the invitation's guest
        // tunnel until the hub answers.
        if (m_join.byInvite())
            m_node.joinedByInvite(m_join.invite());
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
            refreshAdminPin();
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
    if (askPin([this]() { startJoin(true); },
               [this]() { m_join.fail({QCoreApplication::translate("Errors", "Joining as an admin needs the admin PIN."), QStringLiteral("join: no PIN")}); }))
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
            if (key.pinNeeded && askPin([this]() { startJoin(true); }))
                return;
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
    if (askPin([this, qr, makeAdmin]() { startAdmit(qr, makeAdmin); },
               [this]() { m_admit.fail({QCoreApplication::translate("Errors", "Adding a device needs the admin PIN."), QStringLiteral("admit: no PIN")}); }))
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
            if (key.pinNeeded && askPin([this, qr, makeAdmin]() { startAdmit(qr, makeAdmin); }))
                return;
            m_admit.fail(key.failure);
            return;
        }
        m_admit.admit(qr, m_node.handle(), key.publicKey, m_member.adminCa, makeAdmin && m_member.root);
    });
    thread->start();
}

void App::startInvite(int seconds)
{
    if (!m_member.isAdmin()) {
        m_invite.fail({QCoreApplication::translate("Errors", "Only an admin makes an invitation: an admin phone here, or cbb invite on an admin computer."),
                       QStringLiteral("invite: not an admin")});
        return;
    }
    if (m_busy)
        return;
    m_busy = true;
    emit keyChanged();
    m_invite.setPreparing();
    auto *thread = new KeyThread(KeyStore::Which::Admin);
    connect(thread, &QThread::finished, this, [this, thread, seconds]() {
        const KeyStore::Key key = thread->key;
        thread->deleteLater();
        m_busy = false;
        emit keyChanged();
        if (key.state != KeyStore::State::Ready) {
            m_invite.fail(key.failure);
            return;
        }
        m_invite.open(m_node.handle(), key.publicKey, m_member.adminCa, seconds);
    });
    thread->start();
}

void App::startJoinByInvite(const QString &text)
{
    if (m_publicKey.isEmpty()) {
        show(Errors::shown({QCoreApplication::translate("Errors", "The phone has no key yet."), QStringLiteral("join: no key")}));
        return;
    }
    if (!m_member.isNull()) {
        show(Errors::shown({QCoreApplication::translate("Errors", "This phone is in a group already. Leave it first to join another."),
                            QStringLiteral("join: in a group")}));
        return;
    }
    m_join.startInvite(phoneName(), phoneOs(), m_publicKey, text);
}

void App::resolve(const QStringList &records)
{
    manage(QStringLiteral("resolve"), QString(), records.join(QLatin1Char(',')));
}

void App::manage(const QString &action, const QString &device, const QString &name, int forMinutes)
{
    QJsonObject extra{
        {QStringLiteral("name"), name},
        {QStringLiteral("for_ms"), double(qint64(forMinutes) * 60 * 1000)},
    };
    // A resolve's records come joined in name, as QML hands them.
    if (action == QStringLiteral("resolve"))
        extra.insert(QStringLiteral("records"), QJsonArray::fromStringList(name.split(QLatin1Char(','), QString::SkipEmptyParts)));
    runManage(action, device, extra, nullptr);
}

void App::runManage(const QString &action, const QString &device, const QJsonObject &extra,
                    std::function<void(const QJsonObject &)> done)
{
    if (!m_member.isAdmin() || !m_node.handle()) {
        show(Errors::shown({QCoreApplication::translate("Errors", "Only an admin of the group changes its devices."),
                            QStringLiteral("manage: not an admin or no member")}));
        emit managed(action, device, false);
        return;
    }
    if (m_busy)
        return;
    if (askPin([this, action, device, extra, done]() { runManage(action, device, extra, done); },
               [this, action, device]() { emit managed(action, device, false); }))
        return;
    m_busy = true;
    emit keyChanged();
    auto *thread = new ManageThread;
    thread->member = m_node.handle();
    thread->request = extra;
    thread->request.insert(QStringLiteral("action"), action);
    thread->request.insert(QStringLiteral("device"), device);
    if (!m_member.adminCa.isEmpty() && !m_member.root)
        thread->request.insert(QStringLiteral("admin_ca"), QString::fromLatin1(m_member.adminCa.toBase64()));
    connect(thread, &QThread::finished, this, [this, thread, action, device, extra, done]() {
        const Failure failure = thread->failure;
        const QJsonObject answer = thread->answer;
        const bool pinNeeded = thread->sign.pinNeeded;
        thread->deleteLater();
        m_busy = false;
        emit keyChanged();
        if (!failure.isNull() && pinNeeded
            && askPin([this, action, device, extra, done]() { runManage(action, device, extra, done); },
                      [this, action, device]() { emit managed(action, device, false); }))
            return;
        if (!failure.isNull()) {
            show(Errors::shown(failure));
            emit managed(action, device, false);
            return;
        }
        Errors::log(QStringLiteral("manage: %1 %2").arg(action, device));
        show(QString());
        if (done)
            done(answer);
        m_node.pollDevices();
        emit managed(action, device, true);
    });
    thread->start();
}

void App::setTakeoverDelay(int hours)
{
    if (!m_member.root)
        return;
    runManage(QStringLiteral("takeover_delay"), QString(),
              QJsonObject{{QStringLiteral("delay_ms"), double(qint64(hours) * 3600 * 1000)}}, nullptr);
}

void App::setGroupKeyLevel(const QString &level)
{
    if (!m_member.root)
        return;
    runManage(QStringLiteral("key_level"), QString(), QJsonObject{{QStringLiteral("level"), level}},
              [this](const QJsonObject &a) {
                  m_belowLevel = a.value(QStringLiteral("below")).toVariant().toStringList();
                  emit recoveryChanged();
              });
}

void App::handOver(const QString &device)
{
    if (!m_member.root)
        return;
    runManage(QStringLiteral("hand_over"), device, QJsonObject(), nullptr);
}

void App::makeRecovery()
{
    if (!m_member.root)
        return;
    runManage(QStringLiteral("make_recovery"), QString(), QJsonObject(), [this](const QJsonObject &a) {
        m_recoveryText = a.value(QStringLiteral("text")).toString();
        m_recoveryModules.clear();
        for (const QJsonValue &row : a.value(QStringLiteral("modules")).toArray())
            m_recoveryModules.append(row.toString());
        emit recoveryChanged();
    });
}

void App::forgetRecovery()
{
    // The sheet is shown once; nothing of the key stays in the app.
    m_recoveryText.fill(QLatin1Char('0'));
    m_recoveryText.clear();
    for (QString &row : m_recoveryModules)
        row.fill(QLatin1Char('0'));
    m_recoveryModules.clear();
    emit recoveryChanged();
}

void App::removeRecovery()
{
    if (!m_member.root)
        return;
    runManage(QStringLiteral("remove_recovery"), QString(), QJsonObject(), nullptr);
}

void App::renew()
{
    // Renewals wait for a time the user entered the admin PIN anyway.
    if (m_busy || !m_member.isAdmin() || !m_node.running() || !KeyStore::adminPinHeld())
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

bool App::keep(const Membership &next)
{
    Failure failure;
    if (!next.saveIdentity(&failure)) {
        show(Errors::shown(failure));
        return false;
    }
    m_member = next;
    return true;
}

void App::takeOver(const QString &device)
{
    if (m_busy || !m_member.isAdmin() || m_member.root || !m_member.claim.isEmpty() || !m_node.running())
        return;
    if (askPin([this, device]() { takeOver(device); }))
        return;
    m_busy = true;
    emit keyChanged();
    // The new root is the admin key itself, which stays in the TEE: a root
    // CA for it first, kept before the claim goes out, so that a claim never
    // takes effect for a root this phone lost.
    auto *thread = new ManageThread;
    thread->member = m_node.handle();
    thread->request = QJsonObject{{QStringLiteral("action"), QStringLiteral("root_ca")}};
    connect(thread, &QThread::finished, this, [this, thread, device]() {
        const Failure failure = thread->failure;
        const QByteArray rootCa = QByteArray::fromBase64(thread->answer.value(QStringLiteral("root_ca")).toString().toLatin1());
        thread->deleteLater();
        Membership next = m_member;
        next.claim = rootCa;
        if (!failure.isNull() || rootCa.isEmpty() || !keep(next)) {
            m_busy = false;
            emit keyChanged();
            if (!failure.isNull())
                show(Errors::shown(failure));
            return;
        }
        auto *claim = new ManageThread;
        claim->member = m_node.handle();
        claim->request = QJsonObject{
            {QStringLiteral("action"), QStringLiteral("take_handed_over")},
            {QStringLiteral("device"), device},
            {QStringLiteral("root_ca"), QString::fromLatin1(rootCa.toBase64())},
            {QStringLiteral("admin_ca"), QString::fromLatin1(m_member.adminCa.toBase64())},
        };
        claim->fallback = QStringLiteral("take_over");
        connect(claim, &QThread::finished, this, [this, claim, device]() {
            const Failure failure = claim->failure;
            const QString refused = claim->refused;
            claim->deleteLater();
            m_busy = false;
            emit keyChanged();
            if (!refused.isEmpty())
                Errors::log(QStringLiteral("takeover: no handover (%1)").arg(refused));
            if (!failure.isNull()) {
                Membership next = m_member;
                next.claim.clear();
                keep(next);
                show(Errors::shown(failure));
                emit claimChanged();
                return;
            }
            Errors::log(QStringLiteral("takeover: claimed the group from %1").arg(device));
            m_claimState = QStringLiteral("pending");
            emit claimChanged();
            show(QString());
            m_claimTimer.start();
            finishTakeover();
        });
        claim->start();
    });
    thread->start();
}

void App::finishTakeover()
{
    if (m_member.claim.isEmpty()) {
        m_claimTimer.stop();
        return;
    }
    if (m_busy || !m_node.running())
        return;
    Failure failure;
    const QByteArray secret = sealSecret(&failure);
    const QJsonObject seal = secret.isEmpty() ? QJsonObject()
        : Core::call(QStringLiteral("seal_public"), QJsonObject{{QStringLiteral("secret"), QString::fromLatin1(secret.toBase64())}}, &failure).toObject();
    m_busy = true;
    emit keyChanged();
    auto *thread = new ManageThread;
    thread->member = m_node.handle();
    thread->request = QJsonObject{
        {QStringLiteral("action"), QStringLiteral("finish_takeover")},
        {QStringLiteral("root_ca"), QString::fromLatin1(m_member.claim.toBase64())},
        {QStringLiteral("name"), phoneName()},
        {QStringLiteral("os"), phoneOs()},
        {QStringLiteral("store"), KeyStore::store()},
    };
    if (seal.contains(QStringLiteral("key")))
        thread->request.insert(QStringLiteral("seal"), seal.value(QStringLiteral("key")));
    connect(thread, &QThread::finished, this, [this, thread]() {
        const Failure failure = thread->failure;
        const QJsonObject a = thread->answer;
        const bool pinNeeded = thread->sign.pinNeeded;
        thread->deleteLater();
        m_busy = false;
        emit keyChanged();
        // The claim took effect and the new root signs now: the user's PIN
        // first, asked once; the timer tries again after a cancel.
        if (!failure.isNull() && pinNeeded && !m_pinRun) {
            Errors::log(QStringLiteral("takeover: the claim took effect, the admin PIN is asked"));
            askPin([this]() { finishTakeover(); });
            return;
        }
        if (!failure.isNull()) {
            // Tried again in a minute; the log says why.
            Errors::log(QStringLiteral("takeover: %1 (%2)").arg(failure.message, failure.details));
            return;
        }
        const QString state = a.value(QStringLiteral("state")).toString();
        m_claimLeftMs = qint64(a.value(QStringLiteral("left_ms")).toDouble());
        if (state == QStringLiteral("effective")) {
            Membership next = m_member;
            next.root = true;
            next.adminCa.clear();
            next.claim.clear();
            next.cert = QByteArray::fromBase64(a.value(QStringLiteral("cert")).toString().toLatin1());
            next.issuer.clear();
            if (!keep(next))
                return;
            m_claimTimer.stop();
            Errors::log(QStringLiteral("takeover: this phone is the group's root now"));
            emit groupChanged();
        } else if (state == QStringLiteral("cancelled") || state == QStringLiteral("void")) {
            Membership next = m_member;
            next.claim.clear();
            if (!keep(next))
                return;
            m_claimTimer.stop();
            Errors::log(QStringLiteral("takeover: the claim is %1").arg(state));
            // A phone that restored the group from its sheet is no admin.
            const bool admin = m_member.isAdmin();
            const bool cancelled = state == QStringLiteral("cancelled");
            const QString shown = admin
                ? (cancelled ? QCoreApplication::translate("Errors", "The group's root cancelled the claim; the phone stays an admin.")
                             : QCoreApplication::translate("Errors", "The claim to take the group over became void; the phone stays an admin."))
                : (cancelled ? QCoreApplication::translate("Errors", "The group's root cancelled the claim to restore the group.")
                             : QCoreApplication::translate("Errors", "The claim to restore the group became void."));
            if (!admin)
                setRestoreState(QStringLiteral("failed"));
            show(Errors::shown({shown, QStringLiteral("takeover: the claim is %1").arg(state)}));
        }
        m_claimState = state;
        emit claimChanged();
    });
    thread->start();
}

QString App::scanSheet(const QVariant &frame)
{
    QImage img = frame.value<QImage>();
    if (img.isNull())
        return QString();
    if (img.width() > maxSheetFrameSide || img.height() > maxSheetFrameSide)
        img = img.scaled(maxSheetFrameSide, maxSheetFrameSide, Qt::KeepAspectRatio, Qt::FastTransformation);
    img = img.convertToFormat(QImage::Format_Grayscale8);
    size_t len = 0;
    Failure failure;
    const QJsonObject read = Core::take(cbb_qr_read(img.constBits(), size_t(img.width()), size_t(img.height()), size_t(img.bytesPerLine()), &len),
                                        len, QStringLiteral("qr"), &failure);
    if (!failure.isNull()) {
        Errors::log(QStringLiteral("restore: reading a frame: %1: %2").arg(failure.message, failure.details));
        return QString();
    }
    for (const QJsonValue &t : read.value(QStringLiteral("texts")).toArray()) {
        const QString text = t.toString().trimmed();
        if (text.startsWith(QStringLiteral("cbb://recover?")))
            return text;
        const QString hint = QCoreApplication::translate("Errors", "This is not the QR code of a CBB recovery sheet.");
        if (m_restoreHint != hint) {
            m_restoreHint = hint;
            emit restoreChanged();
        }
    }
    return QString();
}

void App::setRestoreState(const QString &state)
{
    if (m_restoreState == state)
        return;
    m_restoreState = state;
    emit restoreChanged();
}

void App::resetRestore()
{
    if (m_restoreState == QStringLiteral("restoring") || m_restoreState == QStringLiteral("claiming"))
        return;
    m_restoreHint.clear();
    m_restoreState.clear();
    emit restoreChanged();
}

void App::restore(const QString &sheet)
{
    if (m_busy)
        return;
    // A phone that restored the group but did not get its claim out claims
    // again; any other phone in a group has nothing to restore.
    if (!m_member.isNull()) {
        if (!m_member.isAdmin() && m_member.claim.isEmpty() && m_node.running())
            claimWithSheet(sheet);
        return;
    }
    if (m_publicKey.isEmpty()) {
        show(Errors::shown({QCoreApplication::translate("Errors", "The phone has no key yet."), QStringLiteral("restore: no key")}));
        setRestoreState(QStringLiteral("failed"));
        return;
    }
    m_busy = true;
    emit keyChanged();
    m_restoreHint.clear();
    setRestoreState(QStringLiteral("restoring"));
    show(QString());
    auto *thread = new RestoreThread;
    thread->request = QJsonObject{
        {QStringLiteral("sheet"), sheet},
        {QStringLiteral("public"), QString::fromLatin1(m_publicKey.toBase64())},
        {QStringLiteral("name"), phoneName()},
        {QStringLiteral("os"), phoneOs()},
    };
    connect(thread, &QThread::finished, this, [this, thread, sheet]() {
        const QJsonObject answer = thread->answer;
        Failure failure = thread->failure;
        thread->deleteLater();
        m_busy = false;
        emit keyChanged();
        if (!failure.isNull()) {
            show(Errors::shown(restoreFailure(failure)));
            setRestoreState(QStringLiteral("failed"));
            return;
        }
        Membership m = Membership::fromJoined(answer);
        m.root = false;
        if (m.isNull() || !m.save(&failure)) {
            show(Errors::shown(failure.isNull() ? Failure{QCoreApplication::translate("Errors", "The phone could not save the group."), QStringLiteral("restore: no device in the answer")} : failure));
            setRestoreState(QStringLiteral("failed"));
            return;
        }
        Errors::log(QStringLiteral("restore: restored %1 as %2 from %3").arg(m.groupTag(), m.device, answer.value(QStringLiteral("addr")).toString()));
        m_member = m;
        emit groupChanged();
        startMember();
        claimWithSheet(sheet);
    });
    thread->start();
}

void App::claimWithSheet(const QString &sheet)
{
    if (!m_node.running()) {
        show(Errors::shown({QCoreApplication::translate("Errors", "The phone is not connected to its group yet. Try again in a moment."),
                            QStringLiteral("restore: no member")}));
        setRestoreState(QStringLiteral("failed"));
        return;
    }
    m_busy = true;
    emit keyChanged();
    setRestoreState(QStringLiteral("claiming"));
    // The new root is the admin key, which stays in the TEE: its root CA is
    // kept before the claim goes out, as in takeOver.
    auto *thread = new ManageThread;
    thread->member = m_node.handle();
    thread->request = QJsonObject{{QStringLiteral("action"), QStringLiteral("root_ca")}};
    connect(thread, &QThread::finished, this, [this, thread, sheet]() {
        const Failure failure = thread->failure;
        const QByteArray rootCa = QByteArray::fromBase64(thread->answer.value(QStringLiteral("root_ca")).toString().toLatin1());
        thread->deleteLater();
        Membership next = m_member;
        next.claim = rootCa;
        if (!failure.isNull() || rootCa.isEmpty() || !keep(next)) {
            m_busy = false;
            emit keyChanged();
            if (!failure.isNull())
                show(Errors::shown(failure));
            setRestoreState(QStringLiteral("failed"));
            return;
        }
        auto *claim = new ManageThread;
        claim->member = m_node.handle();
        claim->request = QJsonObject{
            {QStringLiteral("action"), QStringLiteral("recover_with_sheet")},
            {QStringLiteral("sheet"), sheet},
            {QStringLiteral("root_ca"), QString::fromLatin1(rootCa.toBase64())},
        };
        connect(claim, &QThread::finished, this, [this, claim]() {
            const Failure failure = claim->failure;
            claim->deleteLater();
            m_busy = false;
            emit keyChanged();
            if (!failure.isNull()) {
                Membership next = m_member;
                next.claim.clear();
                keep(next);
                show(Errors::shown(restoreFailure(failure)));
                setRestoreState(QStringLiteral("failed"));
                emit claimChanged();
                return;
            }
            Errors::log(QStringLiteral("restore: claimed the group with the recovery key"));
            m_claimState = QStringLiteral("pending");
            emit claimChanged();
            show(QString());
            setRestoreState(QStringLiteral("claimed"));
            m_claimTimer.start();
            finishTakeover();
        });
        claim->start();
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
    if (askPin([this]() { makeGroup(); }))
        return;
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
        const bool pinNeeded = thread->sign.pinNeeded;
        thread->deleteLater();
        m_busy = false;
        emit keyChanged();
        if (!failure.isNull() && pinNeeded && askPin([this]() { makeGroup(); }))
            return;
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
    m_paste.forgetLog();
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

bool App::askPin(std::function<void()> run, std::function<void()> cancel)
{
    if (m_adminPin == QStringLiteral("unknown")) {
        // Before the first answer came: asked here, a short call to the TEE.
        const KeyStore::PinStatus status = KeyStore::adminPin();
        if (status.state != KeyStore::PinState::Failed)
            setAdminPin(pinStateName(status.state));
    }
    if (m_adminPin == QStringLiteral("none") || KeyStore::adminPinHeld())
        return false;
    if (m_adminPin == QStringLiteral("locked")) {
        show(Errors::shown({QCoreApplication::translate("Errors", "Seven wrong PINs locked the admin key for good; the phone stays in the group as a member."),
                            QStringLiteral("pin: locked")}));
        if (cancel)
            cancel();
        return true;
    }
    if (m_pinCancel)
        m_pinCancel();
    m_pinRun = std::move(run);
    m_pinCancel = std::move(cancel);
    emit pinNeeded(m_adminPin == QStringLiteral("not_set"));
    return true;
}

void App::setAdminPin(const QString &state)
{
    if (state == m_adminPin)
        return;
    m_adminPin = state;
    Errors::log(QStringLiteral("pin: %1").arg(state));
    emit adminPinChanged();
}

void App::refreshAdminPin()
{
    auto *thread = new PinThread;
    connect(thread, &QThread::finished, this, [this, thread]() {
        const KeyStore::PinStatus status = thread->status;
        thread->deleteLater();
        if (status.state == KeyStore::PinState::Failed)
            Errors::log(QStringLiteral("pin: %1 (%2)").arg(status.failure.message, status.failure.details));
        setAdminPin(pinStateName(status.state));
    });
    thread->start();
}

void App::enterPin(const QString &pin)
{
    auto *thread = new PinThread;
    thread->job = PinThread::Enter;
    thread->pin = pin.toUtf8();
    connect(thread, &QThread::finished, this, [this, thread]() {
        const KeyStore::PinResult result = thread->result;
        const KeyStore::PinStatus status = thread->status;
        const Failure failure = thread->failure;
        thread->deleteLater();
        if (status.state != KeyStore::PinState::Failed)
            setAdminPin(pinStateName(status.state));
        switch (result) {
        case KeyStore::PinResult::Right: {
            emit pinAccepted();
            std::function<void()> run = std::move(m_pinRun);
            m_pinRun = nullptr;
            m_pinCancel = nullptr;
            if (run)
                run();
            // Certificates due for renewal go while the PIN is held.
            QTimer::singleShot(renewFirstMs / 2, this, &App::renew);
            return;
        }
        case KeyStore::PinResult::Wrong:
            Errors::log(QStringLiteral("pin: wrong, %1 tries left").arg(status.triesLeft));
            emit pinRefused(false, status.triesLeft);
            return;
        case KeyStore::PinResult::Locked:
            emit pinRefused(true, 0);
            cancelPin();
            show(Errors::shown({QCoreApplication::translate("Errors", "Seven wrong PINs locked the admin key for good; the phone stays in the group as a member."),
                                QStringLiteral("pin: locked")}));
            return;
        case KeyStore::PinResult::Failed:
            break;
        }
        emit pinRefused(false, -1);
        cancelPin();
        show(Errors::shown(failure));
    });
    thread->start();
}

void App::cancelPin()
{
    std::function<void()> cancel = std::move(m_pinCancel);
    m_pinRun = nullptr;
    m_pinCancel = nullptr;
    if (cancel)
        cancel();
}

void App::changePin(const QString &old, const QString &pin)
{
    auto *thread = new PinThread;
    thread->job = PinThread::Change;
    thread->old = old.toUtf8();
    thread->pin = pin.toUtf8();
    connect(thread, &QThread::finished, this, [this, thread]() {
        const KeyStore::PinResult result = thread->result;
        const KeyStore::PinStatus status = thread->status;
        const Failure failure = thread->failure;
        thread->deleteLater();
        if (status.state != KeyStore::PinState::Failed)
            setAdminPin(pinStateName(status.state));
        if (result == KeyStore::PinResult::Failed)
            show(Errors::shown(failure));
        if (result == KeyStore::PinResult::Right)
            Errors::log(QStringLiteral("pin: changed"));
        emit pinChanged(result == KeyStore::PinResult::Right, result == KeyStore::PinResult::Locked, status.triesLeft);
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

bool App::tipClosed(const QString &name) const
{
    return QSettings().value(QStringLiteral("tips/") + name).toBool();
}

void App::closeTip(const QString &name)
{
    QSettings().setValue(QStringLiteral("tips/") + name, true);
}

QString App::languageName(const QString &code) const
{
    const QString name = QLocale(code).nativeLanguageName();
    return name.isEmpty() ? code : name.left(1).toUpper() + name.mid(1);
}

static const QString arrangementKey = QStringLiteral("ui/arrangement");

bool App::hasArrangement() const
{
    return QSettings().contains(arrangementKey);
}

QJsonObject App::callArrange(const QStringList &ids, bool prune, const QJsonValue &op)
{
    QSettings settings;
    const QJsonDocument stored = QJsonDocument::fromJson(settings.value(arrangementKey).toByteArray());
    QJsonObject args{
        {QStringLiteral("group"), m_member.groupTag()},
        {QStringLiteral("devices"), QJsonArray::fromStringList(ids)},
        {QStringLiteral("prune"), prune},
    };
    if (!m_member.device.isEmpty())
        args.insert(QStringLiteral("self"), m_member.device);
    if (stored.isObject())
        args.insert(QStringLiteral("stored"), stored.object());
    if (!op.isNull())
        args.insert(QStringLiteral("op"), op);
    Failure failure;
    const QJsonObject answer = Core::call(QStringLiteral("arrange"), args, &failure).toObject();
    if (!failure.isNull()) {
        show(Errors::shown(failure));
        return QJsonObject();
    }
    // Until the user changes something nothing is stored (docs/apps.md).
    const QJsonObject next = answer.value(QStringLiteral("stored")).toObject();
    if (next.value(QStringLiteral("items")).toArray().isEmpty())
        settings.remove(arrangementKey);
    else if (!stored.isObject() || stored.object() != next)
        settings.setValue(arrangementKey, QJsonDocument(next).toJson(QJsonDocument::Compact));
    return answer;
}

QVariantList App::arranged(const QVariantList &devices, int)
{
    if (m_member.isNull())
        return QVariantList();
    QStringList ids;
    QHash<QString, QVariant> byId;
    for (const QVariant &d : devices) {
        const QString id = d.toMap().value(QStringLiteral("device")).toString();
        ids << id;
        byId.insert(id, d);
    }
    m_arrangeIds = ids;
    const QJsonObject answer = callArrange(ids, ids.contains(m_member.device), QJsonValue());
    if (answer.isEmpty()) {
        // The group's order, so the devices still show.
        QVariantList flat;
        for (const QVariant &d : devices)
            flat << QVariantMap{{QStringLiteral("kind"), QStringLiteral("device")}, {QStringLiteral("device"), d}};
        return flat;
    }
    // This phone is an item of the core's view, first until the user
    // moves it.
    QVariantList view;
    for (const QJsonValue &item : answer.value(QStringLiteral("view")).toArray()) {
        const QJsonObject o = item.toObject();
        if (o.contains(QStringLiteral("device"))) {
            view << QVariantMap{{QStringLiteral("kind"), QStringLiteral("device")},
                                {QStringLiteral("device"), byId.value(o.value(QStringLiteral("device")).toString())}};
            continue;
        }
        const QJsonObject c = o.value(QStringLiteral("collection")).toObject();
        QVariantList inside;
        for (const QJsonValue &id : c.value(QStringLiteral("devices")).toArray())
            inside << byId.value(id.toString());
        view << QVariantMap{{QStringLiteral("kind"), QStringLiteral("collection")},
                            {QStringLiteral("id"), c.value(QStringLiteral("id")).toString()},
                            {QStringLiteral("name"), c.value(QStringLiteral("name")).toString()},
                            {QStringLiteral("devices"), inside}};
    }
    return view;
}

bool App::arrange(const QVariantMap &op)
{
    if (m_member.isNull())
        return false;
    const bool ok = !callArrange(m_arrangeIds, false, QJsonObject::fromVariantMap(op)).isEmpty();
    ++m_arrangement;
    emit arrangementChanged();
    return ok;
}
