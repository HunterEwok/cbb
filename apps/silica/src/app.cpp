// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

#include "app.h"

#include "core.h"
#include "errors.h"
#include "pinrule.h"
#include "platform/keystore.h"

#include <cbb_core.h>

#include <QClipboard>
#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QGuiApplication>
#include <QHash>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLocale>
#include <QPageSize>
#include <QPainter>
#include <QPdfWriter>
#include <QRegularExpression>
#include <QSettings>
#include <QStandardPaths>
#include <QSysInfo>
#include <QThread>
#include <QUrl>

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
    QJsonObject answer;
    Failure failure;
    Core::AdminSign sign; // whether the admin key waited for its PIN
    bool keyless = false; // a step that signs nothing, as change_preview

protected:
    void run() override
    {
        if (keyless) {
            request.insert(QStringLiteral("public"), QString());
            answer = call();
            return;
        }
        const KeyStore::Key key = KeyStore::ensure(KeyStore::Which::Admin);
        if (key.state != KeyStore::State::Ready) {
            sign.pinNeeded = key.pinNeeded;
            failure = key.failure;
            return;
        }
        request.insert(QStringLiteral("public"), QString::fromLatin1(key.publicKey.toBase64()));
        const QJsonObject a = answer = call();
        // A command the device refused answers with its reason.
        const QJsonObject result = a.value(QStringLiteral("result")).toObject();
        const QString status = result.value(QStringLiteral("status")).toString();
        const QString reason = result.value(QStringLiteral("reason")).toString();
        if (failure.isNull() && !result.isEmpty() && status != QStringLiteral("done")) {
            failure = Failure{QCoreApplication::translate("Errors", "The device did not take the command."),
                              QStringLiteral("manage: %1: %2").arg(status, reason)};
            // Why a paste did not go in is the device's own word, such as
            // remote paste being off there, which the user needs to see.
            if (request.value(QStringLiteral("action")).toString() == QStringLiteral("paste")) {
                failure.message = QCoreApplication::translate("Errors", "The device did not paste.");
                if (!reason.isEmpty())
                    failure.message += QLatin1Char(' ') + reason;
            }
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

// Runs a step of the recovery key on a YubiKey off the GUI thread: the
// core is the client of the system's pcscd (cbb_piv's transport pcsc), which
// takes a YubiKey plugged into the USB-C port itself, and waits through the
// card's touch.
class PivThread : public QThread
{
public:
    QJsonObject request; // without transport
    QJsonObject answer;
    Failure failure;

protected:
    void run() override
    {
        request.insert(QStringLiteral("transport"), QStringLiteral("pcsc"));
        const QByteArray bytes = QJsonDocument(request).toJson(QJsonDocument::Compact);
        size_t len = 0;
        answer = Core::take(cbb_piv(reinterpret_cast<const uint8_t *>(bytes.constData()), size_t(bytes.size()), noCard, nullptr, &len),
                            len, QStringLiteral("yubikey"), &failure);
        if (!failure.isNull()) {
            // The core's own words go to the details (shown in debug, logged
            // always), so that a refusal names its step and status word.
            const QString core = failure.details.isEmpty() ? failure.message : failure.message + QStringLiteral(": ") + failure.details;
            failure.message = shownFor(failure.message, failure.details);
            failure.details = core;
        }
    }

private:
    // With pcsc the core never calls the app's card; the ABI still wants one.
    static int32_t noCard(void *, const uint8_t *, size_t, uint8_t *, size_t, size_t *) { return 1; }

    // The core's refusal in the user's words (member/src/piv.rs and
    // piv/recovery.rs); its own words stay in the details.
    static QString shownFor(const QString &m, const QString &details)
    {
        const QString d = m + QLatin1Char(' ') + details;
        if (d.contains(QStringLiteral("PIN is blocked")))
            return QCoreApplication::translate("Errors", "The YubiKey's PIN is blocked. Unblock it with its PUK in Yubico Authenticator, then try again.");
        if (d.contains(QStringLiteral("wrong PIN")) || d.contains(QStringLiteral("PIN has 6 to 8")))
            return QCoreApplication::translate("Errors", "Wrong PIN. After three wrong tries the YubiKey blocks its PIN.");
        if (d.contains(QStringLiteral("firmware 5.3")))
            return QCoreApplication::translate("Errors", "This YubiKey is older than firmware 5.3, which the recovery key needs. Use the printed sheet instead.");
        if (d.contains(QStringLiteral("holds no recovery key")))
            return QCoreApplication::translate("Errors", "This YubiKey holds no recovery key.");
        if (d.contains(QStringLiteral("already holds this group's recovery key")))
            return QCoreApplication::translate("Errors", "This YubiKey holds this group's recovery key already.");
        if (d.contains(QStringLiteral("retired PIV slot")))
            return QCoreApplication::translate("Errors", "Every place for keys on this YubiKey is in use. Use another YubiKey or the sheet.");
        if (d.contains(QStringLiteral("two recovery keys for this group")) || d.contains(QStringLiteral("more than one group")))
            return QCoreApplication::translate("Errors", "This YubiKey holds two recovery keys for this group. Use the sheet instead.");
        if (d.contains(QStringLiteral("management key")))
            return QCoreApplication::translate("Errors", "The app cannot use this YubiKey's management key. Use the printed sheet instead.");
        if (d.contains(QStringLiteral("two YubiKeys")))
            return QCoreApplication::translate("Errors", "Two YubiKeys are plugged in. Leave only one and try again.");
        if (d.contains(QStringLiteral("no YubiKey found")))
            return QCoreApplication::translate("Errors", "No YubiKey is plugged in. Plug it into the USB-C port and try again.");
        return QCoreApplication::translate("Errors", "The YubiKey did not answer as expected. Plug it in again and try again.");
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
    else if (m_member.before06)
        Errors::log(QStringLiteral("group: made before 0.6, which this version no longer runs"));
    else if (!m_member.isNull())
        Errors::log(QStringLiteral("group: %1 as %2").arg(m_member.groupTag(), m_member.device));
    connect(&m_node, &Member::devicesChanged, this, [this]() { m_events.observe(m_node.devices()); });
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
    // A member that broke stops and starts again; the user sees what
    // broke, the details only in debug mode (Errors::showDetails).
    // Reports that waited for the network go now.
    QTimer::singleShot(0, this, [this]() { m_bugs.resend(); });
    connect(&m_node, &Member::panicked, this, [this](const QString &details) {
        show(Errors::shown({QCoreApplication::translate("Errors", "Something in CBB broke. It starts again."), details}));
        // In release mode the app asks to send a report (Bugs); in debug
        // mode the error shows whole and nothing is asked.
        if (!Errors::showDetails()) {
            QJsonArray names, log;
            for (const QVariant &d : m_node.devices())
                names.append(d.toMap().value(QStringLiteral("name")).toString());
            for (const QString &l : m_node.recentLog())
                log.append(l);
            m_bugs.offer(QJsonObject{{QStringLiteral("kind"), QStringLiteral("panic")},
                                     {QStringLiteral("code"), 5},
                                     {QStringLiteral("name"), QStringLiteral("panic")},
                                     {QStringLiteral("message"), QStringLiteral("Something in CBB broke, and it started again.")},
                                     {QStringLiteral("details"), details},
                                     {QStringLiteral("app"), QStringLiteral("aurora")},
                                     {QStringLiteral("version"), version()},
                                     {QStringLiteral("os"), phoneOs()},
                                     {QStringLiteral("os_version"), m_os.version},
                                     {QStringLiteral("model"), QSysInfo::prettyProductName()},
                                     {QStringLiteral("arch"), QSysInfo::currentCpuArchitecture()},
                                     {QStringLiteral("log"), log},
                                     {QStringLiteral("names"), names}});
        }
        QTimer::singleShot(0, this, [this]() {
            m_node.stop();
            startMember();
        });
    });
    // A phone that joined a group of 0.6: the set is in the app's folder.
    connect(&m_joiner, &Joiner::joined, this, [this](const QString &group, const QString &device) {
        Membership m;
        m.device = device;
        m.group = group;
        if (!keep(m))
            return;
        emit groupChanged();
        startMember();
    });
    // The group's records say who is an admin; the member's devices list
    // them.
    connect(&m_node, &Member::devicesChanged, this, [this]() {
        for (const QVariant &v : m_node.devices()) {
            const QVariantMap d = v.toMap();
            if (!d.value(QStringLiteral("self")).toBool())
                continue;
            const bool admin = d.value(QStringLiteral("admin")).toBool();
            if (admin != m_member.admin) {
                Membership next = m_member;
                next.admin = admin;
                if (keep(next)) {
                    Errors::log(QStringLiteral("admin: the records %1 this phone an admin").arg(admin ? QStringLiteral("make") : QStringLiteral("no longer make")));
                    emit groupChanged();
                }
            }
            return;
        }
    });
    // Joined from afar: the member reaches the hub through the invitation's
    // guest tunnel, kept with the set, until the hub's offer comes.
    connect(&m_join, &Join::joined, this, [this](const QString &group, const QString &device) {
        Membership m;
        m.device = device;
        m.group = group;
        if (!keep(m))
            return;
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

void App::stopJoin()
{
    m_join.stop();
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
        m_invite.open(m_node.handle(), key.publicKey, seconds);
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
    m_join.startInvite(text, Membership::directory(), phoneName(), phoneOs(), m_publicKey);
}

void App::manage(const QString &action, const QString &device, const QString &name, int forMinutes)
{
    QJsonObject extra{
        {QStringLiteral("name"), name},
        {QStringLiteral("for_ms"), double(qint64(forMinutes) * 60 * 1000)},
    };
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

void App::changePreview(const QVariantMap &recovery, const QStringList &leaveOut)
{
    if (m_member.root || !m_node.handle() || m_busy)
        return;
    m_busy = true;
    emit keyChanged();
    auto *thread = new ManageThread;
    thread->member = m_node.handle();
    thread->keyless = true;
    thread->request = QJsonObject{
        {QStringLiteral("action"), QStringLiteral("change_preview")},
        {QStringLiteral("device"), QString()},
        {QStringLiteral("recovery"), QJsonObject::fromVariantMap(recovery)},
        {QStringLiteral("leave_out"), QJsonArray::fromStringList(leaveOut)},
    };
    connect(thread, &QThread::finished, this, [this, thread]() {
        const Failure failure = thread->failure;
        const QJsonObject answer = thread->answer;
        thread->deleteLater();
        m_busy = false;
        emit keyChanged();
        if (!failure.isNull()) {
            show(Errors::shown(failure));
            emit changePreviewed(false, QVariantList(), false);
            return;
        }
        show(QString());
        emit changePreviewed(true, answer.value(QStringLiteral("rows")).toArray().toVariantList(),
                             answer.value(QStringLiteral("waiting")).toBool());
    });
    thread->start();
}

void App::changeRoot(const QVariantMap &recovery, const QStringList &leaveOut, bool overWaiting)
{
    if (m_member.root || !m_node.handle() || m_busy)
        return;
    // The admin key in the TEE, behind its PIN, becomes the root key.
    if (askPin([this, recovery, leaveOut, overWaiting]() { changeRoot(recovery, leaveOut, overWaiting); },
               [this]() { emit rootChangedHere(false); }))
        return;
    m_busy = true;
    emit keyChanged();
    auto *thread = new ManageThread;
    thread->member = m_node.handle();
    thread->request = QJsonObject{
        {QStringLiteral("action"), QStringLiteral("change_root")},
        {QStringLiteral("device"), QString()},
        {QStringLiteral("recovery"), QJsonObject::fromVariantMap(recovery)},
        {QStringLiteral("leave_out"), QJsonArray::fromStringList(leaveOut)},
        {QStringLiteral("over_waiting"), overWaiting},
    };
    connect(thread, &QThread::finished, this, [this, thread, recovery, leaveOut, overWaiting]() {
        const Failure failure = thread->failure;
        const bool pinNeeded = thread->sign.pinNeeded;
        thread->deleteLater();
        m_busy = false;
        emit keyChanged();
        if (!failure.isNull() && pinNeeded
            && askPin([this, recovery, leaveOut, overWaiting]() { changeRoot(recovery, leaveOut, overWaiting); },
                      [this]() { emit rootChangedHere(false); }))
            return;
        if (!failure.isNull()) {
            show(Errors::shown(failure));
            emit rootChangedHere(false);
            return;
        }
        Membership next = m_member;
        next.root = true;
        if (!keep(next)) {
            emit rootChangedHere(false);
            return;
        }
        Errors::log(QStringLiteral("change root: this phone is the group's root now, by the recovery key"));
        show(QString());
        m_node.pollDevices();
        emit groupChanged();
        emit rootChangedHere(true);
    });
    thread->start();
}

void App::paste(const QString &device, const QString &text, bool typing, bool enter, bool secret)
{
    // An empty field sends what the phone's clipboard holds.
    const QString out = text.isEmpty() ? QGuiApplication::clipboard()->text() : text;
    if (out.isEmpty()) {
        show(Errors::shown({tr("The clipboard holds no text."), QStringLiteral("paste: the clipboard is empty")}));
        emit managed(QStringLiteral("paste"), device, false);
        return;
    }
    // The device waits 5 s for its target, and 5 ms more for each typed byte.
    const qint64 wait = 10000 + (typing ? qint64(out.toUtf8().size()) * 5 : 0);
    runManage(QStringLiteral("paste"), device,
              QJsonObject{
                  {QStringLiteral("text"), out},
                  {QStringLiteral("mode"), typing ? QStringLiteral("type") : QStringLiteral("paste")},
                  {QStringLiteral("kind"), secret ? QStringLiteral("secret") : QStringLiteral("text")},
                  {QStringLiteral("enter"), enter},
                  {QStringLiteral("timeout_ms"), double(wait)},
              },
              nullptr);
}

void App::pasteFiles(const QString &device, const QStringList &files, bool enter)
{
    if (m_busy || files.isEmpty())
        return;
    QStringList paths;
    for (const QString &f : files) {
        const QUrl url(f);
        paths.append(url.isLocalFile() ? url.toLocalFile() : f);
    }
    Failure failure;
    const QString copy = m_node.copyFiles(paths, &failure);
    if (copy.isEmpty()) {
        if (failure.isNull())
            failure = Failure{tr("There is nothing to send: no file could be read."), QStringLiteral("paste: no copy")};
        show(Errors::shown(failure));
        emit managed(QStringLiteral("paste"), device, false);
        return;
    }
    // The device waits up to 20 s for the copy, then 8 s for its desktop.
    runManage(QStringLiteral("paste"), device,
              QJsonObject{
                  {QStringLiteral("text"), copy},
                  {QStringLiteral("mode"), QStringLiteral("paste")},
                  {QStringLiteral("kind"), QStringLiteral("media")},
                  {QStringLiteral("enter"), enter},
                  {QStringLiteral("timeout_ms"), 35000.0},
              },
              nullptr);
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

void App::setGroupTtl(double ttlMs, double secretTtlMs)
{
    QJsonObject extra;
    if (ttlMs > 0)
        extra.insert(QStringLiteral("ttl_ms"), ttlMs);
    if (secretTtlMs > 0)
        extra.insert(QStringLiteral("secret_ttl_ms"), secretTtlMs);
    runManage(QStringLiteral("ttl"), QString(), extra, [](const QJsonObject &) {});
}

void App::openCard(const QString &pin)
{
    if (m_busy)
        return;
    m_busy = true;
    emit keyChanged();
    auto *thread = new PivThread;
    // The group's slot on the card is named by its tag (docs/protocol.md,
    // "The recovery key on a YubiKey (0.6)").
    thread->request = QJsonObject{{QStringLiteral("op"), QStringLiteral("open")},
                                  {QStringLiteral("pin"), pin},
                                  {QStringLiteral("group"), m_member.group}};
    connect(thread, &QThread::finished, this, [this, thread]() {
        const Failure failure = thread->failure;
        const QString secret = thread->answer.value(QStringLiteral("secret")).toString();
        thread->deleteLater();
        m_busy = false;
        emit keyChanged();
        if (!failure.isNull() || secret.isEmpty()) {
            show(Errors::shown(failure.isNull() ? Failure{QCoreApplication::translate("Errors", "The YubiKey did not answer as expected. Plug it in again and try again."), QStringLiteral("yubikey: open answered no secret")} : failure));
            emit cardOpened(false, QString());
            return;
        }
        // The secret goes to the core for one change of root, and the page drops it.
        show(QString());
        emit cardOpened(true, secret);
    });
    thread->start();
}

void App::sealCard(const QString &pin)
{
    if (!m_member.root || m_recoveryText.isEmpty() || m_busy)
        return;
    m_busy = true;
    emit keyChanged();
    auto *thread = new PivThread;
    thread->request = QJsonObject{
        {QStringLiteral("op"), QStringLiteral("seal")},
        {QStringLiteral("pin"), pin},
        {QStringLiteral("recovery"), QJsonObject{{QStringLiteral("text"), m_recoveryText}}},
        {QStringLiteral("group"), m_member.group},
    };
    connect(thread, &QThread::finished, this, [this, thread]() {
        const Failure failure = thread->failure;
        const int slot = thread->answer.value(QStringLiteral("slot")).toInt();
        const bool defaultKey = thread->answer.value(QStringLiteral("default_key")).toBool();
        thread->deleteLater();
        m_busy = false;
        emit keyChanged();
        if (!failure.isNull()) {
            show(Errors::shown(failure));
            emit cardSealed(false);
            return;
        }
        Errors::log(QStringLiteral("yubikey: sealed in slot %1, factory management key %2").arg(slot, 0, 16).arg(defaultKey));
        show(QString());
        emit cardSealed(true);
    });
    thread->start();
}

QString App::saveSheet()
{
    if (m_recoveryText.isEmpty() || m_recoveryModules.isEmpty())
        return QString();
    const QString dir = QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation);
    const QString name = QCoreApplication::translate("RecoveryPage", "CBB recovery key");
    QString path = dir + QLatin1Char('/') + name + QStringLiteral(".pdf");
    for (int n = 2; QFile::exists(path); ++n)
        path = dir + QLatin1Char('/') + name + QStringLiteral(" (%1).pdf").arg(n);
    QPdfWriter pdf(path);
    pdf.setPageSize(QPageSize(QPageSize::A4));
    pdf.setResolution(300);
    pdf.setTitle(name);
    QPainter p;
    if (!QDir().mkpath(dir) || !p.begin(&pdf)) {
        show(Errors::shown(Failure{QCoreApplication::translate("Errors", "The phone could not save the sheet."), QStringLiteral("recovery: cannot write %1").arg(path)}));
        return QString();
    }
    const int width = pdf.width();
    const int margin = 150;
    int y = margin;
    auto text = [&](const QString &s, int pt, bool bold, bool mono) {
        QFont f(mono ? QStringLiteral("monospace") : QString(), pt);
        f.setBold(bold);
        if (mono)
            f.setStyleHint(QFont::Monospace);
        p.setFont(f);
        const QRect r = p.boundingRect(QRect(margin, y, width - 2 * margin, 100000), Qt::TextWordWrap, s);
        p.drawText(r, Qt::TextWordWrap, s);
        y = r.bottom() + 60;
    };
    p.setPen(Qt::black);
    text(name, 20, true, false);
    // The QR code, from the core's modules, on white with its quiet zone.
    const int count = m_recoveryModules.size();
    const int side = qMin(width - 2 * margin, 1100);
    const int cell = side / (count + 8);
    const int left = (width - cell * (count + 8)) / 2;
    for (int row = 0; row < count; ++row)
        for (int col = 0; col < m_recoveryModules.at(row).size(); ++col)
            if (m_recoveryModules.at(row).at(col) == QLatin1Char('1'))
                p.fillRect(left + (col + 4) * cell, y + (row + 4) * cell, cell, cell, Qt::black);
    y += cell * (count + 8) + 60;
    text(m_recoveryText, 14, true, true);
    text(QCoreApplication::translate("RecoveryPage", "Keep this sheet somewhere safe, away from your phones. Anyone who has it and a device of the group can take your group over."), 11, false, false);
    p.end();
    Errors::log(QStringLiteral("recovery: the sheet saved as a PDF in Documents"));
    return path;
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

bool App::keep(const Membership &next)
{
    Failure failure;
    if (!next.save(&failure)) {
        show(Errors::shown(failure));
        return false;
    }
    m_member = next;
    return true;
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
    m_busy = true;
    emit keyChanged();
    auto *thread = new GroupThread;
    // A group of 0.6: the set is kept in the app's folder, where the member
    // then starts on it (ffi's cbb_group_new with dir).
    thread->request = QJsonObject{
        {QStringLiteral("dir"), Membership::directory()},
        {QStringLiteral("name"), phoneName()},
        {QStringLiteral("os"), phoneOs()},
        {QStringLiteral("store"), KeyStore::store()},
        {QStringLiteral("public"), QString::fromLatin1(m_publicKey.toBase64())},
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
        Membership m;
        m.device = group.value(QStringLiteral("device")).toString();
        m.group = group.value(QStringLiteral("group")).toString();
        m.root = true;
        if (m.device.isEmpty() || m.group.isEmpty() || !m.save(&failure)) {
            show(Errors::shown(failure.isNull() ? Failure{QCoreApplication::translate("Errors", "The phone could not save the group."), QStringLiteral("group: no device in the answer")} : failure));
            return;
        }
        Errors::log(QStringLiteral("group: made %1 as its root").arg(m.groupTag()));
        m_member = m;
        // The recovery sheet, shown once and then forgotten (RecoveryPage).
        const QJsonObject sheet = group.value(QStringLiteral("recovery")).toObject();
        QStringList lines;
        for (const QJsonValue &l : sheet.value(QStringLiteral("text")).toArray())
            lines.append(l.toString());
        m_recoveryText = lines.join(QLatin1Char('\n'));
        m_recoveryModules.clear();
        for (const QJsonValue &row : sheet.value(QStringLiteral("modules")).toArray())
            m_recoveryModules.append(row.toString());
        show(QString());
        emit groupChanged();
        emit recoveryChanged();
        emit groupMade();
        startMember();
    });
    thread->start();
}

void App::openWindow()
{
    if (!m_member.isAdmin()) {
        m_window.fail({QCoreApplication::translate("Errors", "Only an admin of the group adds devices."), QStringLiteral("window: not an admin")});
        return;
    }
    if (m_busy)
        return;
    if (askPin([this]() { openWindow(); },
               [this]() { m_window.fail({QCoreApplication::translate("Errors", "Adding a device needs the admin PIN."), QStringLiteral("window: no PIN")}); }))
        return;
    Failure failure;
    if (!m_node.listen(&failure)) {
        m_window.fail(failure);
        return;
    }
    m_busy = true;
    emit keyChanged();
    m_window.setPreparing();
    auto *thread = new KeyThread(KeyStore::Which::Admin);
    connect(thread, &QThread::finished, this, [this, thread]() {
        const KeyStore::Key key = thread->key;
        thread->deleteLater();
        m_busy = false;
        emit keyChanged();
        if (m_window.state() != QStringLiteral("preparing"))
            return; // closed while the key was found
        if (key.state != KeyStore::State::Ready) {
            if (key.pinNeeded && askPin([this]() { openWindow(); }, std::function<void()>()))
                return;
            m_window.fail(key.failure);
            return;
        }
        m_window.open(m_node.handle(), key.publicKey);
    });
    thread->start();
}

void App::joinByWindow(const QString &text)
{
    if (!m_member.isNull())
        return;
    if (m_publicKey.isEmpty()) {
        m_joiner.fail({QCoreApplication::translate("Errors", "The phone has no key yet."), QStringLiteral("joiner: no key")});
        return;
    }
    const QString t = text.trimmed();
    QString digits = t;
    digits.remove(QLatin1Char(' '));
    static const QRegularExpression six(QStringLiteral("^[0-9]{6}$"));
    if (six.match(digits).hasMatch())
        m_joiner.start(Membership::directory(), QString(), digits, phoneName(), phoneOs(), m_publicKey);
    else
        m_joiner.start(Membership::directory(), t, QString(), phoneName(), phoneOs(), m_publicKey);
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

bool App::askPin(std::function<void()> run, std::function<void()> cancel, const QString &reason)
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
    emit pinNeeded(m_adminPin == QStringLiteral("not_set"), reason);
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

bool App::pinAllowed(const QString &pin) const
{
    return PinRule::check(pin.toStdString()) == PinRule::Verdict::Ok;
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
        emit pinChanged(result == KeyStore::PinResult::Right, result == KeyStore::PinResult::Locked,
                        result == KeyStore::PinResult::Wrong ? status.triesLeft : -1);
    });
    thread->start();
}

void App::startMember()
{
    if (m_member.isNull() || m_member.before06 || m_publicKey.isEmpty() || m_node.running())
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

bool App::advanced() const
{
    return QSettings().value(QStringLiteral("ui/advanced")).toBool();
}

void App::setAdvanced(bool on)
{
    if (on == advanced())
        return;
    QSettings().setValue(QStringLiteral("ui/advanced"), on);
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

bool App::hasArrangement() const
{
    Failure failure;
    return m_node.view(QJsonValue(), &failure).value(QStringLiteral("custom")).toBool();
}

QVariantList App::arranged(const QVariantList &devices, int)
{
    QHash<QString, QVariant> byId;
    for (const QVariant &d : devices)
        byId.insert(d.toMap().value(QStringLiteral("id")).toString(), d);
    Failure failure;
    const QJsonObject view = m_node.view(QJsonValue(), &failure);
    if (!failure.isNull()) {
        // The group's order, so the devices still show.
        QVariantList flat;
        for (const QVariant &d : devices)
            flat << QVariantMap{{QStringLiteral("kind"), QStringLiteral("device")}, {QStringLiteral("device"), d}};
        return flat;
    }
    // Each device as Member::devices lists it, or as the view gives it.
    const auto device = [&byId](const QJsonValue &d) {
        const QJsonObject o = d.toObject();
        return byId.value(o.value(QStringLiteral("id")).toString(), o.toVariantMap());
    };
    QVariantList out;
    for (const QJsonValue &tile : view.value(QStringLiteral("tiles")).toArray()) {
        const QJsonObject o = tile.toObject();
        if (o.contains(QStringLiteral("device"))) {
            out << QVariantMap{{QStringLiteral("kind"), QStringLiteral("device")},
                               {QStringLiteral("device"), device(o.value(QStringLiteral("device")))}};
            continue;
        }
        const QJsonObject c = o.value(QStringLiteral("collection")).toObject();
        QVariantList inside;
        for (const QJsonValue &d : c.value(QStringLiteral("devices")).toArray())
            inside << device(d);
        out << QVariantMap{{QStringLiteral("kind"), QStringLiteral("collection")},
                           {QStringLiteral("id"), c.value(QStringLiteral("id")).toString()},
                           {QStringLiteral("name"), c.value(QStringLiteral("name")).toString()},
                           {QStringLiteral("devices"), inside}};
    }
    return out;
}

bool App::arrange(const QVariantMap &op)
{
    Failure failure;
    m_node.view(QJsonObject::fromVariantMap(op), &failure);
    if (!failure.isNull())
        show(Errors::shown(failure));
    ++m_arrangement;
    emit arrangementChanged();
    return failure.isNull();
}
