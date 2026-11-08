// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

#include "member.h"

#include "core.h"
#include "errors.h"
#include "platform/keystore.h"

#include <cbb_core.h>

#include <QBuffer>
#include <QClipboard>
#include <QCryptographicHash>
#include <QDir>
#include <QFileInfo>
#include <QMimeData>
#include <QMimeDatabase>
#include <QStandardPaths>
#include <QThread>
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

// Asks the member through cbb_member_call: {"op", "args"}.
QJsonObject call(cbb_member *m, const QString &op, const QJsonObject &args, Failure *failure)
{
    const QByteArray req =
        QJsonDocument(QJsonObject{{QStringLiteral("op"), op}, {QStringLiteral("args"), args}}).toJson(QJsonDocument::Compact);
    size_t len = 0;
    return Core::take(cbb_member_call(m, reinterpret_cast<const uint8_t *>(req.constData()), size_t(req.size()), &len), len,
                      QStringLiteral("member"), failure);
}

QString b64(const QByteArray &b)
{
    return QString::fromLatin1(b.toBase64());
}

// Fetches a copy's images or files off the GUI thread: the core waits
// for the network.
class FetchThread : public QThread
{
public:
    cbb_member *member = nullptr;
    QJsonObject args;
    QJsonObject answer;
    Failure failure;

protected:
    void run() override { answer = call(member, QStringLiteral("fetch"), args, &failure); }
};

// The most bytes the phone fetches of a copy, or sends of shared files.
const qint64 maxFetchBytes = 200ll << 20;
const qint64 maxSendBytes = 50ll << 20;

// How often the main page's devices are brought up to date.
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
    pollDevices();
    emit changed();
}

void Member::stop()
{
    if (!m_member)
        return;
    // A fetch under way ends with the member; its answer is dropped.
    if (m_fetch) {
        m_fetch->disconnect(this);
        m_fetch->wait();
        m_fetch->deleteLater();
        m_fetch = nullptr;
    }
    current.store(nullptr);
    m_peerTimer.stop();
    cbb_member_stop(m_member);
    m_member = nullptr;
    m_peers.clear();
    m_devices.clear();
    m_alerts.clear();
    emit devicesChanged();
    m_paused = m_muted = false;
    readAway(QJsonValue());
    Errors::log(QStringLiteral("member: stopped"));
    emit changed();
}

void Member::button()
{
    if (!m_member || m_fetch)
        return;
    Failure failure;
    const QJsonObject copy = call(m_member, QStringLiteral("waiting"), QJsonObject(), &failure)
                                 .value(QStringLiteral("copy"))
                                 .toObject();
    if (!failure.isNull()) {
        m_error = Errors::shown(failure);
        emit changed();
        return;
    }
    if (!copy.isEmpty())
        take(copy);
    else
        sendClipboard();
}

void Member::sendClipboard()
{
    // A muted phone's copies stay its own; the main page says so.
    if (!m_member || m_muted)
        return;
    const QMimeData *data = QGuiApplication::clipboard()->mimeData();
    if (data && data->hasImage() && !data->hasText()) {
        sendImage(qvariant_cast<QImage>(data->imageData()));
        return;
    }
    const QString text = QGuiApplication::clipboard()->text();
    if (text.isEmpty())
        return;
    Failure failure;
    const bool sends = call(m_member, QStringLiteral("sends"), QJsonObject{{QStringLiteral("board"), text}}, &failure)
                           .value(QStringLiteral("sends"))
                           .toBool();
    if (failure.isNull() && sends)
        call(m_member, QStringLiteral("copy"), QJsonObject{{QStringLiteral("text"), text}, {QStringLiteral("board"), true}},
             &failure);
    if (!failure.isNull()) {
        m_error = Errors::shown(failure);
        emit changed();
        return;
    }
    if (!sends)
        return;
    m_known = text;
    m_error.clear();
    setLast(text, false);
}

void Member::sendText(const QString &text)
{
    if (!m_member || m_muted || text.isEmpty())
        return;
    Failure failure;
    call(m_member, QStringLiteral("copy"), QJsonObject{{QStringLiteral("text"), text}}, &failure);
    if (!failure.isNull()) {
        m_error = Errors::shown(failure);
        emit changed();
        return;
    }
    m_error.clear();
    setLast(text, false);
}

QString Member::imageKey(const QByteArray &png)
{
    return QChar(0) + QStringLiteral("image:") + QString::fromLatin1(QCryptographicHash::hash(png, QCryptographicHash::Sha256).toHex());
}

void Member::sendImage(const QImage &image)
{
    if (image.isNull())
        return;
    QByteArray png;
    QBuffer buf(&png);
    buf.open(QIODevice::WriteOnly);
    image.save(&buf, "PNG");
    const QString key = imageKey(png);
    if (key == m_tookImage || png.size() > maxSendBytes)
        return;
    Failure failure;
    const bool sends = call(m_member, QStringLiteral("sends"), QJsonObject{{QStringLiteral("board"), key}}, &failure)
                           .value(QStringLiteral("sends"))
                           .toBool();
    if (failure.isNull() && sends) {
        const QJsonObject part{{QStringLiteral("type"), QStringLiteral("image/png")},
                               {QStringLiteral("data"), b64(png)}};
        call(m_member, QStringLiteral("copy_media"),
             QJsonObject{{QStringLiteral("parts"), QJsonArray{part}}, {QStringLiteral("board"), true}}, &failure);
    }
    if (!failure.isNull()) {
        m_error = Errors::shown(failure);
        emit changed();
        return;
    }
    if (!sends)
        return;
    m_error.clear();
    m_last = tr("An image");
    emit changed();
}

void Member::sendFiles(const QStringList &paths)
{
    if (!m_member || m_muted || paths.isEmpty())
        return;
    QMimeDatabase mimes;
    QJsonArray parts;
    qint64 total = 0;
    for (const QString &p : paths) {
        const QFileInfo fi(p);
        if (!fi.isFile())
            continue;
        total += fi.size();
        const QString type = mimes.mimeTypeForFile(fi).name();
        QJsonObject part{{QStringLiteral("path"), fi.fileName()}, {QStringLiteral("file"), fi.absoluteFilePath()}};
        // A lone image goes as clipboard data, so that it lands in the
        // other devices' clipboards; files keep their names.
        if (paths.size() == 1 && (type == QStringLiteral("image/png") || type == QStringLiteral("image/jpeg")))
            part = QJsonObject{{QStringLiteral("type"), type}, {QStringLiteral("file"), fi.absoluteFilePath()}};
        parts.append(part);
    }
    Failure failure;
    if (parts.isEmpty())
        failure = Failure{tr("There is nothing to send: no file could be read."), QStringLiteral("share: no readable file")};
    else if (total > maxSendBytes)
        failure = Failure{tr("The files are too large: up to 50 MB go together."),
                          QStringLiteral("share: %1 bytes").arg(total)};
    else
        call(m_member, QStringLiteral("copy_media"), QJsonObject{{QStringLiteral("parts"), parts}}, &failure);
    if (!failure.isNull()) {
        m_error = Errors::shown(failure);
        emit changed();
        return;
    }
    m_error.clear();
    m_last = parts.size() == 1 ? QFileInfo(paths.first()).fileName() : tr("%1 files").arg(parts.size());
    emit changed();
}

void Member::take(const QJsonObject &copy)
{
    const QString id = copy.value(QStringLiteral("id")).toString();
    const QString kind = copy.value(QStringLiteral("kind")).toString();
    if (kind != QStringLiteral("media")) {
        write(copy.value(QStringLiteral("text")).toString(), kind == QStringLiteral("secret"), 0);
        Failure failure;
        call(m_member, QStringLiteral("took"), QJsonObject{{QStringLiteral("id"), id}}, &failure);
        return;
    }
    if (m_fetch)
        return;
    const QString base = QStandardPaths::writableLocation(QStandardPaths::DownloadLocation);
    const QString folder = QDir(base.isEmpty() ? QDir::homePath() : base)
                               .filePath(QStringLiteral("CBB/") + QDateTime::currentDateTime().toString(QStringLiteral("yyyy-MM-dd hh.mm.ss")));
    auto *t = new FetchThread;
    t->member = m_member;
    t->args = QJsonObject{{QStringLiteral("id"), id}, {QStringLiteral("max"), double(maxFetchBytes)}, {QStringLiteral("out"), folder}};
    m_fetch = t;
    emit changed();
    connect(t, &QThread::finished, this, [this, t, id, folder]() {
        const QJsonArray parts = t->answer.value(QStringLiteral("parts")).toArray();
        const Failure failure = t->failure;
        m_fetch = nullptr;
        t->deleteLater();
        if (!failure.isNull()) {
            m_error = Errors::shown(failure);
            emit changed();
            return;
        }
        Failure f;
        call(m_member, QStringLiteral("took"), QJsonObject{{QStringLiteral("id"), id}}, &f);
        int files = 0;
        QString image;
        for (const QJsonValue &v : parts) {
            const QJsonObject p = v.toObject();
            if (p.value(QStringLiteral("dir")).toBool())
                continue;
            ++files;
            const QString type = p.value(QStringLiteral("type")).toString();
            if (type == QStringLiteral("image/png") || type == QStringLiteral("image/jpeg"))
                image = p.value(QStringLiteral("file")).toString();
        }
        // One image goes into the clipboard as well, and stays out of the
        // phone's next sending.
        if (files == 1 && !image.isEmpty()) {
            const QImage img(image);
            if (!img.isNull()) {
                QGuiApplication::clipboard()->setImage(img);
                QByteArray png;
                QBuffer buf(&png);
                buf.open(QIODevice::WriteOnly);
                img.save(&buf, "PNG");
                m_tookImage = imageKey(png);
            }
        }
        m_error.clear();
        m_last = files == 1 && !image.isEmpty() ? tr("An image") : tr("%1 files in Downloads").arg(files);
        Errors::log(QStringLiteral("member: saved %1 files of the group's copy").arg(files));
        emit saved(folder, files);
        emit changed();
    });
    t->start();
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
    } else if (type == QStringLiteral("copy")) {
        // Images or files from another device come by themselves while the
        // phone takes the group's copies, as texts do through write; the
        // button takes them otherwise.
        const QJsonObject copy = e.value(QStringLiteral("copy")).toObject();
        if (copy.value(QStringLiteral("kind")).toString() == QStringLiteral("media") && !m_paused)
            take(copy);
    }
}

void Member::pause(int minutes)
{
    if (!m_member)
        return;
    Failure failure;
    const QJsonObject a = call(m_member, QStringLiteral("sync"),
                               QJsonObject{{QStringLiteral("on"), false},
                                           {QStringLiteral("for_ms"), double(qint64(minutes) * 60 * 1000)}},
                               &failure);
    if (!failure.isNull()) {
        m_error = Errors::shown(failure);
        emit changed();
        return;
    }
    Errors::log(minutes > 0 ? QStringLiteral("member: sync is off for %1 min").arg(minutes)
                            : QStringLiteral("member: sync is off until turned on"));
    readMuted(a);
}

void Member::resume()
{
    if (!m_member)
        return;
    Failure failure;
    const QJsonObject a =
        call(m_member, QStringLiteral("sync"), QJsonObject{{QStringLiteral("on"), true}}, &failure);
    if (!failure.isNull()) {
        m_error = Errors::shown(failure);
        emit changed();
        return;
    }
    Errors::log(QStringLiteral("member: sync is on"));
    readMuted(a);
}

void Member::pollMuted()
{
    if (!m_member)
        return;
    Failure failure;
    const QJsonObject a = call(m_member, QStringLiteral("muted"), QJsonObject(), &failure);
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
    const bool paused = a.value(QStringLiteral("sync_off")).toBool();
    const bool muted = a.value(QStringLiteral("muted")).toBool();
    const QDateTime pausedUntil = paused ? until(a.value(QStringLiteral("sync_off_ms"))) : QDateTime();
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
    Failure failure;
    const QJsonObject a = call(m_member, QStringLiteral("peers"), QJsonObject(), &failure);
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
    pollDevices();
    pollAway();
}

void Member::setAway(bool on)
{
    if (!m_member)
        return;
    Failure failure;
    const QJsonObject a = call(m_member, QStringLiteral("away"), QJsonObject{{QStringLiteral("on"), on}}, &failure);
    if (!failure.isNull()) {
        m_error = Errors::shown(failure);
        emit changed();
        pollAway();
        return;
    }
    Errors::log(on ? QStringLiteral("member: sync away from home is on")
                   : QStringLiteral("member: sync away from home is off"));
    readAway(a.value(QStringLiteral("away")));
}

void Member::pollAway()
{
    if (!m_member)
        return;
    Failure failure;
    const QJsonObject a = call(m_member, QStringLiteral("away_status"), QJsonObject(), &failure);
    if (!failure.isNull()) {
        Errors::log(QStringLiteral("member: sync away from home: %1 (%2)").arg(failure.message, failure.details));
        return;
    }
    readAway(a.value(QStringLiteral("away")));
}

void Member::readAway(const QJsonValue &away)
{
    const QJsonObject o = away.toObject();
    const bool on = away.isObject() && o.value(QStringLiteral("keys_in_file")).toBool();
    const QString hub = o.value(QStringLiteral("hub_device")).toString();
    QString status = QStringLiteral("off");
    QString hubName;
    if (on) {
        bool online = false;
        for (const QVariant &d : m_devices) {
            const QVariantMap m = d.toMap();
            if (m.value(QStringLiteral("device")).toString() == hub) {
                hubName = m.value(QStringLiteral("name")).toString();
                online = m.value(QStringLiteral("online")).toBool();
            }
        }
        if (hub.isEmpty())
            status = QStringLiteral("waiting");
        else if (o.value(QStringLiteral("through")).toBool())
            status = QStringLiteral("connected");
        else if (online)
            status = QStringLiteral("home");
        else
            status = QStringLiteral("connecting");
    }
    // The error of a state that could not be read shows even while off.
    const Failure failure{o.value(QStringLiteral("error")).toString(), o.value(QStringLiteral("detail")).toString()};
    bool changed = on != m_awayOn || status != m_awayStatus || hubName != m_awayHub;
    if (failure.message != m_awayFailure) {
        m_awayFailure = failure.message;
        m_awayError = failure.isNull() ? QString() : Errors::shown(failure);
        changed = true;
    }
    m_awayOn = on;
    m_awayStatus = status;
    m_awayHub = hubName;
    if (changed)
        emit awayChanged();
}

void Member::pollDevices()
{
    if (!m_member)
        return;
    Failure failure;
    const QJsonObject a = call(m_member, QStringLiteral("devices"), QJsonObject(), &failure);
    if (!failure.isNull()) {
        Errors::log(QStringLiteral("member: the devices: %1 (%2)").arg(failure.message, failure.details));
        return;
    }
    const QVariantList devices = a.value(QStringLiteral("devices")).toArray().toVariantList();
    const QJsonObject al = call(m_member, QStringLiteral("alerts"), QJsonObject(), &failure);
    const QVariantList alerts =
        failure.isNull() ? al.value(QStringLiteral("alerts")).toArray().toVariantList() : m_alerts;
    if (devices != m_devices || alerts != m_alerts) {
        m_devices = devices;
        m_alerts = alerts;
        emit devicesChanged();
    }
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
