// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

#include "blekeyboard.h"

#include "core.h"
#include "errors.h"

#include <QClipboard>
#include <QDBusArgument>
#include <QDBusMessage>
#include <QDBusMetaType>
#include <QDBusObjectPath>
#include <QDBusPendingCallWatcher>
#include <QDBusPendingReply>
#include <QDBusVariant>
#include <QGuiApplication>
#include <QJsonArray>
#include <QJsonObject>
#include <QMap>
#include <QSettings>

typedef QMap<QString, QVariantMap> Interfaces;
typedef QMap<QDBusObjectPath, Interfaces> Objects;
Q_DECLARE_METATYPE(Interfaces)
Q_DECLARE_METATYPE(Objects)

namespace {

// BlueZ's names on the system bus.
const QString bluez = QStringLiteral("org.bluez");
const QString adapterIface = QStringLiteral("org.bluez.Adapter1");
const QString deviceIface = QStringLiteral("org.bluez.Device1");
const QString gattManager = QStringLiteral("org.bluez.GattManager1");
const QString advManager = QStringLiteral("org.bluez.LEAdvertisingManager1");
const QString serviceIface = QStringLiteral("org.bluez.GattService1");
const QString charIface = QStringLiteral("org.bluez.GattCharacteristic1");
const QString descIface = QStringLiteral("org.bluez.GattDescriptor1");
const QString advIface = QStringLiteral("org.bluez.LEAdvertisement1");
const QString objectManager = QStringLiteral("org.freedesktop.DBus.ObjectManager");
const QString propsIface = QStringLiteral("org.freedesktop.DBus.Properties");

// Where the keyboard's objects live on the bus.
const QString root = QStringLiteral("/tools/cbb/keyboard");
const QString advPath = root + QStringLiteral("/advertisement");

// The GAP appearance of a keyboard.
const quint16 appearanceKeyboard = 0x03c1;

// How long a new host can find the phone.
const int visibleMs = 2 * 60 * 1000;

// The services, by their paths under root (the HID over GATT profile, the
// battery's and the device information's).
const QList<QPair<QString, QString>> services = {
    {root + QStringLiteral("/hid"), QStringLiteral("1812")},
    {root + QStringLiteral("/battery"), QStringLiteral("180f")},
    {root + QStringLiteral("/info"), QStringLiteral("180a")},
};

QVariantMap options(const QDBusMessage &m, int at)
{
    if (m.arguments().size() <= at)
        return QVariantMap();
    return qdbus_cast<QVariantMap>(m.arguments().at(at));
}

} // namespace

QString KeyboardObjects::introspect(const QString &) const
{
    // BlueZ asks the application's objects through GetManagedObjects, not
    // by introspection.
    return QString();
}

bool KeyboardObjects::handleMessage(const QDBusMessage &m, const QDBusConnection &bus)
{
    if (m.type() != QDBusMessage::MethodCallMessage)
        return false;
    const QString path = m.path();
    const QString iface = m.interface();
    const QString name = m.member();
    auto reply = [&](const QVariantList &args) {
        QDBusMessage r = m.createReply(args);
        bus.send(r);
        return true;
    };
    auto refuse = [&](const QString &error) {
        bus.send(m.createErrorReply(error, QString()));
        return true;
    };

    if (path == root && iface == objectManager && name == QLatin1String("GetManagedObjects")) {
        Objects out;
        for (const auto &s : services)
            out[QDBusObjectPath(s.first)][serviceIface] =
                QVariantMap{{QStringLiteral("UUID"), s.second}, {QStringLiteral("Primary"), true}};
        for (const auto &c : m_k->m_chars) {
            out[QDBusObjectPath(c.path)][charIface] = QVariantMap{
                {QStringLiteral("UUID"), c.uuid},
                {QStringLiteral("Service"), QVariant::fromValue(QDBusObjectPath(c.service))},
                {QStringLiteral("Flags"), c.flags},
            };
            for (const auto &d : c.descriptors)
                out[QDBusObjectPath(d.path)][descIface] = QVariantMap{
                    {QStringLiteral("UUID"), d.uuid},
                    {QStringLiteral("Characteristic"), QVariant::fromValue(QDBusObjectPath(c.path))},
                    {QStringLiteral("Flags"), QStringList{QStringLiteral("encrypt-read")}},
                };
        }
        return reply({QVariant::fromValue(out)});
    }

    if (path == advPath) {
        const QVariantMap props{
            {QStringLiteral("Type"), QStringLiteral("peripheral")},
            {QStringLiteral("ServiceUUIDs"), QStringList{QStringLiteral("1812")}},
            {QStringLiteral("Appearance"), QVariant::fromValue(appearanceKeyboard)},
            {QStringLiteral("LocalName"), QStringLiteral("CBB keyboard")},
            {QStringLiteral("Discoverable"), m_k->m_discoverable},
        };
        if (iface == advIface && name == QLatin1String("Release")) {
            m_k->m_adv = false;
            return reply({});
        }
        if (iface == propsIface && name == QLatin1String("GetAll"))
            return reply({props});
        if (iface == propsIface && name == QLatin1String("Get") && m.arguments().size() == 2) {
            const QString prop = m.arguments().at(1).toString();
            if (!props.contains(prop))
                return refuse(QStringLiteral("org.freedesktop.DBus.Error.InvalidArgs"));
            return reply({QVariant::fromValue(QDBusVariant(props.value(prop)))});
        }
        return false;
    }

    for (auto &c : m_k->m_chars) {
        for (const auto &d : c.descriptors) {
            if (path == d.path && iface == descIface && name == QLatin1String("ReadValue"))
                return reply({d.value.mid(options(m, 0).value(QStringLiteral("offset")).toInt())});
        }
        if (path != c.path || iface != charIface)
            continue;
        if (name == QLatin1String("ReadValue")) {
            const QVariantMap opts = options(m, 0);
            m_k->sawHost(opts);
            return reply({c.value.mid(opts.value(QStringLiteral("offset")).toInt())});
        }
        if (name == QLatin1String("WriteValue") && m.arguments().size() >= 1) {
            if (!c.flags.contains(QStringLiteral("write-without-response")) &&
                !c.flags.contains(QStringLiteral("encrypt-write")))
                return refuse(QStringLiteral("org.bluez.Error.NotPermitted"));
            c.value = m.arguments().at(0).toByteArray();
            return reply({});
        }
        if (name == QLatin1String("StartNotify") || name == QLatin1String("StopNotify")) {
            if (!c.flags.contains(QStringLiteral("notify")))
                return refuse(QStringLiteral("org.bluez.Error.NotSupported"));
            const bool start = name == QLatin1String("StartNotify");
            const bool input = &c == &m_k->m_chars[m_k->m_report] || &c == &m_k->m_chars[m_k->m_boot];
            if (c.notifying != start) {
                c.notifying = start;
                if (input)
                    m_k->listen(start);
            }
            return reply({});
        }
        return false;
    }
    return false;
}

BleKeyboard::BleKeyboard(QObject *parent)
    : QObject(parent), m_bus(QDBusConnection::systemBus()), m_objects(this)
{
    qDBusRegisterMetaType<Interfaces>();
    qDBusRegisterMetaType<Objects>();
    build();
    m_hide.setSingleShot(true);
    connect(&m_hide, &QTimer::timeout, this, [this]() {
        m_visible = QDateTime();
        if (m_app)
            advertise(false);
        emit stateChanged();
    });
    connect(&m_typing, &QTimer::timeout, this, &BleKeyboard::step);
    if (on())
        QTimer::singleShot(0, this, &BleKeyboard::start);
}

BleKeyboard::~BleKeyboard()
{
    stop();
}

bool BleKeyboard::on() const
{
    return QSettings().value(QStringLiteral("keyboard/on")).toBool();
}

void BleKeyboard::setOn(bool on)
{
    if (on == this->on())
        return;
    QSettings().setValue(QStringLiteral("keyboard/on"), on);
    emit settingsChanged();
    if (on)
        start();
    else
        stop();
}

QString BleKeyboard::layout() const
{
    const QString l = QSettings().value(QStringLiteral("keyboard/layout")).toString();
    return l == QLatin1String("ru") ? l : QStringLiteral("us");
}

void BleKeyboard::setLayout(const QString &layout)
{
    QSettings().setValue(QStringLiteral("keyboard/layout"), layout);
    emit settingsChanged();
}

int BleKeyboard::rate() const
{
    return qBound(minRate, QSettings().value(QStringLiteral("keyboard/rate"), 20).toInt(), maxRate);
}

void BleKeyboard::setRate(int rate)
{
    QSettings().setValue(QStringLiteral("keyboard/rate"), qBound(minRate, rate, maxRate));
    emit settingsChanged();
}

QDateTime BleKeyboard::visibleUntil() const
{
    return m_visible.isValid() && m_visible > QDateTime::currentDateTime() ? m_visible : QDateTime();
}

void BleKeyboard::build()
{
    Failure failure;
    const QJsonObject k = Core::call(QStringLiteral("keyboard"), QJsonObject{{QStringLiteral("layout"), QStringLiteral("us")}},
                                     &failure).toObject();
    const QByteArray map = QByteArray::fromBase64(k.value(QStringLiteral("map")).toString().toLatin1());
    const QString hid = services.at(0).first;
    const QStringList input{QStringLiteral("encrypt-read"), QStringLiteral("notify")};
    const QStringList output{QStringLiteral("encrypt-read"), QStringLiteral("encrypt-write"),
                             QStringLiteral("write-without-response")};
    add(hid, QStringLiteral("report"), QStringLiteral("2a4d"), input, QByteArray(8, 0))
        .descriptors << Descriptor{QString(), QStringLiteral("2908"), QByteArray::fromHex("0001")}; // report ID 0, input
    m_report = m_chars.size() - 1;
    add(hid, QStringLiteral("output"), QStringLiteral("2a4d"), output, QByteArray(1, 0))
        .descriptors << Descriptor{QString(), QStringLiteral("2908"), QByteArray::fromHex("0002")}; // report ID 0, output
    add(hid, QStringLiteral("boot_input"), QStringLiteral("2a22"), input, QByteArray(8, 0));
    m_boot = m_chars.size() - 1;
    add(hid, QStringLiteral("boot_output"), QStringLiteral("2a32"), output, QByteArray(1, 0));
    // HID 1.11, no country, normally connectable.
    add(hid, QStringLiteral("info"), QStringLiteral("2a4a"), {QStringLiteral("encrypt-read")}, QByteArray::fromHex("11010002"));
    add(hid, QStringLiteral("map"), QStringLiteral("2a4b"), {QStringLiteral("encrypt-read")}, map);
    add(hid, QStringLiteral("control"), QStringLiteral("2a4c"), {QStringLiteral("write-without-response")}, QByteArray(1, 0));
    // The report protocol until the host asks for the boot one.
    add(hid, QStringLiteral("protocol"), QStringLiteral("2a4e"),
        {QStringLiteral("encrypt-read"), QStringLiteral("write-without-response")}, QByteArray(1, 1));
    m_protocol = m_chars.size() - 1;
    add(services.at(1).first, QStringLiteral("level"), QStringLiteral("2a19"),
        {QStringLiteral("read"), QStringLiteral("notify")}, QByteArray(1, 100));
    // The vendor ID source (USB), the Linux Foundation's vendor ID, a
    // product and a version, as the computer's.
    add(services.at(2).first, QStringLiteral("pnp"), QStringLiteral("2a50"), {QStringLiteral("read")},
        QByteArray::fromHex("026b1d46010001"));
    for (auto &c : m_chars)
        for (auto &d : c.descriptors)
            d.path = c.path + QStringLiteral("/ref");
}

BleKeyboard::Characteristic &BleKeyboard::add(const QString &service, const QString &name, const QString &uuid,
                                              const QStringList &flags, const QByteArray &value)
{
    Characteristic c;
    c.path = service + QLatin1Char('/') + name;
    c.service = service;
    c.uuid = uuid;
    c.flags = flags;
    c.value = value;
    m_chars << c;
    return m_chars.last();
}

void BleKeyboard::setState(const QString &state)
{
    m_state = state;
    if (state != QLatin1String("failed"))
        m_error.clear();
    emit stateChanged();
}

void BleKeyboard::fail(const QString &message, const QString &details)
{
    Failure f;
    f.message = message;
    f.details = details;
    m_error = Errors::shown(f);
    m_state = QStringLiteral("failed");
    emit stateChanged();
}

void BleKeyboard::start()
{
    if (m_state != QLatin1String("off") && m_state != QLatin1String("failed"))
        return;
    setState(QStringLiteral("starting"));
    // BlueZ's first adapter that can be an LE peripheral, when it is
    // powered.
    QDBusMessage ask = QDBusMessage::createMethodCall(bluez, QStringLiteral("/"), objectManager,
                                                      QStringLiteral("GetManagedObjects"));
    auto *w = new QDBusPendingCallWatcher(m_bus.asyncCall(ask), this);
    connect(w, &QDBusPendingCallWatcher::finished, this, [this, w]() {
        w->deleteLater();
        const QDBusMessage r = w->reply();
        if (r.type() == QDBusMessage::ErrorMessage) {
            fail(tr("The phone's Bluetooth did not answer. CBB may not be allowed to use it."),
                 r.errorName() + QStringLiteral(": ") + r.errorMessage());
            return;
        }
        Objects objs;
        r.arguments().value(0).value<QDBusArgument>() >> objs;
        QString found;
        bool powered = false;
        for (auto it = objs.constBegin(); it != objs.constEnd(); ++it) {
            const Interfaces &i = it.value();
            if (i.contains(adapterIface) && i.contains(gattManager) && i.contains(advManager)) {
                found = it.key().path();
                powered = i.value(adapterIface).value(QStringLiteral("Powered")).toBool();
                break;
            }
        }
        if (found.isEmpty()) {
            fail(tr("This phone's Bluetooth cannot act as a keyboard."), QStringLiteral("no adapter with GattManager1 and LEAdvertisingManager1"));
            return;
        }
        if (!powered) {
            fail(tr("Bluetooth is off. Turn it on in the phone's settings, then turn the keyboard on again."), QString());
            return;
        }
        m_adapter = found;
        if (!m_exported) {
            if (!m_bus.registerVirtualObject(root, &m_objects, QDBusConnection::SubPath)) {
                fail(tr("The phone could not be a keyboard."), m_bus.lastError().message());
                return;
            }
            m_exported = true;
            m_bus.connect(bluez, QString(), propsIface, QStringLiteral("PropertiesChanged"), this,
                          SLOT(onDeviceChanged(QDBusMessage)));
        }
        QDBusMessage reg = QDBusMessage::createMethodCall(bluez, m_adapter, gattManager, QStringLiteral("RegisterApplication"));
        reg << QVariant::fromValue(QDBusObjectPath(root)) << QVariantMap();
        auto *rw = new QDBusPendingCallWatcher(m_bus.asyncCall(reg, 25000), this);
        connect(rw, &QDBusPendingCallWatcher::finished, this, [this, rw]() {
            rw->deleteLater();
            const QDBusMessage rr = rw->reply();
            if (rr.type() == QDBusMessage::ErrorMessage) {
                fail(tr("The phone's Bluetooth did not take the keyboard."), rr.errorName() + QStringLiteral(": ") + rr.errorMessage());
                return;
            }
            registered();
        });
    });
}

void BleKeyboard::registered()
{
    m_app = true;
    Errors::log(QStringLiteral("cbb: keyboard: registered with BlueZ at ") + m_adapter);
    setState(m_listening > 0 ? QStringLiteral("connected") : QStringLiteral("ready"));
    advertise(visibleUntil().isValid());
}

void BleKeyboard::advertise(bool discoverable)
{
    // BlueZ reads an advertisement's properties only when it is
    // registered, so a change registers it again.
    if (m_adv) {
        m_bus.asyncCall(QDBusMessage::createMethodCall(bluez, m_adapter, advManager, QStringLiteral("UnregisterAdvertisement"))
                        << QVariant::fromValue(QDBusObjectPath(advPath)));
        m_adv = false;
    }
    m_discoverable = discoverable;
    QDBusMessage reg = QDBusMessage::createMethodCall(bluez, m_adapter, advManager, QStringLiteral("RegisterAdvertisement"));
    reg << QVariant::fromValue(QDBusObjectPath(advPath)) << QVariantMap();
    auto *w = new QDBusPendingCallWatcher(m_bus.asyncCall(reg), this);
    connect(w, &QDBusPendingCallWatcher::finished, this, [this, w]() {
        w->deleteLater();
        const QDBusMessage r = w->reply();
        if (r.type() == QDBusMessage::ErrorMessage) {
            fail(tr("The phone could not advertise the keyboard."), r.errorName() + QStringLiteral(": ") + r.errorMessage());
            return;
        }
        m_adv = true;
    });
}

void BleKeyboard::stop()
{
    m_typing.stop();
    m_hide.stop();
    m_visible = QDateTime();
    if (!m_adapter.isEmpty()) {
        if (m_adv)
            m_bus.call(QDBusMessage::createMethodCall(bluez, m_adapter, advManager, QStringLiteral("UnregisterAdvertisement"))
                       << QVariant::fromValue(QDBusObjectPath(advPath)));
        if (m_app)
            m_bus.call(QDBusMessage::createMethodCall(bluez, m_adapter, gattManager, QStringLiteral("UnregisterApplication"))
                       << QVariant::fromValue(QDBusObjectPath(root)));
    }
    m_adv = m_app = false;
    if (m_exported) {
        m_bus.disconnect(bluez, QString(), propsIface, QStringLiteral("PropertiesChanged"), this,
                         SLOT(onDeviceChanged(QDBusMessage)));
        m_bus.unregisterObject(root, QDBusConnection::UnregisterTree);
        m_exported = false;
    }
    for (auto &c : m_chars)
        c.notifying = false;
    m_listening = 0;
    m_host.clear();
    if (m_state != QLatin1String("off"))
        setState(QStringLiteral("off"));
}

void BleKeyboard::makeVisible()
{
    m_visible = QDateTime::currentDateTime().addMSecs(visibleMs);
    m_hide.start(visibleMs);
    if (m_app)
        advertise(true);
    else
        start();
    emit stateChanged();
}

void BleKeyboard::sawHost(const QVariantMap &opts)
{
    const QString device = qvariant_cast<QDBusObjectPath>(opts.value(QStringLiteral("device"))).path();
    if (device.isEmpty() || !m_host.isEmpty())
        return;
    QDBusMessage get = QDBusMessage::createMethodCall(bluez, device, propsIface, QStringLiteral("Get"));
    get << deviceIface << QStringLiteral("Alias");
    auto *w = new QDBusPendingCallWatcher(m_bus.asyncCall(get), this);
    connect(w, &QDBusPendingCallWatcher::finished, this, [this, w]() {
        w->deleteLater();
        QDBusPendingReply<QDBusVariant> r = *w;
        if (r.isValid()) {
            m_host = r.value().variant().toString();
            emit stateChanged();
        }
    });
}

void BleKeyboard::listen(bool more)
{
    m_listening = qMax(0, m_listening + (more ? 1 : -1));
    Errors::log(more ? QStringLiteral("cbb: keyboard: a host connected") : QStringLiteral("cbb: keyboard: a host disconnected"));
    if (m_listening == 0)
        m_host.clear();
    if (m_app)
        setState(m_listening > 0 ? QStringLiteral("connected") : QStringLiteral("ready"));
}

void BleKeyboard::onDeviceChanged(const QDBusMessage &message)
{
    const QVariantList a = message.arguments();
    if (a.size() < 2 || a.at(0).toString() != deviceIface)
        return;
    const QVariantMap changed = qdbus_cast<QVariantMap>(a.at(1));
    // A host that went away takes no more notifications, whether or not
    // it said so.
    if (changed.contains(QStringLiteral("Connected")) && !changed.value(QStringLiteral("Connected")).toBool() && m_listening > 0) {
        for (auto &c : m_chars)
            c.notifying = false;
        m_listening = 1;
        listen(false);
    }
}

void BleKeyboard::type(const QString &text)
{
    if (m_typing.isActive())
        return;
    if (m_listening == 0) {
        finish(tr("No device is connected. Connect to this phone from the device, in its Bluetooth settings."));
        return;
    }
    if (text.isEmpty()) {
        finish(tr("The clipboard holds no text."));
        return;
    }
    if (text.size() > maxChars) {
        finish(tr("The text has more than %1 characters, more than a keyboard types.").arg(maxChars));
        return;
    }
    Failure failure;
    const QJsonObject k = Core::call(QStringLiteral("keyboard"),
                                     QJsonObject{{QStringLiteral("layout"), layout()}, {QStringLiteral("text"), text}},
                                     &failure).toObject();
    if (!failure.isNull()) {
        finish(Errors::shown(failure));
        return;
    }
    const QString untypeable = k.value(QStringLiteral("untypeable")).toString();
    if (!untypeable.isEmpty()) {
        QStringList cs;
        for (const QChar c : untypeable)
            cs << QString(c);
        finish(tr("The device's layout has no key for: %1. Pick its layout above.").arg(cs.join(QLatin1Char(' '))));
        return;
    }
    m_reports.clear();
    for (const QJsonValue &r : k.value(QStringLiteral("reports")).toArray())
        m_reports << QByteArray::fromBase64(r.toString().toLatin1());
    m_next = 0;
    m_typed.clear();
    // A report down and one up for each character.
    m_typing.start(qMax(1, 1000 / (2 * rate())));
    emit stateChanged();
}

void BleKeyboard::typeClipboard()
{
    type(QGuiApplication::clipboard()->text());
}

void BleKeyboard::step()
{
    if (m_next >= m_reports.size()) {
        finish(QStringLiteral("typed"));
        return;
    }
    if (!send(m_reports.at(m_next++))) {
        send(QByteArray(8, 0));
        finish(tr("The device went away; the text was not typed whole."));
    }
}

bool BleKeyboard::send(const QByteArray &report)
{
    if (m_listening == 0)
        return false;
    // The boot keyboard's report when the host chose the boot protocol.
    Characteristic &c = m_chars[m_chars[m_protocol].value.startsWith(char(0)) ? m_boot : m_report];
    c.value = report;
    QDBusMessage s = QDBusMessage::createSignal(c.path, propsIface, QStringLiteral("PropertiesChanged"));
    s << charIface << QVariantMap{{QStringLiteral("Value"), report}} << QStringList();
    return m_bus.send(s);
}

void BleKeyboard::finish(const QString &typed)
{
    m_typing.stop();
    m_reports.clear();
    m_typed = typed;
    emit stateChanged();
}
