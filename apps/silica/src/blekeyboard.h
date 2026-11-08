// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// The phone as a Bluetooth LE keyboard (docs/apps.md, "Bluetooth keyboard"),
// as the Linux computer's internal/blekeyboard: BlueZ publishes the HID
// service of HID over GATT that this class exports on the system bus, and
// a TV, a tablet or a computer that pairs with the phone takes what it
// types as a keyboard's keys, with nothing installed there. The reports
// and the report map come from the core (cbb_core::keyboard, its keyboard
// call); the system's own agent asks the user about a pairing.
#pragma once

#include <QByteArray>
#include <QDBusConnection>
#include <QDBusVirtualObject>
#include <QDateTime>
#include <QList>
#include <QObject>
#include <QString>
#include <QStringList>
#include <QTimer>

class BleKeyboard;

// The keyboard's objects under one path, answered by hand: the GATT
// application, its characteristics and descriptors, and the advertisement.
class KeyboardObjects : public QDBusVirtualObject
{
public:
    explicit KeyboardObjects(BleKeyboard *k) : m_k(k) {}
    QString introspect(const QString &path) const override;
    bool handleMessage(const QDBusMessage &message, const QDBusConnection &connection) override;

private:
    BleKeyboard *m_k;
};

class BleKeyboard : public QObject
{
    Q_OBJECT
    // The user's switch, kept in the settings.
    Q_PROPERTY(bool on READ on WRITE setOn NOTIFY settingsChanged)
    // The host's layout: "us" or "ru" (cbb_core::keyboard).
    Q_PROPERTY(QString layout READ layout WRITE setLayout NOTIFY settingsChanged)
    // Characters a second, 5 to 60.
    Q_PROPERTY(int rate READ rate WRITE setRate NOTIFY settingsChanged)
    // "off", "starting", "ready" (registered, no host), "connected", or
    // "failed" (error says why).
    Q_PROPERTY(QString state READ state NOTIFY stateChanged)
    Q_PROPERTY(QString error READ error NOTIFY stateChanged)
    // Until when a new host can find the phone; invalid when it cannot.
    Q_PROPERTY(QDateTime visibleUntil READ visibleUntil NOTIFY stateChanged)
    Q_PROPERTY(QString host READ host NOTIFY stateChanged)
    Q_PROPERTY(bool typing READ typing NOTIFY stateChanged)
    // What came of the last text: "" while typing or before any, "typed",
    // or why it was not typed.
    Q_PROPERTY(QString typed READ typed NOTIFY stateChanged)

public:
    static const int minRate = 5;
    static const int maxRate = 60;
    static const int maxChars = 4096;

    explicit BleKeyboard(QObject *parent = nullptr);
    ~BleKeyboard() override;

    bool on() const;
    void setOn(bool on);
    QString layout() const;
    void setLayout(const QString &layout);
    int rate() const;
    void setRate(int rate);
    QString state() const { return m_state; }
    QString error() const { return m_error; }
    QDateTime visibleUntil() const;
    QString host() const { return m_host; }
    bool typing() const { return m_typing.isActive(); }
    QString typed() const { return m_typed; }

    // Makes the phone discoverable as a keyboard for two minutes, so
    // that a new host finds it in its Bluetooth settings.
    Q_INVOKABLE void makeVisible();
    // Types text on the connected host; typed tells how it went.
    Q_INVOKABLE void type(const QString &text);
    // Types the clipboard's text.
    Q_INVOKABLE void typeClipboard();

signals:
    void settingsChanged();
    void stateChanged();

private:
    friend class KeyboardObjects;

    struct Descriptor
    {
        QString path;
        QString uuid;
        QByteArray value;
    };
    struct Characteristic
    {
        QString path;
        QString service;
        QString uuid;
        QStringList flags;
        QByteArray value;
        QList<Descriptor> descriptors;
        bool notifying = false;
    };

    void start();
    void stop();
    void registered();
    void advertise(bool discoverable);
    void fail(const QString &message, const QString &details);
    void setState(const QString &state);
    void build();
    Characteristic &add(const QString &service, const QString &name, const QString &uuid, const QStringList &flags,
                        const QByteArray &value);
    void sawHost(const QVariantMap &options);
    void listen(bool more);
    void step();
    bool send(const QByteArray &report);
    void finish(const QString &typed);
    Q_SLOT void onDeviceChanged(const QDBusMessage &message);

    QDBusConnection m_bus;
    KeyboardObjects m_objects;
    QString m_adapter;
    QString m_state = QStringLiteral("off");
    QString m_error;
    QString m_host;
    QString m_typed;
    QList<Characteristic> m_chars;
    int m_report = -1; // the input report in the report protocol
    int m_boot = -1;   // the boot keyboard's input report
    int m_protocol = -1;
    int m_listening = 0;
    bool m_exported = false;
    bool m_app = false;
    bool m_adv = false;
    bool m_discoverable = false;
    QDateTime m_visible;
    QTimer m_hide;
    QTimer m_typing;
    QList<QByteArray> m_reports;
    int m_next = 0;
};
