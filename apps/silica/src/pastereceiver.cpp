// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

#include "pastereceiver.h"

#include "blekeyboard.h"
#include "errors.h"
#include "member.h"

#include <QJsonArray>
#include <QJsonDocument>
#include <QSettings>

PasteReceiver::PasteReceiver(Member *member, BleKeyboard *keyboard, QObject *parent)
    : QObject(parent), m_member(member), m_keyboard(keyboard)
{
    connect(m_member, &Member::commandArrived, this, &PasteReceiver::carryOut);
}

bool PasteReceiver::on() const
{
    return QSettings().value(QStringLiteral("paste/on")).toBool();
}

void PasteReceiver::setOn(bool on)
{
    QSettings s;
    s.setValue(QStringLiteral("paste/on"), on);
    // Enter goes off with the switch, so that turning it on again asks anew.
    if (!on)
        s.setValue(QStringLiteral("paste/enter"), false);
    emit settingsChanged();
}

bool PasteReceiver::enter() const
{
    return on() && QSettings().value(QStringLiteral("paste/enter")).toBool();
}

void PasteReceiver::setEnter(bool on)
{
    QSettings().setValue(QStringLiteral("paste/enter"), on);
    emit settingsChanged();
}

QVariantList PasteReceiver::log() const
{
    const QJsonArray a = QJsonDocument::fromJson(QSettings().value(QStringLiteral("paste/log")).toByteArray()).array();
    QVariantList out;
    for (int i = a.size() - 1; i >= 0; --i) {
        QVariantMap m = a.at(i).toObject().toVariantMap();
        m.insert(QStringLiteral("time"), QDateTime::fromMSecsSinceEpoch(qint64(m.value(QStringLiteral("time_ms")).toDouble())));
        out << m;
    }
    return out;
}

void PasteReceiver::forgetLog()
{
    QSettings().remove(QStringLiteral("paste/log"));
    emit logChanged();
}

bool PasteReceiver::allow(const QString &sender, qint64 nowMs)
{
    for (auto it = m_sent.begin(); it != m_sent.end();) {
        QList<qint64> &ts = it.value();
        while (!ts.isEmpty() && nowMs - ts.first() >= 60000)
            ts.removeFirst();
        it = ts.isEmpty() ? m_sent.erase(it) : it + 1;
    }
    QList<qint64> &ts = m_sent[sender];
    if (ts.size() >= burst || (!ts.isEmpty() && nowMs - ts.last() < everyMs)) {
        if (ts.isEmpty())
            m_sent.remove(sender);
        return false;
    }
    ts.append(nowMs);
    return true;
}

void PasteReceiver::carryOut(const QJsonObject &checked)
{
    const double token = checked.value(QStringLiteral("token")).toDouble();
    const QJsonObject body = checked.value(QStringLiteral("command")).toObject();
    const QString by = body.value(QStringLiteral("by")).toString();
    if (body.value(QStringLiteral("type")).toString() == QStringLiteral("paste-off")) {
        Errors::log(QStringLiteral("paste: %1 turned remote paste off").arg(by));
        setOn(false);
        m_member->answer(token, QStringLiteral("done"), QString());
        return;
    }
    const bool verified = checked.value(QStringLiteral("verified")).toBool();
    const QString sender = checked.value(QStringLiteral("sender")).toString();
    const QString text = checked.value(QStringLiteral("clean")).toString();
    const QString raw = body.value(QStringLiteral("text")).toString();
    const bool withEnter = body.value(QStringLiteral("enter")).toBool();
    const bool secret = body.value(QStringLiteral("kind")).toString() == QStringLiteral("secret");
    QString name;
    if (verified) {
        for (const QVariant &d : m_member->devices()) {
            const QVariantMap m = d.toMap();
            if (m.value(QStringLiteral("device")).toString() == by)
                name = m.value(QStringLiteral("name")).toString();
        }
    }
    QString status = QStringLiteral("refused");
    QString reason;
    bool refused = true;
    if (!on()) {
        reason = QStringLiteral("remote paste is off on this device; its user turns it on in the app's settings");
    } else if (withEnter && !enter()) {
        reason = QStringLiteral("this device takes pastes without Enter only; its user allows Enter in the app's settings");
    } else if (!allow(sender, QDateTime::currentMSecsSinceEpoch())) {
        reason = QStringLiteral("too many pastes: at most one a second and 30 a minute from one device");
    } else if (text.isEmpty()) {
        reason = QStringLiteral("the text has nothing that may be pasted: only control characters");
    } else if (text.contains(QLatin1Char('\n')) && !enter()) {
        // Keys go straight in, so a line break presses Enter.
        reason = QStringLiteral("the text has a line break, which the Bluetooth keyboard types as Enter; this device's "
                                "user allows Enter in the app's settings");
    } else {
        reason = m_keyboard->typeRemote(withEnter ? text + QLatin1Char('\n') : text, &refused);
        if (reason.isEmpty())
            status = QStringLiteral("done");
        else if (!refused)
            status = QStringLiteral("failed");
    }
    const QString who = verified ? by : by + QStringLiteral(" (unverified)");
    if (status == QStringLiteral("done")) {
        Errors::log(QStringLiteral("paste: %1 pasted %2 characters here").arg(who).arg(raw.size()));
        emit pasted(name.isEmpty() ? by : name);
    } else {
        Errors::log(QStringLiteral("paste: a paste from %1: %2: %3").arg(who, status, reason));
    }
    if (!secret) {
        QJsonObject e{
            {QStringLiteral("time_ms"), double(QDateTime::currentMSecsSinceEpoch())},
            {QStringLiteral("by"), by},
            {QStringLiteral("bytes"), raw.toUtf8().size()},
            {QStringLiteral("enter"), withEnter},
            {QStringLiteral("status"), status},
        };
        if (!name.isEmpty())
            e.insert(QStringLiteral("name"), name);
        if (!reason.isEmpty())
            e.insert(QStringLiteral("reason"), reason);
        if (!verified)
            e.insert(QStringLiteral("unverified"), true);
        keep(e);
    }
    m_member->answer(token, status, reason);
}

void PasteReceiver::keep(const QJsonObject &entry)
{
    QSettings s;
    QJsonArray a = QJsonDocument::fromJson(s.value(QStringLiteral("paste/log")).toByteArray()).array();
    a.append(entry);
    while (a.size() > logSize)
        a.removeFirst();
    s.setValue(QStringLiteral("paste/log"), QJsonDocument(a).toJson(QJsonDocument::Compact));
    emit logChanged();
}
