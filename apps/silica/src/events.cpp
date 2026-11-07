// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

#include "events.h"

#include <QJsonDocument>
#include <QJsonObject>
#include <QSettings>

#include <algorithm>

namespace {

const QString seenKey = QStringLiteral("events/seen");

QByteArray encode(const QMap<QString, Events::Seen> &seen)
{
    QJsonObject o;
    for (auto it = seen.cbegin(); it != seen.cend(); ++it)
        o.insert(it.key(), QJsonObject{{QStringLiteral("name"), it->name},
                                       {QStringLiteral("admin"), it->admin},
                                       {QStringLiteral("frozen"), it->frozen},
                                       {QStringLiteral("root"), it->root}});
    return QJsonDocument(o).toJson(QJsonDocument::Compact);
}

bool decode(const QByteArray &data, QMap<QString, Events::Seen> *seen)
{
    const QJsonDocument doc = QJsonDocument::fromJson(data);
    if (!doc.isObject())
        return false;
    const QJsonObject o = doc.object();
    for (auto it = o.constBegin(); it != o.constEnd(); ++it) {
        const QJsonObject d = it->toObject();
        seen->insert(it.key(), Events::Seen(d.value(QStringLiteral("name")).toString(), d.value(QStringLiteral("admin")).toBool(),
                                d.value(QStringLiteral("frozen")).toBool(), d.value(QStringLiteral("root")).toBool()));
    }
    return true;
}

typedef QPair<QString, Events::Seen> Entry;

// The entries sorted by name, then ID, for a fixed order.
QList<Entry> byName(const QMap<QString, Events::Seen> &m)
{
    QList<Entry> l;
    for (auto it = m.cbegin(); it != m.cend(); ++it)
        l.append(Entry(it.key(), *it));
    std::stable_sort(l.begin(), l.end(), [](const Entry &a, const Entry &b) { return a.second.name < b.second.name; });
    return l;
}

} // namespace

Events::Events(QObject *parent) : QObject(parent) {}

QMap<QString, Events::Seen> Events::seen(const QVariantList &devices)
{
    QMap<QString, Seen> m;
    for (const QVariant &v : devices) {
        const QVariantMap d = v.toMap();
        if (d.value(QStringLiteral("self")).toBool())
            continue;
        const QString id = d.value(QStringLiteral("device")).toString();
        if (id.isEmpty() || m.contains(id))
            continue;
        m.insert(id, Seen(d.value(QStringLiteral("name")).toString(), d.value(QStringLiteral("admin")).toBool(),
                          d.value(QStringLiteral("frozen")).toBool(), d.value(QStringLiteral("root")).toBool()));
    }
    return m;
}

QList<Events::Event> Events::between(const QMap<QString, Seen> &old, const QMap<QString, Seen> &now)
{
    QList<Event> events;
    for (const Entry &e : byName(now)) {
        const QString &n = e.second.name;
        if (!old.contains(e.first)) {
            events.append(Event(QStringLiteral("devices"), tr("%1 joined the group.").arg(n)));
            continue;
        }
        const Seen was = old.value(e.first);
        if (e.second.root && !was.root)
            events.append(Event(QStringLiteral("takeover"), tr("%1 took the group over: it holds the group's root now.").arg(n)));
        else if (e.second.admin && !was.admin)
            events.append(Event(QStringLiteral("admins"), tr("%1 is an admin now.").arg(n)));
        if (e.second.frozen != was.frozen)
            events.append(Event(QStringLiteral("frozen"),
                                e.second.frozen ? tr("%1 was frozen: the others refuse it until an admin unfreezes it.").arg(n)
                                                : tr("%1 was unfrozen.").arg(n)));
    }
    for (const Entry &e : byName(old))
        if (!now.contains(e.first))
            events.append(Event(QStringLiteral("devices"), tr("%1 was removed from the group.").arg(e.second.name)));
    return events;
}

bool Events::isOn(const QString &kind) const
{
    return QSettings().value(QStringLiteral("notify/") + kind, true).toBool();
}

void Events::setOn(const QString &kind, bool on)
{
    QSettings().setValue(QStringLiteral("notify/") + kind, on);
}

void Events::observe(const QVariantList &devices)
{
    if (devices.isEmpty())
        return;
    const QMap<QString, Seen> now = seen(devices);
    QSettings settings;
    QMap<QString, Seen> old;
    const bool known = decode(settings.value(seenKey).toByteArray(), &old);
    if (known && old == now)
        return;
    settings.setValue(seenKey, encode(now));
    if (!known)
        return;
    for (const Event &e : between(old, now)) {
        m_recent.prepend(e.text);
        while (m_recent.size() > 5)
            m_recent.removeLast();
        emit recentChanged();
        if (isOn(e.kind))
            emit posted(e.text, e.kind);
    }
}

void Events::forget()
{
    QSettings().remove(seenKey);
    m_recent.clear();
    emit recentChanged();
}
