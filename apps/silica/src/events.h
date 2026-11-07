// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// The group's events the app notifies of (docs/apps.md, Notifications), as
// the iPhone's GroupEvents and Android's do: it compares the group's devices
// with what it saw last time, so it learns of events while the app runs.

#pragma once

#include <QObject>
#include <QString>
#include <QStringList>
#include <QVariantList>
#include <QVariantMap>

class Events : public QObject
{
    Q_OBJECT
    // The latest events, newest first, for the cover.
    Q_PROPERTY(QStringList recent READ recent NOTIFY recentChanged)

public:
    explicit Events(QObject *parent = nullptr);

    // What the app knew of a device when it last looked.
    struct Seen
    {
        Seen() = default;
        Seen(const QString &n, bool a, bool f, bool r) : name(n), admin(a), frozen(f), root(r) {}
        QString name;
        bool admin = false;
        bool frozen = false;
        bool root = false;
        bool operator==(const Seen &o) const
        {
            return name == o.name && admin == o.admin && frozen == o.frozen && root == o.root;
        }
    };
    struct Event
    {
        Event(const QString &k, const QString &t) : kind(k), text(t) {}
        QString kind; // devices, admins, frozen or takeover
        QString text;
    };

    // The other devices of a list from the core, by ID.
    static QMap<QString, Seen> seen(const QVariantList &devices);
    // The events between two looks, by name, removals after the rest.
    static QList<Event> between(const QMap<QString, Seen> &old, const QMap<QString, Seen> &now);

    QStringList recent() const { return m_recent; }

    // Each kind's switch, all on by default.
    Q_INVOKABLE bool isOn(const QString &kind) const;
    Q_INVOKABLE void setOn(const QString &kind, bool on);

    // Notifies of what changed since the last look; the first look only
    // remembers.
    void observe(const QVariantList &devices);
    // Forgets the group's devices, once the phone left it.
    void forget();

signals:
    // An event to show, when its kind is on.
    void posted(const QString &text, const QString &kind);
    void recentChanged();

private:
    QStringList m_recent;
};
