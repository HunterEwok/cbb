// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// The bug report (docs/core-api.md, "Bug reports"): the core builds and
// seals the report and keeps the state; this class keeps that state in the
// app's settings, posts reports to bug.cbb.tools and sends again what
// waits, and holds the report the app asks about in release mode.
#pragma once

#include <QJsonObject>
#include <QNetworkAccessManager>
#include <QObject>
#include <QString>
#include <QStringList>

class Bugs : public QObject
{
    Q_OBJECT
    // The app asks "Oops, something broke" while asking is true.
    Q_PROPERTY(bool asking READ asking NOTIFY changed)
    // Whether the question offers "Always allow": after the user allowed twice.
    Q_PROPERTY(bool offerAlways READ offerAlways NOTIFY changed)
    // The version the server said fixes this break, empty when none.
    Q_PROPERTY(QString fixedIn READ fixedIn NOTIFY changed)
    // The report as it would go, for "Technical details".
    Q_PROPERTY(QString report READ report NOTIFY changed)

public:
    explicit Bugs(QObject *parent = nullptr);

    bool asking() const { return !m_offer.isEmpty(); }
    bool offerAlways() const;
    QString fixedIn() const;
    QString report() const;

    // Offers the report of a break: the core's action, ask (asking turns
    // true), send (it goes without asking) or skip; empty when the core
    // refused the input, which goes to the log.
    QString offer(const QJsonObject &input);

    // The user allowed the report asked about, and maybe always.
    Q_INVOKABLE void allow(bool always);
    // The user cancelled it: nothing goes.
    Q_INVOKABLE void cancel();
    // Sends the reports that wait, as at start.
    void resend();

signals:
    void changed();

private:
    QJsonObject state() const;
    void keep(const QJsonValue &answer);
    void send(const QString &fingerprint, const QString &version, const QString &post, const QString &url);

    QJsonObject m_offer;
    QNetworkAccessManager m_net;
};
