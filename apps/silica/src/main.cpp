// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

#include "app.h"
#include "platform/shell.h"

#include <QGuiApplication>
#include <QQmlContext>
#include <QtQml>
#include <QQuickView>
#include <QScopedPointer>
#include <QUrl>

int main(int argc, char *argv[])
{
    QScopedPointer<QGuiApplication> application(Shell::application(argc, argv));
    application->setOrganizationName(QStringLiteral("tools.cbb"));
    application->setApplicationName(QStringLiteral("aurora"));
    application->setApplicationVersion(QStringLiteral(CBB_VERSION));

    qmlRegisterUncreatableType<Join>("tools.cbb", 1, 0, "Join", QStringLiteral("the app makes it"));
    App app;
    QScopedPointer<QQuickView> view(Shell::view());
    view->rootContext()->setContextProperty(QStringLiteral("app"), &app);
    view->setSource(Shell::mainQml());
    view->show();
    app.setUpKey();
    return application->exec();
}
