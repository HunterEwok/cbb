// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

#include "app.h"
#include "platform/shell.h"

#include <QFileInfo>
#include <QGuiApplication>
#include <QLocale>
#include <QQmlContext>
#include <QtQml>
#include <QQuickView>
#include <QScopedPointer>
#include <QSettings>
#include <QTranslator>
#include <QUrl>

int main(int argc, char *argv[])
{
    QScopedPointer<QGuiApplication> application(Shell::application(argc, argv));
    application->setOrganizationName(QStringLiteral("tools.cbb"));
    application->setApplicationName(QStringLiteral(CBB_APP_NAME));
    application->setApplicationVersion(QStringLiteral(CBB_VERSION));
    // The translation of the language Settings chose, else the system's,
    // from the package's share folder (tools.cbb.aurora.pro), English when
    // it has none.
    const QString chosen = QSettings().value(QStringLiteral("ui/language")).toString();
    const QLocale locale = chosen.isEmpty() ? QLocale() : QLocale(chosen);
    // Numbers and dates follow the chosen language too (Aurora's guide:
    // QLocale::setDefault, QML has no way of its own), and Arabic and
    // Hebrew lay the pages out from the right.
    QLocale::setDefault(locale);
    application->setLayoutDirection(locale.textDirection());
    QTranslator translator;
    const QString share = QStringLiteral("/usr/share/") + QFileInfo(QCoreApplication::applicationFilePath()).fileName();
    if (translator.load(locale, QStringLiteral("cbb"), QStringLiteral("-"), share + QStringLiteral("/translations")))
        application->installTranslator(&translator);

    qmlRegisterUncreatableType<Join>("tools.cbb", 1, 0, "Join", QStringLiteral("the app makes it"));
    qmlRegisterUncreatableType<Member>("tools.cbb", 1, 0, "Member", QStringLiteral("the app makes it"));
    qmlRegisterUncreatableType<Admit>("tools.cbb", 1, 0, "Admit", QStringLiteral("the app makes it"));
    qmlRegisterUncreatableType<BleKeyboard>("tools.cbb", 1, 0, "BleKeyboard", QStringLiteral("the app makes it"));
    qmlRegisterUncreatableType<PasteReceiver>("tools.cbb", 1, 0, "PasteReceiver", QStringLiteral("the app makes it"));
    qmlRegisterUncreatableType<Events>("tools.cbb", 1, 0, "Events", QStringLiteral("the app makes it"));
    App app;
    QScopedPointer<QQuickView> view(Shell::view());
    view->rootContext()->setContextProperty(QStringLiteral("app"), &app);
    view->setSource(Shell::mainQml());
    view->show();
    app.setUpKey();
    return application->exec();
}
