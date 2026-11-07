// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

#include "shell.h"

#include <sailfishapp.h>

#include <QGuiApplication>
#include <QQuickView>

namespace Shell {

QGuiApplication *application(int &argc, char **argv)
{
    return SailfishApp::application(argc, argv);
}

QQuickView *view()
{
    return SailfishApp::createView();
}

// The QML keeps the Aurora app's file names in every package.
QUrl mainQml()
{
    return SailfishApp::pathTo(QStringLiteral("qml/tools.cbb.aurora.qml"));
}

} // namespace Shell
