// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

#include "shell.h"

#include <auroraapp.h>

#include <QGuiApplication>
#include <QQuickView>

namespace Shell {

QGuiApplication *application(int &argc, char **argv)
{
    return Aurora::Application::application(argc, argv);
}

QQuickView *view()
{
    return Aurora::Application::createView();
}

QUrl mainQml()
{
    return Aurora::Application::pathToMainQml();
}

} // namespace Shell
