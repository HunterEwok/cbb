// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// The system's application and window, which Aurora's libauroraapp and
// Sailfish's libsailfishapp each give in their own way.
#pragma once

class QGuiApplication;
class QQuickView;
class QUrl;

namespace Shell {

QGuiApplication *application(int &argc, char **argv);
QQuickView *view();
// The main QML file, for the view's source.
QUrl mainQml();

} // namespace Shell
