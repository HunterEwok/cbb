// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import QtQuick 2.6
import Sailfish.Silica 1.0
import "pages"
import "cover"

ApplicationWindow {
    initialPage: Component { MainPage {} }
    cover: Component { CoverPage {} }
    allowedOrientations: defaultAllowedOrientations

    // The notifications and the share menu, each through a module some
    // systems lack; a missing one leaves the rest of the app working.
    Loader { source: "system/Notifier.qml" }
    Loader { source: "system/ShareTarget.qml" }
}
