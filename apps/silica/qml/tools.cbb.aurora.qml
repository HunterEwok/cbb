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
    // Pages from the right in Arabic and Hebrew (main.cpp sets the
    // direction from the language).
    LayoutMirroring.enabled: Qt.application.layoutDirection === Qt.RightToLeft
    LayoutMirroring.childrenInherit: true

    // The notifications and the share menu, each through a module some
    // systems lack; a missing one leaves the rest of the app working.
    Loader { source: "system/Notifier.qml" }
    Loader { source: "system/ShareTarget.qml" }

    // The admin PIN, asked before the admin key signs, again after a wrong
    // one; a request while the app is off the screen waits for it.
    property bool pinWaiting: false
    property bool pinFresh: false
    function askPin(fresh, triesLeft) {
        pageStack.push(Qt.resolvedUrl("pages/PinDialog.qml"), { fresh: fresh, triesLeft: triesLeft })
    }
    Connections {
        target: app
        onPinNeeded: {
            if (Qt.application.state === Qt.ApplicationActive && !pageStack.busy) {
                askPin(fresh, -1)
            } else {
                pinFresh = fresh
                pinWaiting = true
            }
        }
        onPinRefused: {
            if (!locked && triesLeft > 0)
                askPin(false, triesLeft)
        }
    }
    Connections {
        target: Qt.application
        onStateChanged: {
            if (pinWaiting && Qt.application.state === Qt.ApplicationActive) {
                pinWaiting = false
                askPin(pinFresh, -1)
            }
        }
    }
}
