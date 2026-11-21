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
    // one. A request waits while the app is off the screen or a page is on
    // its way in or out (as the join page is when it asks), since the page
    // stack takes no push then.
    property bool pinWaiting: false
    property bool pinFresh: false
    property int pinTries: -1
    property string pinReason: ""
    function askPin(fresh, triesLeft) {
        pinFresh = fresh
        pinTries = triesLeft
        pinWaiting = true
        showPin()
    }
    function showPin() {
        if (!pinWaiting || Qt.application.state !== Qt.ApplicationActive || pageStack.busy)
            return
        pinWaiting = false
        pageStack.push(Qt.resolvedUrl("pages/PinDialog.qml"), { fresh: pinFresh, triesLeft: pinTries, reason: pinReason })
    }
    Connections {
        target: app
        onPinNeeded: {
            pinReason = reason
            askPin(fresh, -1)
        }
        onPinRefused: {
            if (!locked && triesLeft >= 0)
                askPin(false, triesLeft)
        }
    }
    Connections {
        target: Qt.application
        onStateChanged: showPin()
    }
    Connections {
        target: pageStack
        onBusyChanged: showPin()
    }

    // The bug report's question (Bugs), when the member broke in release mode.
    Connections {
        target: app.bugs
        onChanged: {
            if (!app.bugs.asking)
                return
            var d = pageStack.push(Qt.resolvedUrl("pages/BugDialog.qml"))
            d.accepted.connect(function() { app.bugs.allow(d.always) })
            d.rejected.connect(function() { app.bugs.cancel() })
        }
    }
}
