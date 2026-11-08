// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import QtQuick 2.6
import Sailfish.Silica 1.0

// The consent before Everywhere, sync away from home, turns on (D-82): what
// goes where, as on the other phones; accepting turns it on.
Dialog {
    SilicaFlickable {
        anchors.fill: parent
        contentHeight: column.height

        Column {
            id: column
            width: parent.width
            spacing: Theme.paddingLarge

            DialogHeader {
                title: qsTr("Turn Everywhere on?")
                acceptText: qsTr("Turn on")
            }
            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                color: Theme.highlightColor
                text: qsTr("When the phone is not on the home network, it syncs through the WireGuard tunnel of your own hub, a computer of the group set up with cbb global hub; its port is reachable from the internet, but only through WireGuard with the group's keys. The hub answers this phone the next time it connects at home. Nothing goes anywhere else, and without the tunnel there is no connection. Turning it off forgets this phone's tunnel key.")
            }
        }
        VerticalScrollDecorator {}
    }
}
