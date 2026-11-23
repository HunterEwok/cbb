// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import QtQuick 2.6
import Sailfish.Silica 1.0

// An admin mutes a device for the whole group, for a time or until an admin
// unmutes it (docs/design.md, "Muting a device"), as on the iPhone: Mute on
// the device's card, then how long. A tap signs the mute and goes back.
Page {
    id: page
    property var device

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: column.height

        Column {
            id: column
            width: parent.width

            PageHeader {
                title: qsTr("Mute")
                description: page.device ? page.device.name : ""
            }
            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                font.pixelSize: Theme.fontSizeSmall
                color: Theme.secondaryHighlightColor
                text: qsTr("Its copies then reach no device of the group; it still takes theirs.")
            }
            Item { width: 1; height: Theme.paddingLarge }
            Repeater {
                model: [
                    { title: qsTr("For 15 minutes"), minutes: 15 },
                    { title: qsTr("For an hour"), minutes: 60 },
                    { title: qsTr("For 8 hours"), minutes: 8 * 60 },
                    { title: qsTr("Until an admin unmutes it"), minutes: 0 }
                ]
                BackgroundItem {
                    width: column.width
                    enabled: !app.busy
                    onClicked: {
                        app.manage("mute", page.device.id, "", modelData.minutes)
                        pageStack.pop()
                    }
                    Label {
                        x: Theme.horizontalPageMargin
                        width: parent.width - 2 * Theme.horizontalPageMargin
                        anchors.verticalCenter: parent.verticalCenter
                        text: modelData.title
                        color: parent.highlighted ? Theme.highlightColor : Theme.primaryColor
                    }
                }
            }
        }
    }
}
