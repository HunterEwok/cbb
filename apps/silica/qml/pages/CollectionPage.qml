// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import QtQuick 2.6
import Sailfish.Silica 1.0
import "arrange.js" as Arrange

// A collection's page (docs/apps.md, "Collections and the order of the
// tiles"): its devices, a long press arranging each, and its name and
// ungrouping in the pull-down menu.
Page {
    id: page
    property string collection // its ID
    readonly property var view: app.arranged(app.member.devices, app.arrangement)
    readonly property var entry: Arrange.find(view, collection)

    // Ungrouped, or its last device left: back to the main page.
    onEntryChanged: if (entry === null && status === PageStatus.Active) pageStack.pop()

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: column.height

        PullDownMenu {
            visible: page.entry !== null
            MenuItem {
                text: qsTr("Ungroup")
                onClicked: app.arrange({ op: "ungroup", collection: page.collection })
            }
            MenuItem {
                text: qsTr("Rename collection…")
                onClicked: pageStack.push(Qt.resolvedUrl("CollectionNameDialog.qml"),
                                          { collection: page.collection, name: page.entry.name })
            }
        }

        Column {
            id: column
            width: parent.width
            spacing: Theme.paddingMedium

            PageHeader {
                title: page.entry !== null ? page.entry.name : ""
                description: page.entry !== null
                             ? qsTr("%1 of %2 online").arg(Arrange.online(page.entry.devices)).arg(page.entry.devices.length)
                             : ""
            }
            DeviceItems {
                level: page.entry !== null ? Arrange.items(page.entry.devices) : []
                view: page.view
                inCollection: page.collection
            }
            Label {
                visible: page.entry !== null && page.entry.devices.length === 0
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * x
                text: qsTr("No devices in this collection yet. Hold a device's tile on the main page to move it here.")
                wrapMode: Text.Wrap
                color: Theme.highlightColor
            }
        }
        VerticalScrollDecorator {}
    }
}
