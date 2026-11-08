// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import QtQuick 2.6
import Sailfish.Silica 1.0
import "devices.js" as Devices

Page {
    // Aurora lets an app read the clipboard only in the foreground: what the
    // user copied goes to the group when the app comes to the front.
    Connections {
        target: Qt.application
        onStateChanged: if (Qt.application.state === Qt.ApplicationActive) sendSoon.restart()
    }
    Timer {
        id: sendSoon
        interval: 300
        onTriggered: app.member.sendClipboard()
    }

    RemorsePopup { id: remorse }

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: column.height

        PullDownMenu {
            MenuItem {
                visible: app.group === "" && app.keyLevel !== "none"
                text: qsTr("Join a group")
                onClicked: pageStack.push(Qt.resolvedUrl("JoinPage.qml"))
            }
            MenuItem {
                visible: app.group === "" && app.keyLevel !== "none"
                text: qsTr("Join a group as an admin")
                onClicked: pageStack.push(Qt.resolvedUrl("JoinPage.qml"), { admin: true })
            }
            MenuItem {
                visible: app.group === "" && app.keyLevel !== "none"
                text: qsTr("Make a group")
                enabled: !app.busy
                onClicked: pageStack.push(Qt.resolvedUrl("NewGroupPage.qml"))
            }
            MenuItem {
                visible: app.group !== ""
                text: qsTr("Leave the group")
                // The root's key goes with it: the group then has no root
                // until an admin phone takes it over.
                onClicked: remorse.execute(app.root ? qsTr("Leaving the group and deleting its root key")
                                                    : qsTr("Leaving the group"), function() { app.leave() })
            }
            MenuItem {
                visible: app.admin && app.member.running
                text: qsTr("Add a device")
                onClicked: pageStack.push(Qt.resolvedUrl("AddDevicePage.qml"))
            }
            MenuItem {
                visible: app.member.running
                text: qsTr("Sync the clipboard")
                onClicked: app.member.button()
            }
            MenuItem {
                visible: app.keyLevel === "none"
                text: qsTr("Check the key again")
                enabled: !app.busy
                onClicked: app.setUpKey()
            }
            MenuItem {
                text: qsTr("Settings")
                onClicked: pageStack.push(Qt.resolvedUrl("SettingsPage.qml"))
            }
            MenuItem {
                visible: app.member.devices.length > 0
                text: app.deviceList ? qsTr("Show the devices as tiles") : qsTr("Show the devices as a list")
                onClicked: app.deviceList = !app.deviceList
            }
        }

        Column {
            id: column
            width: parent.width
            spacing: Theme.paddingMedium

            PageHeader { title: "CBB" }

            // The quick switch (design.md, "Muting a device"): a tap keeps
            // the group's copies out of the clipboard, or takes them again;
            // a long press picks for how long. The phone's own copies still
            // go out.
            ListItem {
                id: takeCopies
                visible: app.member.running
                contentHeight: Theme.itemSizeMedium
                onClicked: app.member.paused ? app.member.resume() : app.member.pause(0)
                menu: ContextMenu {
                    MenuItem { text: qsTr("For 15 minutes"); onClicked: app.member.pause(15) }
                    MenuItem { text: qsTr("For an hour"); onClicked: app.member.pause(60) }
                    MenuItem { text: qsTr("For 8 hours"); onClicked: app.member.pause(8 * 60) }
                    MenuItem { text: qsTr("Until I turn it on"); onClicked: app.member.pause(0) }
                }
                Switch {
                    id: takeSwitch
                    anchors.verticalCenter: parent.verticalCenter
                    x: Theme.horizontalPageMargin - Theme.paddingLarge
                    automaticCheck: false
                    checked: !app.member.paused
                    onClicked: app.member.paused ? app.member.resume() : app.member.pause(0)
                    onPressAndHold: takeCopies.openMenu()
                }
                Column {
                    anchors.verticalCenter: parent.verticalCenter
                    anchors.left: takeSwitch.right
                    anchors.right: parent.right
                    anchors.rightMargin: Theme.horizontalPageMargin
                    Label {
                        width: parent.width
                        text: !app.member.paused ? qsTr("Taking copies")
                            : app.member.pausedUntil.getTime() > 0
                                ? qsTr("Not taking copies until %1").arg(Qt.formatTime(app.member.pausedUntil, "hh:mm"))
                                : qsTr("Not taking copies")
                        color: takeCopies.highlighted ? Theme.highlightColor : Theme.primaryColor
                        truncationMode: TruncationMode.Fade
                    }
                    Label {
                        width: parent.width
                        text: qsTr("Tap to take no copies from the group, or again; hold it for a time")
                        font.pixelSize: Theme.fontSizeExtraSmall
                        color: Theme.secondaryColor
                        wrapMode: Text.Wrap
                    }
                }
            }

            Label {
                visible: app.member.muted
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                text: app.member.mutedUntil.getTime() > 0
                      ? qsTr("An admin muted this phone until %1: its copies do not reach the group.").arg(Qt.formatDateTime(app.member.mutedUntil, "d MMM hh:mm"))
                      : qsTr("An admin muted this phone: its copies do not reach the group until an admin unmutes it.")
                wrapMode: Text.Wrap
                color: Theme.errorColor
                font.pixelSize: Theme.fontSizeSmall
            }

            AlertsCard {}

            // The one button (docs/design.md, "The one button"): a copy from
            // another device that waits comes to the phone; otherwise what the
            // phone copied goes to the group.
            Button {
                visible: app.member.running
                anchors.horizontalCenter: parent.horizontalCenter
                enabled: !app.member.fetching
                text: app.member.fetching ? qsTr("Fetching…") : qsTr("Sync")
                onClicked: app.member.button()
            }

            Label {
                visible: app.group === "" && !app.busy
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                text: app.keyLevel === "none" ? qsTr("The phone has no key yet. Pull down to check it again.")
                                              : qsTr("The phone is in no group yet. Pull down to join one or make one.")
                wrapMode: Text.Wrap
                color: Theme.highlightColor
            }
            DetailItem {
                visible: app.group !== ""
                label: qsTr("In the group")
                value: app.root ? qsTr("Root") : app.admin ? qsTr("Admin") : qsTr("Member")
            }
            DetailItem {
                visible: app.member.last !== ""
                label: qsTr("Last copy")
                value: app.member.last
            }

            // The group's devices (docs/apps.md, "Screens", Home), as tiles
            // or as a list; a tap opens the device's page.
            SectionHeader {
                visible: app.member.devices.length > 0
                text: qsTr("Devices")
            }
            Flow {
                id: tiles
                visible: !app.deviceList
                x: Theme.horizontalPageMargin - Theme.paddingSmall
                width: parent.width - 2 * x
                // Tiles at least as wide as on the other phones, two in a
                // row on a phone held upright, so their words fit.
                property int perRow: Math.max(2, Math.floor(width / (Theme.itemSizeExtraLarge * 2.2)))
                Repeater {
                    model: tiles.visible ? Devices.selfFirst(app.member.devices) : []
                    DeviceTile {
                        width: tiles.width / tiles.perRow
                        device: modelData
                    }
                }
            }
            Repeater {
                model: app.deviceList ? Devices.selfFirst(app.member.devices) : []
                ListItem {
                    contentHeight: Theme.itemSizeMedium
                    onClicked: pageStack.push(Qt.resolvedUrl("DevicePage.qml"), { device: modelData })
                    Rectangle {
                        id: dot
                        x: Theme.horizontalPageMargin
                        anchors.verticalCenter: parent.verticalCenter
                        width: Theme.paddingMedium
                        height: width
                        radius: width / 2
                        color: modelData.online || modelData.self ? Theme.highlightColor : "transparent"
                        border.color: Theme.secondaryColor
                        border.width: modelData.online || modelData.self ? 0 : 1
                    }
                    Column {
                        anchors.left: dot.right
                        anchors.leftMargin: Theme.paddingMedium
                        anchors.right: parent.right
                        anchors.rightMargin: Theme.horizontalPageMargin
                        anchors.verticalCenter: parent.verticalCenter
                        Label {
                            width: parent.width
                            text: Devices.name(modelData)
                            color: highlighted ? Theme.highlightColor : Theme.primaryColor
                            truncationMode: TruncationMode.Fade
                        }
                        Label {
                            width: parent.width
                            text: [Devices.kind(modelData), Devices.system(modelData), Devices.mark(modelData)].filter(function(s) { return s !== "" }).join(" · ")
                            font.pixelSize: Theme.fontSizeExtraSmall
                            color: Theme.secondaryColor
                            truncationMode: TruncationMode.Fade
                        }
                    }
                }
            }

            BusyIndicator {
                anchors.horizontalCenter: parent.horizontalCenter
                running: app.busy
                visible: running
                size: BusyIndicatorSize.Medium
            }

            Label {
                visible: app.member.error !== ""
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                text: app.member.error
                wrapMode: Text.Wrap
                color: Theme.errorColor
                font.pixelSize: Theme.fontSizeSmall
            }

            Label {
                visible: app.error !== ""
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                text: app.error
                wrapMode: Text.Wrap
                color: Theme.errorColor
                font.pixelSize: Theme.fontSizeSmall
            }
        }
        VerticalScrollDecorator {}
    }
}
