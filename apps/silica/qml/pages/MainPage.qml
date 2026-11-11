// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import QtQuick 2.6
import Sailfish.Silica 1.0

Page {
    id: page
    // The devices in the user's order and collections (App::arranged).
    readonly property var view: app.arranged(app.member.devices, app.arrangement)

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

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: column.height

        PullDownMenu {
            MenuItem {
                visible: app.keyboard.state === "connected"
                text: qsTr("Type the clipboard on %1").arg(app.keyboard.host !== "" ? app.keyboard.host : qsTr("the keyboard's device"))
                enabled: !app.keyboard.typing
                onClicked: app.keyboard.typeClipboard()
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
                visible: app.hasArrangement
                text: qsTr("Back to the group's order")
                onClicked: app.arrange({ op: "reset" })
            }
            MenuItem {
                visible: app.member.devices.length > 0 && app.group !== ""
                text: qsTr("New collection…")
                onClicked: pageStack.push(Qt.resolvedUrl("CollectionNameDialog.qml"))
            }
            MenuItem {
                visible: app.member.devices.length > 0
                text: app.deviceList ? qsTr("Show the devices as tiles") : qsTr("Show the devices as a list")
                onClicked: app.deviceList = !app.deviceList
            }
            MenuItem {
                visible: app.admin && app.member.running
                text: qsTr("Send an invitation")
                onClicked: pageStack.push(Qt.resolvedUrl("InvitePage.qml"))
            }
            MenuItem {
                visible: app.admin && app.member.running
                text: qsTr("Scan a code")
                onClicked: pageStack.push(Qt.resolvedUrl("AddDevicePage.qml"))
            }
        }

        Column {
            id: column
            width: parent.width
            spacing: Theme.paddingMedium

            PageHeader {
                visible: app.group !== ""
                title: "CBB"
            }

            // Start (docs/apps.md, Start): the name, then make a group or
            // join one; the settings and the language are in the pull-down
            // menu, as in every Silica app.
            Column {
                visible: app.group === ""
                width: parent.width
                spacing: Theme.paddingLarge

                Item { width: 1; height: Theme.itemSizeLarge }
                Label {
                    anchors.horizontalCenter: parent.horizontalCenter
                    text: "CBB"
                    font.pixelSize: Theme.fontSizeHuge * 1.5
                    font.bold: true
                    color: Theme.highlightColor
                }
                Label {
                    anchors.horizontalCenter: parent.horizontalCenter
                    text: "Copy Beyond Borders"
                    color: Theme.secondaryHighlightColor
                }
                Item { width: 1; height: Theme.paddingLarge }
                Button {
                    visible: app.keyLevel !== "none"
                    anchors.horizontalCenter: parent.horizontalCenter
                    preferredWidth: Theme.buttonWidthLarge
                    text: qsTr("Create a group")
                    enabled: !app.busy
                    onClicked: pageStack.push(Qt.resolvedUrl("NewGroupPage.qml"))
                }
                Button {
                    visible: app.keyLevel !== "none"
                    anchors.horizontalCenter: parent.horizontalCenter
                    preferredWidth: Theme.buttonWidthLarge
                    text: qsTr("Join a group")
                    onClicked: pageStack.push(Qt.resolvedUrl("JoinPage.qml"))
                }
                Button {
                    visible: app.keyLevel !== "none"
                    anchors.horizontalCenter: parent.horizontalCenter
                    preferredWidth: Theme.buttonWidthLarge
                    text: qsTr("Join a group as an admin")
                    onClicked: pageStack.push(Qt.resolvedUrl("JoinPage.qml"), { admin: true })
                }
                Button {
                    visible: app.keyLevel !== "none"
                    anchors.horizontalCenter: parent.horizontalCenter
                    preferredWidth: Theme.buttonWidthLarge
                    text: qsTr("Join with an invitation")
                    onClicked: pageStack.push(Qt.resolvedUrl("InvitationPage.qml"))
                }
                Button {
                    visible: app.keyLevel !== "none"
                    anchors.horizontalCenter: parent.horizontalCenter
                    preferredWidth: Theme.buttonWidthLarge
                    text: qsTr("Restore with a recovery sheet")
                    enabled: !app.busy
                    onClicked: pageStack.push(Qt.resolvedUrl("RestorePage.qml"))
                }
                Label {
                    visible: app.keyLevel === "none" && !app.busy
                    x: Theme.horizontalPageMargin
                    width: parent.width - 2 * Theme.horizontalPageMargin
                    horizontalAlignment: Text.AlignHCenter
                    text: qsTr("The phone has no key yet. Pull down to check it again.")
                    wrapMode: Text.Wrap
                    color: Theme.highlightColor
                }
            }

            // Home's top (docs/apps.md, Home): how many devices are online,
            // and the two switches. The house: a tap turns sync off or on, a
            // long press picks for how long it stays off. The globe:
            // Everywhere, after its consent; it waits while sync is off.
            Item {
                id: summary
                visible: app.member.running
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                height: Math.max(house.height, words.height)

                Column {
                    id: words
                    anchors.left: parent.left
                    anchors.right: house.left
                    anchors.rightMargin: Theme.paddingMedium
                    anchors.verticalCenter: parent.verticalCenter
                    Label {
                        width: parent.width
                        text: qsTr("%1 of %2 online").arg(app.member.devices.filter(function(d) { return d.online }).length)
                                                     .arg(app.member.devices.length)
                        color: Theme.highlightColor
                        truncationMode: TruncationMode.Fade
                    }
                    Label {
                        width: parent.width
                        text: !app.member.paused ? qsTr("Sync is on")
                            : app.member.pausedUntil.getTime() > 0
                              ? qsTr("Sync is off until %1").arg(Qt.formatTime(app.member.pausedUntil, "hh:mm"))
                              : qsTr("Sync is off")
                        font.pixelSize: Theme.fontSizeSmall
                        color: Theme.secondaryHighlightColor
                        wrapMode: Text.Wrap
                    }
                    Label {
                        width: parent.width
                        text: !app.member.awayOn ? qsTr("Everywhere is off")
                            : app.member.paused ? qsTr("Everywhere waits while sync is off")
                            : app.member.awayStatus === "home" ? qsTr("At home: syncing directly.")
                            : app.member.awayStatus === "connecting" ? qsTr("Connecting to the hub through the tunnel…")
                            : app.member.awayStatus === "connected"
                              ? (app.member.awayHub !== "" ? qsTr("Connected to the hub %1 through the tunnel.").arg(app.member.awayHub)
                                                           : qsTr("Connected to the hub through the tunnel."))
                            : qsTr("Waiting for the hub: open the app at home once, near a computer of the group.")
                        font.pixelSize: Theme.fontSizeExtraSmall
                        color: Theme.secondaryColor
                        wrapMode: Text.Wrap
                    }
                    Label {
                        visible: app.member.awayError !== ""
                        width: parent.width
                        text: app.member.awayError
                        font.pixelSize: Theme.fontSizeExtraSmall
                        color: Theme.errorColor
                        wrapMode: Text.Wrap
                    }
                }
                SwitchFace {
                    id: house
                    anchors.right: globe.left
                    anchors.verticalCenter: parent.verticalCenter
                    glyph: "house"
                    on: !app.member.paused
                    action: on ? qsTr("Turn sync off") : qsTr("Turn sync on")
                    onClicked: app.member.paused ? app.member.resume() : app.member.pause(0)
                    onPressAndHold: if (!app.member.paused) syncMenu.open(summary)
                }
                SwitchFace {
                    id: globe
                    anchors.right: parent.right
                    anchors.verticalCenter: parent.verticalCenter
                    glyph: "globe"
                    on: app.member.awayOn
                    enabled: app.member.awayOn || !app.member.paused
                    action: on ? qsTr("Turn Everywhere off") : qsTr("Turn Everywhere on")
                    onClicked: {
                        if (app.member.awayOn)
                            app.member.setAway(false)
                        else
                            pageStack.push(Qt.resolvedUrl("AwayDialog.qml")).accepted.connect(function() { app.member.setAway(true) })
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

            // "Lost phone?" on the group's only admin: how a second phone
            // becomes one. Closed once, it stays closed.
            BackgroundItem {
                id: lost
                property bool closed: app.tipClosed("lostPhone")
                visible: !closed && app.admin && app.member.running
                         && app.member.devices.filter(function(d) { return d.admin }).length === 1
                height: visible ? lostWords.height + 2 * Theme.paddingMedium : 0
                onClicked: {
                    app.closeTip("lostPhone")
                    closed = true
                }
                Column {
                    id: lostWords
                    x: Theme.horizontalPageMargin
                    width: parent.width - 2 * Theme.horizontalPageMargin
                    anchors.verticalCenter: parent.verticalCenter
                    Label {
                        width: parent.width
                        text: qsTr("Lost phone?")
                        color: Theme.highlightColor
                    }
                    Label {
                        width: parent.width
                        text: qsTr("Make a second phone an admin: on it, tap Join a group as an admin, then scan its code here with Scan a code. Tap to close.")
                        font.pixelSize: Theme.fontSizeExtraSmall
                        color: Theme.secondaryColor
                        wrapMode: Text.Wrap
                    }
                }
            }

            // The group's devices (docs/apps.md, "Screens", Home), as tiles
            // or as a list, in the user's order and collections; a tap opens
            // the device's page, a long press arranges it.
            SectionHeader {
                visible: app.member.devices.length > 0
                text: qsTr("Devices")
            }
            DeviceItems {
                level: page.view
                view: page.view
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
        // The house's times, opened under Home's top by a long press.
        ContextMenu {
            id: syncMenu
            MenuItem { text: qsTr("Off for 15 minutes"); onClicked: app.member.pause(15) }
            MenuItem { text: qsTr("Off for an hour"); onClicked: app.member.pause(60) }
            MenuItem { text: qsTr("Off for 8 hours"); onClicked: app.member.pause(8 * 60) }
            MenuItem { text: qsTr("Off until I turn it on"); onClicked: app.member.pause(0) }
        }
        VerticalScrollDecorator {}
    }
}
