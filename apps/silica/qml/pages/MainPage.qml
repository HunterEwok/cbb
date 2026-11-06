// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import QtQuick 2.6
import Sailfish.Silica 1.0

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
                visible: app.group === "" && app.keyLevel === "hardware"
                text: qsTr("Join a group")
                onClicked: pageStack.push(Qt.resolvedUrl("JoinPage.qml"))
            }
            MenuItem {
                visible: app.group !== ""
                text: qsTr("Leave the group")
                onClicked: remorse.execute(qsTr("Leaving the group"), function() { app.leave() })
            }
            MenuItem {
                visible: app.member.running
                text: qsTr("Send the clipboard")
                onClicked: app.member.sendClipboard()
            }
            MenuItem {
                text: qsTr("Check the key again")
                enabled: !app.busy
                onClicked: app.setUpKey()
            }
        }

        Column {
            id: column
            width: parent.width
            spacing: Theme.paddingMedium

            PageHeader { title: "CBB" }

            DetailItem { label: qsTr("Version"); value: app.version }
            DetailItem { label: qsTr("Core"); value: app.core }
            DetailItem { label: qsTr("System"); value: app.system }
            DetailItem {
                label: qsTr("Key")
                value: app.busy ? qsTr("Checking…")
                     : app.keyLevel === "hardware" ? qsTr("In the secure element")
                     : qsTr("None yet")
            }
            DetailItem {
                label: qsTr("Group")
                value: app.group !== "" ? app.group : qsTr("None yet")
            }
            DetailItem {
                visible: app.device !== ""
                label: qsTr("Device")
                value: app.device
            }
            DetailItem {
                visible: app.group !== ""
                label: qsTr("Connected to")
                value: app.member.peers.length > 0 ? app.member.peers.join(", ") : qsTr("No one yet")
            }
            DetailItem {
                visible: app.member.last !== ""
                label: qsTr("Last copy")
                value: app.member.last
            }
            DetailItem {
                visible: app.keyFingerprint !== ""
                label: qsTr("Key fingerprint")
                value: app.keyFingerprint
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
