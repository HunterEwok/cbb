// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import QtQuick 2.6
import Sailfish.Silica 1.0

// The phone's QR code, which the group's phone or computer scans to admit
// it (docs/protocol.md, section 6, "The joiner listens"). With admin, the
// phone asks to be an admin, which only the group's root admits.
Page {
    id: page
    property bool admin: false

    Component.onCompleted: app.startJoin(admin)
    Component.onDestruction: if (app.join.state !== "joined") app.join.stop()

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: column.height

        Column {
            id: column
            width: parent.width
            spacing: Theme.paddingLarge

            PageHeader { title: page.admin ? qsTr("Join as an admin") : qsTr("Join a group") }

            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                color: Theme.highlightColor
                text: app.join.state === "joined" ? qsTr("The phone is in the group now.")
                    : app.join.state === "joining" ? qsTr("Joining…")
                    : app.join.state === "failed" ? ""
                    : app.busy ? qsTr("Making the admin key…")
                    : page.admin ? qsTr("On the group's root computer, admit this phone as an admin with this code: in the CBB app, add a device and choose to admit it as an admin, or run cbb pair -qr -admin. Keep this screen open.")
                    : qsTr("On a phone of the group, tap + and scan this code. On a computer of the group, tap + and type the numbers. Keep this screen open.")
            }

            // The QR code on white, with the quiet zone the scanners need.
            Rectangle {
                visible: app.join.state === "listening" || app.join.state === "joining"
                anchors.horizontalCenter: parent.horizontalCenter
                color: "white"
                property int count: app.join.modules.length
                property real cell: Math.floor((page.width - 2 * Theme.horizontalPageMargin) / Math.max(count + 8, 1))
                width: cell * (count + 8)
                height: width

                Grid {
                    x: parent.cell * 4
                    y: parent.cell * 4
                    columns: parent.count
                    Repeater {
                        model: parent.parent.count * parent.parent.count
                        Rectangle {
                            property int row: Math.floor(index / parent.columns)
                            property int col: index % parent.columns
                            width: parent.parent.cell
                            height: width
                            color: app.join.modules[row].charAt(col) === "1" ? "black" : "white"
                        }
                    }
                }
            }

            Label {
                visible: app.join.code !== "" && (app.join.state === "listening" || app.join.state === "joining")
                anchors.horizontalCenter: parent.horizontalCenter
                text: app.join.code
                font.pixelSize: Theme.fontSizeHuge
                font.letterSpacing: Theme.paddingSmall
            }

            BusyIndicator {
                anchors.horizontalCenter: parent.horizontalCenter
                running: app.join.state === "joining" || app.busy
                visible: running
                size: BusyIndicatorSize.Medium
            }

            Label {
                visible: app.join.error !== "" && app.join.state !== "joined"
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                text: app.join.error
                wrapMode: Text.Wrap
                color: Theme.errorColor
            }

            Button {
                visible: app.join.state === "failed"
                anchors.horizontalCenter: parent.horizontalCenter
                text: qsTr("Try again")
                onClicked: app.startJoin(page.admin)
            }
        }
        VerticalScrollDecorator {}
    }
}
