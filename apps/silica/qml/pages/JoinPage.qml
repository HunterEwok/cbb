// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import QtQuick 2.6
import Sailfish.Silica 1.0

// The phone's QR code, which the group's phone or computer scans to admit
// it (docs/protocol.md, section 6, "The joiner listens"). The phone joins
// as a member; the group's root may make it an admin later, with the admin
// key its hellos offer, which joining makes behind the admin PIN. With
// invite, an invitation the user accepted (section 12): the phone dials
// the invitation's hub and shows the words the inviting admin compares.
Page {
    id: page
    property string invite: ""
    readonly property bool byInvite: invite !== ""

    function start() {
        if (byInvite)
            app.startJoinByInvite(invite)
        else
            app.startJoin()
    }

    // Started once the page is in place: it may ask for the PIN first, and
    // the page stack takes no dialog while this page is still being pushed.
    property bool started: false
    onStatusChanged: {
        if (status === PageStatus.Active && !started) {
            started = true
            start()
        }
    }
    Component.onDestruction: if (app.join.state !== "joined") app.stopJoin()

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: column.height

        Column {
            id: column
            width: parent.width
            spacing: Theme.paddingLarge

            PageHeader { title: page.byInvite ? qsTr("Join with an invitation") : qsTr("Join a group") }

            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                color: Theme.highlightColor
                text: app.join.state === "joined" ? qsTr("The phone is in the group now.")
                    : app.join.state === "joining" && !page.byInvite ? qsTr("Joining…")
                    : app.join.state === "failed" ? ""
                    : page.byInvite ? qsTr("Whoever invited you sees these words on their device and admits this phone if they match. Keep this screen open.")
                    : app.busy ? qsTr("Making the admin key…")
                    // Shown with the code only: before it, the PIN dialog
                    // may cover the page at once, and a text that flashes
                    // by can't be read.
                    : app.join.state !== "listening" ? ""
                    : qsTr("On a phone of the group, tap + and scan this code. On a computer of the group, tap + and type the numbers. Keep this screen open.")
            }

            Label {
                visible: page.byInvite && app.join.fingerprint !== "" && (app.join.state === "dialing" || app.join.state === "joining")
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                horizontalAlignment: Text.AlignHCenter
                text: app.join.fingerprint
                font.pixelSize: Theme.fontSizeExtraLarge
                font.bold: true
                wrapMode: Text.Wrap
            }

            Label {
                visible: page.byInvite && app.join.state === "dialing"
                anchors.horizontalCenter: parent.horizontalCenter
                text: qsTr("Connecting to the group's hub…")
                color: Theme.secondaryHighlightColor
            }

            // The QR code on white, with the quiet zone the scanners need.
            Rectangle {
                visible: !page.byInvite && (app.join.state === "listening" || app.join.state === "joining")
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
                running: app.join.state === "joining" || app.join.state === "dialing" || app.busy
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
                onClicked: page.start()
            }
        }
        VerticalScrollDecorator {}
    }
}
