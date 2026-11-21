// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import QtQuick 2.6
import Sailfish.Silica 1.0

// Joining by an invitation the user accepted (docs/protocol.md, section
// 12): the phone dials the invitation's hub and shows the words the
// inviting admin compares. Joining at home is JoinWindowPage's.
Page {
    id: page
    property string invite: ""

    function start() {
        app.startJoinByInvite(invite)
    }

    // Started once the page is in place, as the page stack takes nothing
    // more while this page is still being pushed.
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

            PageHeader { title: qsTr("Join with an invitation") }

            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                color: Theme.highlightColor
                text: app.join.state === "joined" ? qsTr("The phone is in the group now.")
                    : app.join.state === "failed" ? ""
                    : qsTr("Whoever invited you sees these words on their device and admits this phone if they match. Keep this screen open.")
            }

            Label {
                visible: app.join.fingerprint !== "" && (app.join.state === "dialing" || app.join.state === "joining")
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                horizontalAlignment: Text.AlignHCenter
                text: app.join.fingerprint
                font.pixelSize: Theme.fontSizeExtraLarge
                font.bold: true
                wrapMode: Text.Wrap
            }

            Label {
                visible: app.join.state === "dialing"
                anchors.horizontalCenter: parent.horizontalCenter
                text: qsTr("Connecting to the group's hub…")
                color: Theme.secondaryHighlightColor
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
