// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import QtQuick 2.6
import Sailfish.Silica 1.0

// Send an invitation (docs/protocol.md, section 12), as an admin: the
// invitation opens on this phone when it is the group's hub, else through a
// hub of the group, and its QR code is shown for the person who joins from
// afar; its text can be copied when the QR code goes another way. A device
// that uses it is admitted only once the user sees the same words on it.
Page {
    id: page

    readonly property string step: app.invite.state
    readonly property bool shown: step === "open" || step === "joining"

    Component.onCompleted: app.startInvite(3600)
    Component.onDestruction: app.invite.cancel()

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: column.height

        Column {
            id: column
            width: parent.width
            spacing: Theme.paddingLarge

            PageHeader { title: qsTr("Send an invitation") }

            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                color: Theme.highlightColor
                text: page.step === "preparing" || page.step === "opening" ? qsTr("Opening the invitation on the group's hub…")
                    : page.shown ? qsTr("On a new phone, open CBB, tap Join with an invitation and scan the code. On a computer, run cbb pair -invite with its text. It works once, until %1.")
                                   .arg(Qt.formatTime(new Date(app.invite.expiresMs), Qt.DefaultLocaleShortDate))
                    : page.step === "done" ? qsTr("%1 joined the group; it appears in the list once it connects.").arg(app.invite.joined)
                    : ""
            }

            // The QR code on white, with the quiet zone the scanners need.
            Rectangle {
                visible: page.shown
                anchors.horizontalCenter: parent.horizontalCenter
                color: "white"
                property int count: app.invite.modules.length
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
                            color: app.invite.modules[row].charAt(col) === "1" ? "black" : "white"
                        }
                    }
                }
            }

            Label {
                visible: page.shown
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                color: Theme.secondaryHighlightColor
                text: qsTr("Show or send the code only to the person who joins: anyone who has it can ask to join.")
            }

            Button {
                visible: page.shown
                anchors.horizontalCenter: parent.horizontalCenter
                text: qsTr("Copy the invitation's text")
                onClicked: Clipboard.text = app.invite.text
            }

            BusyIndicator {
                anchors.horizontalCenter: parent.horizontalCenter
                running: page.step === "preparing" || page.step === "opening"
                visible: running
                size: BusyIndicatorSize.Medium
            }

            // A device used the invitation: the user compares its words.
            Label {
                visible: page.step === "joining"
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                font.bold: true
                text: qsTr("Admit %1 (%2)? Admit it only if the device shows the same words:").arg(app.invite.joiningName).arg(app.invite.joiningOs)
            }
            Label {
                visible: page.step === "joining"
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                horizontalAlignment: Text.AlignHCenter
                wrapMode: Text.Wrap
                font.pixelSize: Theme.fontSizeExtraLarge
                text: app.invite.fingerprint
            }
            Button {
                visible: page.step === "joining"
                anchors.horizontalCenter: parent.horizontalCenter
                preferredWidth: Theme.buttonWidthLarge
                text: qsTr("Admit")
                onClicked: app.invite.answer(true)
            }
            Button {
                visible: page.step === "joining"
                anchors.horizontalCenter: parent.horizontalCenter
                preferredWidth: Theme.buttonWidthLarge
                text: qsTr("Not this one")
                onClicked: app.invite.answer(false)
            }

            Label {
                visible: app.invite.error !== ""
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                text: app.invite.error
                wrapMode: Text.Wrap
                color: Theme.errorColor
            }

            Button {
                visible: page.step === "failed" || page.step === "done"
                anchors.horizontalCenter: parent.horizontalCenter
                text: page.step === "failed" ? qsTr("Try again") : qsTr("Invite another device")
                onClicked: app.startInvite(3600)
            }
        }
        VerticalScrollDecorator {}
    }
}
