// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import QtQuick 2.6
import Sailfish.Silica 1.0

// "Add a device" in a group of 0.6 (docs/apps.md, "Screens"): the admin
// phone opens its pairing window, shows its QR code and announces it at
// home; a new phone scans the code or finds the window by itself, and the
// code both screens show waits for the person's "they match". Leaving the
// page closes the window.
Page {
    id: page
    readonly property string step: app.window.state

    // Opened once the page is in place: it may ask for the PIN first, and
    // the page stack takes no dialog while this page is still being pushed.
    property bool opened: false
    onStatusChanged: {
        if (status === PageStatus.Active && !opened) {
            opened = true
            app.openWindow()
        }
    }
    Component.onDestruction: app.window.close()

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: column.height

        Column {
            id: column
            width: parent.width
            spacing: Theme.paddingLarge

            PageHeader { title: qsTr("Add a device") }

            CodeQuestion {
                visible: page.step === "joining"
                who: qsTr("%1 asks to join.").arg(app.window.joiningName)
                code: app.window.code
                onAnswered: app.window.answer(yes)
            }

            Label {
                visible: page.step === "done"
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                color: Theme.highlightColor
                text: qsTr("%1 is in the group now.").arg(app.window.joined)
            }

            // The QR code on white, with the quiet zone the scanners need.
            Rectangle {
                visible: (page.step === "open" || page.step === "done") && app.window.modules.length > 0
                anchors.horizontalCenter: parent.horizontalCenter
                color: "white"
                property int count: app.window.modules.length
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
                            color: app.window.modules[row].charAt(col) === "1" ? "black" : "white"
                        }
                    }
                }
            }

            Label {
                visible: page.step === "open" || page.step === "done"
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                color: Theme.secondaryHighlightColor
                text: qsTr("On the new phone, open CBB, tap Join a group and scan this code. A new computer finds this window by itself when it joins. Keep this screen open.")
            }

            Row {
                visible: page.step === "open" || page.step === "done" || page.step === "preparing"
                anchors.horizontalCenter: parent.horizontalCenter
                spacing: Theme.paddingMedium
                BusyIndicator {
                    running: parent.visible
                    size: BusyIndicatorSize.Small
                    anchors.verticalCenter: parent.verticalCenter
                }
                Label {
                    anchors.verticalCenter: parent.verticalCenter
                    color: Theme.secondaryHighlightColor
                    text: page.step === "preparing" ? qsTr("Connecting to the device…") : qsTr("Waiting for the new device…")
                }
            }

            Label {
                visible: page.step === "closed"
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                color: Theme.highlightColor
                text: qsTr("The time to add a device is up.")
            }

            Label {
                visible: app.window.error !== ""
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                text: app.window.error
                wrapMode: Text.Wrap
                color: Theme.errorColor
            }

            Button {
                visible: page.step === "failed" || page.step === "closed"
                anchors.horizontalCenter: parent.horizontalCenter
                text: qsTr("Try again")
                onClicked: app.openWindow()
            }
        }
        VerticalScrollDecorator {}
    }
}
