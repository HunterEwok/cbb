// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import QtQuick 2.6
import Sailfish.Silica 1.0

// "Add a device" in a group of 0.6 (docs/apps.md, "Screens"): the admin
// phone opens its home window, shows its QR code and six digits and
// announces it at home; a new phone scans the code, or a device without a
// camera finds the window and its person types the digits. Nobody is asked;
// the window lets one device in. Leaving the page closes the window.
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
                visible: (page.step === "open" || page.step === "joining") && app.window.modules.length > 0
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

            // The digits a device without a camera types, in two groups of three.
            Label {
                visible: (page.step === "open" || page.step === "joining") && app.window.digits !== ""
                anchors.horizontalCenter: parent.horizontalCenter
                text: app.window.digits.substring(0, 3) + " " + app.window.digits.substring(3)
                font.family: "monospace"
                font.pixelSize: Theme.fontSizeHuge
                font.bold: true
                font.letterSpacing: Theme.paddingSmall
            }

            Label {
                visible: page.step === "open" || page.step === "joining"
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                color: Theme.secondaryHighlightColor
                text: qsTr("On the new phone, open CBB, tap Join a group and scan this code. A device without a camera, such as a computer, asks for these six digits. Keep this screen open.")
            }

            Row {
                visible: page.step === "open" || page.step === "joining" || page.step === "preparing"
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
                visible: page.step === "closed" && app.window.error === ""
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
                visible: page.step === "failed" || page.step === "closed" || page.step === "done"
                anchors.horizontalCenter: parent.horizontalCenter
                text: page.step === "done" ? qsTr("Add a device") : qsTr("Try again")
                onClicked: app.openWindow()
            }
        }
        VerticalScrollDecorator {}
    }
}
