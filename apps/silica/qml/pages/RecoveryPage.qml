// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import QtQuick 2.6
import Sailfish.Silica 1.0

// The group's recovery key, on the root phone (docs/protocol.md, section 10,
// "The recovery key"): the core makes the key, the root key signs its admin
// CA and the recovery record, and the sheet, a QR code and the key in groups
// of four, is shown here once; then the app forgets it. A new key replaces
// the old one. While the sheet is shown, the root can seal it onto a YubiKey
// plugged into the USB-C port (app.sealCard, through the system's pcscd).
Page {
    id: page
    readonly property bool shown: app.recoveryModules.length > 0
    property bool askingPin: false
    property string sealed: ""

    Connections {
        target: app
        onCardSealed: {
            if (ok)
                page.sealed = defaultKey
                    ? qsTr("The recovery key is on the YubiKey, which keeps its factory management key: whoever holds it could erase the key without the PIN. Keep the sheet too.")
                    : qsTr("The recovery key is on the YubiKey. The YubiKey and the sheet hold the same key: keep both, in different places.")
        }
    }

    RemorsePopup { id: remorse }

    // Leaving the page forgets the sheet.
    Component.onDestruction: app.forgetRecovery()

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: column.height + Theme.paddingLarge

        PullDownMenu {
            visible: !page.shown && app.root && app.member.running
            busy: app.busy
            MenuItem {
                visible: app.member.rootView.recovery
                text: qsTr("Remove the recovery key")
                onClicked: remorse.execute(qsTr("Removing the recovery key"), function() { app.removeRecovery() })
            }
            MenuItem {
                text: app.member.rootView.recovery ? qsTr("Make a new recovery key") : qsTr("Make a recovery key")
                onClicked: {
                    if (app.member.rootView.recovery)
                        remorse.execute(qsTr("Replacing the recovery key"), function() { app.makeRecovery() })
                    else
                        app.makeRecovery()
                }
            }
        }

        Column {
            id: column
            width: parent.width
            spacing: Theme.paddingMedium

            PageHeader { title: qsTr("Recovery key") }

            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                color: Theme.highlightColor
                text: page.shown
                      ? qsTr("Write the key down or print this page, and keep it safe. It is shown only once.")
                      : app.member.rootView.recovery
                        ? qsTr("The group has a recovery key. With it a computer of the group or a new phone takes the group over if this phone is lost.")
                        : qsTr("A recovery key lets a computer of the group or a new phone take the group over if this phone is lost. Pull down to make one.")
            }

            Rectangle {
                visible: page.shown
                anchors.horizontalCenter: parent.horizontalCenter
                color: "white"
                property int count: app.recoveryModules.length
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
                            color: app.recoveryModules[row].charAt(col) === "1" ? "black" : "white"
                        }
                    }
                }
            }

            Label {
                visible: page.shown
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                horizontalAlignment: Text.AlignHCenter
                wrapMode: Text.Wrap
                font.family: "monospace"
                font.pixelSize: Theme.fontSizeLarge
                text: app.recoveryText
            }

            Button {
                visible: page.shown && !page.askingPin
                anchors.horizontalCenter: parent.horizontalCenter
                text: qsTr("Put it on a YubiKey")
                enabled: !app.busy
                onClicked: { page.sealed = ""; page.askingPin = true }
            }

            Label {
                visible: page.shown && page.askingPin
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                color: Theme.highlightColor
                text: qsTr("The YubiKey keeps the same key as this sheet, behind its PIN and a touch. If it still has its factory management key, anyone could look that key up and erase the recovery key without the PIN; the app can replace it with one the PIN protects.")
            }

            Label {
                visible: page.shown && page.askingPin
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                color: Theme.secondaryHighlightColor
                text: qsTr("Plug the YubiKey into the USB-C port, type its PIN, then touch it when it blinks.")
            }

            PasswordField {
                id: pin
                visible: page.shown && page.askingPin
                width: parent.width
                label: qsTr("The YubiKey's PIN")
                placeholderText: label
                maximumLength: 8
            }

            Button {
                visible: page.shown && page.askingPin
                anchors.horizontalCenter: parent.horizontalCenter
                text: qsTr("Replace its factory key")
                enabled: !app.busy && pin.text.length >= 6
                onClicked: { var p = pin.text; pin.text = ""; page.askingPin = false; app.sealCard(p, true) }
            }

            Button {
                visible: page.shown && page.askingPin
                anchors.horizontalCenter: parent.horizontalCenter
                text: qsTr("Keep its factory key")
                enabled: !app.busy && pin.text.length >= 6
                onClicked: { var p = pin.text; pin.text = ""; page.askingPin = false; app.sealCard(p, false) }
            }

            Label {
                visible: page.shown && page.sealed !== ""
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                color: Theme.secondaryHighlightColor
                text: page.sealed
            }

            Label {
                visible: app.error !== ""
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                color: Theme.errorColor
                text: app.error
            }

            Button {
                visible: page.shown
                anchors.horizontalCenter: parent.horizontalCenter
                text: qsTr("I wrote it down")
                onClicked: { app.forgetRecovery(); pageStack.pop() }
            }

            BusyIndicator {
                anchors.horizontalCenter: parent.horizontalCenter
                running: app.busy
                visible: running
                size: BusyIndicatorSize.Medium
            }
        }
        VerticalScrollDecorator {}
    }
}
