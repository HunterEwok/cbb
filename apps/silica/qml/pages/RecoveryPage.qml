// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import QtQuick 2.6
import Sailfish.Silica 1.0

// The group's recovery key, on the root phone (docs/protocol.md, section 9,
// "The recovery sheet (0.6)"): made with the group and fixed in its ID. Right
// after the group is made the page offers to save it on a sheet (shown here,
// saved as a PDF in Documents), on a YubiKey plugged into the USB-C port
// (app.sealCard, through the system's pcscd), or both; leaving without
// either asks first. Then the app forgets the sheet. Later the page only
// says that the key was made with the group (D-126).
Page {
    id: page
    readonly property bool shown: app.recoveryModules.length > 0
    // What the person looks at: the choice, the sheet, or the YubiKey.
    property string step: "choice"
    property bool sheetSeen: false
    property string savedAt: ""
    property bool sealed: false
    readonly property bool saved: page.sealed || page.savedAt !== ""

    // The sheet leaves only through Done, which asks when nothing was saved.
    backNavigation: !page.shown
    showNavigationIndicator: !page.shown

    Connections {
        target: app
        onCardSealed: if (ok) page.sealed = true
    }

    // Leaving the page forgets the sheet.
    Component.onDestruction: app.forgetRecovery()

    function leave() {
        app.forgetRecovery()
        pageStack.pop()
    }

    Component {
        id: unsaved
        Dialog {
            onAccepted: page.leave()
            Column {
                width: parent.width
                spacing: Theme.paddingLarge
                DialogHeader { acceptText: qsTr("Leave without saving") }
                Label {
                    x: Theme.horizontalPageMargin
                    width: parent.width - 2 * Theme.horizontalPageMargin
                    wrapMode: Text.Wrap
                    color: Theme.highlightColor
                    font.pixelSize: Theme.fontSizeLarge
                    text: qsTr("Leave without saving the recovery key?")
                }
                Label {
                    x: Theme.horizontalPageMargin
                    width: parent.width - 2 * Theme.horizontalPageMargin
                    wrapMode: Text.Wrap
                    color: Theme.secondaryHighlightColor
                    text: qsTr("Without it, losing this phone means making a new group and joining every device to it again.")
                }
            }
        }
    }

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: column.height + Theme.paddingLarge

        Column {
            id: column
            width: parent.width
            spacing: Theme.paddingMedium

            PageHeader { title: page.shown ? qsTr("Save the group's recovery key") : qsTr("Recovery key") }

            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                color: Theme.highlightColor
                text: !page.shown
                      ? qsTr("Made with the group, and its sheet was shown once. Without the sheet the group's main device cannot change: if the sheet is lost, make a new group.")
                      : page.step === "choice"
                        ? qsTr("Save it on a sheet, on a YubiKey, or both. Only with it can the group move to another main device if this phone is lost. It is shown only now.")
                        : page.step === "sheet"
                          ? qsTr("Write the key down or save this page, and keep it safe.")
                          : qsTr("Insert your YubiKey into the USB-C port, type its PIN, then touch it when it blinks.")
            }

            // The choice: both are allowed, one after the other.
            Button {
                visible: page.shown && page.step === "choice"
                anchors.horizontalCenter: parent.horizontalCenter
                text: qsTr("Write on a sheet")
                onClicked: { page.step = "sheet"; page.sheetSeen = true }
            }
            Button {
                visible: page.shown && page.step === "choice"
                anchors.horizontalCenter: parent.horizontalCenter
                text: qsTr("Write to YubiKey")
                enabled: !app.busy && !page.sealed
                onClicked: page.step = "yubikey"
            }
            Label {
                visible: page.shown && page.step === "choice" && (page.saved || page.sheetSeen)
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                color: Theme.secondaryHighlightColor
                text: [page.savedAt !== "" ? qsTr("The sheet is saved in Documents.") : "",
                       page.sealed ? qsTr("The recovery key is on the YubiKey. The YubiKey and the sheet hold the same key: keep both, in different places.") : ""]
                      .filter(function(s) { return s !== "" }).join("\n")
            }

            // The sheet.
            Rectangle {
                visible: page.shown && page.step === "sheet"
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
                visible: page.shown && page.step === "sheet"
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                horizontalAlignment: Text.AlignHCenter
                wrapMode: Text.Wrap
                font.family: "monospace"
                font.pixelSize: Theme.fontSizeLarge
                text: app.recoveryText
            }
            Button {
                visible: page.shown && page.step === "sheet"
                anchors.horizontalCenter: parent.horizontalCenter
                text: qsTr("Save as PDF")
                onClicked: { var at = app.saveSheet(); if (at !== "") page.savedAt = at }
            }
            Label {
                visible: page.shown && page.step === "sheet"
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                color: Theme.secondaryHighlightColor
                text: page.savedAt !== ""
                      ? qsTr("Saved as %1. This file is the group's key: copy it off the phone to paper or a drive kept safe, then delete it here.").arg(page.savedAt)
                      : qsTr("A saved file is the group's key: copy it off the phone to paper or a drive kept safe, then delete it here.")
            }

            // The YubiKey: plugged in, its PIN, then a touch.
            PasswordField {
                id: pin
                visible: page.shown && page.step === "yubikey" && !page.sealed
                width: parent.width
                label: qsTr("The YubiKey's PIN")
                placeholderText: label
                maximumLength: 8
                inputMethodHints: Qt.ImhDigitsOnly
                EnterKey.enabled: text.length >= 6 && !app.busy
                EnterKey.onClicked: go.clicked(null)
            }
            Button {
                id: go
                visible: page.shown && page.step === "yubikey" && !page.sealed
                anchors.horizontalCenter: parent.horizontalCenter
                text: qsTr("Continue")
                enabled: !app.busy && pin.text.length >= 6
                onClicked: { var p = pin.text; pin.text = ""; app.sealCard(p) }
            }
            Label {
                visible: page.shown && page.step === "yubikey" && app.busy
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                color: Theme.highlightColor
                text: qsTr("Touch the YubiKey when it blinks.")
            }
            Label {
                visible: page.shown && page.step === "yubikey" && page.sealed
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                color: Theme.secondaryHighlightColor
                text: qsTr("The recovery key is on the YubiKey. The YubiKey and the sheet hold the same key: keep both, in different places.")
            }

            Label {
                visible: app.error !== ""
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                color: Theme.errorColor
                text: app.error
            }

            BusyIndicator {
                anchors.horizontalCenter: parent.horizontalCenter
                running: app.busy
                visible: running
                size: BusyIndicatorSize.Medium
            }

            Button {
                visible: page.shown && page.step !== "choice"
                anchors.horizontalCenter: parent.horizontalCenter
                text: qsTr("Back")
                enabled: !app.busy
                onClicked: page.step = "choice"
            }
            // Done: straight out once something is saved; after only looking
            // at the sheet it means it was written down; else it asks.
            Button {
                visible: page.shown && page.step === "choice"
                anchors.horizontalCenter: parent.horizontalCenter
                text: page.saved ? qsTr("Done") : page.sheetSeen ? qsTr("I wrote it down") : qsTr("Done")
                enabled: !app.busy
                onClicked: {
                    if (page.saved || page.sheetSeen)
                        page.leave()
                    else
                        pageStack.push(unsaved)
                }
            }
        }
        VerticalScrollDecorator {}
    }
}
