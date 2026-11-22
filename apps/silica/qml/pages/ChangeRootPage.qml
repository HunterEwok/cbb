// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import QtQuick 2.6
import Sailfish.Silica 1.0

// Moving the group's main device to this phone with the recovery key, on
// 0.6 (docs/apps.md, "Changing the main device"): the sheet's text or its QR
// code's text typed or pasted (the phone has no camera), or the secret a
// YubiKey plugged into the USB-C port opens (app.openCard, through the
// system's pcscd), then the list of who stays, which the core writes
// and the person only unticks (this phone is never in it), then the admin
// PIN, after which the admin key in the TEE becomes the root key. The old
// main device starts unticked. The key stays on the page only until the
// change is made or the page closes.
Page {
    id: page
    property var recovery: null
    property var rows: []
    property bool waiting: false
    property var leaveOut: []
    property bool overWaiting: false
    property bool askingPin: false
    property string note: ""

    Component.onDestruction: page.recovery = null

    function oldRoots() {
        var out = []
        var ds = app.member.devices
        for (var i = 0; i < ds.length; i++)
            if (ds[i].root)
                out.push(ds[i].id)
        return out
    }

    function start(text) {
        var t = text.trim()
        startWith(t.indexOf("cbb://") === 0 ? { "qr": t } : { "text": t })
    }

    function startWith(r) {
        page.leaveOut = oldRoots()
        page.pending = r
        app.changePreview(r, page.leaveOut)
    }

    function toggle(device) {
        var out = page.leaveOut.slice()
        var i = out.indexOf(device)
        if (i >= 0)
            out.splice(i, 1)
        else
            out.push(device)
        page.leaveOut = out
        app.changePreview(page.recovery, out)
    }

    function outcome(row) {
        switch (row.outcome) {
        case "out": return qsTr("Removed")
        case "admin_kept": return qsTr("Stays, and stays an admin")
        case "admin_lost": return qsTr("Stays, no longer an admin: make it an admin again later")
        case "frozen": return qsTr("Stays, frozen until you unfreeze it")
        default: return row.frozen ? qsTr("Stays, frozen until you unfreeze it") : qsTr("Stays")
        }
    }

    // The recovery key being read, before the core said who stays.
    property var pending: null

    Connections {
        target: app
        onChangePreviewed: {
            if (!ok) {
                page.pending = null
                return
            }
            if (page.recovery === null)
                page.recovery = page.pending
            page.pending = null
            page.rows = rows
            page.waiting = waiting
        }
        onRootChangedHere: if (ok) pageStack.pop()
        onCardOpened: {
            if (!ok)
                return
            page.note = qsTr("The YubiKey opened the recovery key.")
            // The secret goes to the core for this change only.
            page.startWith({ "secret": secret })
        }
    }

    RemorsePopup { id: remorse }

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: column.height

        Column {
            id: column
            width: parent.width
            spacing: Theme.paddingLarge

            PageHeader { title: qsTr("Move the group to this phone") }

            Label {
                visible: page.recovery === null
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                color: Theme.highlightColor
                text: qsTr("With the group's recovery key, this phone becomes the main device, for example when the old one is lost.")
            }

            TextArea {
                id: key
                visible: page.recovery === null
                width: parent.width
                label: qsTr("The recovery key's text, as on the sheet")
                placeholderText: label
                font.family: "monospace"
                inputMethodHints: Qt.ImhNoAutoUppercase | Qt.ImhNoPredictiveText | Qt.ImhSensitiveData
            }

            Button {
                visible: page.recovery === null
                anchors.horizontalCenter: parent.horizontalCenter
                text: qsTr("Next")
                enabled: !app.busy && key.text.trim() !== ""
                onClicked: page.start(key.text)
            }

            Button {
                visible: page.recovery === null && !page.askingPin
                anchors.horizontalCenter: parent.horizontalCenter
                text: qsTr("Use a YubiKey instead")
                enabled: !app.busy
                onClicked: page.askingPin = true
            }

            Label {
                visible: page.recovery === null && page.askingPin
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                color: Theme.highlightColor
                text: qsTr("Plug the YubiKey into the USB-C port, type its PIN, then touch it when it blinks.")
            }

            PasswordField {
                id: pin
                visible: page.recovery === null && page.askingPin
                width: parent.width
                label: qsTr("The YubiKey's PIN")
                placeholderText: label
                maximumLength: 8
            }

            Button {
                visible: page.recovery === null && page.askingPin
                anchors.horizontalCenter: parent.horizontalCenter
                text: qsTr("Continue")
                enabled: !app.busy && pin.text.length >= 6
                onClicked: { var p = pin.text; pin.text = ""; page.askingPin = false; app.openCard(p) }
            }

            Label {
                visible: page.note !== ""
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                color: Theme.secondaryHighlightColor
                text: page.note
            }

            Label {
                visible: page.recovery !== null
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                color: Theme.highlightColor
                text: qsTr("Who stays in the group")
            }

            Repeater {
                model: page.recovery !== null ? page.rows : []
                TextSwitch {
                    width: column.width
                    text: modelData.name !== "" ? modelData.name : modelData.device
                    description: page.outcome(modelData)
                    checked: page.leaveOut.indexOf(modelData.device) < 0
                    automaticCheck: false
                    enabled: !app.busy
                    onClicked: page.toggle(modelData.device)
                }
            }

            Label {
                visible: page.recovery !== null && page.waiting
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                color: Theme.errorColor
                text: qsTr("A change of the main device is already on its way, and its records have not all arrived. Connect to your devices first; write over it only if that change will never arrive, for example because the phone that made it is lost.")
            }

            TextSwitch {
                visible: page.recovery !== null && page.waiting
                text: qsTr("Write a new change over it")
                checked: page.overWaiting
                onClicked: page.overWaiting = checked
            }

            Button {
                visible: page.recovery !== null
                anchors.horizontalCenter: parent.horizontalCenter
                text: qsTr("Make this phone the main device")
                enabled: !app.busy && (!page.waiting || page.overWaiting)
                onClicked: remorse.execute(qsTr("Making this phone the main device"), function() {
                    app.changeRoot(page.recovery, page.leaveOut, page.overWaiting)
                })
            }

            Label {
                visible: page.recovery !== null
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                font.pixelSize: Theme.fontSizeSmall
                color: Theme.secondaryHighlightColor
                text: qsTr("This cannot be undone. The admin PIN confirms it, and the group's devices follow this phone as soon as they connect.")
            }

            BusyIndicator {
                visible: app.busy
                running: visible
                size: BusyIndicatorSize.Small
                anchors.horizontalCenter: parent.horizontalCenter
            }

            Label {
                visible: app.error !== ""
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                text: app.error
                wrapMode: Text.Wrap
                color: Theme.errorColor
            }
        }
        VerticalScrollDecorator {}
    }
}
