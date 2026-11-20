// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import QtQuick 2.6
import Sailfish.Silica 1.0

// An admin gives a device of the group another name, which every member
// then shows (docs/protocol.md, section 10). Accepting signs it.
Dialog {
    id: dialog
    property var device
    // Like the core's rule: 1 to 64 bytes, no control characters.
    canAccept: !app.busy && field.text.trim().length > 0 && unescape(encodeURIComponent(field.text.trim())).length <= 64
               && !/[\u0000-\u001f\u007f-\u009f]/.test(field.text)

    onAccepted: app.manage("rename", device.id, field.text.trim())

    Column {
        width: parent.width

        DialogHeader {
            title: qsTr("Rename the device")
            acceptText: qsTr("Rename")
        }
        TextField {
            id: field
            width: parent.width
            label: qsTr("Name")
            placeholderText: label
            text: dialog.device ? dialog.device.name : ""
            focus: true
            EnterKey.enabled: dialog.canAccept
            EnterKey.onClicked: dialog.accept()
        }
        Label {
            x: Theme.horizontalPageMargin
            width: parent.width - 2 * Theme.horizontalPageMargin
            wrapMode: Text.Wrap
            font.pixelSize: Theme.fontSizeSmall
            color: Theme.secondaryHighlightColor
            text: qsTr("Every device of the group shows the new name.")
        }
    }
}
