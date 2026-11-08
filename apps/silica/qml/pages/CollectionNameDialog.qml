// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import QtQuick 2.6
import Sailfish.Silica 1.0

// A collection's name: a new collection of devices, or a new name for
// collection.
Dialog {
    id: dialog
    property var devices: []
    property string collection: ""
    property string name: ""

    canAccept: field.text.trim() !== "" && field.text.trim() !== dialog.name

    Column {
        width: parent.width
        DialogHeader {
            acceptText: dialog.collection === "" ? qsTr("Make") : qsTr("Rename")
            title: dialog.collection === "" ? qsTr("New collection") : qsTr("Rename collection")
        }
        TextField {
            id: field
            width: parent.width
            focus: true
            label: qsTr("Name")
            placeholderText: qsTr("Office, Home, TVs…")
            text: dialog.name
            // A name has at most 64 bytes (docs/apps.md); the core refuses a longer one.
            maximumLength: 64
            EnterKey.enabled: dialog.canAccept
            EnterKey.onClicked: dialog.accept()
        }
    }

    onAccepted: app.arrange(dialog.collection === ""
                            ? { op: "new", name: field.text.trim(), devices: dialog.devices }
                            : { op: "rename", collection: dialog.collection, name: field.text.trim() })
}
