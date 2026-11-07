// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import QtQuick 2.6
import Sailfish.Silica 1.0

// Making a group of the phone's own (docs/apps.md, "Screens", Start): the
// phone becomes the group's root, its root key in the TEE, and adds the
// computers and phones by their QR codes.
Dialog {
    id: dialog
    canAccept: !app.busy

    onAccepted: app.makeGroup()

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: column.height

        Column {
            id: column
            width: parent.width
            spacing: Theme.paddingLarge

            DialogHeader {
                title: qsTr("Make a group")
                acceptText: qsTr("Make")
            }
            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                color: Theme.highlightColor
                text: qsTr("This phone becomes the group's root: it adds the other devices by their QR codes and makes the phones that ask admins.")
            }
            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                font.pixelSize: Theme.fontSizeSmall
                color: Theme.secondaryHighlightColor
                text: app.keyLevel === "hardware"
                      ? qsTr("The group's root key is made in the phone's secure element and never leaves it.")
                      : qsTr("The group's root key is kept in a file on the phone: anyone who copies it can act as the group's root.")
            }
            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                font.pixelSize: Theme.fontSizeSmall
                color: Theme.secondaryHighlightColor
                text: qsTr("Make another phone an admin soon: if this phone is lost, an admin phone takes the group over.")
            }
        }
    }
}
