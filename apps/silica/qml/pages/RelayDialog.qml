// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import QtQuick 2.6
import Sailfish.Silica 1.0

// The consent before the group meets at a blind relay, as on the other
// phones: what the relay learns; accepting sets it.
Dialog {
    SilicaFlickable {
        anchors.fill: parent
        contentHeight: column.height

        Column {
            id: column
            width: parent.width
            spacing: Theme.paddingLarge

            DialogHeader {
                title: qsTr("Meet at this relay?")
                acceptText: qsTr("Meet at this relay")
            }
            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                color: Theme.highlightColor
                text: qsTr("The clipboard stays encrypted end to end between the devices: the relay cannot read it or pose as a device. It does learn, while the devices use it, which devices of the group are online and their internet addresses, and which of them talk to each other, when and how much they send. A hub of the group's own lets none of this out. Use a relay you run yourself, or one whose operator you trust with this.")
            }
        }
        VerticalScrollDecorator {}
    }
}
