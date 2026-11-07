// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import QtQuick 2.6
import Sailfish.Silica 1.0
import "devices.js" as Devices

// A device's tile on the main page (docs/apps.md, "Screens", Home): its
// icon, a live dot, its name, its system and, on a line of its own, its
// mark, so a narrow tile cuts neither.
BackgroundItem {
    id: tile
    property var device

    height: words.y + nameLabel.height + 2 * systemLabel.height + Theme.paddingMedium

    Item {
        id: glyph
        anchors.horizontalCenter: parent.horizontalCenter
        y: Theme.paddingMedium
        width: Theme.iconSizeMedium
        height: Theme.iconSizeMedium

        Image {
            id: image
            anchors.fill: parent
            source: Devices.icon(tile.device) + "?" + (tile.highlighted ? Theme.highlightColor : Theme.primaryColor)
            sourceSize.width: width
            sourceSize.height: height
        }
        Label {
            visible: image.status !== Image.Ready
            anchors.centerIn: parent
            text: Devices.name(tile.device).charAt(0).toUpperCase()
            font.pixelSize: Theme.fontSizeLarge
            color: tile.highlighted ? Theme.highlightColor : Theme.primaryColor
        }
        Rectangle {
            visible: tile.device.online || tile.device.self
            anchors.right: parent.right
            anchors.top: parent.top
            width: Theme.paddingMedium
            height: width
            radius: width / 2
            color: Theme.highlightColor
        }
    }

    Column {
        id: words
        anchors.top: glyph.bottom
        anchors.topMargin: Theme.paddingSmall
        x: Theme.paddingSmall
        width: parent.width - 2 * Theme.paddingSmall

        Label {
            id: nameLabel
            width: parent.width
            horizontalAlignment: Text.AlignHCenter
            text: Devices.name(tile.device)
            font.pixelSize: Theme.fontSizeSmall
            color: tile.highlighted ? Theme.highlightColor : Theme.primaryColor
            truncationMode: TruncationMode.Fade
        }
        Label {
            id: systemLabel
            width: parent.width
            horizontalAlignment: Text.AlignHCenter
            text: Devices.system(tile.device)
            font.pixelSize: Theme.fontSizeExtraSmall
            color: Theme.secondaryColor
            truncationMode: TruncationMode.Fade
        }
        Label {
            width: parent.width
            horizontalAlignment: Text.AlignHCenter
            text: Devices.mark(tile.device)
            font.pixelSize: Theme.fontSizeExtraSmall
            color: Theme.secondaryColor
            truncationMode: TruncationMode.Fade
        }
    }

    onClicked: pageStack.push(Qt.resolvedUrl("DevicePage.qml"), { device: tile.device })
}
