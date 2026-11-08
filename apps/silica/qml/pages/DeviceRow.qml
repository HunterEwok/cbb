// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import QtQuick 2.6
import Sailfish.Silica 1.0
import "devices.js" as Devices

// A device's row in the list view of the main page and a collection's
// page: a live dot, its name, its kind, system and mark.
BackgroundItem {
    id: row
    property var device

    height: Theme.itemSizeMedium
    onClicked: pageStack.push(Qt.resolvedUrl("DevicePage.qml"), { device: row.device })

    Rectangle {
        id: dot
        x: Theme.horizontalPageMargin
        anchors.verticalCenter: parent.verticalCenter
        width: Theme.paddingMedium
        height: width
        radius: width / 2
        color: row.device.online || row.device.self ? Theme.highlightColor : "transparent"
        border.color: Theme.secondaryColor
        border.width: row.device.online || row.device.self ? 0 : 1
    }
    Column {
        anchors.left: dot.right
        anchors.leftMargin: Theme.paddingMedium
        anchors.right: parent.right
        anchors.rightMargin: Theme.horizontalPageMargin
        anchors.verticalCenter: parent.verticalCenter
        Label {
            width: parent.width
            text: Devices.name(row.device)
            color: row.highlighted ? Theme.highlightColor : Theme.primaryColor
            truncationMode: TruncationMode.Fade
        }
        Label {
            width: parent.width
            text: [Devices.kind(row.device), Devices.system(row.device), Devices.mark(row.device)].filter(function(s) { return s !== "" }).join(" · ")
            font.pixelSize: Theme.fontSizeExtraSmall
            color: Theme.secondaryColor
            truncationMode: TruncationMode.Fade
        }
    }
}
