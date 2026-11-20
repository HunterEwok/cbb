// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import QtQuick 2.6
import Sailfish.Silica 1.0
import "arrange.js" as Arrange
import "devices.js" as Devices

// A collection's tile on the main page (docs/apps.md, "Collections and the
// order of the tiles"): up to four of its devices' icons, its name, how
// many are online, and the error colour when one inside is frozen.
BackgroundItem {
    id: tile
    // On a big screen a collection opens as the sidebar's section.
    property var open: null
    property var collection // an item of App::arranged of kind "collection"
    readonly property bool attention: tile.collection.devices.some(function(d) { return d.frozen })

    height: Theme.itemSizeExtraLarge + Theme.paddingLarge

    Rectangle {
        id: glyph
        anchors.horizontalCenter: parent.horizontalCenter
        y: Theme.paddingMedium - Theme.paddingSmall
        width: Theme.iconSizeMedium + 2 * Theme.paddingSmall
        height: width
        radius: Theme.paddingSmall
        color: "transparent"
        border.width: 1
        border.color: tile.attention ? Theme.errorColor : Theme.secondaryColor

        Grid {
            anchors.centerIn: parent
            columns: 2
            Repeater {
                model: tile.collection.devices.slice(0, 4)
                Image {
                    width: Theme.iconSizeMedium / 2
                    height: width
                    source: Devices.icon(modelData) + "?" + (tile.highlighted ? Theme.highlightColor : Theme.primaryColor)
                    sourceSize.width: width
                    sourceSize.height: height
                }
            }
        }
    }

    Column {
        anchors.top: glyph.bottom
        anchors.topMargin: Theme.paddingSmall
        x: Theme.paddingSmall
        width: parent.width - 2 * Theme.paddingSmall

        Label {
            width: parent.width
            horizontalAlignment: Text.AlignHCenter
            text: tile.collection.name
            font.pixelSize: Theme.fontSizeSmall
            color: tile.highlighted ? Theme.highlightColor : Theme.primaryColor
            truncationMode: TruncationMode.Fade
        }
        Label {
            width: parent.width
            horizontalAlignment: Text.AlignHCenter
            text: qsTr("%1 of %2 online").arg(Arrange.online(tile.collection.devices)).arg(tile.collection.devices.length)
            font.pixelSize: Theme.fontSizeExtraSmall
            color: tile.attention ? Theme.errorColor : Theme.secondaryColor
            truncationMode: TruncationMode.Fade
        }
    }

    onClicked: tile.open ? tile.open(tile.collection.id) : pageStack.push(Qt.resolvedUrl("CollectionPage.qml"), { collection: tile.collection.id })
}
