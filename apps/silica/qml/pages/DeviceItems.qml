// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import QtQuick 2.6
import Sailfish.Silica 1.0
import "arrange.js" as Arrange

// The items of one level of the arrangement (App::arranged), as tiles or
// as a list (the setting deviceList), on the main page and a collection's
// page. A tap opens a device or a collection; a long press opens the
// changes of the arrangement for it. In the list a collection is a section:
// its header, then its devices.
Column {
    id: items
    property var level: []         // the items, of kind "device" or "collection"
    property var view: []          // the whole view, for the collections
    property string inCollection: "" // the collection these devices are in

    // This phone stays first, out of the arrangement: its level leaves it out.
    function arrange(level, index, inCollection) {
        var item = level[index]
        if (item.kind === "device" && item.device.self)
            return
        var others = level.filter(function(i) { return !(i.kind === "device" && i.device.self) })
        pageStack.push(Qt.resolvedUrl("ArrangePage.qml"), {
            item: item, level: others, index: others.indexOf(item), view: items.view, inCollection: inCollection
        })
    }

    width: parent.width

    Flow {
        id: tiles
        visible: !app.deviceList
        x: Theme.horizontalPageMargin - Theme.paddingSmall
        width: parent.width - 2 * x
        // Tiles at least as wide as on the other phones, two in a row on a
        // phone held upright, so their words fit.
        property int perRow: Math.max(2, Math.floor(width / (Theme.itemSizeExtraLarge * 2.2)))
        Repeater {
            model: tiles.visible ? items.level : []
            Loader {
                width: tiles.width / tiles.perRow
                sourceComponent: modelData.kind === "device" ? deviceTile : collectionTile
                property var entry: modelData
                property int at: index
            }
        }
        Component {
            id: deviceTile
            DeviceTile {
                device: entry.device
                onPressAndHold: items.arrange(items.level, at, items.inCollection)
            }
        }
        Component {
            id: collectionTile
            CollectionTile {
                collection: entry
                onPressAndHold: items.arrange(items.level, at, "")
            }
        }
    }

    Repeater {
        model: app.deviceList ? items.level : []
        Column {
            width: items.width
            property var entry: modelData
            property int at: index
            DeviceRow {
                visible: entry.kind === "device"
                width: parent.width
                device: entry.kind === "device" ? entry.device : ({})
                onPressAndHold: items.arrange(items.level, at, items.inCollection)
            }
            BackgroundItem {
                visible: entry.kind === "collection"
                width: parent.width
                height: Theme.itemSizeSmall
                onClicked: pageStack.push(Qt.resolvedUrl("CollectionPage.qml"), { collection: entry.id })
                onPressAndHold: items.arrange(items.level, at, "")
                Label {
                    x: Theme.horizontalPageMargin
                    width: parent.width - 2 * x
                    anchors.verticalCenter: parent.verticalCenter
                    horizontalAlignment: Text.AlignRight
                    text: entry.kind === "collection"
                          ? entry.name + " · " + qsTr("%1 of %2 online").arg(Arrange.online(entry.devices)).arg(entry.devices.length)
                          : ""
                    font.pixelSize: Theme.fontSizeSmall
                    color: Theme.highlightColor
                    truncationMode: TruncationMode.Fade
                }
            }
            Repeater {
                model: entry.kind === "collection" ? entry.devices : []
                DeviceRow {
                    width: items.width
                    device: modelData
                    onPressAndHold: items.arrange(Arrange.items(entry.devices), index, entry.id)
                }
            }
        }
    }
}
