// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import QtQuick 2.6
import Sailfish.Silica 1.0
import "arrange.js" as Arrange
import "devices.js" as Devices

// The items of one level of the arrangement (App::arranged), as tiles or
// as a list (the setting deviceList), on the main page and a collection's
// page. A tap opens a device or a collection; a long press opens the
// changes of the arrangement for it, and among the tiles a long press then
// a drag carries the tile over the others (Arrange.drop). In the list a
// collection is a section: its header, then its devices.
Column {
    id: items
    property var level: []         // the items, of kind "device" or "collection"
    property var view: []          // the whole view, for the collections
    property string inCollection: "" // the collection these devices are in

    // This phone is an item as the others are: first until the user moves it.
    function arrange(level, index, inCollection) {
        pageStack.push(Qt.resolvedUrl("ArrangePage.qml"), {
            item: level[index], level: level, index: index, view: items.view, inCollection: inCollection
        })
    }

    // The tile being dragged and the one under the finger, as indexes of
    // level, -1 when none.
    property int dragFrom: -1
    property int dragOver: -1
    property bool dragMoved: false

    function tileAt(x, y) {
        for (var i = 0; i < tileRepeater.count; i++) {
            var t = tileRepeater.itemAt(i)
            if (t && x >= t.x && x < t.x + t.width && y >= t.y && y < t.y + t.height)
                return i
        }
        return -1
    }
    function dragStart(at) {
        dragFrom = at
        dragOver = at
        dragMoved = false
    }
    function dragMove(tile, mouse) {
        if (dragFrom < 0)
            return
        var p = tile.mapToItem(tiles, mouse.x, mouse.y)
        ghost.x = tiles.x + p.x - ghost.width / 2
        ghost.y = p.y - ghost.height / 2
        var over = tileAt(p.x, p.y)
        if (over !== dragFrom)
            dragMoved = true
        if (over >= 0)
            dragOver = over
    }
    function dragEnd(dropped) {
        var from = dragFrom, to = dragOver, moved = dragMoved
        dragFrom = -1
        dragOver = -1
        if (from < 0 || !dropped)
            return
        if (!moved) {
            items.arrange(items.level, from, items.level[from].kind === "device" ? items.inCollection : "")
            return
        }
        var op = Arrange.drop(items.level, from, to)
        if (op)
            app.arrange(op)
    }

    width: parent.width

    Item {
        visible: !app.deviceList
        width: parent.width
        height: tiles.height

        Flow {
            id: tiles
            x: Theme.horizontalPageMargin - Theme.paddingSmall
            width: parent.width - 2 * x
            // Tiles at least as wide as on the other phones, two in a row on
            // a phone held upright, so their words fit.
            property int perRow: Math.max(2, Math.floor(width / (Theme.itemSizeExtraLarge * 2.2)))
            Repeater {
                id: tileRepeater
                model: !app.deviceList ? items.level : []
                Loader {
                    width: tiles.width / tiles.perRow
                    sourceComponent: modelData.kind === "device" ? deviceTile : collectionTile
                    property var entry: modelData
                    property int at: index
                    opacity: items.dragFrom === at ? 0.3 : 1
                    // Where the dragged tile goes.
                    Rectangle {
                        visible: items.dragMoved && items.dragOver === at && items.dragFrom !== at
                        anchors.fill: parent
                        anchors.margins: Theme.paddingSmall
                        radius: Theme.paddingSmall
                        color: "transparent"
                        border.width: 2
                        border.color: Theme.highlightColor
                    }
                }
            }
        }
        Component {
            id: deviceTile
            DeviceTile {
                id: dt
                device: entry.device
                preventStealing: items.dragFrom === at
                onPressAndHold: items.dragStart(at)
                onPositionChanged: items.dragMove(dt, mouse)
                onReleased: items.dragEnd(true)
                onCanceled: items.dragEnd(false)
            }
        }
        Component {
            id: collectionTile
            CollectionTile {
                id: ct
                collection: entry
                preventStealing: items.dragFrom === at
                onPressAndHold: items.dragStart(at)
                onPositionChanged: items.dragMove(ct, mouse)
                onReleased: items.dragEnd(true)
                onCanceled: items.dragEnd(false)
            }
        }

        // The dragged tile's name under the finger.
        Rectangle {
            id: ghost
            visible: items.dragFrom >= 0 && items.dragMoved
            z: 10
            width: tiles.width / tiles.perRow - 2 * Theme.paddingMedium
            height: Theme.itemSizeSmall
            radius: Theme.paddingSmall
            color: Theme.rgba(Theme.highlightBackgroundColor, 0.9)
            Label {
                anchors.centerIn: parent
                width: parent.width - 2 * Theme.paddingSmall
                horizontalAlignment: Text.AlignHCenter
                truncationMode: TruncationMode.Fade
                text: items.dragFrom < 0 || items.dragFrom >= items.level.length ? ""
                      : items.level[items.dragFrom].kind === "device" ? Devices.name(items.level[items.dragFrom].device)
                      : items.level[items.dragFrom].name
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
