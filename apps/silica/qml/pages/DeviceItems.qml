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
// a drag carries the tile over the others. In the list a
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

    // A drag among the tiles, as on the iPhone: the tile itself follows the
    // finger, lifted, the others make way as it passes over them, and a
    // device held over the middle of a collection goes into it. shown holds
    // the indexes of level in the order the tiles show now.
    property int dragFrom: -1   // the index in level of the dragged item
    property int dragPos: -1    // where it shows now, in shown
    property int dragInto: -1   // the collection it goes into, in shown
    property int dragHit: -1    // the item it last passed over, in level
    property bool dragMoved: false
    property real grabX: 0
    property real grabY: 0

    ListModel { id: shown }

    function rebuild() {
        shown.clear()
        if (app.deviceList)
            return
        for (var i = 0; i < level.length; i++)
            shown.append({ idx: i })
    }
    onLevelChanged: if (dragFrom < 0) rebuild()
    Component.onCompleted: rebuild()
    Connections {
        target: app
        onSettingsChanged: if (items.dragFrom < 0) items.rebuild()
    }

    function tileAt(x, y) {
        for (var i = 0; i < tileRepeater.count; i++) {
            var t = tileRepeater.itemAt(i)
            if (t && x >= t.x && x < t.x + t.width && y >= t.y && y < t.y + t.height)
                return i
        }
        return -1
    }
    function dragStart(at, tile, mouse) {
        var pos = -1
        for (var i = 0; i < shown.count; i++)
            if (shown.get(i).idx === at)
                pos = i
        if (pos < 0)
            return
        dragFrom = at
        dragPos = pos
        dragInto = -1
        dragHit = -1
        dragMoved = false
        grabX = mouse.x
        grabY = mouse.y
        var p = tile.mapToItem(tileBox, 0, 0)
        ghost.x = p.x
        ghost.y = p.y
    }
    function dragMove(tile, mouse) {
        if (dragFrom < 0 || settle.running)
            return
        var p = tile.mapToItem(tileBox, mouse.x, mouse.y)
        ghost.x = p.x - grabX
        ghost.y = p.y - grabY
        dragMoved = true
        // The others are still moving out of the way.
        if (shifting.running)
            return
        var f = tile.mapToItem(tiles, mouse.x, mouse.y)
        var over = tileAt(f.x, f.y)
        if (over < 0) {
            dragHit = -1
            dragInto = -1
            return
        }
        // The tile it passed over keeps its outline as it makes way.
        if (over === dragPos) {
            dragInto = -1
            return
        }
        dragHit = shown.get(over).idx
        var t = tileRepeater.itemAt(over)
        var target = items.level[shown.get(over).idx]
        if (target.kind === "collection" && items.level[dragFrom].kind === "device") {
            // The middle of a collection takes the device; its edges make way.
            var cx = Math.abs(f.x - (t.x + t.width / 2)) < t.width / 4
            var cy = Math.abs(f.y - (t.y + t.height / 2)) < t.height / 4
            if (cx && cy) {
                dragInto = over
                return
            }
        }
        dragInto = -1
        shown.move(dragPos, over, 1)
        dragPos = over
        shifting.restart()
    }
    function dragEnd(dropped) {
        if (dragFrom < 0)
            return
        if (!dropped) {
            finish()
            return
        }
        if (!dragMoved) {
            var at = dragFrom
            finish()
            items.arrange(items.level, at, items.level[at].kind === "device" ? items.inCollection : "")
            return
        }
        // Settles into its place, or into the collection, then changes.
        var slot = tileRepeater.itemAt(dragInto >= 0 ? dragInto : dragPos)
        var p = slot.mapToItem(tileBox, 0, 0)
        settleX.to = p.x
        settleY.to = p.y
        settleScale.to = dragInto >= 0 ? 0.4 : 1
        settle.start()
    }
    function finish() {
        var from = dragFrom, pos = dragPos, into = dragInto, moved = dragMoved
        dragFrom = -1
        dragPos = -1
        dragInto = -1
        dragHit = -1
        dragMoved = false
        if (!moved || from < 0)
            return
        var item = items.level[from]
        var op = null
        if (into >= 0) {
            op = { op: "into", device: item.device.device, collection: items.level[shown.get(into).idx].id }
        } else if (pos !== from) {
            op = pos + 1 < shown.count
                    ? { op: "move", item: Arrange.ref(item), before: Arrange.ref(items.level[shown.get(pos + 1).idx]) }
                    : { op: "move", item: Arrange.ref(item) }
        }
        if (op)
            app.arrange(op)
        else
            rebuild()
    }
    Timer { id: shifting; interval: 220 }

    width: parent.width

    Item {
        id: tileBox
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
            // The others make way as the dragged tile passes.
            move: Transition {
                NumberAnimation { properties: "x,y"; duration: 200; easing.type: Easing.OutCubic }
            }
            Repeater {
                id: tileRepeater
                model: shown
                Loader {
                    width: tiles.width / tiles.perRow
                    readonly property var entry: items.level[model.idx]
                    readonly property int at: model.idx
                    sourceComponent: entry && entry.kind === "collection" ? collectionTile : deviceTile
                    // The dragged tile's place stays empty under it.
                    opacity: items.dragFrom === at ? 0 : 1
                    // The tile the dragged one passes over.
                    Rectangle {
                        visible: items.dragMoved && items.dragHit === at && items.dragInto < 0
                        anchors.fill: parent
                        anchors.margins: Theme.paddingSmall
                        radius: Theme.paddingSmall
                        color: "transparent"
                        border.width: 2
                        border.color: Theme.highlightColor
                    }
                    // A collection that takes the dragged device.
                    Rectangle {
                        visible: items.dragInto === index
                        anchors.fill: parent
                        anchors.margins: Theme.paddingSmall
                        radius: Theme.paddingSmall
                        color: Theme.rgba(Theme.highlightBackgroundColor, 0.2)
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
                enabled: at >= 0
                preventStealing: items.dragFrom === at && at >= 0
                onPressAndHold: items.dragStart(at, dt, mouse)
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
                enabled: at >= 0
                preventStealing: items.dragFrom === at && at >= 0
                onPressAndHold: items.dragStart(at, ct, mouse)
                onPositionChanged: items.dragMove(ct, mouse)
                onReleased: items.dragEnd(true)
                onCanceled: items.dragEnd(false)
            }
        }

        // The dragged tile itself, lifted above the others.
        Loader {
            id: ghost
            visible: items.dragFrom >= 0
            z: 10
            width: tiles.width / tiles.perRow
            scale: 1.08
            opacity: 0.95
            readonly property var entry: items.dragFrom >= 0 ? items.level[items.dragFrom] : null
            readonly property int at: -1
            sourceComponent: entry === null ? null : entry.kind === "collection" ? collectionTile : deviceTile
            Rectangle {
                z: -1
                anchors.fill: parent
                radius: Theme.paddingSmall
                color: Theme.rgba(Theme.highlightBackgroundColor, 0.25)
            }
        }
        ParallelAnimation {
            id: settle
            NumberAnimation { id: settleX; target: ghost; property: "x"; duration: 180; easing.type: Easing.OutCubic }
            NumberAnimation { id: settleY; target: ghost; property: "y"; duration: 180; easing.type: Easing.OutCubic }
            NumberAnimation { id: settleScale; target: ghost; property: "scale"; duration: 180; easing.type: Easing.OutCubic }
            onStopped: {
                ghost.scale = 1.08
                items.finish()
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
