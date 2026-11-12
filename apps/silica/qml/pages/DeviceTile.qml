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

    // The mute button in the corner (docs/apps.md, "Muting from the tile"):
    // on this phone's tile the house, on another device's an admin's mute
    // for the group. A tap holds until undone, a long press picks a time.
    // The tile shows the new state at once: pending holds it until the
    // admin's command is answered.
    readonly property bool cornered: device.self || (app.admin && app.member.running)
    property var pending: undefined
    readonly property bool muted: pending !== undefined ? pending
                                  : device.self ? app.member.paused : device.muted === true

    Connections {
        target: app
        onManaged: if (device === tile.device.device) tile.pending = undefined
    }

    // Muted, the tile's line turns dashed in the warning colour.
    Canvas {
        id: dashes
        anchors.fill: parent
        visible: tile.muted
        onVisibleChanged: requestPaint()
        onWidthChanged: requestPaint()
        onHeightChanged: requestPaint()
        onPaint: {
            var c = getContext("2d")
            c.reset()
            c.strokeStyle = Theme.errorColor
            c.lineWidth = 2
            // Dashes drawn one by one: Qt 5.6's canvas has no line dash.
            function dashed(x1, y1, x2, y2) {
                var len = Math.sqrt((x2 - x1) * (x2 - x1) + (y2 - y1) * (y2 - y1))
                c.beginPath()
                for (var t = 0; t < len; t += 14) {
                    var e = Math.min(t + 8, len)
                    c.moveTo(x1 + (x2 - x1) * t / len, y1 + (y2 - y1) * t / len)
                    c.lineTo(x1 + (x2 - x1) * e / len, y1 + (y2 - y1) * e / len)
                }
                c.stroke()
            }
            var r = width - 1, b = height - 1
            dashed(1, 1, r, 1); dashed(r, 1, r, b); dashed(r, b, 1, b); dashed(1, b, 1, 1)
        }
    }

    function setMuted(on, minutes) {
        if (device.self) {
            if (on) app.member.pause(minutes)
            else app.member.resume()
            return
        }
        pending = on
        if (on) app.manage("mute", device.device, "", minutes)
        else app.manage("unmute", device.device)
    }

    BackgroundItem {
        id: corner
        visible: tile.cornered
        anchors.right: parent.right
        anchors.top: parent.top
        width: Theme.itemSizeSmall
        height: width
        Accessible.role: Accessible.CheckBox
        Accessible.checkable: true
        Accessible.checked: tile.muted
        Accessible.name: tile.device.self ? (tile.muted ? qsTr("Turn sync on") : qsTr("Turn sync off"))
                                          : (tile.muted ? qsTr("Unmute") : qsTr("Mute until unmuted"))
        Accessible.description: Devices.name(tile.device)

        Rectangle {
            anchors.centerIn: parent
            width: Theme.iconSizeSmall + Theme.paddingSmall
            height: width
            radius: Theme.paddingSmall / 2
            color: tile.muted ? Theme.errorColor : "transparent"
            border.width: 1
            border.color: tile.muted ? Theme.errorColor : Theme.secondaryColor
        }
        Canvas {
            id: speaker
            anchors.centerIn: parent
            width: Theme.iconSizeSmall * 0.75
            height: width
            property color tint: tile.muted ? Theme.highlightDimmerColor : corner.highlighted ? Theme.highlightColor : Theme.secondaryColor
            property bool off: tile.muted
            onTintChanged: requestPaint()
            onOffChanged: requestPaint()
            onPaint: {
                var c = getContext("2d")
                var u = width / 24
                c.reset()
                c.strokeStyle = tint
                c.lineWidth = 2 * u
                c.lineCap = "round"
                c.lineJoin = "round"
                c.beginPath()
                c.moveTo(4 * u, 9 * u); c.lineTo(8 * u, 9 * u); c.lineTo(13 * u, 5 * u)
                c.lineTo(13 * u, 19 * u); c.lineTo(8 * u, 15 * u); c.lineTo(4 * u, 15 * u)
                c.closePath()
                c.stroke()
                c.beginPath()
                if (off) {
                    c.moveTo(16 * u, 9 * u); c.lineTo(21 * u, 15 * u)
                    c.moveTo(21 * u, 9 * u); c.lineTo(16 * u, 15 * u)
                } else {
                    c.arc(16.5 * u, 12 * u, 4 * u, -Math.PI / 3, Math.PI / 3)
                }
                c.stroke()
            }
        }

        onClicked: tile.setMuted(!tile.muted, 0)
        onPressAndHold: if (!tile.muted) times.open(tile)
    }

    ContextMenu {
        id: times
        MenuItem {
            text: tile.device.self ? qsTr("Off for 15 minutes") : qsTr("Mute for 15 minutes")
            onClicked: tile.setMuted(true, 15)
        }
        MenuItem {
            text: tile.device.self ? qsTr("Off for an hour") : qsTr("Mute for an hour")
            onClicked: tile.setMuted(true, 60)
        }
        MenuItem {
            text: tile.device.self ? qsTr("Off for 8 hours") : qsTr("Mute for 8 hours")
            onClicked: tile.setMuted(true, 8 * 60)
        }
        MenuItem {
            text: tile.device.self ? qsTr("Off until I turn it on") : qsTr("Mute until unmuted")
            onClicked: tile.setMuted(true, 0)
        }
    }
}
