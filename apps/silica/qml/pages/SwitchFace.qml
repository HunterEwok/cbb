// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import QtQuick 2.6
import Sailfish.Silica 1.0

// One of Home's two switches (docs/apps.md, Home): the house for sync on
// this phone, the globe for Everywhere, sync away from home; drawn on the
// same grid as the other apps' glyphs, filled with the highlight when on.
BackgroundItem {
    id: face
    property string glyph: "house"
    property bool on: false
    // What a screen reader says it does when tapped.
    property string action: ""

    width: Theme.itemSizeLarge
    height: Theme.itemSizeLarge
    Accessible.role: Accessible.CheckBox
    Accessible.checkable: true
    Accessible.checked: on
    Accessible.name: action

    Rectangle {
        anchors.centerIn: parent
        width: parent.width - Theme.paddingSmall
        height: width
        radius: width / 2
        color: face.on ? Theme.rgba(Theme.highlightBackgroundColor, Theme.highlightBackgroundOpacity) : "transparent"
        border.width: face.on ? 0 : 1
        border.color: Theme.rgba(Theme.secondaryColor, face.enabled ? 1 : 0.4)
    }

    Canvas {
        id: canvas
        anchors.centerIn: parent
        width: Theme.iconSizeMedium
        height: width
        property color tint: !face.enabled ? Theme.rgba(Theme.secondaryColor, 0.4)
                             : face.on || face.highlighted ? Theme.highlightColor : Theme.primaryColor
        onTintChanged: requestPaint()
        onPaint: {
            var c = getContext("2d")
            var u = width / 24
            c.reset()
            c.strokeStyle = tint
            c.lineWidth = 1.8 * u
            c.lineCap = "round"
            c.lineJoin = "round"
            function line(x1, y1, x2, y2) {
                c.beginPath()
                c.moveTo(x1 * u, y1 * u)
                c.lineTo(x2 * u, y2 * u)
                c.stroke()
            }
            if (face.glyph === "house") {
                line(3, 11.5, 12, 3.5); line(12, 3.5, 21, 11.5)
                line(5.5, 9.5, 5.5, 20.5); line(18.5, 9.5, 18.5, 20.5); line(5.5, 20.5, 18.5, 20.5)
                line(10, 20.5, 10, 15); line(10, 15, 14, 15); line(14, 15, 14, 20.5)
            } else {
                c.beginPath()
                c.arc(12 * u, 12 * u, 9 * u, 0, 2 * Math.PI)
                c.stroke()
                c.beginPath()
                c.ellipse(8 * u, 3 * u, 8 * u, 18 * u)
                c.stroke()
                line(3, 12, 21, 12)
                line(4.5, 7.5, 19.5, 7.5); line(4.5, 16.5, 19.5, 16.5)
            }
        }
    }
}
