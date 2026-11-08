// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import QtQuick 2.6
import Sailfish.Silica 1.0

// The phone as a Bluetooth keyboard (docs/apps.md, "Bluetooth keyboard"),
// as on Android: it types the clipboard, at a tap, into a TV, a tablet, a
// console or a computer that paired with it, which needs nothing
// installed. Aurora's own pairing dialog asks the user about a new device.
Page {
    id: page
    readonly property var kb: app.keyboard

    // Ticks the time left while the phone is visible.
    Timer {
        id: clock
        property date now: new Date()
        interval: 1000
        repeat: true
        running: page.kb.visibleUntil.getTime() > 0
        onTriggered: now = new Date()
    }

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: column.height

        Column {
            id: column
            width: parent.width

            PageHeader { title: qsTr("Bluetooth keyboard") }

            TextSwitch {
                text: qsTr("Act as a Bluetooth keyboard")
                description: qsTr("This phone types into a TV, a tablet, a console or a computer it is paired with, which needs nothing installed: the clipboard, at your tap.")
                automaticCheck: false
                checked: page.kb.on
                onClicked: page.kb.on = !page.kb.on
            }

            Label {
                visible: page.kb.on
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * x
                wrapMode: Text.Wrap
                color: page.kb.state === "failed" ? Theme.errorColor : Theme.highlightColor
                text: page.kb.state === "starting" ? qsTr("Getting ready…")
                    : page.kb.state === "failed" ? page.kb.error
                    : page.kb.state === "connected"
                        ? (page.kb.host !== "" ? qsTr("Connected to %1.").arg(page.kb.host) : qsTr("A device is connected."))
                    : qsTr("No device is connected. Connect to this phone from the device, in its Bluetooth settings.")
            }

            Item { width: 1; height: Theme.paddingMedium }

            Button {
                visible: page.kb.on && page.kb.state !== "failed"
                anchors.horizontalCenter: parent.horizontalCenter
                enabled: page.kb.visibleUntil.getTime() === 0
                text: page.kb.visibleUntil.getTime() > 0
                      ? qsTr("Visible for %1 s").arg(Math.max(0, Math.round((page.kb.visibleUntil.getTime() - clock.now.getTime()) / 1000)))
                      : qsTr("Make this phone visible")
                onClicked: page.kb.makeVisible()
            }
            Label {
                visible: page.kb.on && page.kb.state !== "failed"
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * x
                wrapMode: Text.Wrap
                font.pixelSize: Theme.fontSizeExtraSmall
                color: Theme.secondaryColor
                text: qsTr("A new device finds this phone as “CBB keyboard” in its Bluetooth settings while it is visible.")
            }

            Button {
                visible: page.kb.on && page.kb.state === "failed"
                anchors.horizontalCenter: parent.horizontalCenter
                text: qsTr("Try again")
                onClicked: { page.kb.on = false; page.kb.on = true }
            }

            ComboBox {
                label: qsTr("The device's keyboard layout")
                property var codes: ["us", "ru"]
                currentIndex: Math.max(codes.indexOf(page.kb.layout), 0)
                menu: ContextMenu {
                    MenuItem { text: qsTr("English (US)") }
                    MenuItem { text: qsTr("Russian") }
                }
                onCurrentIndexChanged: if (codes[currentIndex] !== page.kb.layout) page.kb.layout = codes[currentIndex]
            }

            // As on Android: slow devices drop keys typed too fast.
            ComboBox {
                label: qsTr("Speed")
                property var rates: [10, 20, 40]
                currentIndex: Math.max(rates.indexOf(page.kb.rate), 0)
                menu: ContextMenu {
                    Repeater {
                        model: [10, 20, 40]
                        MenuItem { text: qsTr("%1 characters a second").arg(modelData) }
                    }
                }
                onCurrentIndexChanged: if (rates[currentIndex] !== page.kb.rate) page.kb.rate = rates[currentIndex]
            }

            Button {
                visible: page.kb.on
                anchors.horizontalCenter: parent.horizontalCenter
                enabled: page.kb.state === "connected" && !page.kb.typing
                text: page.kb.typing ? qsTr("Typing…") : qsTr("Type the clipboard")
                onClicked: page.kb.typeClipboard()
            }
            Label {
                visible: page.kb.typed !== "" && page.kb.typed !== "typed"
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * x
                wrapMode: Text.Wrap
                color: Theme.errorColor
                font.pixelSize: Theme.fontSizeSmall
                text: page.kb.typed
            }
        }
        VerticalScrollDecorator {}
    }
}
