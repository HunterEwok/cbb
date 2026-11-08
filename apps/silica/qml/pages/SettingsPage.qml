// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import QtQuick 2.6
import Sailfish.Silica 1.0

// Settings (docs/apps.md, "Screens", Settings): the language, sync away from
// home, the notifications, and about the app; seven taps on the version
// show the switch for the error details.
// The colours follow the phone's ambience, as every Silica app's do.
Page {
    id: page
    property int taps: 0

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: column.height

        Column {
            id: column
            width: parent.width

            PageHeader { title: qsTr("Settings") }

            ComboBox {
                id: language
                label: qsTr("Language")
                description: app.languagePending ? qsTr("Applies when the app starts again") : ""
                property var codes: ["", "en", "zh", "es", "ru", "ar", "sw", "he", "hi"]
                currentIndex: Math.max(codes.indexOf(app.language), 0)
                // The languages by their own names, which no translation changes.
                menu: ContextMenu {
                    Repeater {
                        model: language.codes
                        MenuItem { text: modelData === "" ? qsTr("As the phone") : app.languageName(modelData) }
                    }
                }
                onCurrentIndexChanged: app.language = codes[currentIndex] || ""
            }

            TextSwitch {
                visible: page.taps >= 7 || app.errorDetails
                text: qsTr("Show error details")
                description: qsTr("Puts the error itself under each error message")
                automaticCheck: false
                checked: app.errorDetails
                onClicked: app.errorDetails = !app.errorDetails
            }

            SectionHeader { text: qsTr("Bluetooth keyboard") }
            ValueButton {
                label: qsTr("Act as a Bluetooth keyboard")
                value: !app.keyboard.on ? qsTr("Off")
                     : app.keyboard.state === "connected" ? qsTr("Connected")
                     : app.keyboard.state === "failed" ? qsTr("Not working")
                     : qsTr("On")
                onClicked: pageStack.push(Qt.resolvedUrl("KeyboardPage.qml"))
            }

            SectionHeader {
                visible: app.member.running
                text: qsTr("Away from home")
            }

            // Sync away from home (docs/protocol.md, section 11), as on the
            // other phones: through the group's own hub only, off until the
            // user turns it on.
            TextSwitch {
                visible: app.member.running
                text: qsTr("Sync away from home")
                description: qsTr("When the phone is not on the home network, it syncs through the WireGuard tunnel of your own hub, a computer of the group set up with cbb global hub; its port is reachable from the internet, but only through WireGuard with the group's keys. The hub answers this phone the next time it connects at home. Nothing goes anywhere else, and without the tunnel there is no connection. Turning it off forgets this phone's tunnel key.")
                automaticCheck: false
                checked: app.member.awayOn
                onClicked: app.member.setAway(!checked)
            }
            Label {
                visible: app.member.running && app.member.awayOn
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                font.pixelSize: Theme.fontSizeSmall
                color: app.member.awayStatus === "connected" ? Theme.highlightColor : Theme.secondaryColor
                text: app.member.awayStatus === "home" ? qsTr("At home: syncing directly.")
                    : app.member.awayStatus === "connecting" ? qsTr("Connecting to the hub through the tunnel…")
                    : app.member.awayStatus === "connected"
                      ? (app.member.awayHub !== "" ? qsTr("Connected to the hub %1 through the tunnel.").arg(app.member.awayHub)
                                                   : qsTr("Connected to the hub through the tunnel."))
                    : qsTr("Waiting for the hub: open the app at home once, near a computer of the group.")
            }
            Label {
                visible: app.member.running && app.member.awayError !== ""
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                font.pixelSize: Theme.fontSizeExtraSmall
                color: Theme.errorColor
                text: app.member.awayError
            }

            SectionHeader { text: qsTr("Notifications") }

            // One switch for each kind of the group's events (src/events.h),
            // all on by default, as on the other phones.
            Repeater {
                model: [
                    { kind: "devices", text: qsTr("Devices join or leave") },
                    { kind: "admins", text: qsTr("A device becomes an admin") },
                    { kind: "frozen", text: qsTr("A device is frozen or unfrozen") },
                    { kind: "takeover", text: qsTr("Another phone takes the group over") }
                ]
                TextSwitch {
                    text: modelData.text
                    automaticCheck: false
                    checked: app.events.isOn(modelData.kind)
                    onClicked: {
                        app.events.setOn(modelData.kind, !checked)
                        checked = app.events.isOn(modelData.kind)
                    }
                }
            }

            SectionHeader { text: qsTr("About") }

            BackgroundItem {
                height: version.height
                onClicked: page.taps++
                DetailItem {
                    id: version
                    label: qsTr("Version")
                    value: app.version
                }
            }
            DetailItem { label: qsTr("Core"); value: app.core }
            DetailItem { label: qsTr("System"); value: app.system }
            DetailItem {
                label: qsTr("Key")
                value: app.busy ? qsTr("Checking…")
                     : app.keyLevel === "hardware" ? qsTr("In the secure element")
                     : app.keyLevel === "file" ? qsTr("In a file on the phone")
                     : qsTr("None yet")
            }
            DetailItem {
                visible: app.keyFingerprint !== ""
                label: qsTr("Key fingerprint")
                value: app.keyFingerprint
            }
            DetailItem {
                label: qsTr("Group")
                value: app.group !== "" ? app.group : qsTr("None yet")
            }
            DetailItem {
                visible: app.device !== ""
                label: qsTr("Device")
                value: app.device
            }
        }
        VerticalScrollDecorator {}
    }
}
