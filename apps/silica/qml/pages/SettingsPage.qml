// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import QtQuick 2.6
import Sailfish.Silica 1.0

// Settings (docs/apps.md, "Screens", Settings): the language, the
// notifications, the root's settings, leaving the group, and about the app;
// seven taps on the version show the switch for the error details; the
// advanced settings switch shows why the phone does not sync. Everywhere,
// sync away from home, is the globe on Home.
// The colours follow the phone's ambience, as every Silica app's do.
Page {
    id: page
    property int taps: 0
    // How the last change of the admin PIN went.
    property string pinNote: ""

    RemorsePopup { id: remorse }

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

            TextSwitch {
                text: qsTr("Advanced settings")
                automaticCheck: false
                checked: app.advanced
                onClicked: app.advanced = !app.advanced
            }
            WhySection {
                visible: app.group !== "" && app.advanced
            }

            // The lab: what works but is no promise of 1.0 (docs/apps.md,
            // "The lab").
            SectionHeader {
                visible: app.advanced
                text: qsTr("Lab")
            }
            ValueButton {
                visible: app.advanced
                label: qsTr("Act as a Bluetooth keyboard")
                value: !app.keyboard.on ? qsTr("Off")
                     : app.keyboard.state === "connected" ? qsTr("Connected")
                     : app.keyboard.state === "failed" ? qsTr("Not working")
                     : qsTr("On")
                onClicked: pageStack.push(Qt.resolvedUrl("KeyboardPage.qml"))
            }

            SectionHeader {
                visible: app.group !== ""
                text: qsTr("Group")
            }
            // The root's settings (cbb_core::root), each signed with the root
            // key: how long a claim from a lost root waits, which keys may be
            // admins, and the recovery key.
            ComboBox {
                id: delay
                visible: app.root && app.member.running
                label: qsTr("A claim to take the group over waits")
                property var hours: [0, 1, 24, 72, 168]
                currentIndex: Math.max(hours.indexOf(Math.round((app.member.rootView.delay_ms || 0) / 3600000)), 0)
                menu: ContextMenu {
                    Repeater {
                        model: [qsTr("No time"), qsTr("1 hour"), qsTr("1 day"), qsTr("3 days"), qsTr("7 days")]
                        MenuItem {
                            text: modelData
                            onClicked: if (delay.hours[index] * 3600000 !== app.member.rootView.delay_ms)
                                           app.setTakeoverDelay(delay.hours[index])
                        }
                    }
                }
            }
            ComboBox {
                id: level
                visible: app.root && app.member.running
                label: qsTr("Keys an admin may keep")
                description: app.belowLevel.length > 0
                             ? qsTr("Some admins keep weaker keys; they stay until removed") : ""
                property var levels: ["proven", "hardware", "files"]
                currentIndex: Math.max(levels.indexOf(app.member.rootView.key_level || "hardware"), 0)
                menu: ContextMenu {
                    Repeater {
                        model: [qsTr("Proven hardware only"), qsTr("Hardware"), qsTr("Hardware or a file")]
                        MenuItem {
                            text: modelData
                            onClicked: if (level.levels[index] !== app.member.rootView.key_level)
                                           app.setGroupKeyLevel(level.levels[index])
                        }
                    }
                }
            }
            ValueButton {
                visible: app.root && app.member.running
                label: qsTr("Recovery key")
                value: app.member.rootView.recovery ? qsTr("Made") : qsTr("None")
                onClicked: pageStack.push(Qt.resolvedUrl("RecoveryPage.qml"))
            }
            // A member phone that joined without an admin key makes it now,
            // for the root's "Make an admin".
            Button {
                visible: app.group !== "" && !app.admin && !app.adminOffered && app.adminPin !== "locked"
                anchors.horizontalCenter: parent.horizontalCenter
                text: qsTr("Get ready to be an admin")
                enabled: !app.busy
                onClicked: app.prepareAdmin()
            }
            Label {
                visible: app.group !== "" && app.adminOffered
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                font.pixelSize: Theme.fontSizeSmall
                color: Theme.secondaryHighlightColor
                text: qsTr("The group's root can make this phone an admin: on the root, open this phone and tap Make an admin.")
            }
            // The admin PIN, which the TEE checks before the admin key signs.
            Button {
                visible: app.adminPin === "set"
                anchors.horizontalCenter: parent.horizontalCenter
                text: qsTr("Change the admin PIN")
                onClicked: pageStack.push(Qt.resolvedUrl("ChangePinDialog.qml"))
            }
            Label {
                visible: app.adminPin === "locked" || page.pinNote !== ""
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                font.pixelSize: Theme.fontSizeSmall
                color: app.adminPin === "locked" ? Theme.errorColor : Theme.secondaryHighlightColor
                text: app.adminPin === "locked"
                      ? qsTr("Seven wrong PINs locked the admin key for good. The phone stays in the group as a member; to be an admin again, reinstall CBB and join as a new device.")
                      : page.pinNote
            }
            Connections {
                target: app
                onPinChanged: page.pinNote = ok ? qsTr("The admin PIN is changed.")
                                           : locked ? ""
                                           : triesLeft > 0 ? qsTr("Wrong PIN. Tries left: %1.").arg(triesLeft)
                                           : qsTr("The admin PIN is not changed.")
            }
            // Room between the PIN and leaving, which is far from undone.
            Item {
                visible: app.group !== ""
                width: 1
                height: Theme.paddingLarge * 2
            }
            // The root's key goes with it: the group then has no root until
            // an admin phone takes it over.
            Button {
                visible: app.group !== ""
                anchors.horizontalCenter: parent.horizontalCenter
                text: qsTr("Leave the group")
                onClicked: remorse.execute(app.root ? qsTr("Leaving the group and deleting its root key")
                                                    : qsTr("Leaving the group"), function() { app.leave(); pageStack.pop() })
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
