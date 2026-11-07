// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import QtQuick 2.6
import Sailfish.Silica 1.0

// Settings (docs/apps.md, "Screens", Settings): the language, and about the
// app; seven taps on the version show the switch for the error details.
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
