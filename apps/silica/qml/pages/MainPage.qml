// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import QtQuick 2.6
import Sailfish.Silica 1.0

Page {
    SilicaFlickable {
        anchors.fill: parent
        contentHeight: column.height

        PullDownMenu {
            MenuItem {
                text: qsTr("Check the key again")
                enabled: !app.busy
                onClicked: app.setUpKey()
            }
        }

        Column {
            id: column
            width: parent.width
            spacing: Theme.paddingMedium

            PageHeader { title: "CBB" }

            DetailItem { label: qsTr("Version"); value: app.version }
            DetailItem { label: qsTr("Core"); value: app.core }
            DetailItem { label: qsTr("System"); value: app.system }
            DetailItem {
                label: qsTr("Key")
                value: app.busy ? qsTr("Checking…")
                     : app.keyLevel === "hardware" ? qsTr("In the secure element")
                     : qsTr("None yet")
            }
            DetailItem {
                visible: app.keyFingerprint !== ""
                label: qsTr("Key fingerprint")
                value: app.keyFingerprint
            }

            BusyIndicator {
                anchors.horizontalCenter: parent.horizontalCenter
                running: app.busy
                visible: running
                size: BusyIndicatorSize.Medium
            }

            Label {
                visible: app.error !== ""
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                text: app.error
                wrapMode: Text.Wrap
                color: Theme.errorColor
                font.pixelSize: Theme.fontSizeSmall
            }
        }
        VerticalScrollDecorator {}
    }
}
