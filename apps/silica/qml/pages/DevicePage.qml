// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import QtQuick 2.6
import Sailfish.Silica 1.0
import "devices.js" as Devices

// A device's page (docs/apps.md, "Screens", Devices): its summary, brought
// up to date while the page is open.
Page {
    id: page
    property var device

    // The newest entry of the device, which the main page's list renews.
    Connections {
        target: app.member
        onDevicesChanged: {
            var all = app.member.devices
            for (var i = 0; i < all.length; i++) {
                if (all[i].device === page.device.device) {
                    page.device = all[i]
                    return
                }
            }
        }
    }

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: column.height

        Column {
            id: column
            width: parent.width

            PageHeader {
                title: Devices.name(page.device)
                description: Devices.mark(page.device)
            }

            DetailItem { label: qsTr("Type"); value: Devices.kind(page.device) }
            DetailItem {
                visible: value !== ""
                label: qsTr("System")
                value: Devices.system(page.device)
            }
            DetailItem { label: qsTr("In the group"); value: Devices.role(page.device) }
            DetailItem { label: qsTr("Status"); value: Devices.status(page.device) }
            DetailItem { label: qsTr("Device ID"); value: page.device.device }
        }
        VerticalScrollDecorator {}
    }
}
