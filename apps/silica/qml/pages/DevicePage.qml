// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import QtQuick 2.6
import Sailfish.Silica 1.0
import "devices.js" as Devices

// A device's page (docs/apps.md, "Screens", Devices): its summary, brought
// up to date while the page is open, and for an admin the device's actions,
// each confirmed before the admin key signs it.
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

    // Whether this phone may act on the device: an admin, not on itself.
    readonly property bool acts: app.admin && app.member.running && !page.device.self

    RemorsePopup { id: remorse }

    Connections {
        target: app
        onManaged: {
            if (ok && action === "remove" && device === page.device.device)
                pageStack.pop()
        }
    }

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: column.height

        PullDownMenu {
            visible: page.acts || (app.admin && app.member.running)
            busy: app.busy
            MenuItem {
                visible: page.acts && !page.device.root
                text: qsTr("Remove")
                onClicked: remorse.execute(qsTr("Removing %1").arg(Devices.name(page.device)),
                                           function() { app.manage("remove", page.device.device) })
            }
            MenuItem {
                visible: page.acts && page.device.frozen
                text: qsTr("Unfreeze")
                onClicked: remorse.execute(qsTr("Unfreezing %1").arg(Devices.name(page.device)),
                                           function() { app.manage("thaw", page.device.device) })
            }
            MenuItem {
                visible: page.acts
                text: qsTr("Unmute")
                onClicked: app.manage("unmute", page.device.device)
            }
            MenuItem {
                visible: page.acts
                text: qsTr("Mute until unmuted")
                onClicked: remorse.execute(qsTr("Muting %1").arg(Devices.name(page.device)),
                                           function() { app.manage("mute", page.device.device, "", 0) })
            }
            MenuItem {
                visible: page.acts
                text: qsTr("Mute for an hour")
                onClicked: remorse.execute(qsTr("Muting %1").arg(Devices.name(page.device)),
                                           function() { app.manage("mute", page.device.device, "", 60) })
            }
            MenuItem {
                visible: app.admin && app.member.running
                text: qsTr("Rename")
                onClicked: pageStack.push(Qt.resolvedUrl("RenameDevicePage.qml"), { device: page.device })
            }
        }

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
