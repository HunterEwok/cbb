// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import QtQuick 2.6
import Sailfish.Silica 1.0
import "devices.js" as Devices

// A device's card (docs/apps.md, "Screens", Devices): its marks, one line,
// the house, the rest under More, brought up to date while it is open; for
// an admin the device's actions in the pull-down menu, each confirmed
// before the admin key signs it. A page of its own (DevicePage), or on a
// big screen a pane beside the tiles (pane), which Close or removing the
// device closes.
Item {
    id: page
    property var device
    property bool pane: false
    signal closed()

    // The newest entry of the device, which the main page's list renews;
    // a pane's comes from the main page, which chose it.
    Connections {
        target: app.member
        onDevicesChanged: {
            if (page.pane)
                return
            var all = app.member.devices
            for (var i = 0; i < all.length; i++) {
                if (all[i].id === page.device.id) {
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
            if (ok && action === "remove" && device === page.device.id) {
                if (page.pane)
                    page.closed()
                else
                    pageStack.pop()
            }
        }
    }

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: column.height

        PullDownMenu {
            visible: page.pane || page.acts || (app.admin && app.member.running)
            busy: app.busy
            MenuItem {
                visible: page.pane
                text: qsTr("Close")
                onClicked: page.closed()
            }
            MenuItem {
                // An admin takes a lost root's group over (cbb_core::takeover).
                visible: page.acts && page.device.root && !app.root && app.claimState === ""
                text: qsTr("Take the group over")
                onClicked: remorse.execute(qsTr("Taking the group over from %1").arg(Devices.name(page.device)),
                                           function() { app.takeOver(page.device.id) })
            }
            MenuItem {
                visible: page.acts && !page.device.root
                text: qsTr("Remove")
                onClicked: remorse.execute(qsTr("Removing %1").arg(Devices.name(page.device)),
                                           function() { app.manage("remove", page.device.id) })
            }
            MenuItem {
                // The admin key comes from the device's hello: a computer's
                // with the admin capability, or a phone's.
                visible: page.acts && app.root && !page.device.admin
                         && (Devices.can(page.device, "admin") || page.device.role === "phone")
                         && page.device.online
                text: qsTr("Make an admin")
                onClicked: remorse.execute(qsTr("Making %1 an admin").arg(Devices.name(page.device)),
                                           function() { app.manage("make_admin", page.device.id) })
            }
            MenuItem {
                // The root lets an admin's claim take effect at once (cbb_core::root).
                visible: page.acts && app.root && page.device.admin && !page.device.frozen
                         && app.member.rootView.handed_to !== page.device.id
                text: qsTr("Hand the group over")
                onClicked: remorse.execute(qsTr("Handing the group over to %1").arg(Devices.name(page.device)),
                                           function() { app.handOver(page.device.id) })
            }
            MenuItem {
                visible: page.acts && page.device.frozen
                text: qsTr("Unfreeze")
                onClicked: remorse.execute(qsTr("Unfreezing %1").arg(Devices.name(page.device)),
                                           function() { app.manage("thaw", page.device.id) })
            }
            MenuItem {
                // Members and Android and Aurora phones take pastes; iPhones cannot.
                visible: page.acts && Devices.takesPaste(page.device)
                text: qsTr("Paste on it…")
                onClicked: pageStack.push(Qt.resolvedUrl("PastePage.qml"), { device: page.device })
            }
            MenuItem {
                visible: page.acts
                text: qsTr("Unmute")
                onClicked: app.manage("unmute", page.device.id)
            }
            MenuItem {
                visible: page.acts
                text: qsTr("Mute until unmuted")
                onClicked: remorse.execute(qsTr("Muting %1").arg(Devices.name(page.device)),
                                           function() { app.manage("mute", page.device.id, "", 0) })
            }
            MenuItem {
                visible: page.acts
                text: qsTr("Mute for an hour")
                onClicked: remorse.execute(qsTr("Muting %1").arg(Devices.name(page.device)),
                                           function() { app.manage("mute", page.device.id, "", 60) })
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
                IconButton {
                    visible: page.pane
                    anchors.left: parent.left
                    anchors.leftMargin: Theme.paddingSmall
                    anchors.verticalCenter: parent.verticalCenter
                    icon.source: "image://theme/icon-m-dismiss"
                    onClicked: page.closed()
                }
                title: Devices.name(page.device)
                description: [Devices.mark(page.device), page.device.self ? "" : Devices.status(page.device)].filter(function(s) { return s !== "" }).join(" · ")
            }

            // One line: its system and its CBB version.
            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                text: Devices.line(page.device)
                color: Theme.highlightColor
                truncationMode: TruncationMode.Fade
            }

            // The house (docs/apps.md, Devices): this phone's sync, or for an
            // admin another device's, through a mode command it signs.
            TextSwitch {
                visible: page.device.self ? app.member.running : page.acts && page.device.mode !== ""
                text: qsTr("Sync")
                description: page.device.self ? (app.member.paused ? qsTr("Sync is off") : qsTr("Sync is on"))
                                              : (page.device.mode === "shared" ? qsTr("Sync is on") : qsTr("Sync is off"))
                automaticCheck: false
                checked: page.device.self ? !app.member.paused : page.device.mode === "shared"
                onClicked: {
                    if (page.device.self)
                        app.member.paused ? app.member.resume() : app.member.pause(0)
                    else
                        app.manage(checked ? "sync_off" : "sync_on", page.device.id)
                }
            }

            DetailItem {
                visible: app.root && app.member.rootView.handed_to === page.device.id
                label: qsTr("The group is handed over")
                value: qsTr("Its claim takes the group at once")
            }

            DetailItem {
                visible: page.device.root && app.claimState !== ""
                label: qsTr("Taking the group over")
                value: app.claimState === "pending"
                       ? qsTr("Waiting, %1 h left").arg(Math.ceil(app.claimLeftMs / 3600000))
                       : app.claimState === "none" ? qsTr("Waiting for the group to get the claim")
                       : qsTr("In dispute: the group's root answered the claim")
            }

            // The rest under More.
            ExpandingSectionGroup {
                ExpandingSection {
                    title: qsTr("More")
                    content.sourceComponent: Column {
                        width: parent.width
                        DetailItem { label: qsTr("Type"); value: Devices.kind(page.device) }
                        DetailItem { label: qsTr("In the group"); value: Devices.role(page.device) }
                        DetailItem {
                            visible: value !== ""
                            label: qsTr("System version")
                            value: page.device.os_version || ""
                        }
                        DetailItem {
                            visible: value !== ""
                            label: qsTr("MAC address")
                            value: page.device.mac || ""
                        }
                        DetailItem { label: qsTr("Device ID"); value: page.device.id }
                    }
                }
            }
        }
        VerticalScrollDecorator {}
    }
}
