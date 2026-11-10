// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import QtQuick 2.6
import Sailfish.Silica 1.0

// "Why it does not sync" in the advanced settings (docs/apps.md): the core's
// reasons for this phone (the member's why), the one that stops the most
// first; the app only says each code in its words.
Column {
    id: section
    width: parent.width

    function title(r) {
        var names = (r.devices || []).join(", ")
        var date = r.until_ms ? Qt.formatDateTime(new Date(r.until_ms), Qt.DefaultLocaleShortDate) : ""
        switch (r.code) {
        case "not_in_group": return qsTr("This device is in no group.")
        case "removed": return qsTr("This device was removed from the group.")
        case "taken_over": return qsTr("%1 took the group over from this device.").arg(r.device)
        case "frozen": return qsTr("This device's rights as a trusted device are paused.")
        case "cert_expired": return qsTr("This device's certificate ended on %1.").arg(date)
        case "cert_ending": return qsTr("This device's certificate ends on %1.").arg(date)
        case "stopped": return qsTr("The group's records stop the exchange.")
        case "secrets_stopped": return qsTr("The group sends no secrets until its owner decides.")
        case "sync_off": return r.until_ms ? qsTr("Sync is off on this device until %1.").arg(date) : qsTr("Sync is off on this device.")
        case "only_device": return qsTr("This is the group's only device.")
        case "away_off": return qsTr("No device of the group is on this network.")
        case "new_network": return qsTr("This computer has not met its group on this network.")
        case "no_hub": return qsTr("Everywhere is on, but the group has no base.")
        case "tunnel_blocked": return qsTr("The tunnel to the base %1 does not get through.").arg(r.device)
        case "hub_unreachable": return qsTr("The base %1 does not answer.").arg(r.device)
        case "alone": return qsTr("Connected, but no other device of the group is online.")
        case "relay_down": return qsTr("The backup server does not answer.")
        case "hub_waiting": return qsTr("This device is the base, and no device has connected yet.")
        case "muted": return r.until_ms ? qsTr("This device is muted until %1: its copies do not reach the group.").arg(date) : qsTr("This device is muted: its copies do not reach the group.")
        case "forwarder_down": return qsTr("The connection server does not take this base.")
        case "entries_stale": return qsTr("The list of the connection servers' entry points is out of date.")
        case "newer": return qsTr("The group has records of a newer version.")
        case "unreached": return qsTr("Devices at home cannot connect to this one: %1.").arg(names)
        case "devices_offline": return qsTr("Offline: %1.").arg(names)
        case "devices_sync_off": return qsTr("Sync is off on: %1.").arg(names)
        case "devices_muted": return qsTr("Muted: %1.").arg(names)
        case "update": return qsTr("CBB %1 is available.").arg(r.value)
        default: return r.code
        }
    }

    function action(r) {
        switch (r.code) {
        case "not_in_group": return qsTr("Start a group or join one.")
        case "removed": return qsTr("Leave the group on this device, then join again.")
        case "taken_over": return qsTr("If this device was not lost, remove %1 from the group.").arg(r.device)
        case "frozen": return qsTr("Ask the group's owner to restore its rights.")
        case "cert_expired": return qsTr("Bring it home to a trusted device of the group, which renews the certificate.")
        case "cert_ending": return qsTr("Connect it at home to a trusted device of the group before then.")
        case "stopped": return qsTr("The group's owner decides on its alerts.")
        case "sync_off": return qsTr("Turn sync on.")
        case "only_device": return qsTr("Add a phone or a computer.")
        case "away_off": return qsTr("Turn on Everywhere to sync away from home.")
        case "new_network": return qsTr("If this is your home network, mark it as home.")
        case "no_hub": return qsTr("Make a computer at home the base, in its advanced settings.")
        case "tunnel_blocked": return qsTr("This network may block tunnels: turn on Strict networks on the base.")
        case "hub_unreachable": return qsTr("Check that the base is on and online.")
        case "alone": return qsTr("Turn on another device of the group.")
        case "relay_down": return qsTr("Check the internet connection; CBB tries again by itself.")
        case "hub_waiting": return qsTr("Check that the other devices have Everywhere on.")
        case "muted": return qsTr("Unmute it from a trusted device of the group.")
        case "forwarder_down": return qsTr("Devices away from home may not reach it; CBB tries again by itself.")
        case "entries_stale": return qsTr("Update CBB on a computer of the group.")
        case "newer": return qsTr("Update CBB on this device.")
        case "unreached": return qsTr("Let CBB through this computer's firewall.")
        default: return ""
        }
    }

    SectionHeader { text: qsTr("Why it does not sync") }

    Label {
        visible: app.member.why.length === 0
        x: Theme.horizontalPageMargin
        width: parent.width - 2 * Theme.horizontalPageMargin
        wrapMode: Text.Wrap
        color: Theme.highlightColor
        text: qsTr("Everything syncs.")
    }

    Repeater {
        model: app.member.why
        Column {
            width: section.width
            spacing: Theme.paddingSmall
            bottomPadding: Theme.paddingMedium

            Label {
                visible: index === 1
                x: Theme.horizontalPageMargin
                font.pixelSize: Theme.fontSizeSmall
                color: Theme.secondaryHighlightColor
                text: qsTr("Also")
            }
            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                font.pixelSize: index === 0 ? Theme.fontSizeLarge : Theme.fontSizeMedium
                color: modelData.level === "stop" ? Theme.errorColor : Theme.highlightColor
                text: section.title(modelData)
            }
            Label {
                visible: text !== ""
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                font.pixelSize: Theme.fontSizeSmall
                color: Theme.secondaryHighlightColor
                text: section.action(modelData)
            }
            Label {
                visible: app.errorDetails
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                font.pixelSize: Theme.fontSizeExtraSmall
                font.family: "monospace"
                color: Theme.secondaryColor
                text: [modelData.code, modelData.detail || ""].filter(function (s) { return s !== "" }).join(": ")
            }
        }
    }
}
