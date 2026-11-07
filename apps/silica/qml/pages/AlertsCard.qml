// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import QtQuick 2.6
import Sailfish.Silica 1.0

// What the group's records stop and what ends it (docs/apps.md, Home, the
// card above the button; docs/protocol.md, section 10, "Stopping the
// exchange"), as the other phones' card: on the group's root the decision,
// confirmed first; on any other device, that the root decides.
Column {
    id: card
    width: parent.width
    spacing: Theme.paddingSmall
    visible: app.member.alerts.length > 0

    RemorsePopup { id: remorse }

    function who(a) {
        return a.names.length > 0 ? a.names.join(", ") : qsTr("devices unknown here")
    }

    function text(a) {
        switch (a.kind) {
        case "stopped": return qsTr("The group is stopped: its devices exchange only their records, no clipboard, until the group's root decides.")
        case "secrets_stopped": return qsTr("The group sends no secrets until its root decides.")
        case "two_histories": return qsTr("%1 signed two histories with one key, as a stolen key or a restore from a backup would.").arg(who(a))
        case "admins": return qsTr("Admins removed or froze each other without seeing it: %1. The root removes one of them.").arg(who(a))
        case "claims": return qsTr("Two claims to take the group over: %1.").arg(who(a))
        case "claim_pending":
            if (!a.left_ms)
                return qsTr("%1 claims the group, to take it over from its root.").arg(who(a))
            var hours = Math.ceil(a.left_ms / 3600000)
            return qsTr("%1 claims the group, to take it over from its root: it takes effect in %2 h.").arg(who(a)).arg(hours)
        case "claim_stopped": return qsTr("%1 claims the group, and the group is stopped until its root decides.").arg(who(a))
        case "newer": return qsTr("The group holds records of a later version (%1): update the app to read them.").arg(a.count)
        }
        return a.kind
    }

    Repeater {
        model: app.member.alerts
        Column {
            width: card.width
            spacing: Theme.paddingSmall
            property var alert: modelData

            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                color: alert.kind === "newer" ? Theme.highlightColor : Theme.errorColor
                text: card.text(alert)
            }
            Button {
                visible: app.root && alert.kind === "two_histories"
                anchors.horizontalCenter: parent.horizontalCenter
                enabled: !app.busy
                text: qsTr("Void both histories")
                onClicked: remorse.execute(qsTr("Voiding both histories"), function() { app.resolve(alert.records) })
            }
            Button {
                visible: app.root && (alert.kind === "claims" || alert.kind === "claim_pending" || alert.kind === "claim_stopped")
                anchors.horizontalCenter: parent.horizontalCenter
                enabled: !app.busy
                text: qsTr("Cancel the claim")
                onClicked: remorse.execute(qsTr("Cancelling the claim"), function() { app.resolve(alert.records) })
            }
            Repeater {
                model: app.root && alert.kind === "admins" ? alert.devices.length : 0
                Button {
                    anchors.horizontalCenter: parent.horizontalCenter
                    enabled: !app.busy
                    text: qsTr("Remove %1").arg(alert.names[index] || alert.devices[index])
                    onClicked: remorse.execute(qsTr("Removing %1").arg(alert.names[index] || alert.devices[index]),
                                               function() { app.manage("remove", alert.devices[index]) })
                }
            }
            Label {
                visible: !app.root && ["two_histories", "admins", "claims", "claim_pending", "claim_stopped"].indexOf(alert.kind) >= 0
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                font.pixelSize: Theme.fontSizeSmall
                color: Theme.secondaryHighlightColor
                text: qsTr("The group's root decides.")
            }
        }
    }
}
