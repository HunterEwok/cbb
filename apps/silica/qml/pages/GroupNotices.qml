// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import QtQuick 2.6
import Sailfish.Silica 1.0

// The group's notices on Home (docs/apps.md, "Notices" and "Changing the
// main device"), as the other phones show them: that the group removed
// this phone, with Leave; that the main device
// changed, with "This wasn't me", until the person saw it; then the
// member's notices, each in a sentence, with a button that hides one that
// may be hidden.
Column {
    id: card
    width: parent.width
    spacing: Theme.paddingSmall
    visible: removed || changed || shown.length > 0

    property var changed: app.member.rootChanged && app.member.rootChanged.to ? app.member.rootChanged : null
    property var shown: app.member.notices.filter(function(n) { return text(n) !== "" })
    property bool notMe: false
    // The group's records, once it has some, no longer list this phone.
    property bool removed: {
        var g = app.member.groupState
        var me = g.me ? g.me.device : ""
        var listed = g.devices || []
        return listed.length > 0 && me !== "" && !listed.some(function(d) { return d.device === me })
    }

    RemorsePopup { id: remorse }

    function name(id) {
        var ds = app.member.devices.filter(function(d) { return d.device === id })
        return ds.length > 0 && ds[0].name ? ds[0].name : id
    }

    // The notice in a sentence; empty for a kind this app does not show.
    function text(n) {
        var args = n.args || {}
        var device = args.device ? name(args.device) : ""
        switch (n.kind) {
        case "change_arriving": return qsTr("A change of the group's main device is on its way.")
        case "admins_silent":
            var days = parseInt(args.days_left) || 0
            return days > 0
                ? qsTr("No word from the admin %1 for a long time: its admin rights end in %2 days unless it connects.").arg(device).arg(days)
                : qsTr("No word from the admin %1 for a long time: its admin rights end now.").arg(device)
        case "removals_waiting": return qsTr("Removals wait until every admin has seen them.")
        case "root_room_waiting":
            return qsTr("Removals that wait for admins fill %1 of the main device's room for records: bring those admins online.").arg((args.percent || "") + "%")
        case "ack_owed": return qsTr("This phone has a removal to confirm; it does so with your next admin action.")
        case "frozen_holding": return qsTr("The frozen admin %1 holds removals back: unfreeze it or remove it.").arg(device)
        case "checkpoint_stuck": return qsTr("The main device's records wait for records no device has passed on.")
        case "returned_after_removal":
            return qsTr("%1 was removed before the main device changed, and counts again now: remove it again if it should not be in the group.").arg(device)
        case "recovery_not_saved":
            return qsTr("The group's recovery key is not saved yet: without it, losing this phone means making the group again.")
        }
        return ""
    }

    Column {
        visible: card.removed
        width: card.width
        spacing: Theme.paddingSmall

        SectionHeader { text: qsTr("This phone was removed from the group") }
        Label {
            x: Theme.horizontalPageMargin
            width: parent.width - 2 * Theme.horizontalPageMargin
            wrapMode: Text.Wrap
            color: Theme.highlightColor
            text: qsTr("The group's devices refuse it now. Leave the group to delete its keys here; then it can join a group again.")
        }
        Button {
            anchors.horizontalCenter: parent.horizontalCenter
            enabled: !app.busy
            text: qsTr("Leave the group")
            onClicked: remorse.execute(qsTr("Leaving the group"), function() {
                app.member.rootChangeSeen()
                app.leave()
            })
        }
    }

    Column {
        visible: card.changed !== null
        width: card.width
        spacing: Theme.paddingSmall

        SectionHeader { text: qsTr("The group's main device changed") }
        Label {
            x: Theme.horizontalPageMargin
            width: parent.width - 2 * Theme.horizontalPageMargin
            wrapMode: Text.Wrap
            color: Theme.highlightColor
            text: card.changed ? qsTr("%1 is now the group's main device, in place of %2.").arg(card.changed.to).arg(card.changed.from) : ""
        }
        Row {
            anchors.horizontalCenter: parent.horizontalCenter
            spacing: Theme.paddingMedium
            Button {
                text: qsTr("OK")
                onClicked: app.member.rootChangeSeen()
            }
            Button {
                text: qsTr("This wasn't me")
                onClicked: card.notMe = !card.notMe
            }
        }
        Label {
            visible: card.notMe
            x: Theme.horizontalPageMargin
            width: parent.width - 2 * Theme.horizontalPageMargin
            wrapMode: Text.Wrap
            color: Theme.errorColor
            font.bold: true
            text: qsTr("Someone has the group's recovery key")
        }
        Label {
            visible: card.notMe
            x: Theme.horizontalPageMargin
            width: parent.width - 2 * Theme.horizontalPageMargin
            wrapMode: Text.Wrap
            color: Theme.secondaryHighlightColor
            text: qsTr("Only the recovery key changes the main device, and nothing undoes it. Leave the group on each of your devices, then make a new group and join them to it.")
        }
        Button {
            visible: card.notMe
            anchors.horizontalCenter: parent.horizontalCenter
            enabled: !app.busy
            text: qsTr("Leave the group")
            onClicked: remorse.execute(qsTr("Leaving the group"), function() {
                app.member.rootChangeSeen()
                app.leave()
            })
        }
    }

    Repeater {
        model: card.shown
        Item {
            width: card.width
            height: Math.max(label.height, hide.height)
            Label {
                id: label
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin - (hide.visible ? hide.width : 0)
                wrapMode: Text.Wrap
                color: Theme.highlightColor
                text: card.text(modelData)
            }
            IconButton {
                id: hide
                visible: modelData.dismissable !== false
                anchors.right: parent.right
                anchors.rightMargin: Theme.horizontalPageMargin
                icon.source: "image://theme/icon-m-clear"
                onClicked: app.member.dismissNotice(modelData.id)
            }
        }
    }
}
