// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import QtQuick 2.6
import Sailfish.Silica 1.0

// The app's cover, Aurora's widget: whether the phone takes copies, how many
// devices it reaches, the last copy, and the group's latest event; its
// actions send the clipboard and pause or resume taking copies (docs/apps.md,
// the one-tap control).
CoverBackground {
    readonly property bool member: app.member.running

    Column {
        anchors {
            left: parent.left; right: parent.right; top: parent.top
            margins: Theme.paddingLarge
        }
        spacing: Theme.paddingSmall

        Label {
            text: "CBB"
            font.pixelSize: Theme.fontSizeLarge
            color: Theme.highlightColor
        }
        Label {
            width: parent.width
            wrapMode: Text.Wrap
            font.pixelSize: Theme.fontSizeSmall
            text: !member ? (app.group === "" ? qsTr("Not in a group") : qsTr("Not running"))
                : app.member.muted ? qsTr("Muted")
                : app.member.paused ? qsTr("Sync is off")
                : app.member.peers.length === 0 ? qsTr("Looking for devices")
                : qsTr("Connected devices: %1").arg(app.member.peers.length)
        }
        Label {
            visible: member && app.member.last !== ""
            width: parent.width
            maximumLineCount: 3
            wrapMode: Text.Wrap
            elide: Text.ElideRight
            font.pixelSize: Theme.fontSizeExtraSmall
            color: Theme.secondaryColor
            text: app.member.last
        }
        Label {
            visible: app.events.recent.length > 0
            width: parent.width
            maximumLineCount: 2
            wrapMode: Text.Wrap
            elide: Text.ElideRight
            font.pixelSize: Theme.fontSizeExtraSmall
            color: Theme.secondaryHighlightColor
            text: app.events.recent.length > 0 ? app.events.recent[0] : ""
        }
    }

    CoverActionList {
        enabled: member
        CoverAction {
            iconSource: app.member.paused ? "image://theme/icon-cover-play" : "image://theme/icon-cover-pause"
            onTriggered: app.member.paused ? app.member.resume() : app.member.pause(0)
        }
    }
}
