// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import QtQuick 2.6
import Sailfish.Silica 1.0

// Joining a group of 0.6 (docs/apps.md, "Screens"): the person types the six
// digits a phone of the group shows in its Add a device, and the phone finds
// that window at home and proves them; or the person pastes the window's QR
// code text. The phone has no camera, so it scans nothing.
Page {
    id: page
    readonly property string step: app.joiner.state
    property string typed: ""

    Component.onDestruction: if (step !== "done") app.joiner.stop()

    // Six digits, spaces aside, or a window's code text.
    function usable(text) {
        var t = text.trim()
        return /^[0-9]{6}$/.test(t.replace(/ /g, "")) || t.indexOf("cbb://pair?") === 0
    }

    function dial(text) {
        page.typed = text
        app.joiner.stop()
        app.joinByWindow(text)
    }

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: column.height

        Column {
            id: column
            width: parent.width
            spacing: Theme.paddingLarge

            PageHeader { title: qsTr("Join a group") }

            Label {
                visible: page.step === "done"
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                color: Theme.highlightColor
                text: qsTr("The phone is in the group now.")
            }

            Row {
                visible: page.step === "dialing"
                anchors.horizontalCenter: parent.horizontalCenter
                spacing: Theme.paddingMedium
                BusyIndicator {
                    running: parent.visible
                    size: BusyIndicatorSize.Small
                    anchors.verticalCenter: parent.verticalCenter
                }
                Label {
                    anchors.verticalCenter: parent.verticalCenter
                    color: Theme.secondaryHighlightColor
                    text: qsTr("Looking for the group's phone on this network…")
                }
            }

            Label {
                visible: page.step !== "done"
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                color: Theme.highlightColor
                text: qsTr("On a phone of the group, tap Add a device and type the six digits it shows. Keep both phones on the same Wi-Fi.")
            }

            TextField {
                visible: page.step !== "dialing" && page.step !== "done"
                width: parent.width
                label: qsTr("Six digits or the code's text")
                placeholderText: label
                inputMethodHints: Qt.ImhNoAutoUppercase | Qt.ImhNoPredictiveText
                EnterKey.enabled: page.usable(text)
                EnterKey.iconSource: "image://theme/icon-m-enter-accept"
                EnterKey.onClicked: page.dial(text.trim())
            }

            Label {
                visible: app.joiner.error !== ""
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                text: app.joiner.error
                wrapMode: Text.Wrap
                color: Theme.errorColor
            }

            Button {
                visible: page.step === "failed"
                anchors.horizontalCenter: parent.horizontalCenter
                text: qsTr("Try again")
                onClicked: page.dial(page.typed)
            }
        }
        VerticalScrollDecorator {}
    }
}
