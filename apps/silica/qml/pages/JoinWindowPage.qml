// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import QtQuick 2.6
import Sailfish.Silica 1.0

// Joining a group of 0.6 (docs/apps.md, "Screens"): the phone finds the one
// pairing window a phone of the group announces at home (its Add a device),
// or dials the window whose QR code text the person pasted, and the code both
// screens show waits for the person's "they match".
Page {
    id: page
    readonly property string step: app.joiner.state

    property bool started: false
    onStatusChanged: {
        if (status === PageStatus.Active && !started) {
            started = true
            app.joinByWindow("")
        }
    }
    Component.onDestruction: if (step !== "done") app.joiner.stop()

    function dial(text) {
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

            CodeQuestion {
                visible: page.step === "joining"
                who: qsTr("Joining the group of %1.").arg(app.joiner.memberName)
                code: app.joiner.code
                onAnswered: app.joiner.answer(yes)
            }

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
                visible: page.step === "dialing" || page.step === "failed"
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                color: Theme.highlightColor
                text: qsTr("On a phone of the group, tap Add a device: this phone finds it by itself. Keep both phones on the same Wi-Fi.")
            }

            TextField {
                visible: page.step === "dialing" || page.step === "failed"
                width: parent.width
                label: qsTr("Or paste the code's text, cbb://pair…")
                placeholderText: label
                inputMethodHints: Qt.ImhNoAutoUppercase | Qt.ImhNoPredictiveText | Qt.ImhUrlCharactersOnly
                EnterKey.enabled: text.trim().indexOf("cbb://pair?") === 0
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
                onClicked: page.dial("")
            }
        }
        VerticalScrollDecorator {}
    }
}
