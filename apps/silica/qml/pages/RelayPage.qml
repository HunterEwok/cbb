// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import QtQuick 2.6
import Sailfish.Silica 1.0

// The group's blind relay, as the other phones show it (docs/apps.md,
// "Away from home"): where the devices meet when the group has no hub, a
// computer, a router or a board. The root sets it once the user read what
// a relay learns, and renews the group's keys for it; the others see
// where it stands.
Page {
    id: page
    property string note: ""

    // A server's key: the pin of its public key, 44 characters of base64.
    readonly property int keyLength: 44

    function line() {
        if (app.member.relayAt === "")
            return qsTr("Off: this phone meets nobody at a relay.")
        if (!app.member.running || app.member.paused)
            return qsTr("Waiting: the relay works while the app syncs.")
        if (!app.member.relayConnected)
            return qsTr("Connecting to the relay…")
        return app.member.relayOnline === 0
            ? qsTr("At the relay: no other device of the group is there now.")
            : qsTr("At the relay; devices of the group there: %1.").arg(app.member.relayOnline)
    }

    // An address with its port and a key, or both empty.
    function fits(address, key) {
        var a = address.trim(), k = key.trim()
        return (a === "" && k === "") || (a.indexOf(":") > 0 && k.length === keyLength)
    }

    function meet() {
        if (!fits(address.text, key.text)) {
            page.note = qsTr("Give the relay's address with its port and its key, as cbb relay prints them, or leave both empty.")
            return
        }
        page.note = ""
        if (address.text.trim() === "") {
            app.setRelay("", "")
            return
        }
        pageStack.push(Qt.resolvedUrl("RelayDialog.qml")).accepted.connect(function() {
            app.setRelay(address.text, key.text)
        })
    }

    Connections {
        target: app
        onRelaySet: if (ok && address.text.trim() === "") key.text = ""
    }

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: column.height

        Column {
            id: column
            width: parent.width
            spacing: Theme.paddingMedium

            PageHeader { title: qsTr("Blind relay") }

            // The root's key renews the group's server keys; until it does,
            // the relay and the hubs' forwarders take nobody.
            Label {
                visible: app.member.periodOverdue
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                color: Theme.errorColor
                text: qsTr("The group's keys for sync away from home have expired: its relay and hubs take no device until this phone renews them with the main device's key.")
            }
            Button {
                visible: app.root && (app.member.periodDue || app.member.periodOverdue)
                anchors.horizontalCenter: parent.horizontalCenter
                enabled: !app.busy && app.member.running
                text: qsTr("Renew the group's keys for sync away from home")
                onClicked: app.renewPeriod()
            }
            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                color: Theme.secondaryHighlightColor
                text: app.root
                      ? qsTr("For a group without a hub of its own: the devices meet at a relay, such as one set up with cbb relay, while the app syncs. The clipboard stays encrypted between the devices, but the relay learns which of them are online and their addresses, and which talk to each other, when and how much. Leave both fields empty to stop.")
                      : qsTr("The group's main device sets the relay for every device; this phone meets the others there while sync away from home is on.")
            }
            TextField {
                id: address
                visible: app.root
                width: parent.width
                label: qsTr("Relay address, such as 198.51.100.9:8764")
                placeholderText: label
                text: app.member.relayAt
                inputMethodHints: Qt.ImhNoAutoUppercase | Qt.ImhNoPredictiveText | Qt.ImhUrlCharactersOnly
                EnterKey.iconSource: "image://theme/icon-m-enter-next"
                EnterKey.onClicked: key.focus = true
            }
            TextField {
                id: key
                visible: app.root
                width: parent.width
                label: qsTr("Relay key, 44 characters")
                placeholderText: label
                maximumLength: page.keyLength
                font.family: "monospace"
                inputMethodHints: Qt.ImhNoAutoUppercase | Qt.ImhNoPredictiveText
                EnterKey.enabled: page.fits(address.text, key.text)
                EnterKey.onClicked: page.meet()
            }
            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                color: app.member.relayConnected ? Theme.highlightColor : Theme.secondaryHighlightColor
                text: page.line()
            }
            Label {
                visible: app.member.relayError !== ""
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                color: Theme.errorColor
                text: app.member.relayError
            }
            Row {
                visible: app.root
                anchors.horizontalCenter: parent.horizontalCenter
                spacing: Theme.paddingMedium
                Button {
                    enabled: !app.busy && app.member.running
                    text: qsTr("Meet at this relay")
                    onClicked: page.meet()
                }
                Button {
                    visible: app.member.relayAt !== ""
                    enabled: !app.busy
                    text: qsTr("Leave the relay")
                    onClicked: {
                        address.text = ""
                        key.text = ""
                        app.setRelay("", "")
                    }
                }
            }
            Label {
                visible: page.note !== "" || app.error !== ""
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                color: Theme.errorColor
                text: page.note !== "" ? page.note : app.error
            }
        }
        VerticalScrollDecorator {}
    }
}
