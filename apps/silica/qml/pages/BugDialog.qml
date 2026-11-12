// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import QtQuick 2.6
import Sailfish.Silica 1.0

// The bug report's question in release mode (docs/core-api.md, "Bug
// reports"): "Oops, something broke", Allow and Cancel, "Always allow"
// after the user allowed twice, and a small "Technical details" link that
// shows the report as it would go.
Dialog {
    property alias always: alwaysSwitch.checked

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: column.height

        Column {
            id: column
            width: parent.width
            spacing: Theme.paddingLarge

            DialogHeader {
                title: qsTr("Oops, something broke")
                acceptText: qsTr("Allow")
                cancelText: qsTr("Cancel")
            }
            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                color: Theme.highlightColor
                text: qsTr("Sorry! Allow us to send a short report so that we can fix it? It holds only what broke, the versions of CBB and the system, the device's model and CBB's own records. Your texts, files, keys, device names and addresses are not in it. The report is anonymous.")
            }
            Label {
                visible: app.bugs.fixedIn !== ""
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                text: qsTr("Version %1 fixes this: update CBB.").arg(app.bugs.fixedIn)
            }
            TextSwitch {
                id: alwaysSwitch
                visible: app.bugs.offerAlways
                text: qsTr("Always allow")
            }
            BackgroundItem {
                id: detailsLink
                property bool open: false
                width: parent.width
                height: Theme.itemSizeExtraSmall
                onClicked: open = !open
                Label {
                    x: Theme.horizontalPageMargin
                    anchors.verticalCenter: parent.verticalCenter
                    font.pixelSize: Theme.fontSizeExtraSmall
                    color: Theme.secondaryHighlightColor
                    text: qsTr("Technical details")
                }
            }
            Label {
                visible: detailsLink.open
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.WrapAnywhere
                font.family: "monospace"
                font.pixelSize: Theme.fontSizeTiny
                color: Theme.secondaryColor
                text: app.bugs.report
            }
        }
        VerticalScrollDecorator {}
    }
}
