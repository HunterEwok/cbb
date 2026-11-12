// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import QtQuick 2.6
import Sailfish.Silica 1.0
import "devices.js" as Devices

// Remote paste (docs/design.md, "Remote paste"), as the iPhone's PasteView
// and Android's PasteOn: a text to put where a device's focus is, pasted or
// typed, with Enter after it if asked; or a picture or files, which go to
// the group as a copy that the device pastes. The device takes it only
// when its user turned remote paste on there. Sending signs a paste
// command with the admin key.
Page {
    id: page
    property var device
    // Whether this page sent something, so that app.error is its answer.
    property bool tried: false
    property bool closing: false

    function close() {
        if (pageStack.busy)
            closing = true
        else
            pageStack.pop(pageStack.previousPage(page))
    }

    Connections {
        target: pageStack
        onBusyChanged: if (!pageStack.busy && page.closing) {
                           page.closing = false
                           page.close()
                       }
    }

    Connections {
        target: app
        onManaged: {
            if (action !== "paste" || device !== page.device.id)
                return
            page.tried = true
            if (ok)
                page.close()
        }
    }

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: column.height + Theme.paddingLarge

        Column {
            id: column
            width: parent.width
            spacing: Theme.paddingMedium

            PageHeader {
                title: qsTr("Paste on %1").arg(Devices.name(page.device))
            }

            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                font.pixelSize: Theme.fontSizeSmall
                color: Theme.secondaryHighlightColor
                text: qsTr("It goes where %1's keyboard focus is, once its user turned remote paste on there. Left empty, Paste sends what the clipboard holds.").arg(Devices.name(page.device))
            }

            TextArea {
                id: field
                width: parent.width
                label: qsTr("Text")
                placeholderText: label
                inputMethodHints: Qt.ImhNoAutoUppercase | Qt.ImhNoPredictiveText
                focus: true
            }

            // Why the device did not take it, right under the text, where
            // the keyboard does not hide it.
            Label {
                visible: page.tried && !app.busy && app.error !== ""
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                color: Theme.errorColor
                text: app.error
            }

            Button {
                anchors.horizontalCenter: parent.horizontalCenter
                text: qsTr("Paste")
                enabled: !app.busy
                onClicked: {
                    field.focus = false
                    page.tried = false
                    app.paste(page.device.id, field.text, typing.checked, enter.checked, secret.checked)
                }
            }
            BusyIndicator {
                anchors.horizontalCenter: parent.horizontalCenter
                size: BusyIndicatorSize.Medium
                running: app.busy
                visible: running
            }

            TextSwitch {
                id: typing
                text: qsTr("Type it key by key")
            }
            TextSwitch {
                id: enter
                text: qsTr("Press Enter after it")
            }
            TextSwitch {
                id: secret
                text: qsTr("A secret")
            }
            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                font.pixelSize: Theme.fontSizeSmall
                color: Theme.secondaryHighlightColor
                text: qsTr("A paste suits most apps; typing suits those that take no paste, and only up to 4 KB. Enter runs a command in a terminal, so the computer takes it only when its user allowed that. A secret leaves no trace in the computer's log or clipboard.")
            }

            Button {
                anchors.horizontalCenter: parent.horizontalCenter
                text: qsTr("Paste a picture or files…")
                enabled: !app.busy
                // The picker is a page of its own, so that this page works
                // where the system has no pickers.
                onClicked: pageStack.push(Qt.resolvedUrl("PasteFilesDialog.qml"), {
                    picked: function(files) {
                        page.tried = false
                        app.pasteFiles(page.device.id, files, enter.checked)
                    }
                })
            }
            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                font.pixelSize: Theme.fontSizeSmall
                color: Theme.secondaryHighlightColor
                text: qsTr("A picture or files go to the group as a copy, and the computer pastes them where its focus is, as Ctrl+V would: into a chat, a document or a folder. Enter, if on, sends them in a chat.")
            }
        }
        VerticalScrollDecorator {}
    }
}
