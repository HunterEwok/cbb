// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import QtQuick 2.6
import QtMultimedia 5.6
import Sailfish.Silica 1.0

// Join with an invitation (docs/apps.md, Start): the camera reads the
// invitation's QR code, the usual way, or its text is pasted when it came
// another way. The invitation found waits for the user: Join opens the
// join page with it, Decline sends nothing.
Page {
    id: page

    // What the core read of the invitation: {group, hub, expiresMs}, or
    // {error}; empty while scanning.
    property var found: ({})
    property string text: ""
    readonly property bool scanning: page.text === ""

    function use(t) {
        if (t === "")
            return
        var r = app.invite.read(t)
        if (r.error !== undefined) {
            error.text = r.error
            return
        }
        error.text = ""
        page.found = r
        page.text = t.trim()
    }

    Camera {
        id: camera
        cameraState: page.scanning && page.status === PageStatus.Active && Qt.application.active
                     ? Camera.ActiveState : Camera.UnloadedState
        captureMode: Camera.CaptureViewfinder
        focus.focusMode: Camera.FocusContinuous
    }

    Timer {
        interval: 400
        repeat: true
        running: page.scanning && camera.cameraState === Camera.ActiveState
        onTriggered: viewfinder.grabToImage(function(result) { page.use(app.invite.scan(result.image)) })
    }

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: column.height

        Column {
            id: column
            width: parent.width
            spacing: Theme.paddingLarge

            PageHeader { title: page.scanning ? qsTr("Join with an invitation") : qsTr("You are invited to a group") }

            Label {
                visible: page.scanning
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                color: Theme.highlightColor
                text: qsTr("Point the camera at the invitation's QR code.")
            }

            Item {
                visible: page.scanning
                width: parent.width
                height: width

                VideoOutput {
                    id: viewfinder
                    anchors.fill: parent
                    anchors.margins: Theme.horizontalPageMargin
                    source: camera
                    fillMode: VideoOutput.PreserveAspectCrop
                    autoOrientation: true
                }
            }

            Label {
                visible: page.scanning && camera.errorCode !== Camera.NoError
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                color: Theme.errorColor
                text: qsTr("The camera does not start: %1").arg(camera.errorString)
            }

            TextField {
                id: pasted
                visible: page.scanning
                width: parent.width
                label: qsTr("Or paste the invitation's text, cbb://invite…")
                placeholderText: label
                inputMethodHints: Qt.ImhNoAutoUppercase | Qt.ImhNoPredictiveText | Qt.ImhUrlCharactersOnly
                EnterKey.enabled: text.trim() !== ""
                EnterKey.iconSource: "image://theme/icon-m-enter-accept"
                EnterKey.onClicked: page.use(text)
            }

            DetailItem {
                visible: !page.scanning
                label: qsTr("Group")
                value: page.found.group !== undefined ? page.found.group : ""
            }
            DetailItem {
                visible: !page.scanning
                label: qsTr("Hub")
                value: page.found.hub !== undefined ? page.found.hub : ""
            }
            DetailItem {
                visible: !page.scanning
                label: qsTr("Valid until")
                value: page.found.expiresMs !== undefined ? Qt.formatDateTime(new Date(page.found.expiresMs), Qt.DefaultLocaleShortDate) : ""
            }

            Label {
                visible: !page.scanning
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                color: Theme.secondaryHighlightColor
                text: qsTr("Join only if you asked for this invitation. Whoever made it admits this phone once they see the words it shows.")
            }

            Button {
                visible: !page.scanning
                anchors.horizontalCenter: parent.horizontalCenter
                preferredWidth: Theme.buttonWidthLarge
                text: qsTr("Join")
                onClicked: pageStack.replace(Qt.resolvedUrl("JoinPage.qml"), { invite: page.text })
            }
            Button {
                visible: !page.scanning
                anchors.horizontalCenter: parent.horizontalCenter
                preferredWidth: Theme.buttonWidthLarge
                text: qsTr("Decline")
                onClicked: pageStack.pop()
            }

            Label {
                id: error
                visible: text !== ""
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                color: Theme.errorColor
            }
        }
        VerticalScrollDecorator {}
    }
}
