// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import QtQuick 2.6
import QtMultimedia 5.6
import Sailfish.Silica 1.0

// Adds a device to the group, as an admin phone: the camera reads the code
// the device shows when it joins (cbb join -qr on a computer, Join a group
// on a phone), and the phone dials it and admits it (docs/protocol.md,
// section 6, "The joiner listens"). The code's text can be pasted instead.
Page {
    id: page

    readonly property string step: app.admit.state
    readonly property bool scanning: step === "scanning"

    Component.onCompleted: app.admit.reset()
    Component.onDestruction: app.admit.reset()

    function use(text) {
        if (text !== "")
            app.startAdmit(text)
    }

    Camera {
        id: camera
        cameraState: page.scanning && page.status === PageStatus.Active && Qt.application.active
                     ? Camera.ActiveState : Camera.UnloadedState
        captureMode: Camera.CaptureViewfinder
        focus.focusMode: Camera.FocusContinuous
    }

    // A frame every so often goes to the core's reader.
    Timer {
        interval: 400
        repeat: true
        running: page.scanning && camera.cameraState === Camera.ActiveState
        onTriggered: viewfinder.grabToImage(function(result) { page.use(app.admit.scan(result.image)) })
    }

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: column.height

        Column {
            id: column
            width: parent.width
            spacing: Theme.paddingLarge

            PageHeader { title: qsTr("Add a device") }

            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                color: Theme.highlightColor
                text: page.scanning ? qsTr("On the device to add, choose to join a group, then point the camera at the code it shows.")
                    : page.step === "preparing" || page.step === "dialing" ? qsTr("Connecting to the device…")
                    : page.step === "admitting" ? qsTr("Adding the device…")
                    : page.step === "admitted" || page.step === "confirmed"
                      ? (app.admit.device !== "" ? qsTr("%1 is in the group now.").arg(app.admit.device) : qsTr("The device is in the group now."))
                    : ""
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
                visible: page.scanning && app.admit.hint !== ""
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                color: Theme.secondaryHighlightColor
                text: app.admit.hint
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
                label: qsTr("Or paste the code's text, cbb://join…")
                placeholderText: label
                inputMethodHints: Qt.ImhNoAutoUppercase | Qt.ImhNoPredictiveText | Qt.ImhUrlCharactersOnly
                EnterKey.enabled: text.indexOf("cbb://join?") === 0
                EnterKey.iconSource: "image://theme/icon-m-enter-accept"
                EnterKey.onClicked: page.use(text.trim())
            }

            BusyIndicator {
                anchors.horizontalCenter: parent.horizontalCenter
                running: page.step === "preparing" || page.step === "dialing" || page.step === "admitting"
                visible: running
                size: BusyIndicatorSize.Medium
            }

            Label {
                visible: app.admit.error !== ""
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                text: app.admit.error
                wrapMode: Text.Wrap
                color: Theme.errorColor
            }

            Button {
                visible: page.step === "failed" || page.step === "admitted" || page.step === "confirmed"
                anchors.horizontalCenter: parent.horizontalCenter
                text: page.step === "failed" ? qsTr("Try again") : qsTr("Add another device")
                onClicked: { pasted.text = ""; app.admit.reset() }
            }
        }
        VerticalScrollDecorator {}
    }
}
