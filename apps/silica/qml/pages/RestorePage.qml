// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import QtQuick 2.6
import QtMultimedia 5.6
import Sailfish.Silica 1.0

// Restores the group on a new phone with its recovery sheet (docs/protocol.md,
// section 10, "The recovery key"): the camera reads the sheet's QR code, the
// phone finds a phone or a computer of the group on this network and takes
// the group's records from it, then claims the group, which waits the
// group's delay unless the root cancels it. The code's text can be pasted
// instead.
Page {
    id: page

    readonly property string step: app.restoreState
    readonly property bool scanning: step === "" || step === "failed"
    property string sheet: ""

    Component.onCompleted: app.resetRestore()
    Component.onDestruction: app.resetRestore()

    function use(text) {
        if (text === "" || app.busy)
            return
        page.sheet = text
        app.restore(text)
    }

    Camera {
        id: camera
        cameraState: page.scanning && page.sheet === "" && page.status === PageStatus.Active && Qt.application.active
                     ? Camera.ActiveState : Camera.UnloadedState
        captureMode: Camera.CaptureViewfinder
        focus.focusMode: Camera.FocusContinuous
    }

    // A frame every so often goes to the core's reader.
    Timer {
        interval: 400
        repeat: true
        running: page.scanning && page.sheet === "" && camera.cameraState === Camera.ActiveState
        onTriggered: viewfinder.grabToImage(function(result) { page.use(app.scanSheet(result.image)) })
    }

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: column.height

        Column {
            id: column
            width: parent.width
            spacing: Theme.paddingLarge

            PageHeader { title: qsTr("Restore the group") }
            // Restoring makes this device the group's main one (NewGroupPage).
            Label {
                visible: !app.root
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                font.pixelSize: Theme.fontSizeSmall
                color: Theme.errorColor
                text: qsTr("This device has no secure key chip or no strong fingerprint or face sensor: as the group's main device it guards the group less well than a phone that has both.")
            }

            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                color: Theme.highlightColor
                text: app.root ? qsTr("This phone is the group's root now.")
                    : page.step === "restoring" ? qsTr("Looking for a phone or a computer of the group on this network…")
                    : page.step === "claiming" ? qsTr("Claiming the group…")
                    : page.step === "claimed"
                      ? (app.claimState === "pending" && app.claimLeftMs > 0
                         ? qsTr("The group is restored on this phone. It becomes the group's root when the waiting time ends, %1 h from now, unless the root cancels the claim.").arg(Math.ceil(app.claimLeftMs / 3600000))
                         : qsTr("The group is restored on this phone. It becomes the group's root once the group's waiting time passes, unless the root cancels the claim."))
                    : page.sheet === "" ? qsTr("Point the camera at the QR code of the group's recovery sheet. Keep a phone or a computer of the group turned on and on this network.")
                    : ""
            }

            Item {
                visible: page.scanning && page.sheet === ""
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
                visible: page.scanning && page.sheet === "" && app.restoreHint !== ""
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                color: Theme.secondaryHighlightColor
                text: app.restoreHint
            }

            Label {
                visible: page.scanning && page.sheet === "" && camera.errorCode !== Camera.NoError
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                color: Theme.errorColor
                text: qsTr("The camera does not start: %1").arg(camera.errorString)
            }

            TextField {
                id: pasted
                visible: page.scanning && page.sheet === ""
                width: parent.width
                label: qsTr("Or paste the code's text, cbb://recover…")
                placeholderText: label
                inputMethodHints: Qt.ImhNoAutoUppercase | Qt.ImhNoPredictiveText | Qt.ImhUrlCharactersOnly
                EnterKey.enabled: text.trim().indexOf("cbb://recover?") === 0
                EnterKey.iconSource: "image://theme/icon-m-enter-accept"
                EnterKey.onClicked: page.use(text.trim())
            }

            BusyIndicator {
                anchors.horizontalCenter: parent.horizontalCenter
                running: page.step === "restoring" || page.step === "claiming"
                visible: running
                size: BusyIndicatorSize.Medium
            }

            Label {
                visible: page.step === "failed" && app.error !== ""
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                text: app.error
                wrapMode: Text.Wrap
                color: Theme.errorColor
            }

            // A phone that restored the group but whose claim did not go
            // out claims again with the same sheet; else the camera reads
            // the sheet again.
            Button {
                visible: page.step === "failed"
                anchors.horizontalCenter: parent.horizontalCenter
                text: qsTr("Try again")
                onClicked: {
                    if (app.group !== "" && !app.admin && app.claimState === "" && page.sheet !== "") {
                        app.restore(page.sheet)
                    } else {
                        pasted.text = ""
                        page.sheet = ""
                        app.resetRestore()
                    }
                }
            }
        }
        VerticalScrollDecorator {}
    }
}
