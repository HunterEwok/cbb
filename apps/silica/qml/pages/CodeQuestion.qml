// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import QtQuick 2.6
import Sailfish.Silica 1.0

// The code both screens show while a device joins a group of 0.6, and the
// person's answer (docs/apps.md, "Screens"): WindowPage and JoinWindowPage.
Column {
    id: question
    property string who: ""
    property string code: ""
    signal answered(bool yes)

    width: parent.width
    spacing: Theme.paddingLarge

    Label {
        x: Theme.horizontalPageMargin
        width: parent.width - 2 * Theme.horizontalPageMargin
        horizontalAlignment: Text.AlignHCenter
        wrapMode: Text.Wrap
        color: Theme.highlightColor
        text: question.who
    }
    Label {
        anchors.horizontalCenter: parent.horizontalCenter
        text: question.code
        font.family: "monospace"
        font.pixelSize: Theme.fontSizeHuge
        font.bold: true
        font.letterSpacing: Theme.paddingSmall
    }
    Label {
        x: Theme.horizontalPageMargin
        width: parent.width - 2 * Theme.horizontalPageMargin
        horizontalAlignment: Text.AlignHCenter
        wrapMode: Text.Wrap
        text: qsTr("Does the other screen show this code?")
    }
    Button {
        anchors.horizontalCenter: parent.horizontalCenter
        preferredWidth: Theme.buttonWidthLarge
        text: qsTr("They match")
        onClicked: question.answered(true)
    }
    Button {
        anchors.horizontalCenter: parent.horizontalCenter
        preferredWidth: Theme.buttonWidthLarge
        text: qsTr("They don't match")
        onClicked: question.answered(false)
    }
}
