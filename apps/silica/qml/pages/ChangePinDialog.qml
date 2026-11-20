// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import QtQuick 2.6
import Sailfish.Silica 1.0

// Settings: a new admin PIN, after the current one, which the TEE checks.
Dialog {
    id: dialog
    readonly property int minLength: 4
    // The new PIN passes the rule: six digits or more, none easy to guess.
    readonly property bool allowed: app.pinAllowed(pin.text)

    canAccept: old.text.length >= minLength && allowed && again.text === pin.text

    onAccepted: app.changePin(old.text, pin.text)

    Column {
        width: parent.width
        spacing: Theme.paddingMedium

        DialogHeader {
            title: qsTr("Change the admin PIN")
            acceptText: qsTr("Change")
        }
        PasswordField {
            id: old
            width: parent.width
            label: qsTr("Current PIN")
            placeholderText: label
            inputMethodHints: Qt.ImhDigitsOnly | Qt.ImhNoPredictiveText
            focus: true
            EnterKey.onClicked: pin.forceActiveFocus()
        }
        PasswordField {
            id: pin
            width: parent.width
            label: qsTr("New PIN")
            placeholderText: label
            inputMethodHints: Qt.ImhDigitsOnly | Qt.ImhNoPredictiveText
            EnterKey.onClicked: again.forceActiveFocus()
        }
        PasswordField {
            id: again
            width: parent.width
            label: qsTr("The new PIN again")
            placeholderText: label
            inputMethodHints: Qt.ImhDigitsOnly | Qt.ImhNoPredictiveText
            EnterKey.enabled: dialog.canAccept
            EnterKey.onClicked: dialog.accept()
        }
        Label {
            visible: pin.text.length > 0 && !dialog.allowed
            x: Theme.horizontalPageMargin
            width: parent.width - 2 * Theme.horizontalPageMargin
            wrapMode: Text.Wrap
            color: Theme.errorColor
            text: qsTr("At least six digits, and not an easy one such as 123456 or 111111.")
        }
    }
}
