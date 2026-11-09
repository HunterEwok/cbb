// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import QtQuick 2.6
import Sailfish.Silica 1.0

// The admin PIN before the admin key signs (docs/apps.md, "The admin PIN on
// Aurora"): the phone's TEE checks it and locks the key after seven wrong
// ones. fresh: no PIN yet, so the user chooses one and types it twice.
Dialog {
    id: dialog
    property bool fresh: false
    // After a wrong PIN: the tries left, as the app counted them.
    property int triesLeft: -1
    readonly property int minLength: 4

    canAccept: pin.text.length >= minLength && (!fresh || again.text === pin.text)

    onAccepted: app.enterPin(pin.text)
    onRejected: app.cancelPin()

    Column {
        width: parent.width
        spacing: Theme.paddingMedium

        DialogHeader {
            title: dialog.fresh ? qsTr("Choose the admin PIN") : qsTr("Admin PIN")
            acceptText: dialog.fresh ? qsTr("Set") : qsTr("Confirm")
        }
        PasswordField {
            id: pin
            width: parent.width
            label: qsTr("PIN")
            placeholderText: label
            inputMethodHints: Qt.ImhDigitsOnly | Qt.ImhNoPredictiveText
            focus: true
            EnterKey.enabled: dialog.fresh ? text.length >= dialog.minLength : dialog.canAccept
            EnterKey.onClicked: dialog.fresh ? again.forceActiveFocus() : dialog.accept()
        }
        PasswordField {
            id: again
            visible: dialog.fresh
            width: parent.width
            label: qsTr("The PIN again")
            placeholderText: label
            inputMethodHints: Qt.ImhDigitsOnly | Qt.ImhNoPredictiveText
            EnterKey.enabled: dialog.canAccept
            EnterKey.onClicked: dialog.accept()
        }
        Label {
            visible: dialog.triesLeft >= 0
            x: Theme.horizontalPageMargin
            width: parent.width - 2 * Theme.horizontalPageMargin
            wrapMode: Text.Wrap
            color: Theme.errorColor
            text: dialog.triesLeft === 1
                  ? qsTr("Wrong PIN. One try is left: the next wrong PIN locks the admin key for good.")
                  : qsTr("Wrong PIN. Tries left: %1.").arg(dialog.triesLeft)
        }
        Label {
            x: Theme.horizontalPageMargin
            width: parent.width - 2 * Theme.horizontalPageMargin
            wrapMode: Text.Wrap
            font.pixelSize: Theme.fontSizeSmall
            color: Theme.secondaryHighlightColor
            text: dialog.fresh
                  ? qsTr("CBB's own PIN, at least four digits. Do not use the phone's unlock code. The phone's secure element checks it before every admin action; seven wrong PINs lock the admin key for good, and no one can unlock it.")
                  : qsTr("The phone's secure element checks the PIN; seven wrong PINs lock the admin key for good.")
        }
    }
}
