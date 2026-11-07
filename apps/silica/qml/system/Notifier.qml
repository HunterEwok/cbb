// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import QtQuick 2.6
import Nemo.Notifications 1.0

// Shows the group's events (src/events.h) as the system's notifications.
// Loaded apart, so that a system without the module still runs the app.
Item {
    Notification {
        id: note
        appName: "CBB"
        summary: "CBB"
        previewSummary: "CBB"
        urgency: Notification.Normal
    }

    // The images or files of a copy from another device are saved.
    Connections {
        target: app.member
        onSaved: {
            note.body = qsTr("Saved %1 from the group in Downloads").arg(count === 1 ? qsTr("a file") : qsTr("%1 files").arg(count))
            note.previewBody = note.body
            note.replacesId = 0
            note.publish()
        }
    }

    Connections {
        target: app.events
        onPosted: {
            note.body = text
            note.previewBody = text
            note.replacesId = 0
            note.publish()
        }
    }
}
