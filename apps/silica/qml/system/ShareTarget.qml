// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import QtQuick 2.6
import Sailfish.Share 1.0

// CBB in the system's share menu (the desktop entry's X-Share Method text):
// a text shared to it goes to the group as this phone's copy, as the
// iPhone's share extension and Android's share sheet do. Loaded apart, so
// that a system without Sailfish.Share still runs the app.
ShareProvider {
    method: "text"
    capabilities: ["text/plain"]

    onTriggered: {
        for (var i = 0; i < resources.length; i++) {
            var r = resources[i]
            // Only text: a file would need images and files, which the app
            // does not send yet.
            if (!r || typeof r.data !== "string" || r.data === "")
                continue
            if (r.type === undefined || r.type === ShareResource.StringDataType)
                app.member.sendText(r.data)
        }
    }
}
