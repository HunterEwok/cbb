// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import QtQuick 2.6
import Sailfish.Share 1.0

// CBB in the system's share menu (the desktop entry's X-Share Methods text
// and files): a text shared to it goes to the group as this phone's copy,
// and so do images and files, up to 50 MB together, as the iPhone's share
// extension and Android's share sheet do. Loaded apart, so that a system
// without Sailfish.Share still runs the app.
Item {
    ShareProvider {
        method: "text"
        capabilities: ["text/plain"]

        onTriggered: {
            for (var i = 0; i < resources.length; i++) {
                var r = resources[i]
                if (!r || typeof r.data !== "string" || r.data === "")
                    continue
                if (r.type === undefined || r.type === ShareResource.StringDataType)
                    app.member.sendText(r.data)
            }
        }
    }

    ShareProvider {
        method: "files"
        capabilities: ["image/*", "video/*", "audio/*", "application/*", "text/*"]

        onTriggered: {
            var paths = []
            for (var i = 0; i < resources.length; i++) {
                var r = resources[i]
                if (r && typeof r.filePath === "string" && r.filePath !== "")
                    paths.push(r.filePath)
                else if (typeof r === "string" && r !== "")
                    paths.push(r.replace(/^file:\/\//, ""))
            }
            app.member.sendFiles(paths)
        }
    }
}
