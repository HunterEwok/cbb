// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import QtQuick 2.6
import Sailfish.Silica 1.0
import Sailfish.Pickers 1.0

// The pictures and files a remote paste sends (PastePage): the system's
// picker, its choice handed to picked as a list of file URLs.
MultiContentPickerDialog {
    property var picked

    onAccepted: {
        var files = []
        for (var i = 0; i < selectedContent.count; i++)
            files.push(selectedContent.get(i).url.toString())
        if (files.length > 0 && picked)
            picked(files)
    }
}
