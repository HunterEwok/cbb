// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import QtQuick 2.6
import Sailfish.Silica 1.0

// A device's card as a page of its own (DeviceCard).
Page {
    id: page
    property var device

    DeviceCard {
        anchors.fill: parent
        device: page.device
    }
}
