// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Words and icons for a device of cbb_member_devices (docs/core-api.md),
// shared by the main page's tiles and list and the device's page.

// The devices with this phone first, as every app shows the device it runs
// on until the user moves it (moving tiles is not on Aurora yet).
function selfFirst(list) {
    var out = []
    for (var i = 0; i < list.length; i++)
        if (list[i].self)
            out.push(list[i])
    for (var j = 0; j < list.length; j++)
        if (!list[j].self)
            out.push(list[j])
    return out
}

// The name of its system, "device" for firmware without one.
function system(d) {
    switch (d.os) {
    case "linux": return "Linux"
    case "windows": return "Windows"
    case "macos": return "macOS"
    case "ios": return "iOS"
    case "android": return "Android"
    case "aurora": return "Aurora OS"
    case "sailfish": return "Sailfish OS"
    case "watchos": return "watchOS"
    case "wearos": return "Wear OS"
    case "": return d.role === "lite" ? qsTr("lite member") : ""
    default: return qsTr("device")
    }
}

// Its kind, from its role and system.
function kind(d) {
    if (d.role === "phone")
        return qsTr("Phone")
    if (d.role === "watch")
        return qsTr("Watch")
    if (d.role === "lite")
        return d.os === "none" ? qsTr("Board") : qsTr("Lite member")
    return qsTr("Computer")
}

// A theme icon for it; the tile shows its first letter when the theme has
// none.
function icon(d) {
    if (d.role === "phone")
        return "image://theme/icon-m-phone"
    if (d.role === "watch")
        return "image://theme/icon-m-watch"
    if (d.role === "lite")
        return "image://theme/icon-m-device"
    return "image://theme/icon-m-computer"
}

// Its mark: this phone, the root, an admin, frozen, or none.
function mark(d) {
    if (d.self)
        return qsTr("this phone")
    if (d.frozen)
        return qsTr("frozen")
    if (d.root)
        return qsTr("root")
    if (d.admin)
        return qsTr("admin")
    return ""
}

// Its place in the group, for its page.
function role(d) {
    if (d.frozen)
        return qsTr("Admin, frozen by another admin")
    if (d.root && d.admin)
        return qsTr("Root and admin")
    if (d.root)
        return qsTr("Root")
    if (d.admin)
        return qsTr("Admin")
    if (!d.listed)
        return qsTr("Not in the records yet")
    return qsTr("Member")
}

// Whether it is online, for its page.
function status(d) {
    if (d.self)
        return qsTr("This phone")
    return d.online ? qsTr("Online") : qsTr("Offline")
}

// Its name, or the start of its ID when it has none.
function name(d) {
    return d.name !== "" ? d.name : d.device.substring(0, 8)
}
