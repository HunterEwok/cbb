// SPDX-License-Identifier: AGPL-3.0-only

import SwiftUI

/// What a device is, for its icon: the iPhone app's kinds, with SF Symbols.
enum DeviceKind: String, CaseIterable {
    case laptop, desktop, phone, tablet, tv, board, server, router, console, watch, retro, other

    var symbol: String {
        switch self {
        case .laptop: "laptopcomputer"
        case .desktop: "desktopcomputer"
        case .phone: "iphone"
        case .tablet: "ipad"
        case .tv: "tv"
        case .board: "cpu"
        case .server: "server.rack"
        case .router: "wifi.router"
        case .console: "gamecontroller"
        case .watch: "applewatch"
        case .retro: "keyboard"
        case .other: "shippingbox"
        }
    }

    var title: LocalizedStringKey {
        switch self {
        case .laptop: "Laptop"
        case .desktop: "Computer"
        case .phone: "Phone"
        case .tablet: "Tablet"
        case .tv: "TV"
        case .board: "Board"
        case .server: "Server"
        case .router: "Router"
        case .console: "Game console"
        case .watch: "Watch"
        case .retro: "Retro computer"
        case .other: "Device"
        }
    }
}

extension Control.Device {
    /// Its kind as its hello says, or else as its role and system tell: a
    /// Mac is taken for a laptop, another computer for a desktop.
    var kind: DeviceKind {
        if let form, let k = DeviceKind(rawValue: form) { return k }
        return switch (role, os) {
        case ("phone", _), ("shortcut", _): .phone
        case ("lite", _): .board
        case ("watch", _): .watch
        case (_, "macos"): .laptop
        case (_, "ios"), (_, "android"): .phone
        default: .desktop
        }
    }

    /// The name of its operating system, the same in every language.
    var system: String? {
        switch os {
        case "linux": "Linux"
        case "windows": "Windows"
        case "macos": "macOS"
        case "ios": "iOS"
        case "android": "Android"
        case "watchos": "watchOS"
        case "wearos": "Wear OS"
        default: nil
        }
    }

    /// Its system with the version its hello gives; Linux names its
    /// distribution, which says more than "Linux".
    var systemWithVersion: String? {
        guard let system else { return osVersion }
        guard let v = osVersion else { return system }
        return os == "linux" ? v : "\(system) \(v)"
    }

    /// Its place in the group, in a word; nil for a plain member.
    var standing: LocalizedStringKey? {
        if isSelf { return admin ? "This Mac · admin" : "This Mac" }
        if frozen { return "frozen" }
        if root { return "root" }
        if admin { return "admin" }
        return nil
    }

    var roleTitle: LocalizedStringKey {
        switch role {
        case "phone": "Phone app"
        case "lite": "Lite member"
        case "shortcut": "Shortcut"
        case "watch": "Watch"
        default: "Full member"
        }
    }
}

/// A device's icon on a soft square, bright while it is online.
struct DeviceIcon: View {
    let device: Control.Device
    var size: CGFloat = 44
    @Environment(\.palette) private var palette

    var body: some View {
        Image(systemName: device.kind.symbol)
            .font(.system(size: size * 0.48, weight: .medium))
            .frame(width: size, height: size)
            .foregroundStyle(device.online || device.isSelf ? palette.accent : palette.textDim)
            .background(device.online || device.isSelf ? palette.soft : palette.line, in: RoundedRectangle(cornerRadius: size * 0.3, style: .continuous))
            .accessibilityHidden(true)
    }
}

/// The live dot: the accent while online, dim while not.
struct OnlineDot: View {
    let online: Bool
    @Environment(\.palette) private var palette

    var body: some View {
        Circle().fill(online ? palette.accent : palette.textDim).frame(width: 8, height: 8)
            .accessibilityHidden(true)
    }
}

/// The chosen colour and appearance on a window's views.
struct Themed: ViewModifier {
    @AppStorage(AccentChoice.key) private var color = Tokens.colors[0].name
    @AppStorage(Appearance.key) private var appearance = Appearance.system.rawValue
    @Environment(\.colorScheme) private var scheme

    func body(content: Content) -> some View {
        let a = Appearance(rawValue: appearance) ?? .system
        content
            .environment(\.palette, a.palette(color, for: scheme))
            .tint(a.palette(color, for: scheme).accent)
            .preferredColorScheme(a.scheme)
    }
}
