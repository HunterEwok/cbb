// SPDX-License-Identifier: AGPL-3.0-only

import CBBKit
import Foundation

#if DEBUG
/// A group made up for screenshots and the UI tests of Home, in debug
/// builds only: the app starts with it when launched with -showcase
/// (docs/testing.md, "The apps' languages, accessibility and screenshots").
/// With -showcaseAlerts too, Home also shows the cards about the group
/// itself: a group from before 0.6 and the member's notices. Nothing leaves
/// the app; every change only changes these devices.
@MainActor
final class ShowcaseGroup: GroupController {
    /// The group for the launch arguments, if they ask for it.
    static func requested(_ arguments: [String] = ProcessInfo.processInfo.arguments) -> ShowcaseGroup? {
        arguments.contains("-showcase") ? ShowcaseGroup(alerts: arguments.contains("-showcaseAlerts")) : nil
    }

    init(alerts: Bool = false) {
        before06 = alerts
        notices = alerts ? Self.someNotices : []
    }

    /// A notice that may be hidden and one that may not, as the member
    /// tells them.
    private static let someNotices: [Notice] = (try? JSONDecoder().decode([Notice].self, from: Data("""
        [{"id": "recovery", "kind": "recovery_not_saved", "args": {}, "dismissable": true},
         {"id": "silent", "kind": "admins_silent", "args": {"device": "deck", "days_left": 12}, "dismissable": false}]
        """.utf8))) ?? []

    let before06: Bool
    private(set) var notices: [Notice]
    func dismissNotice(_ id: String) async throws { notices.removeAll { $0.id == id } }

    var hasGroup: Bool { true }
    var isAdmin: Bool { true }
    var isRoot: Bool { true }
    var computers: [AppModel.Computer] = [
        .init(id: "mac", name: "studio-mac", online: true, caps: ["admin", "dials", "hub"], os: "macos", admin: true,
              device: .init(form: "laptop", osVersion: "26.1", version: "0.6.0"), mode: "all", mayHub: true),
        .init(id: "thinkpad", name: "thinkpad", online: true, os: "linux",
              device: .init(form: "laptop", osVersion: "Ubuntu 26.04", version: "0.6.0"), mode: "all"),
        .init(id: "win", name: "win-desk", online: false, os: "windows", device: .init(form: "desktop", osVersion: "11")),
        .init(id: "pixel", name: "pixel-9", online: true, role: "phone", os: "android", admin: true),
        .init(id: "deck", name: "steamdeck", online: false, os: "linux", admin: true, frozen: true,
              device: .init(form: "console", osVersion: "SteamOS 3.8")),
        .init(id: "pi", name: "pi4", online: true, os: "linux",
              device: .init(form: "board", osVersion: "Raspberry Pi OS 13", version: "0.6.0"), mode: "all"),
    ]
    private var syncOff: AppModel.Hold?
    var devices: [AppModel.Computer] {
        [.init(id: "me", name: "ewok-ipad", online: true, role: "phone", os: "ios", isSelf: true, admin: true, isRoot: true,
               device: .init(form: "tablet", osVersion: "27.0"), syncOff: syncOff)] + computers
    }

    func prepare() throws {}
    func refresh() async {}
    func remove(_ id: String) async throws { computers.removeAll { $0.id == id } }
    func makeAdmin(_ id: String) async throws {
        if let i = computers.firstIndex(where: { $0.id == id }) { computers[i].admin = true }
    }
    func rename(_ id: String, to name: String) async throws {
        if let i = computers.firstIndex(where: { $0.id == id }) { computers[i].name = name }
    }
    func setSync(_ on: Bool, forMS: Int64) throws { syncOff = on ? nil : AppModel.Hold(until: nil) }
    func setMuted(_ id: String, _ on: Bool, forMS: Int64) async throws {
        if let i = computers.firstIndex(where: { $0.id == id }) { computers[i].muted = on ? AppModel.Hold(until: nil) : nil }
    }
    func sync(board: AppModel.Board?) async throws -> AppModel.SyncResult { .sent(to: computers.filter(\.online).map(\.name)) }
}
#endif
