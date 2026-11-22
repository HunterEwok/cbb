// SPDX-License-Identifier: AGPL-3.0-only

import Foundation

/// What the app and its share extension both use: the group's file in the
/// app group's container and the label of this phone's member key, which
/// the keychain access group shared by both holds (the entitlements, with
/// the Apple developer account). Without the app group, as in a simulator
/// build signed ad hoc, the app keeps its file in its own Application
/// Support and the extension finds no group.
enum Shared {
    static let appGroup = "group.tools.cbb"
    static let memberLabel = "tools.cbb.member"

    /// The app group's container, or nil without the entitlement. Asked
    /// once: without it, every use of the group's settings would wait on
    /// the system's settings daemon until it times out.
    static let container = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroup)

    /// The group's file: in the app group's container when the app may
    /// write there, else in the app's own Application Support.
    static var groupFile: URL {
        if let c = container,
           (try? FileManager.default.createDirectory(at: c.appendingPathComponent("cbb"), withIntermediateDirectories: true)) != nil {
            return c.appendingPathComponent("cbb/group.json")
        }
        return FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("cbb/group.json")
    }

    /// The settings the app and the extension share: the app group's, or
    /// the app's own without the app group.
    static let defaults: UserDefaults = container.flatMap { _ in UserDefaults(suiteName: appGroup) } ?? .standard

    /// Whether a message names the error underneath: on in debug builds,
    /// off in release ones, and either way the app's switch "Show error
    /// details" (seven taps on the version in Settings) when it was set.
    static var showsErrorDetails: Bool {
        if let set = defaults.object(forKey: "ShowErrorDetails") as? Bool { return set }
        #if DEBUG
        return true
        #else
        return false
        #endif
    }
}

/// What Share hands the app (docs/apps.md, "Share"): a text, or images or
/// files, kept in the app group until the app's member sends it, the next
/// time the app runs. The extension runs no member of its own: two members
/// with one device key would fight over the group's state.
enum ShareQueue {
    /// One shared item: a text, or parts, each a file of the item's folder
    /// with its type (one image) or its path (files).
    struct Item: Codable, Equatable {
        struct Part: Codable, Equatable {
            var file: String
            var type: String?
            var path: String?
        }
        var text: String?
        var parts: [Part] = []
    }

    static var dir: URL { Shared.groupFile.deletingLastPathComponent().appendingPathComponent("share-queue", isDirectory: true) }

    /// Keeps a text, or parts as (bytes, type, path), for the app to send.
    static func add(text: String? = nil, parts: [(Data, String?, String?)] = [], in dir: URL = dir) throws {
        // Named by time, so the app sends them in order.
        let name = String(format: "%013.0f-", Date().timeIntervalSince1970 * 1000) + UUID().uuidString
        let tmp = dir.appendingPathComponent("." + name, isDirectory: true)
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        var item = Item(text: text)
        for (i, (data, type, path)) in parts.enumerated() {
            try data.write(to: tmp.appendingPathComponent("\(i)"), options: .completeFileProtectionUntilFirstUserAuthentication)
            item.parts.append(.init(file: "\(i)", type: type, path: path))
        }
        try JSONEncoder().encode(item).write(to: tmp.appendingPathComponent("item.json"))
        // Whole or not at all: the app reads only folders without the dot.
        try FileManager.default.moveItem(at: tmp, to: dir.appendingPathComponent(name, isDirectory: true))
    }

    /// The items waiting, oldest first, each with its folder.
    static func items(in dir: URL = dir) -> [(folder: URL, item: Item)] {
        let names = ((try? FileManager.default.contentsOfDirectory(atPath: dir.path)) ?? []).filter { !$0.hasPrefix(".") }.sorted()
        return names.compactMap { name in
            let folder = dir.appendingPathComponent(name, isDirectory: true)
            guard let data = try? Data(contentsOf: folder.appendingPathComponent("item.json")),
                  let item = try? JSONDecoder().decode(Item.self, from: data) else {
                try? FileManager.default.removeItem(at: folder)
                return nil
            }
            return (folder, item)
        }
    }

    static func remove(_ folder: URL) { try? FileManager.default.removeItem(at: folder) }
}
