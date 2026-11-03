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
           (try? FileManager.default.createDirectory(at: c.appendingPathComponent("clipboardbridge"), withIntermediateDirectories: true)) != nil {
            return c.appendingPathComponent("clipboardbridge/group.json")
        }
        return FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("clipboardbridge/group.json")
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
