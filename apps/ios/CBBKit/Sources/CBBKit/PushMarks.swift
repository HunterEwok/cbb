// SPDX-License-Identifier: AGPL-3.0-only

import Foundation

/// The hints-only marks (docs/core-api.md, "Push"): when the notification
/// extension opens an event of a removal, a new root or a stop, the group's
/// copies show only as hints until the app has applied that change and
/// drawn a new push key, which it does in one step, or has synced the
/// group's records with a member after the event and found no such change.
/// Kept in the push app group's defaults, nothing secret: per group the
/// marks' events, devices and the phone's time when each arrived.
public enum PushMarks {
    /// The app group the app and its notification extension share for the
    /// marks and the IDs the extension showed, and nothing else: never the
    /// app's group with the group's file and the servers' credentials.
    public static let appGroup = "group.tools.cbb.push"
    /// Its defaults (a process's own in a build without the entitlement).
    public static var defaults: UserDefaults? { UserDefaults(suiteName: appGroup) }

    static let key = "push.marks"
    static let max = 16

    public struct Mark: Codable, Equatable {
        public var event: UInt64
        public var device: Data?
        /// The phone's clock when it arrived.
        public var atMS: UInt64

        public init(event: UInt64, device: Data?, atMS: UInt64) {
            self.event = event
            self.device = device
            self.atMS = atMS
        }

        /// Whether the change it tells of is still to be applied. Any mark
        /// ends with a push key drawn after it (the app draws one when it
        /// applies a removal or a new root); before that, a removal of a
        /// device the app no longer lists, or a new root the app already
        /// knows, was applied before the event came.
        public func inForce(_ g: PushVault.Group) -> Bool {
            guard atMS > (g.keyDrawnMS ?? 0) else { return false }
            switch (event, device, g.members) {
            case let (2, d?, members?): return members.contains(d)
            case let (4, d?, _): return g.root != d
            default: return true
            }
        }
    }

    static func all(_ defaults: UserDefaults?) -> [String: [Mark]] {
        guard let d = defaults?.data(forKey: key) else { return [:] }
        return (try? JSONDecoder().decode([String: [Mark]].self, from: d)) ?? [:]
    }

    static func save(_ marks: [String: [Mark]], _ defaults: UserDefaults?) {
        defaults?.set(try? JSONEncoder().encode(marks), forKey: key)
    }

    /// Marks the group with an event that arrived now.
    public static func mark(_ group: String, event: UInt64, device: Data?, now: Date = Date(), in defaults: UserDefaults?) {
        var marks = all(defaults)
        let at = UInt64(Swift.max(0, now.timeIntervalSince1970 * 1000))
        marks[group, default: []].append(Mark(event: event, device: device, atMS: at))
        marks[group] = Array(marks[group]!.suffix(max))
        save(marks, defaults)
    }

    /// Whether the group shows copies only as hints.
    public static func hintsOnly(_ group: String, _ g: PushVault.Group, in defaults: UserDefaults?) -> Bool {
        (all(defaults)[group] ?? []).contains { $0.inForce(g) }
    }

    /// The app has synced the group's records with a member since `at`
    /// (one has stayed connected a while): the marks that arrived before
    /// then are spent, whether their change was there to apply (and a key
    /// was drawn for it) or not there at all, as for an event made by a
    /// holder of the push key that names a change which never comes.
    public static func synced(_ group: String, at: Date, in defaults: UserDefaults?) {
        var marks = all(defaults)
        guard let list = marks[group] else { return }
        let ms = UInt64(Swift.max(0, at.timeIntervalSince1970 * 1000))
        let left = list.filter { $0.atMS >= ms }
        if left == list { return }
        marks[group] = left.isEmpty ? nil : left
        save(marks, defaults)
    }

    /// Drops the marks the group's state has spent.
    public static func spend(_ group: String, _ g: PushVault.Group, in defaults: UserDefaults?) {
        var marks = all(defaults)
        guard let list = marks[group] else { return }
        let left = list.filter { $0.inForce(g) }
        if left == list { return }
        marks[group] = left.isEmpty ? nil : left
        save(marks, defaults)
    }
}
