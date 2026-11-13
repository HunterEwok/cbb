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
    /// How long a mark lasts when nothing ends it before: a week.
    static let lifeMS: UInt64 = 7 * 24 * 3600 * 1000
    /// The clock the marks' age is read on; tests set another.
    static var clock: () -> Date = { Date() }
    static var nowMS: UInt64 { UInt64(Swift.max(0, clock().timeIntervalSince1970 * 1000)) }

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
            guard atMS > (g.keyDrawnMS ?? 0), PushMarks.nowMS < atMS &+ PushMarks.lifeMS else { return false }
            switch (event, device, g.members) {
            case let (2, d?, members?): return members.contains(d)
            case let (4, d?, _): return g.root != d
            default: return true
            }
        }

        /// Whether the group's records as the app applied them say the
        /// change this mark tells of did not happen.
        func contradicted(by g: PushVault.Group) -> Bool {
            switch (event, device) {
            case let (2, d?): return g.members?.contains(d) ?? false
            case let (4, d?): return g.root.map { $0 != d } ?? false
            case (6, _): return !g.halted
            default: return false
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

    /// Marks the group with an event that arrived now. When the list is
    /// full a mark no longer in force goes first; a mark not in force when
    /// it arrives (a removal of a device the group does not list) never
    /// pushes one out.
    public static func mark(_ group: String, event: UInt64, device: Data?, state g: PushVault.Group?, now: Date = Date(),
                            in defaults: UserDefaults?) {
        var marks = all(defaults)
        let at = UInt64(Swift.max(0, now.timeIntervalSince1970 * 1000))
        let m = Mark(event: event, device: device, atMS: at)
        var list = marks[group] ?? []
        let g = g ?? PushVault.Group()
        if list.count >= max {
            guard m.inForce(g) else { return }
            if let i = list.firstIndex(where: { !$0.inForce(g) }) { list.remove(at: i) } else { list.removeFirst() }
        }
        list.append(m)
        marks[group] = Array(list.suffix(max))
        save(marks, defaults)
    }

    /// Whether the group shows copies only as hints.
    public static func hintsOnly(_ group: String, _ g: PushVault.Group, in defaults: UserDefaults?) -> Bool {
        (all(defaults)[group] ?? []).contains { $0.inForce(g) }
    }

    /// The app has synced the group's records with `peers` (members that
    /// stayed connected a while) since `at`, and applied them into `g`;
    /// `recordsAt` is when the app last took in records it did not have.
    /// A mark that arrived before `at` is spent when those records
    /// contradict its event (the device it names is still listed, the root
    /// is not the one it names, the group is not stopped), they came from a
    /// member other than the device it names, and the app took in new
    /// records after the mark: a member that brought nothing newer has not
    /// heard of the change either, and spends nothing. That ends a mark of an
    /// event made by a holder of the push key that names a change which
    /// never comes. A mark whose change is there is spent once the app
    /// applies it (`spend`); any mark ends after a week.
    public static func synced(_ group: String, at: Date, peers: Set<Data>, recordsAt: Date?, state g: PushVault.Group,
                              in defaults: UserDefaults?) {
        var marks = all(defaults)
        guard let list = marks[group] else { return }
        let ms = UInt64(Swift.max(0, at.timeIntervalSince1970 * 1000))
        let newer = recordsAt.map { UInt64(Swift.max(0, $0.timeIntervalSince1970 * 1000)) } ?? 0
        let left = list.filter { m in
            guard m.atMS < ms, newer > m.atMS else { return true }
            guard !peers.subtracting(m.device.map { [$0] } ?? []).isEmpty else { return true }
            return !m.contradicted(by: g)
        }
        if left == list { return }
        marks[group] = left.isEmpty ? nil : left
        save(marks, defaults)
    }

    /// Drops every mark of a group the phone left.
    public static func forget(_ group: String, in defaults: UserDefaults?) {
        var marks = all(defaults)
        guard marks.removeValue(forKey: group) != nil else { return }
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
