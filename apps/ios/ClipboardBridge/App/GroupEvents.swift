// SPDX-License-Identifier: AGPL-3.0-only

import Foundation
import os
import UserNotifications

private let log = Logger(subsystem: "io.github.hunterewok.clipboardbridge", category: "events")

/// An event of the group the app notifies of (docs/apps.md, Notifications);
/// iOS shows the notification on a paired Apple Watch too.
enum GroupEvent: Equatable {
    case added(String)
    case removed(String)
    case madeAdmin(String)
    case frozen(String)
    case unfrozen(String)
    case takenOver(String)
    case hubUnreachable

    /// The settings, one for each kind of event, all on by default.
    enum Kind: String, CaseIterable, Identifiable {
        case devices, admins, frozen, takeover, hub

        var id: String { rawValue }
        var key: String { "notify." + rawValue }

        func on(_ defaults: UserDefaults) -> Bool {
            defaults.object(forKey: key) as? Bool ?? true
        }
    }

    var kind: Kind {
        switch self {
        case .added, .removed: .devices
        case .madeAdmin: .admins
        case .frozen, .unfrozen: .frozen
        case .takenOver: .takeover
        case .hubUnreachable: .hub
        }
    }

    /// The notification's one line, which the watch lists too.
    var text: String {
        switch self {
        case let .added(n): String(localized: "\(n) joined the group.", bundle: .app)
        case let .removed(n): String(localized: "\(n) was removed from the group.", bundle: .app)
        case let .madeAdmin(n): String(localized: "\(n) is an admin now.", bundle: .app)
        case let .frozen(n): String(localized: "\(n) was frozen: the others refuse it until an admin unfreezes it.", bundle: .app)
        case let .unfrozen(n): String(localized: "\(n) was unfrozen.", bundle: .app)
        case let .takenOver(n): String(localized: "\(n) took the group over: it holds the group's root now.", bundle: .app)
        case .hubUnreachable: String(localized: "The hub does not answer through the tunnel.", bundle: .app)
        }
    }

    /// What the app knew of a device when it last looked.
    struct Seen: Codable, Equatable {
        var name: String
        var admin = false
        var frozen = false
        var root = false
    }

    static func seen(_ devices: [AppModel.Computer]) -> [String: Seen] {
        Dictionary(devices.filter { !$0.isSelf }.map { ($0.id, Seen(name: $0.name, admin: $0.admin, frozen: $0.frozen, root: $0.isRoot)) },
                   uniquingKeysWith: { a, _ in a })
    }

    /// The events between what the app saw before and what it sees now, in
    /// a fixed order: by name, removals after the rest.
    static func between(_ old: [String: Seen], _ new: [String: Seen]) -> [GroupEvent] {
        var events: [GroupEvent] = []
        for (id, now) in new.sorted(by: { $0.value.name < $1.value.name }) {
            guard let was = old[id] else {
                events.append(.added(now.name))
                continue
            }
            if now.root, !was.root {
                events.append(.takenOver(now.name))
            } else if now.admin, !was.admin {
                events.append(.madeAdmin(now.name))
            }
            if now.frozen != was.frozen {
                events.append(now.frozen ? .frozen(now.name) : .unfrozen(now.name))
            }
        }
        for (id, was) in old.sorted(by: { $0.value.name < $1.value.name }) where new[id] == nil {
            events.append(.removed(was.name))
        }
        return events
    }
}

/// Notifies of the group's events: compares the devices with what it saw
/// last time, and watches the tunnel while away from home. It learns of
/// events only while the app runs, at each refresh.
@MainActor
final class Notifier {
    static let shared = Notifier()
    static let seenKey = "events.seen"
    /// How long the hub may stay silent before it is news.
    static let hubGrace: Duration = .seconds(120)

    private let defaults: UserDefaults
    private var asked = false
    private var failingSince: ContinuousClock.Instant?
    private var hubNotified = false
    /// The latest events, newest first, for the watch.
    private(set) var recent: [String] = []

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
    }

    /// Notifies of what changed since the last look; the first look only
    /// remembers.
    func observe(_ devices: [AppModel.Computer]) {
        guard !devices.isEmpty else { return }
        askOnce()
        let now = GroupEvent.seen(devices)
        let old = defaults.data(forKey: Self.seenKey).flatMap { try? JSONDecoder().decode([String: GroupEvent.Seen].self, from: $0) }
        guard old != now else { return }
        if let data = try? JSONEncoder().encode(now) { defaults.set(data, forKey: Self.seenKey) }
        if let old { GroupEvent.between(old, now).forEach(post) }
    }

    /// Notifies once when the hub has not answered through the tunnel for
    /// a while, and again only after it answered.
    func away(trying: Bool) {
        guard trying else {
            failingSince = nil
            hubNotified = false
            return
        }
        let now = ContinuousClock.now
        let since = failingSince ?? now
        failingSince = since
        if !hubNotified, now - since >= Self.hubGrace {
            hubNotified = true
            post(.hubUnreachable)
        }
    }

    func post(_ event: GroupEvent) {
        recent.insert(event.text, at: 0)
        recent = Array(recent.prefix(5))
        WatchLink.shared.eventsChanged()
        guard event.kind.on(defaults) else { return }
        let content = UNMutableNotificationContent()
        content.title = "Clipboard Bridge"
        content.body = event.text
        content.threadIdentifier = event.kind.rawValue
        UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil)) { error in
            if let error { log.error("notification not posted: \(String(reflecting: error), privacy: .public)") }
        }
    }

    /// Asks for notifications once the phone is in a group; iOS asks the
    /// user only the first time.
    private func askOnce() {
        guard !asked else { return }
        asked = true
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { _, error in
            if let error { log.error("notifications not allowed: \(String(reflecting: error), privacy: .public)") }
        }
    }
}

/// Lets the group's notifications show while the app is in front too: iOS
/// drops them there unless its delegate says how to present them.
final class ForegroundNotifications: NSObject, UNUserNotificationCenterDelegate, @unchecked Sendable {
    static let shared = ForegroundNotifications()

    func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification) async -> UNNotificationPresentationOptions {
        [.banner, .list, .sound]
    }
}
