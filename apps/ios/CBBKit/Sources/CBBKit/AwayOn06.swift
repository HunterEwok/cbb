// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import Foundation

/// Sync away from home, the phone as a hub and the group's relay on a
/// group of 0.6 (docs/apps.md, "Away from home"). The Live member runs the
/// tunnel, the hub and the link to the relay in the app's process, in user
/// space as before, and keeps their keys and clients itself; the app keeps
/// only what the user chose for the hub, `Prefs`, and maps where the member
/// says they stand (`CoreMember.AwayState`) onto the same cards as before.
/// The hub's forwarder is the root's setting, which its hub command names
/// and the member keeps (`CoreMember.rootForwarder`), as the relay is the
/// group's setting, which the root writes; every device meets the others
/// there.
public enum AwayOn06 {
    /// What the user chose for the hub: whether it is on, how its tunnel
    /// hides and the home networks where it publishes itself.
    public struct Prefs: Codable, Equatable, Sendable {
        public var on = false
        public var disguise = HubOnPhone.Disguise.obfuscate.rawValue
        public var homes: [String] = []

        public init(on: Bool = false, disguise: HubOnPhone.Disguise = .obfuscate, homes: [String] = []) {
            (self.on, self.disguise, self.homes) = (on, disguise.rawValue, homes)
        }

        /// How the hub's tunnel hides.
        public var hides: HubOnPhone.Disguise {
            get { HubOnPhone.Disguise(rawValue: disguise) ?? .obfuscate }
            set { disguise = newValue.rawValue }
        }

        /// Whether home is one of the hub's home networks.
        public func isHome(_ home: String?) -> Bool { home.map { homes.contains($0) } ?? false }

        /// The home networks with home, the oldest dropped past the most the phone remembers.
        public func adding(home: String?) -> Prefs {
            guard let home, !homes.contains(home) else { return self }
            var p = self
            p.homes = Array((homes + [home]).suffix(Self.maxHomes))
            return p
        }

        /// The most home networks the phone remembers.
        public static let maxHomes = 8

        public func encoded() throws -> Data { try JSONEncoder().encode(self) }

        /// The choices in data, or nil when they are not ones this version wrote.
        public static func decode(_ data: Data) -> Prefs? { try? JSONDecoder().decode(Prefs.self, from: data) }
    }

    /// The UDP port of a hub at home only, which its addresses on the home network name.
    public static let homePort: UInt16 = 8764

    /// Has the member serve as a hub with the user's settings, as the
    /// phone of 0.5 was: through the forwarder the root set when there is
    /// one (byRoot; the member takes it itself, VLESS there unless the
    /// tunnel is plain), or at home only, at homeAddrs.
    @discardableResult
    public static func serve(_ node: CoreMember, _ p: Prefs, homeAddrs: [String], byRoot: CoreMember.RootForwarder?) throws -> CoreMember.AwayState? {
        try node.serveAsHub(port: byRoot == nil ? homePort : 0, addrs: byRoot == nil ? homeAddrs.map { "\($0):\(homePort)" } : [],
                            obfuscateOff: p.hides == .plain, vlessOff: p.hides != .vless)
    }

    /// Where sync away from home stands, as Settings shows it: off, or on
    /// a hub (which is no client of another); waiting until a hub offered
    /// its tunnel; through it; or at home, where the member reaches the hub
    /// without it.
    public static func awayStatus(_ a: CoreMember.AwayState?, reached: (String) -> Bool) -> AwayFromHome.Status {
        guard let a, !a.hub else { return .off }
        if a.through { return .connected }
        if a.hubDevice.isEmpty { return .waitingForHub }
        return reached(a.hubDevice) ? .atHome : .connecting
    }

    /// Where the hub stands, as Settings and Home show it, with the reason
    /// it failed: paused while the app is not in front; at home only while
    /// the root set no forwarder (forwarder false); registered once the
    /// forwarder took it.
    public static func hubStatus(_ p: Prefs, _ a: CoreMember.AwayState?, paused: Bool, forwarder: Bool) -> (HubOnPhone.Status, String?) {
        guard p.on else { return (.off, nil) }
        if paused { return (.paused, nil) }
        guard let a, a.hub else {
            if let a, !a.error.isEmpty { return (.failed, reason(a.error, a.detail)) }
            return (.registering, nil)
        }
        if !forwarder { return (.homeOnly, nil) }
        guard let f = a.forwarder else { return (.registering, nil) }
        if f.registered { return (.registered, nil) }
        if !f.error.isEmpty { return (.failed, reason(f.error, f.detail)) }
        return (.registering, nil)
    }

    /// Where the link to the group's relay stands, with the reason it
    /// failed; off while the group has no relay or sync away from home is off.
    public static func relayStatus(_ a: CoreMember.AwayState?) -> (RelayOnPhone.Status, String?) {
        guard let r = a?.relay else { return (.off, nil) }
        if r.connected { return (.connected, nil) }
        if !r.error.isEmpty { return (.failed, reason(r.error, r.detail)) }
        return (.connecting, nil)
    }

    /// The error with its underlying cause, for the log and for the error's details.
    public static func reason(_ error: String, _ detail: String) -> String {
        detail.isEmpty || detail == error ? error : "\(error) (\(detail))"
    }
}
