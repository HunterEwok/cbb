// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import Foundation

/// One reason why this device does not sync, as the core gives it
/// (`cbb_core::why`, docs/apps.md "Why it does not sync"): a stable code the
/// app says in its own words, a level and the parameters. The phone's member
/// answers them (`CoreMember.why`), a computer's status carries them; the
/// Mac app shares this file.
public struct WhyReason: Codable, Equatable, Hashable, Sendable {
    public var code: String
    /// stop (nothing syncs here), warn (some copies or devices do not) or
    /// info.
    public var level: String
    /// When sync turns on again, a mute ends or the certificate ends, in
    /// Unix milliseconds; nil when the reason has no time.
    public var untilMS: Int64?
    /// A device's name: the hub, the admin that took the group over.
    public var device: String?
    /// The devices the reason is about, by name.
    public var devices: [String]?
    /// A version, or a count as text.
    public var value: String?
    /// The member's own words for what went wrong, for the error details.
    public var detail: String?

    public init(code: String, level: String, untilMS: Int64? = nil, device: String? = nil, devices: [String]? = nil,
                value: String? = nil, detail: String? = nil) {
        (self.code, self.level, self.untilMS, self.device, self.devices, self.value, self.detail) =
            (code, level, untilMS, device, devices, value, detail)
    }

    enum CodingKeys: String, CodingKey {
        case code, level, device, devices, value, detail
        case untilMS = "until_ms"
    }

    /// When the reason's time is, nil without one.
    public var until: Date? { untilMS.flatMap { $0 > 0 ? Date(timeIntervalSince1970: Double($0) / 1000) : nil } }
}

/// Where a tunnel the app runs itself stands, for the member's `why`: the
/// phone's sync away from home through RustTunnel, which the member does not
/// see (`cbb_core::why::AwayFacts`).
public struct WhyAway: Codable, Equatable, Sendable {
    public var hub = false
    public var standby = false
    public var hubDevice = ""
    public var through = false
    public var hidden = false
    public var relay = false
    public var relayConnected = false
    public var forwarder = false
    public var forwarderRegistered = false
    public var entriesStale = false
    public var error = ""

    public init() {}

    enum CodingKeys: String, CodingKey {
        case hub, standby, through, hidden, relay, forwarder, error
        case hubDevice = "hub_device"
        case relayConnected = "relay_connected"
        case forwarderRegistered = "forwarder_registered"
        case entriesStale = "entries_stale"
    }
}
