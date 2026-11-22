// SPDX-License-Identifier: AGPL-3.0-only

import Foundation

/// The few shapes of the member protocol (docs/protocol.md) that the app
/// itself reads: the core speaks the protocol (CoreMember).
public enum Member {
    /// The kind of an event: a secret is kept only briefly (section 5);
    /// media is images or files, of which the kit takes the text.
    public enum Kind: String, Codable, Sendable { case text, secret, media }

    /// How a text reached the member that made the event.
    public enum Via: String, Codable, Sendable {
        case copy
        /// Sent from a phone's app.
        case phone
        case universalClipboard = "universal-clipboard"

        public init(from decoder: Decoder) throws {
            let s = try decoder.singleValueContainer().decode(String.self)
            guard let via = Via(rawValue: s) else {
                throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: "unknown via \(s)"))
            }
            self = via
        }
    }

    /// The sync modes (design.md, "Sync modes").
    public static let modes: Set<String> = ["own", "shared", "receive", "send"]

    /// Whether a device in sync mode mode takes the group's copies into its
    /// clipboard by itself; a device without a mode (nil) shares.
    public static func receives(_ mode: String?) -> Bool { mode == nil || mode == "shared" || mode == "receive" }

    /// Whether a device in sync mode mode sends its own copies to the group by itself.
    public static func sends(_ mode: String?) -> Bool { mode == nil || mode == "shared" || mode == "send" }

    /// What a hello says about the sender's device (section 4, "Device"):
    /// its form, its system's version, its own version and its network
    /// card's MAC address. Shown, never trusted; any field may be absent.
    public struct DeviceInfo: Codable, Equatable, Sendable {
        /// The forms a device may name, for its icon.
        public static let forms = ["laptop", "desktop", "phone", "tablet", "tv", "board", "server", "router", "console", "watch", "retro", "other"]

        public var form: String?
        public var osVersion: String?
        public var version: String?
        public var mac: String?

        enum CodingKeys: String, CodingKey { case form, osVersion = "os_version", version, mac }

        public init(form: String? = nil, osVersion: String? = nil, version: String? = nil, mac: String? = nil) {
            (self.form, self.osVersion, self.version, self.mac) = (form, osVersion, version, mac)
        }

        /// The same without its invalid fields: an unknown form, a version
        /// longer than 32 bytes or with control characters, a MAC address
        /// other than six lowercase hex bytes with colons; nil when nothing
        /// is left.
        public var cleaned: DeviceInfo? {
            func short(_ s: String?) -> String? {
                guard let s, !s.isEmpty, s.utf8.count <= 32, !s.unicodeScalars.contains(where: { $0.properties.generalCategory == .control }) else { return nil }
                return s
            }
            let hex = Set("0123456789abcdef")
            let parts = mac?.split(separator: ":", omittingEmptySubsequences: false) ?? []
            let macOK = parts.count == 6 && parts.allSatisfy { $0.count == 2 && $0.allSatisfy(hex.contains) }
            let d = DeviceInfo(form: form.flatMap { Self.forms.contains($0) ? $0 : nil }, osVersion: short(osVersion), version: short(version),
                               mac: macOK ? mac : nil)
            return d == DeviceInfo() ? nil : d
        }
    }

    /// An attestation of one of a device's keys (section 17, "Evidence"):
    /// format android with the Keystore's chain, leaf first, for the key
    /// member, made with the challenge of groupTag (nil outside a group) and
    /// salt.
    public struct Evidence: Codable, Equatable, Sendable {
        public static let android = "android-key"
        public static let member = "member"

        public var format: String
        public var key: String
        public var groupTag: String?
        public var salt: Data
        public var chain: [Data]

        public init(format: String, key: String, groupTag: String?, salt: Data, chain: [Data]) {
            (self.format, self.key, self.groupTag, self.salt, self.chain) = (format, key, groupTag, salt, chain)
        }

        enum CodingKeys: String, CodingKey {
            case format, key, salt, chain
            case groupTag = "group_tag"
        }

        public init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            format = try c.decodeIfPresent(String.self, forKey: .format) ?? ""
            key = try c.decodeIfPresent(String.self, forKey: .key) ?? ""
            groupTag = try c.decodeIfPresent(String.self, forKey: .groupTag).flatMap { $0.isEmpty ? nil : $0 }
            salt = try c.decodeIfPresent(Data.self, forKey: .salt) ?? Data()
            chain = try c.decodeIfPresent([Data].self, forKey: .chain) ?? []
        }
    }
}
