// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import Foundation

/// What the phone as the group's hub works with (docs/design.md, "The phone
/// as the hub", D-64): the forwarder the group's root sets for it, and the
/// home networks where it takes members and publishes itself. On a group
/// of 0.6 the Live member runs the hub (AwayOn06); a phone in a group of
/// 0.5 is no hub (D-123).
public enum HubState {
    /// The forwarder: its endpoint, "ip:port", and the pin of its key:
    /// SHA-256 of its key in standard base64.
    public struct Forwarder: Codable, Equatable, Sendable {
        public var endpoint: String
        public var pin: String
        public init(endpoint: String, pin: String) { (self.endpoint, self.pin) = (endpoint, pin) }

        /// The project's forwarder: its name with the port and the pin of
        /// its key, as cbb has them (internal/forward/project.go).
        public static let projectHost = "cbb.tools:8764"
        public static let projectPin = "efzUG2YzJBqS8FfojZGwqioECt46VzQcFo3oWpPru/g="

        /// Whether this is the project's forwarder.
        public var isProject: Bool { pin == Self.projectPin }
    }

    /// Whether pin is the pin of a forwarder's key, as `cbb forward` prints
    /// it.
    public static func validPin(_ pin: String) -> Bool {
        guard let b = Data(base64Encoded: pin), b.count == 32 else { return false }
        return b.base64EncodedString() == pin
    }

    /// The forwarder's endpoint as the hub takes it, "ip:port", when s is an
    /// IPv4 or a bracketed IPv6 address with its port; a name is not looked
    /// up here.
    public static func endpoint(_ s: String) -> String? {
        let t = s.trimmingCharacters(in: .whitespaces)
        guard let colon = t.lastIndex(of: ":"), let port = UInt16(t[t.index(after: colon)...]), port > 0 else { return nil }
        let host = t[..<colon]
        if host.hasPrefix("[") && host.hasSuffix("]") {
            let inner = host.dropFirst().dropLast()
            return !inner.isEmpty && inner.allSatisfy { $0.isHexDigit || $0 == ":" } && inner.contains(":") ? t : nil
        }
        let b = host.split(separator: ".", omittingEmptySubsequences: false)
        return b.count == 4 && b.allSatisfy { UInt8($0) != nil } ? t : nil
    }

    /// A network as the hub remembers it: its gateway's address and the
    /// network of the phone's IPv4 address on it, as "192.168.0.1
    /// 192.168.0.0/24". Wi-Fi in a café has another, so the phone neither
    /// takes members nor publishes itself there (as D-63 on the computers).
    public static func networkKey(gateway: String?, address: String?, prefixLength: Int) -> String? {
        guard let gateway, let address, (0...32).contains(prefixLength) else { return nil }
        let b = address.split(separator: ".").compactMap { UInt8($0) }
        guard b.count == 4 else { return nil }
        var v = b.reduce(UInt32(0)) { $0 << 8 | UInt32($1) }
        v &= prefixLength == 0 ? 0 : ~UInt32(0) << (32 - prefixLength)
        let net = (0..<4).map { String((v >> (24 - 8 * $0)) & 0xff) }.joined(separator: ".")
        return "\(gateway) \(net)/\(prefixLength)"
    }
}

/// The phone as the group's hub, as the screens show it.
public enum HubOnPhone {
    /// What the screens show.
    public enum Status: Sendable, Equatable { case off, paused, homeOnly, registering, registered, failed }

    /// How the hub's tunnel hides (docs/design.md, "Blocked networks"):
    /// plain WireGuard, AmneziaWG, or AmneziaWG with VLESS to the forwarder.
    public enum Disguise: String, Sendable, CaseIterable { case plain, obfuscate, vless }
}
