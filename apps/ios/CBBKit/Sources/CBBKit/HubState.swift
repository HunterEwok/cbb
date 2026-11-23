// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import Foundation

/// The forwarder of a computer that is the group's hub, which the root
/// names from the phone, and the relay's address and key, as the user gives
/// them. A phone is no hub (D-134).
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
}
