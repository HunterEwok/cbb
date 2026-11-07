// SPDX-License-Identifier: AGPL-3.0-only

import Foundation

/// A Linux member found by mDNS browsing (docs/protocol.md, section 3): its
/// device ID, the first label of its service instance, and what its TXT
/// record says.
public struct FoundMember: Hashable, Sendable {
    public var device: String
    /// The group tag (`g`); nil when the TXT record has none.
    public var group: String?
    /// Whether a computer pairing window is open (`p=1`).
    public var pairing: Bool

    public init(device: String, group: String?, pairing: Bool = false) {
        (self.device, self.group, self.pairing) = (device, group, pairing)
    }
}

public enum Discovery {
    /// The DNS-SD service type the Linux members publish.
    public static let serviceType = "_cbb._tcp"

    /// Reads a found service: the instance name must be a device ID; the TXT
    /// strings are "key=value", keys matched without regard to case, the
    /// value what follows the first "=". Unknown keys are ignored.
    public static func member(instance: String, txt: [String]) -> FoundMember? {
        guard GroupCertificates.isDeviceID(instance) else { return nil }
        var fields: [String: String] = [:]
        for s in txt {
            let (k, v) = s.firstIndex(of: "=").map { (String(s[..<$0]), String(s[s.index(after: $0)...])) } ?? (s, "")
            let key = k.lowercased()
            if fields[key] == nil { fields[key] = v }
        }
        return FoundMember(device: instance, group: fields["g"], pairing: fields["p"] == "1")
    }

    /// The same from a TXT record already split into keys and values, as
    /// Network.framework gives it.
    public static func member(instance: String, txt: [String: String]) -> FoundMember? {
        member(instance: instance, txt: txt.map { "\($0.key)=\($0.value)" })
    }

    /// The TXT record of a device that waits to join, listening with its
    /// QR code on screen: no group tag, so no member dials it, and the
    /// fingerprint of its certificate, which a computer of the group checks
    /// when it admits the device by the code typed there (docs/protocol.md,
    /// sections 3 and 6).
    public static func joinerTXT(fingerprint: String) -> [String: String] {
        ["v": "1", "j": "1", "f": fingerprint]
    }

    /// The members to dial: those browsing found, and the devices of the
    /// group with a known address that it did not find, as a member in
    /// another subnet, which mDNS does not reach (docs/protocol.md, section 9).
    public static func withKnown(_ found: Set<FoundMember>, known: Set<String>, group: String) -> Set<FoundMember> {
        found.union(known.filter { d in !found.contains { $0.device == d } }.map { FoundMember(device: $0, group: group) })
    }
}
