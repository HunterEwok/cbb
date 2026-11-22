// SPDX-License-Identifier: AGPL-3.0-only

import Foundation

/// A Linux member found by mDNS browsing (docs/protocol.md, section 3): its
/// device ID, the first label of its service instance, and what its TXT
/// record says.
public struct FoundMember: Hashable, Sendable {
    public var device: String
    /// The group tag (`g`); nil when the TXT record has none.
    public var group: String?
    /// Whether a pairing window is open (`p=1`).
    public var pairing: Bool
    /// A home window's ID in hex (`i`), beside `p=1`; nil when none is announced.
    public var windowID: String?
    /// The hash of the window's member key in hex (`f`); nil when none is announced.
    public var fingerprint: String?

    public init(device: String, group: String?, pairing: Bool = false, windowID: String? = nil, fingerprint: String? = nil) {
        (self.device, self.group, self.pairing) = (device, group, pairing)
        (self.windowID, self.fingerprint) = (windowID, fingerprint)
    }
}

public enum Discovery {
    /// The DNS-SD service type the Linux members publish.
    public static let serviceType = "_cbb._tcp"

    /// Reads a found service: the instance name must be a device ID; the TXT
    /// strings are "key=value", keys matched without regard to case, the
    /// value what follows the first "=". Unknown keys are ignored.
    public static func member(instance: String, txt: [String]) -> FoundMember? {
        guard Records.isDeviceID(instance) else { return nil }
        var fields: [String: String] = [:]
        for s in txt {
            let (k, v) = s.firstIndex(of: "=").map { (String(s[..<$0]), String(s[s.index(after: $0)...])) } ?? (s, "")
            let key = k.lowercased()
            if fields[key] == nil { fields[key] = v }
        }
        return FoundMember(
            device: instance, group: fields["g"], pairing: fields["p"] == "1",
            windowID: fields["i"].flatMap { $0.isEmpty ? nil : $0 },
            fingerprint: fields["f"].flatMap { $0.isEmpty ? nil : $0 })
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

    /// The TXT record of a phone's open home window of 0.6: v=1, the
    /// group's tag, p=1, the hash of the member key and the window's ID the
    /// window's QR code names, never its digits, so that a device whose
    /// person types the digits finds it (docs/protocol.md, "Pairing in 0.6").
    public static func windowTXT(group: String, fingerprint: String, id: String) -> [String: String] {
        ["v": "1", "g": group, "p": "1", "f": fingerprint, "i": id]
    }

    /// The QR code text of a home window found by mDNS, at address
    /// (host:port, an IPv6 host in brackets), with the six digits the person
    /// typed: cbb://pair?addr=...&fp=...&i=...&c=..., as the core reads it.
    public static func windowLink(address: String, fingerprint: String, id: String, digits: String) -> String {
        let keep = Set("-._~:[]".utf8)
        var addr = ""
        for b in address.utf8 {
            let alnum = (b >= 0x30 && b <= 0x39) || (b >= 0x41 && b <= 0x5A) || (b >= 0x61 && b <= 0x7A)
            if alnum || keep.contains(b) { addr.append(Character(UnicodeScalar(b))) } else { addr += String(format: "%%%02X", b) }
        }
        return "cbb://pair?addr=\(addr)&fp=\(fingerprint)&i=\(id)&c=\(digits)"
    }

    /// The members to dial: those browsing found, and the devices of the
    /// group with a known address that it did not find, as a member in
    /// another subnet, which mDNS does not reach (docs/protocol.md, section 9).
    public static func withKnown(_ found: Set<FoundMember>, known: Set<String>, group: String) -> Set<FoundMember> {
        found.union(known.filter { d in !found.contains { $0.device == d } }.map { FoundMember(device: $0, group: group) })
    }
}
