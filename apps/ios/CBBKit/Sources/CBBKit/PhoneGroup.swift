// SPDX-License-Identifier: AGPL-3.0-only

import Foundation

/// The phone's group as the app notes it beside the member's own folder:
/// the phone's device ID, the group's ID and whether the phone holds the
/// root. The member keeps the group's set itself (CoreMember, D-126) and
/// answers its state (CoreMember.group); the keys stay in the Secure
/// Enclave and the keychain. It is saved as JSON next to the app's other
/// data.
public struct PhoneGroup: Codable, Equatable, Sendable {
    /// This phone's device ID.
    public var device: String
    /// The Group ID (hex) the member's set names.
    public var group06: String
    /// Whether this phone holds the current root's key: it made the group,
    /// or changed its root to itself.
    public var isRoot = true
    /// Whether the member's state names this phone an admin
    /// (GroupState.me.admin); set as the state arrives.
    public var admin06 = false

    enum CodingKeys: String, CodingKey { case device, isRoot, group06, admin06 }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        // A group made before 0.6 names no Group ID.
        guard let group = try c.decodeIfPresent(String.self, forKey: .group06) else { throw Before06() }
        device = try c.decode(String.self, forKey: .device)
        group06 = group
        isRoot = try c.decodeIfPresent(Bool.self, forKey: .isRoot) ?? true
        admin06 = try c.decodeIfPresent(Bool.self, forKey: .admin06) ?? false
    }

    private init(device: String, group: String, root: Bool) {
        (self.device, group06, isRoot) = (device, group, root)
    }

    /// Whether this phone may add and remove devices: the root and the admins.
    public var isAdmin: Bool { isRoot || admin06 }

    /// The group tag the computers publish: the Group ID's first 16 hex digits.
    public var tag: String { String(group06.prefix(16)) }

    public enum Failure: Error, Equatable {
        case notAdmin, notRoot, invalidName, fileKey, rootless
        /// A watch signs nothing from the wrist on 0.6 (D-124).
        case notForWatch
        /// The group's key level does not let the device's keys be an admin
        /// or the root; the root sets another level first.
        case belowKeyLevel
    }

    /// The saved group was made before 0.6, which this version no longer
    /// runs (D-126): the app shows that a new group is needed, and the file
    /// stays until the person leaves it.
    public struct Before06: Error, Equatable {
        public init() {}
    }

    /// A name that the records accept: 1 to 64 bytes without control
    /// characters, or "iPhone".
    public static func validName(_ s: String) -> String {
        var out = ""
        for ch in s where !ch.unicodeScalars.contains(where: { $0.properties.generalCategory == .control }) {
            if (out + String(ch)).utf8.count > 64 { break }
            out.append(ch)
        }
        return out.isEmpty ? "iPhone" : out
    }

    /// A group this phone made (CorePairing.newGroup, root) or joined
    /// (CorePairing.Joiner): its device and Group ID; the member keeps the
    /// set.
    public static func of06(device: String, group: String, root: Bool) -> PhoneGroup {
        PhoneGroup(device: device, group: group, root: root)
    }

    /// Reads a saved group; nil when there is none, Before06 for one made
    /// before 0.6.
    public static func load(from url: URL) throws -> PhoneGroup? {
        guard FileManager.default.fileExists(atPath: url.path) else { return nil }
        return try JSONDecoder().decode(PhoneGroup.self, from: Data(contentsOf: url))
    }

    /// Saves the group in one step, so a crash leaves the old file or the new one.
    /// The file is sealed until the phone is first unlocked after a start,
    /// stated rather than left to the default: the member reads it in the
    /// background later, while the phone may be locked.
    public func save(to url: URL) throws {
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try enc.encode(self).write(to: url, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
    }
}
