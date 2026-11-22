// SPDX-License-Identifier: AGPL-3.0-only

import Crypto
import Foundation

/// What the apps need to know of the group's records (docs/protocol.md,
/// section 10): the names of the key stores and levels and the copies
/// setting's default. The member in the Rust core keeps the records and
/// judges them; nothing here reads or writes one.
public enum Records {
    /// Whether s is a device ID: 32 of 0-9 and a-f.
    public static func isDeviceID(_ s: String?) -> Bool {
        guard let s, s.utf8.count == 32 else { return false }
        return s.utf8.allSatisfy { (0x30...0x39).contains($0) || (0x61...0x66).contains($0) }
    }

    /// The hash that names a key in records: SHA-256 over a
    /// SubjectPublicKeyInfo.
    public static func keyHash(spki: Data) -> Data { Data(SHA256.hash(data: spki)) }

    /// How long a copy and a secret live without a copies record, and the
    /// bounds a copies record keeps, in milliseconds (D-129).
    public static let defaultTtlMS: Int64 = 300_000
    public static let defaultSecretTtlMS: Int64 = 60_000
    public static let ttlBounds: ClosedRange<Int64> = 60_000...3_600_000
    public static let secretTtlBounds: ClosedRange<Int64> = 5_000...60_000

    public static let file = "file"
    public static let hardware = "hardware"
    /// A key in hardware whose attestation a signer checked.
    public static let proven = "proven"
    /// A rootless install's keys: in a file every program of its user may
    /// read, so the device is never the root, an admin or a hub (D-79).
    public static let rootless = "rootless"
    /// The group's key levels (docs/guide/keys.md, "The three levels"):
    /// which keys may be its root, an admin or a hub. The levels proven and
    /// hardware share their names with the stores they let in; files lets
    /// in keys in files too, each after a warning.
    public static let levelFiles = "files"
    public static let keyLevels = [proven, hardware, levelFiles]

    /// Whether the key level lets a device whose keys are in store be the
    /// group's root, an admin or a hub; a key in a file needs consent too.
    public static func levelAllows(_ level: String, store: String, consent: Bool) -> Bool {
        switch store {
        case rootless: return false
        case proven: return true
        case file: return level == levelFiles && consent
        default: return level != proven
        }
    }

    /// Where a device's keys live, as a hello's key_store or a record's
    /// store says (docs/protocol.md, section 17): file, hardware, proven or
    /// rootless. Without one, or with one this version does not know, a
    /// phone's and a watch's keys are in hardware and any other device's in
    /// a file.
    public static func store(_ store: String?, role: String) -> String {
        switch store {
        case let s? where s == file || s == hardware || s == proven || s == rootless: s
        default: role == "phone" || role == "watch" ? hardware : file
        }
    }

    static func ms(_ d: Date) -> Int64 { Int64((d.timeIntervalSince1970 * 1000).rounded(.down)) }
}
