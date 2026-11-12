// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import Crypto
import Foundation

/// The signed files that describe a release (docs/protocol.md, section 16):
/// keys.json, in which a root key certifies the release keys; release.json,
/// which lists a release's files with their hashes; and a channel file such
/// as stable.json, which names the current release of its channel until it
/// expires. The same keys.json certifies the status key that signs
/// attest-status.json, the mirror of Google's revocation list for Android
/// attestations (section 17), and the keys of entries.json. The Rust core
/// checks them all (release_check, docs/core-api.md, "Release files"): both
/// signatures of every file, the roots it pins, the expiries and the
/// sequence numbers. The kit only carries the files and reads the answer.
public enum Releases {
    /// The largest body a file may carry.
    public static let maxBody = 256 << 10
    /// The largest file, its body and its signatures, a device downloads.
    public static let maxFile = 1 << 20

    /// A file the core refused: its reason, for the log.
    public struct Refused: Error, CustomStringConvertible {
        public let description: String
        init(_ s: String) { description = s }
    }

    /// One signature of a file: its algorithm (1 ES256, 4
    /// SLH-DSA-SHA2-128s), SHA-256 of the signing half's
    /// SubjectPublicKeyInfo, and the signature.
    public struct Sig: Codable, Equatable, Sendable {
        public var alg: UInt64
        public var key: Data
        public var sig: Data
    }

    /// The envelope of every release file: the body and its signatures, one
    /// for each algorithm a device requires (section 16, "Two signatures").
    public struct File: Codable, Equatable, Sendable {
        public var body: Data
        public var sigs: [Sig]

        /// SHA-256 over the body, which names a release.json.
        public var hash: Data { Data(SHA256.hash(data: body)) }
    }

    /// A root key's half, for tests and drills that sign with roots of
    /// their own: the core uses the roots it pins when none are given.
    public struct Key: Codable, Equatable, Sendable {
        public var alg: UInt64
        public var key: Data
        public var name: String
        public var use: String
    }

    public struct Binary: Codable, Equatable, Sendable {
        public var name: String
        public var sha256: String
    }

    public struct Asset: Codable, Equatable, Sendable {
        public var name: String
        public var size: Int64
        public var sha256: String
        public var binaries: [Binary]?
    }

    public struct Docker: Codable, Equatable, Sendable {
        public var image: String
        public var digest: String
    }

    /// The body of release.json.
    public struct Release: Codable, Equatable, Sendable {
        public var version: String
        public var channel: String
        public var time_ms: Int64
        public var min_from: String?
        public var files: [Asset]
        public var docker: Docker?

        /// Whether a device at installed may update to this release in one
        /// step, or must first take min_from.
        public func direct(from installed: String) -> Bool {
            guard let m = min_from, !m.isEmpty else { return true }
            return compare(installed, m) >= 0
        }

        /// Checks that data is the release's file name.
        public func checkFile(_ name: String, _ data: Data) throws {
            guard let a = files.first(where: { $0.name == name }) else { throw Refused("\(name) is not in the release") }
            guard a.size == Int64(data.count), hex(Data(SHA256.hash(data: data))) == a.sha256 else {
                throw Refused("\(name) does not match release.json")
            }
        }
    }

    /// What a device keeps between checks: the highest sequence numbers and
    /// version it has taken, as the core gives them back. A channel or
    /// status seq holds only under the keys.json that certified its signer
    /// (channel_keys_seq, status_keys_seq): a newer keys.json, which only a
    /// root signs, starts them again.
    public struct Seen: Codable, Equatable, Sendable {
        public var keys_seq: UInt64 = 0
        public var channel_seq: UInt64 = 0
        public var version: String? = nil
        public var status_seq: UInt64? = nil
        public var channel_keys_seq: UInt64? = nil
        public var status_keys_seq: UInt64? = nil
        /// The highest entries.json seq taken and the keys.json seq it
        /// was taken under, kept apart from the release's.
        public var entries_seq: UInt64? = nil
        public var entries_keys_seq: UInt64? = nil

        public init(keys_seq: UInt64 = 0, channel_seq: UInt64 = 0, version: String? = nil, status_seq: UInt64? = nil,
                    channel_keys_seq: UInt64? = nil, status_keys_seq: UInt64? = nil) {
            self.keys_seq = keys_seq
            self.channel_seq = channel_seq
            self.version = version
            self.status_seq = status_seq
            self.channel_keys_seq = channel_keys_seq
            self.status_keys_seq = status_keys_seq
        }
    }

    /// The body of attest-status.json: the serial numbers Google's list
    /// revokes, as AndroidAttestation.Policy takes them.
    public struct Status: Decodable, Equatable, Sendable {
        public var seq: UInt64
        public var time_ms: Int64
        public var expires_ms: Int64
        public var source_ms: Int64?
        public var android_revoked: [String]
    }

    /// A way in over VLESS to a forwarder that entries.json lists.
    public struct EntryVLESS: Codable, Equatable, Sendable {
        public var transport: String
        public var server_name: String
        public var port: UInt16
        public var path: String

        public init(transport: String, server_name: String, port: UInt16, path: String) {
            (self.transport, self.server_name, self.port, self.path) = (transport, server_name, port, path)
        }
    }

    /// A forwarder of the project in entries.json: host:port and its ways in.
    public struct EntryForwarder: Codable, Equatable, Sendable {
        public var name: String
        public var vless: [EntryVLESS]

        enum CodingKeys: String, CodingKey { case name, vless }

        public init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            name = try c.decode(String.self, forKey: .name)
            // The core leaves out a forwarder's empty list.
            vless = try c.decodeIfPresent([EntryVLESS].self, forKey: .vless) ?? []
        }
    }

    /// The body of entries.json, the signed list of the project's entry
    /// points (docs/protocol.md, section 16, "Entry points").
    public struct Entries: Decodable, Equatable, Sendable {
        public var seq: UInt64
        public var time_ms: Int64
        public var expires_ms: Int64
        public var forwarders: [EntryForwarder]

        /// The entry of the forwarder named name.
        public func forwarder(_ name: String) -> EntryForwarder? { forwarders.first { $0.name == name } }
    }

    /// The signed entry points as members pass them: entries.json and the
    /// keys.json whose key signed it.
    public struct EntriesSet: Codable, Equatable, Sendable {
        public var keys: File
        public var entries: File

        public init(keys: File, entries: File) { (self.keys, self.entries) = (keys, entries) }
    }

    /// The arguments of the core's release calls.
    struct Args: Encodable {
        var keys: File
        var channel: File? = nil
        var release: File? = nil
        var status: File? = nil
        var entries: File? = nil
        var name: String? = nil
        var roots: [Key]?
        var now_ms: Int64
        var seen: Seen
    }

    struct Answer<T: Decodable>: Decodable {
        var value: T
        var seen: Seen
    }

    /// Asks the core: a file it refuses is Refused, with its reason; any
    /// other refusal is the kit's mistake and stays the core's.
    static func ask<T: Decodable>(_ op: String, _ args: Args, as _: T.Type) throws -> (T, Seen) {
        do {
            let a = try Core.run(op, args, as: Answer<T>.self)
            return (a.value, a.seen)
        } catch let r as Core.Refusal where r.name == "signed" {
            guard let d = r.details, !d.isEmpty else { throw Refused(r.message) }
            throw Refused("\(r.message): \(d)")
        }
    }

    /// Checks entries.json: keys.json under the roots (the pinned ones when
    /// nil), the list under a release or channel key of it, its expiry, and
    /// that neither is older than seen. Returns the list and the Seen to
    /// keep.
    public static func checkEntries(_ set: EntriesSet, roots: [Key]? = nil, nowMS: Int64, seen: Seen) throws -> (Entries, Seen) {
        try ask("release_check_entries", Args(keys: set.keys, entries: set.entries, roots: roots, now_ms: nowMS, seen: seen),
                as: Entries.self)
    }

    /// Checks a channel file and the release.json it names: keys.json under
    /// the roots (the pinned ones when nil), the channel file under its
    /// release or channel keys and release.json under its release keys, the
    /// channel's name, both expiries, and that nothing is older than seen.
    /// Returns the release and the Seen to keep.
    public static func check(keys: File, channel: File, release: File, roots: [Key]? = nil, name: String, nowMS: Int64,
                             seen: Seen) throws -> (Release, Seen) {
        try ask("release_check", Args(keys: keys, channel: channel, release: release, name: name, roots: roots, now_ms: nowMS,
                                      seen: seen), as: Release.self)
    }

    /// Checks attest-status.json: keys.json under the roots (the pinned ones
    /// when nil), the list under a status key of it, its expiry, and that
    /// neither is older than seen. Returns the list and the Seen to keep.
    public static func checkStatus(keys: File, status: File, roots: [Key]? = nil, nowMS: Int64, seen: Seen) throws -> (Status, Seen) {
        try ask("release_check_status", Args(keys: keys, status: status, roots: roots, now_ms: nowMS, seen: seen),
                as: Status.self)
    }

    /// X, Y, Z and the release candidate's number, Int.max for a release.
    static func parseVersion(_ s: String) -> [Int]? {
        func number(_ p: Substring, zero: Bool) -> Int? {
            guard !p.isEmpty, p.count <= 6, p.allSatisfy({ $0.isASCII && $0.isNumber }),
                  (p.count == 1 && zero) || !p.hasPrefix("0") else { return nil }
            return Int(p)
        }
        var main = Substring(s)
        var rc = Int.max
        if let r = s.range(of: "-rc.") {
            guard let n = number(s[r.upperBound...], zero: false) else { return nil }
            main = s[..<r.lowerBound]
            rc = n
        }
        let parts = main.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 3 else { return nil }
        var out: [Int] = []
        for p in parts {
            guard let n = number(p, zero: true) else { return nil }
            out.append(n)
        }
        return out + [rc]
    }

    /// Compares two versions X.Y.Z or X.Y.Z-rc.N as -1, 0 or 1, a release
    /// candidate before its release; a string that is not a version sorts
    /// below every version.
    public static func compare(_ a: String, _ b: String) -> Int {
        switch (parseVersion(a), parseVersion(b)) {
        case (nil, nil): return 0
        case (nil, _): return -1
        case (_, nil): return 1
        case let (pa?, pb?):
            for i in 0..<4 where pa[i] != pb[i] { return pa[i] < pb[i] ? -1 : 1 }
            return 0
        }
    }

    static func hex(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }
}
