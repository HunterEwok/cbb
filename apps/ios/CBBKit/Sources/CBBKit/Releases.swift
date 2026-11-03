// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import Crypto
import Foundation

/// The signed files that describe a release (docs/protocol.md, section 16),
/// checked as internal/release does: keys.json, in which a root key
/// certifies the release keys; release.json, which lists a release's files
/// with their hashes; and a channel file such as stable.json, which names
/// the current release of its channel until it expires. The same keys.json
/// certifies the status key that signs attest-status.json, the mirror of
/// Google's revocation list for Android attestations (section 17).
public enum Releases {
    /// The largest body a file may carry.
    public static let maxBody = 256 << 10
    /// The longest a keys or channel file may stay valid after it was signed.
    public static let maxLifetimeMS: Int64 = 100 * 24 * 3600 * 1000
    /// The longest attest-status.json stays valid after it was signed.
    public static let maxStatusLifetimeMS: Int64 = 8 * 24 * 3600 * 1000
    /// The pinned root keys (SubjectPublicKeyInfos, DER), two YubiKeys, as
    /// internal/release/roots/roots.pem.
    public static let roots: [Data] = [
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE9sLfrcGBi23XveQN8dK8Z+lbEuxTLOgnQ9s/gzp/k7xx88IFvkdMuyoL2K7j1necQGYLmq3ifie9wDrF69AO/A==",
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAExGbAq55XGXip3Dtq6jsM2bOYUeoYfDxsggXLisjwoCQoDM28pCYkIoZAfcjwR3aAGOAUWZX+L53og7/TLLpnfg==",
    ].map { Data(base64Encoded: $0)! }

    public static let useRelease = "release"
    public static let useStatus = "status"
    public static let useChannel = "channel"

    public struct Refused: Error, CustomStringConvertible {
        public let description: String
        init(_ s: String) { description = s }
    }

    /// The envelope of every release file; key is SHA-256 of the signer's
    /// SubjectPublicKeyInfo.
    public struct File: Codable, Equatable, Sendable {
        public var body: Data
        public var sig: Data
        public var key: Data

        /// SHA-256 over the body, which names a release.json.
        public var hash: Data { Data(SHA256.hash(data: body)) }

        func verify(_ spkis: [Data]) throws {
            guard body.count <= maxBody else { throw Refused("the file is too large") }
            guard let spki = spkis.first(where: { Data(SHA256.hash(data: $0)) == key }),
                  let pub = P256.Signing.PublicKey(spki: spki),
                  let s = try? P256.Signing.ECDSASignature(derRepresentation: sig),
                  pub.isValidSignature(s, for: body) else { throw Refused("the signature is not valid") }
        }
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
    /// version it has taken. A channel or status seq holds only under the
    /// keys.json that certified its signer (channel_keys_seq,
    /// status_keys_seq; keys_seq when absent, as kept before), as Go's Seen:
    /// a newer keys.json, which only a root signs, starts them again.
    public struct Seen: Codable, Equatable, Sendable {
        public var keys_seq: UInt64 = 0
        public var channel_seq: UInt64 = 0
        public var version: String? = nil
        public var status_seq: UInt64? = nil
        public var channel_keys_seq: UInt64? = nil
        public var status_keys_seq: UInt64? = nil

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

    /// The most a channel or status seq may rise past the one held under
    /// the same keys.json, as Go's MaxSeqStep.
    public static let maxSeqStep: UInt64 = 1 << 16

    /// How far ahead of the device's clock a file may have been signed, when
    /// that clock reads 2026 or later: a day.
    public static let maxAheadMS: Int64 = 24 * 3600 * 1000

    /// 2026-01-01: before it the clock is not trusted to refuse files signed
    /// ahead of it.
    static let plausible: Int64 = 1_767_225_600_000

    /// The seq a file signed under keys.json keysSeq may not go below, as
    /// Go's floor.
    static func seqFloor(_ seq: UInt64, at: UInt64?, seenKeys: UInt64, keysSeq: UInt64) -> UInt64 {
        let at = (at ?? 0) == 0 ? seenKeys : at!
        return keysSeq > at ? 0 : seq
    }

    static func checkSeq(_ seq: UInt64, floor: UInt64) throws {
        guard seq >= floor else { throw Refused("the file is older than one already seen") }
        guard seq - floor <= maxSeqStep else { throw Refused("the file is too far ahead of the one already seen") }
    }

    static func signedAhead(_ timeMS: Int64, nowMS: Int64) -> Bool {
        nowMS >= plausible && timeMS > nowMS + maxAheadMS
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

    struct Head: Decodable {
        var v: Int?
        var type: String?
    }

    struct Key: Decodable {
        var key: Data
        var name: String
        /// A key of a use this reader does not know signs nothing.
        var use: String?
    }

    struct Keys: Decodable {
        var seq: UInt64
        var time_ms: Int64
        var expires_ms: Int64
        var keys: [Key]

        func spkis(_ use: String) -> [Data] { keys.filter { ($0.use ?? useRelease) == use }.map(\.key) }
    }

    struct Channel: Decodable {
        var channel: String
        var seq: UInt64
        var time_ms: Int64
        var expires_ms: Int64
        var release: String
        var release_sha256: String
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

    /// Whether pattern matches all of s. ICU's `$` also matches before a
    /// final line break, so the match must cover the whole string.
    static func matches(_ s: String, _ pattern: String) -> Bool {
        s.range(of: pattern, options: .regularExpression) == s.startIndex..<s.endIndex
    }

    static let sha256RE = "^[0-9a-f]{64}$"
    static let channelRE = "^[a-z][a-z0-9-]{0,31}$"

    static func decode<T: Decodable>(_ body: Data, _ type: String, as: T.Type) throws -> T {
        // The core decides whether the body is taken (parse_body); the
        // checks here and in the callers only read its fields.
        if let why = Core.bodyRefusal(type, body) { throw Refused("the file is not valid: \(why)") }
        // The strict form of signed bodies first, so that every program reads a file alike (docs/protocol.md, section 16).
        do {
            try Strict.check(body, required: ["v", "type"])
        } catch let e as Strict.Invalid {
            throw Refused("the file is not valid: \(e.reason)")
        }
        guard let h = try? JSONDecoder().decode(Head.self, from: body) else { throw Refused("the file is not valid") }
        guard h.type == type else { throw Refused("the file is a \"\(h.type ?? "")\", not a \"\(type)\"") }
        guard h.v == 1 else { throw Refused("unknown version") }
        guard let v = try? JSONDecoder().decode(T.self, from: body) else { throw Refused("the file is not valid") }
        return v
    }

    static func lifetime(_ time: Int64, _ expires: Int64, max: Int64 = maxLifetimeMS) throws {
        // A time before 1970 is no signing time; from it the difference cannot overflow.
        guard time >= 0, expires > time, expires - time <= max else { throw Refused("the file's lifetime is out of range") }
    }

    static func decodeKeys(_ body: Data) throws -> Keys {
        let k = try decode(body, "keys", as: Keys.self)
        // A key is the only plain bytes of the file: only the one encoding of them.
        struct RawKey: Decodable { var key: String }
        struct Raw: Decodable { var keys: [RawKey] }
        guard let raw = try? JSONDecoder().decode(Raw.self, from: body), raw.keys.allSatisfy({ Strict.base64($0.key) != nil }) else { throw Refused("a key is not canonical base64") }
        guard k.seq > 0 else { throw Refused("keys.json has no sequence number") }
        try lifetime(k.time_ms, k.expires_ms)
        guard (1...8).contains(k.keys.count) else { throw Refused("keys.json must hold 1 to 8 keys") }
        for key in k.keys {
            guard !key.name.isEmpty, key.name.utf8.count <= 64 else { throw Refused("a key has no valid name") }
            guard P256.Signing.PublicKey(spki: key.key) != nil else { throw Refused("a key is not P-256") }
            // A release key's use is left out, never written empty.
            guard key.use != "" else { throw Refused("a key's use is empty") }
        }
        return k
    }

    static func decodeRelease(_ body: Data) throws -> Release {
        let r = try decode(body, "release", as: Release.self)
        guard parseVersion(r.version) != nil, (r.min_from ?? "").isEmpty || parseVersion(r.min_from!) != nil else {
            throw Refused("release.json names no valid version")
        }
        guard matches(r.channel, channelRE), (1...256).contains(r.files.count) else { throw Refused("release.json is not valid") }
        var names = Set<String>()
        for a in r.files {
            guard matches(a.name, "^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$"), names.insert(a.name).inserted else {
                throw Refused("\"\(a.name)\" is not a valid file name")
            }
            let bins = a.binaries ?? []
            guard a.size >= 0, matches(a.sha256, sha256RE), bins.count <= 64 else { throw Refused("the entry for \(a.name) is not valid") }
            for b in bins {
                guard matches(b.name, "^[A-Za-z0-9_][A-Za-z0-9._/-]{0,255}$"), !b.name.contains(".."), matches(b.sha256, sha256RE) else {
                    throw Refused("a binary in \(a.name) is not valid")
                }
            }
        }
        if let d = r.docker, d.image.isEmpty || !matches(d.digest, "^sha256:[0-9a-f]{64}$") {
            throw Refused("the Docker image is not valid")
        }
        return r
    }

    static func decodeChannel(_ body: Data) throws -> Channel {
        let c = try decode(body, "channel", as: Channel.self)
        guard matches(c.channel, channelRE), c.seq > 0 else { throw Refused("the channel file is not valid") }
        try lifetime(c.time_ms, c.expires_ms)
        guard parseVersion(c.release) != nil, matches(c.release_sha256, sha256RE) else {
            throw Refused("the channel file names no valid release")
        }
        return c
    }

    static func decodeStatus(_ body: Data) throws -> Status {
        let st = try decode(body, "attest-status", as: Status.self)
        guard st.seq > 0 else { throw Refused("attest-status.json has no sequence number") }
        try lifetime(st.time_ms, st.expires_ms, max: maxStatusLifetimeMS)
        for (i, s) in st.android_revoked.enumerated() {
            guard matches(s, "^(0|[1-9a-f][0-9a-f]{0,63})$"), i == 0 || serialLess(st.android_revoked[i - 1], s) else {
                throw Refused("\"\(s)\" is not a serial number in order")
            }
        }
        return st
    }

    static func within<T>(_ file: String, _ f: () throws -> T) throws -> T {
        do { return try f() } catch let e as Refused { throw Refused("\(file): \(e.description)") }
    }

    /// Checks a channel file and the release.json it names: keys.json under
    /// the pinned roots (SubjectPublicKeyInfos, DER), the channel file under
    /// its release or channel keys and release.json under its release keys,
    /// the channel's name, both expiries, and that nothing is older than
    /// seen. Returns the release and the Seen to keep.
    public static func check(keys: File, channel: File, release: File, roots: [Data], name: String, nowMS: Int64,
                             seen: Seen) throws -> (Release, Seen) {
        let k = try verifyKeys(keys, roots: roots, nowMS: nowMS, seen: seen)
        let spkis = k.spkis(useRelease)
        let c = try within("\(name).json") {
            // A channel key signs channel files and nothing else.
            try channel.verify(spkis + k.spkis(useChannel))
            let c = try decodeChannel(channel.body)
            guard c.channel == name else { throw Refused("the file is for the channel \"\(c.channel)\"") }
            guard nowMS < c.expires_ms else { throw Refused("the file has expired") }
            guard !signedAhead(c.time_ms, nowMS: nowMS) else { throw Refused("the file was signed ahead of this device's clock") }
            try checkSeq(c.seq, floor: seqFloor(seen.channel_seq, at: seen.channel_keys_seq, seenKeys: seen.keys_seq, keysSeq: k.seq))
            return c
        }
        let r = try within("release.json") {
            try release.verify(spkis)
            guard hex(release.hash) == c.release_sha256 else { throw Refused("it is not the release \(name).json names") }
            let r = try decodeRelease(release.body)
            guard r.version == c.release, r.channel == c.channel else {
                throw Refused("it is \(r.version) on \(r.channel), \(name).json names \(c.release)")
            }
            if let s = seen.version, !s.isEmpty, compare(r.version, s) < 0 { throw Refused("it is older than a release already seen") }
            return r
        }
        var version = r.version
        if let s = seen.version, !s.isEmpty, compare(s, r.version) > 0 { version = s }
        let statusKeys = (seen.status_keys_seq ?? 0) == 0 ? seen.keys_seq : seen.status_keys_seq!
        return (r, Seen(keys_seq: k.seq, channel_seq: c.seq, version: version, status_seq: seen.status_seq,
                        channel_keys_seq: k.seq, status_keys_seq: statusKeys == 0 ? nil : statusKeys))
    }

    static func verifyKeys(_ keys: File, roots: [Data], nowMS: Int64, seen: Seen) throws -> Keys {
        try within("keys.json") {
            try keys.verify(roots)
            let k = try decodeKeys(keys.body)
            guard nowMS < k.expires_ms else { throw Refused("the file has expired") }
            guard !signedAhead(k.time_ms, nowMS: nowMS) else { throw Refused("the file was signed ahead of this device's clock") }
            guard k.seq >= seen.keys_seq else { throw Refused("the file is older than one already seen") }
            return k
        }
    }

    /// Orders serial numbers as numbers: the shorter first, then as strings.
    static func serialLess(_ a: String, _ b: String) -> Bool { a.count != b.count ? a.count < b.count : a < b }

    /// Checks attest-status.json: keys.json under the pinned roots, the list
    /// under a status key of it, its expiry, and that neither is older than
    /// seen. Returns the list and the Seen to keep.
    public static func checkStatus(keys: File, status: File, roots: [Data], nowMS: Int64, seen: Seen) throws -> (Status, Seen) {
        let k = try verifyKeys(keys, roots: roots, nowMS: nowMS, seen: seen)
        let st = try within("attest-status.json") {
            try status.verify(k.spkis(useStatus))
            let st = try decodeStatus(status.body)
            guard nowMS < st.expires_ms else { throw Refused("the file has expired") }
            guard !signedAhead(st.time_ms, nowMS: nowMS) else { throw Refused("the file was signed ahead of this device's clock") }
            try checkSeq(st.seq, floor: seqFloor(seen.status_seq ?? 0, at: seen.status_keys_seq, seenKeys: seen.keys_seq, keysSeq: k.seq))
            return st
        }
        var next = seen
        if (seen.channel_keys_seq ?? 0) == 0, seen.keys_seq != 0 { next.channel_keys_seq = seen.keys_seq }
        next.keys_seq = k.seq
        next.status_seq = st.seq
        next.status_keys_seq = k.seq
        return (st, next)
    }
}
