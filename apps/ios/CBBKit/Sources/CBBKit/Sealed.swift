// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import Crypto
import Foundation

/// Copies sealed end to end (docs/protocol.md, section 4): the device that
/// copies seals each copy to the devices of the group that read copies and
/// signs it, so that the members that pass it on, a hub among them, neither
/// read nor change it. The Rust core seals, checks and opens them
/// (cbb_core::copy, docs/core-api.md); the kit carries them.
extension Member {
    /// A copy's key, wrapped for one reader.
    public struct Wrap: Codable, Equatable, Sendable {
        public var to: String
        public var key: Data
    }

    /// A copy as it travels between members: the header in the open, the
    /// content sealed, or only the hash of it in a secret's mark.
    public struct Sealed: Codable, Equatable, Sendable {
        public var id: String
        public var origin: String
        public var time: Timestamp
        /// Milliseconds since the copy, as of the moment the frame is
        /// written; not signed.
        public var ageMS: Int64
        public var cert: Data
        public var issuer: Data?
        public var wraps: [Wrap]
        public var payload: Data?
        public var payloadSHA256: Data?
        public var blob: Media.Blob?
        public var sig: Data

        enum CodingKeys: String, CodingKey {
            case id, origin, time, ageMS = "age_ms", cert, issuer, wraps, payload, payloadSHA256 = "payload_sha256", blob, sig
            // A copy in the open is never taken.
            case kind, text, via, media
        }

        public init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            for k in [CodingKeys.kind, .text, .via, .media] where c.contains(k) {
                throw DecodingError.dataCorruptedError(forKey: k, in: c, debugDescription: "a copy in the open")
            }
            id = try c.decode(String.self, forKey: .id)
            origin = try c.decode(String.self, forKey: .origin)
            time = try c.decode(Timestamp.self, forKey: .time)
            ageMS = try c.decodeIfPresent(Int64.self, forKey: .ageMS) ?? 0
            cert = try c.decode(Data.self, forKey: .cert)
            issuer = try c.decodeIfPresent(Data.self, forKey: .issuer).flatMap { $0.isEmpty ? nil : $0 }
            wraps = try c.decode([Wrap].self, forKey: .wraps)
            payload = try c.decodeIfPresent(Data.self, forKey: .payload).flatMap { $0.isEmpty ? nil : $0 }
            payloadSHA256 = try c.decodeIfPresent(Data.self, forKey: .payloadSHA256).flatMap { $0.isEmpty ? nil : $0 }
            blob = try c.decodeIfPresent(Media.Blob.self, forKey: .blob)
            // The core's sealed copy has no signature yet.
            sig = try c.decodeIfPresent(Data.self, forKey: .sig) ?? Data()
        }

        public func encode(to encoder: Encoder) throws {
            var c = encoder.container(keyedBy: CodingKeys.self)
            try c.encode(id, forKey: .id)
            try c.encode(origin, forKey: .origin)
            try c.encode(time, forKey: .time)
            try c.encode(ageMS, forKey: .ageMS)
            try c.encode(cert, forKey: .cert)
            try c.encodeIfPresent(issuer, forKey: .issuer)
            try c.encode(wraps, forKey: .wraps)
            try c.encodeIfPresent(payload, forKey: .payload)
            try c.encodeIfPresent(payloadSHA256, forKey: .payloadSHA256)
            try c.encodeIfPresent(blob, forKey: .blob)
            try c.encode(sig, forKey: .sig)
        }

        /// Whether it is a secret's mark: the copy without its payload.
        public var isMark: Bool { payload == nil }

        /// The SHA-256 of the payload, which a mark carries.
        public var payloadHash: Data? { payload.map { Data(SHA256.hash(data: $0)) } ?? payloadSHA256 }

        /// The mark of this copy: the same without its payload.
        public var mark: Sealed {
            var m = self
            (m.payloadSHA256, m.payload) = (payloadHash, nil)
            return m
        }

        /// The shape a receiver checks before anything else, as Go's
        /// Sealed.Validate; the core checks the rest.
        public var isValid: Bool {
            guard GroupCertificates.isDeviceID(id), GroupCertificates.isDeviceID(origin), !time.isZero,
                  time.wall <= Timestamp.maxWall, ageMS >= 0, !cert.isEmpty, !sig.isEmpty,
                  (1...Member.maxReaders).contains(wraps.count) else { return false }
            for (i, w) in wraps.enumerated() {
                guard GroupCertificates.isDeviceID(w.to), w.key.count == Member.wrapSize else { return false }
                if i > 0 && wraps[i - 1].to >= w.to { return false }
            }
            switch (payload, payloadSHA256) {
            case let (p?, nil): guard Member.payloadSteps.contains(p.count - 16) else { return false }
            case let (nil, h?): guard h.count == 32 else { return false }
            default: return false
            }
            if let b = blob {
                guard b.size > 0, b.size % Media.sealedSegment == 0, b.size / Media.sealedSegment <= Media.maxSegments,
                      b.sha256.count == 32 else { return false }
            }
            return true
        }
    }

    /// The most readers a copy is sealed to.
    public static let maxReaders = 256
    /// A wrap's size: X-Wing's encapsulated key, the copy's key and its tag.
    public static let wrapSize = 1120 + 32 + 16
    /// The sizes a copy's content is padded to.
    static let payloadSteps: Set<Int> = [1 << 10, 4 << 10, 16 << 10, 64 << 10, 256 << 10, 1 << 20, 2 << 20, 3 << 20, 4 << 20]
}

extension Member.Event {
    /// The engine's event of a copy that arrived sealed, before it is
    /// opened: its header, unread.
    public init(sealed s: Member.Sealed) {
        self.init(id: s.id, origin: s.origin, time: s.time, ageMS: s.ageMS, kind: .text, text: "")
        (sealed, unread) = (s, true)
    }
}

extension Media {
    /// The sealed blob of a copy's images and files: its size and SHA-256.
    public struct Blob: Codable, Equatable, Sendable {
        public var size: Int64
        public var sha256: Data
        public init(size: Int64, sha256: Data) { (self.size, self.sha256) = (size, sha256) }
    }

    /// A blob's segment before sealing, and after.
    public static let segment = 64 << 10
    public static let sealedSegment: Int64 = Int64(segment) + 16
    /// The most segments a blob has: 1 GiB of parts.
    public static let maxSegments = (maxMedia + Int64(segment) - 1) / Int64(segment)

    /// The size of the sealed blob of n bytes of parts.
    public static func blobSize(_ n: Int64) -> Int64 { (n + Int64(segment) - 1) / Int64(segment) * sealedSegment }

    /// Seals the bytes of a copy's parts, one after another, into its blob
    /// under the copy's key (docs/protocol.md, section 4, "The blob").
    public static func sealBlob(key: Data, parts: [Data]) throws -> (blob: Blob, data: Data) {
        let plain = parts.reduce(Data(), +)
        guard !plain.isEmpty else { throw Core.Mismatch(reason: "a blob of no bytes") }
        let n = (plain.count + segment - 1) / segment
        var out = Data()
        out.reserveCapacity(n * Int(sealedSegment))
        for i in 0..<n {
            let start = plain.startIndex + i * segment
            out += try Core.sealSegment(key: key, index: i, last: i == n - 1, data: plain[start..<min(start + segment, plain.endIndex)])
        }
        return (Blob(size: Int64(out.count), sha256: Data(SHA256.hash(data: out))), out)
    }

    /// Opens a copy's blob, checked against its SHA-256 already, into the
    /// bytes of the manifest's parts that hold bytes, each checked against
    /// its own hash; the zeros after them must be zeros.
    public static func openBlob(key: Data, blob: Blob, data: Data, manifest m: Manifest) throws -> [Data] {
        guard m.size > 0, blob.size == blobSize(m.size), Int64(data.count) == blob.size,
              Data(SHA256.hash(data: data)) == blob.sha256 else { throw Content.Failure.mismatch }
        let n = Int(blob.size / sealedSegment)
        var plain = Data()
        plain.reserveCapacity(n * segment)
        for i in 0..<n {
            let start = data.startIndex + i * Int(sealedSegment)
            plain += try Core.openSegment(key: key, index: i, last: i == n - 1, data: data[start..<(start + Int(sealedSegment))])
        }
        guard plain[(plain.startIndex + Int(m.size))...].allSatisfy({ $0 == 0 }) else { throw Content.Failure.mismatch }
        var out: [Data] = []
        var at = plain.startIndex
        for p in m.parts where !p.dir {
            let bytes = plain[at..<(at + Int(p.size))]
            guard Data(SHA256.hash(data: bytes)) == p.sha256 else { throw Content.Failure.mismatch }
            out.append(Data(bytes))
            at += Int(p.size)
        }
        return out
    }
}

extension Core {
    static func sealSegment(key: Data, index: Int, last: Bool, data: Data) throws -> Data {
        struct Args: Encodable { var key: Data, index: Int, last: Bool, data: Data }
        struct Answer: Decodable { var data: Data }
        return try run("seal_segment", Args(key: key, index: index, last: last, data: data), as: Answer.self).data
    }

    static func openSegment(key: Data, index: Int, last: Bool, data: Data) throws -> Data {
        struct Args: Encodable { var key: Data, index: Int, last: Bool, data: Data }
        struct Answer: Decodable { var data: Data }
        return try run("open_segment", Args(key: key, index: index, last: last, data: data), as: Answer.self).data
    }

    /// What a copy sealed to me holds, and the copy's key (open_copy).
    struct Opened: Decodable {
        var kind: Member.Kind
        var via: Member.Via?
        var text: String?
        var media: Media.Manifest?
        var key: Data
    }

    static func openCopy(_ s: Member.Sealed, me: String, secret: Data) throws -> Opened {
        struct Args: Encodable { var event: Member.Sealed, me: String, secret: Data }
        return try run("open_copy", Args(event: s, me: me, secret: secret), as: Opened.self)
    }
}

/// What this phone seals its copies with and opens the others' with: its
/// member certificate and key, which signs, its secret for sealed messages,
/// and the group's records, which name the readers and check the origins.
public final class CopyKeys: @unchecked Sendable {
    public let device: String
    let cert: Data
    let issuer: Data?
    let signer: CertificateSigner
    let secret: Data
    let records: @Sendable () -> RecordSet?

    public init(device: String, cert: Data, issuer: Data?, signer: CertificateSigner, secret: Data, records: @escaping @Sendable () -> RecordSet?) {
        (self.device, self.cert, self.issuer, self.signer, self.secret, self.records) = (device, cert, issuer, signer, secret, records)
    }

    public enum Failure: Error, CustomStringConvertible {
        case noRecords
        public var description: String { "this phone has no records of its group yet, so it neither seals nor checks copies" }
    }

    /// Seals and signs a copy this phone made (docs/protocol.md, section 4,
    /// "Sealing"), with the blob of its images or files sealed under key.
    public func seal(_ e: Member.Event, key: Data?, blob: Media.Blob?) throws -> Member.Sealed {
        guard let set = records() else { throw Failure.noRecords }
        return try set.sealCopy(e, cert: cert, issuer: issuer, key: key, blob: blob, signer: signer)
    }

    /// Checks a copy a peer sent against the records and opens it when it
    /// is sealed to this phone (section 4, "Opening"); a copy that is not
    /// is kept unread, to order and pass on. It throws for a copy the
    /// records refuse, which is dropped.
    public func take(_ s: Member.Sealed) throws -> Member.Event {
        guard let set = records() else { throw Failure.noRecords }
        try set.checkCopy(s)
        var e = Member.Event(sealed: s)
        guard !s.isMark, s.wraps.contains(where: { $0.to == device }) else { return e }
        // A copy sealed to this phone that does not open stays unread, as
        // the others may read theirs.
        guard let o = try? Core.openCopy(s, me: device, secret: secret) else { return e }
        (e.kind, e.via, e.text, e.media, e.key, e.unread) = (o.kind, o.via ?? .copy, o.text ?? "", o.media, o.key, false)
        return e
    }
}
