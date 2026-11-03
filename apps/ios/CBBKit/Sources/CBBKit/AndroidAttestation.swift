// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import _CryptoExtras
import Crypto
import Foundation

/// The challenge a phone's key is made with, so that the key's attestation
/// proves it belongs to this device and, when there is one, this group
/// (docs/protocol.md, section 17):
///
///     SHA-256("cbb attest v1" || field(group tag) || field(member key) || salt)
///
/// field is a two-byte big-endian length and the bytes; the salt is 16
/// random bytes kept with the key and shown with its evidence.
public enum Attestation {
    public static let saltSize = 16

    public static func challenge(groupTag: String, memberKey: Data, salt: Data) throws -> Data {
        guard salt.count == saltSize else { throw AndroidAttestation.Malformed("a salt of \(salt.count) bytes") }
        var h = SHA256()
        h.update(data: Data("cbb attest v1".utf8))
        for f in [Data(groupTag.utf8), memberKey] {
            guard f.count <= 0xffff else { throw AndroidAttestation.Malformed("a field of \(f.count) bytes") }
            h.update(data: Data([UInt8(f.count >> 8), UInt8(f.count & 0xff)]))
            h.update(data: f)
        }
        h.update(data: salt)
        return Data(h.finalize())
    }
}

/// Checks an Android Key Attestation chain, as Go's internal/attest
/// CheckAndroid and the Kotlin kit's AndroidAttestation do
/// (docs/protocol.md, section 17): the leaf certifies the key and carries
/// the Keystore's description of it, every certificate that signs another
/// is a CA that may sign it, and the chain leads to one of Google's
/// attestation roots. testdata/interop/go-attest.json keeps the three in
/// step. An iPhone checks an Android phone's proof with it.
public enum AndroidAttestation {
    /// The SubjectPublicKeyInfos of Google's attestation roots: the RSA root
    /// of every chain until 2026 and the ECDSA P-384 "Key Attestation CA1".
    public static let googleRoots: [Data] = [
        "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xUFmOr75gvMsd/dTEDDJdSSxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5jlRfdnJLmN0pTy/4lj4/7tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y//0rb+T+W8a9nsNL/ggjnar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73XpXyTqRxB/M0n1n/W9nGqC4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYImQQcHtGl/m00QLVWutHQoVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB+TxywElgS70vE0XmLD+OJtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7quvmag8jfPioyKvxnK/EgsTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgpZrt3i5MIlCaY504LzSRiigHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7gLiMm0jhO2B6tUXHI/+MRPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82ixPvZtXQpUpuL12ab+9EaDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+NpUFgNPN9PvQi8WEg5UmAGMCAwEAAQ==",
        "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEI9ojcU7fPlsFCjxy6IRqzgeOoK0b+YsV9FPQywiyw8EQRTkJ9u3qwfnI4DGoSLlBqClTXJfgfCcZvs60FikNMHnu4fkRzObfgDkU2KNXezT9/RQ+XvNslxPHrHCowhGr",
    ].map { Data(base64Encoded: $0)! }

    public static let kindTEE = "android-tee"
    public static let kindStrongBox = "android-strongbox"

    /// What a valid attestation shows of a key; why is "" when its store is
    /// Records.proven.
    public struct Result: Equatable {
        public var store: String
        public var kind: String
        public var rkp: Bool
        public var why: String
        public var serials: [String]
    }

    /// Strict proves only chains of Remote Key Provisioning; revoked holds
    /// lowercase hex serials; roots are Google's when nil.
    public struct Policy {
        public var strict = false
        public var revoked: Set<String> = []
        public var roots: [Data]?
        public init(strict: Bool = false, revoked: Set<String> = [], roots: [Data]? = nil) {
            self.strict = strict
            self.revoked = revoked
            self.roots = roots
        }
    }

    /// An attestation that proves nothing: a broken chain, another root, key
    /// or challenge, a revoked certificate (revoked).
    public struct Invalid: Error, CustomStringConvertible {
        public let reason: String
        public var revoked = false
        public var description: String { "invalid attestation: \(reason)" }
    }

    static let oidKeyDescription = "1.3.6.1.4.1.11129.2.1.17"
    static let oidProvisioning = "1.3.6.1.4.1.11129.2.1.30"
    static let oidBasicConstraints = "2.5.29.19"
    static let oidKeyUsage = "2.5.29.15"
    /// keyCertSign in the first byte of a key usage's bits.
    static let keyCertSign: UInt8 = 0x04
    static let levelSoftware = 0
    static let levelStrongBox = 2
    static let bootVerified = 0
    static let bootSelfSigned = 1
    static let tagRootOfTrust = 704

    /// Checks chain (DER certificates, leaf first) for the key spki made with
    /// challenge; throws Invalid when it proves nothing.
    public static func check(chain: [Data], spki: Data, challenge: Data, policy: Policy = Policy()) throws -> Result {
        guard (2...10).contains(chain.count) else { throw Invalid(reason: "a chain of \(chain.count) certificates") }
        let certs = try chain.enumerated().map { (i, der) throws -> Cert in
            do { return try Cert(Array(der)) } catch { throw Invalid(reason: "certificate \(i): \(error)") }
        }
        var rkp = false
        for (i, c) in certs.enumerated() {
            if i + 1 < certs.count, !c.signed(by: certs[i + 1].spki) {
                throw Invalid(reason: "certificate \(i) is not signed by the next")
            }
            if policy.revoked.contains(c.serial) { throw Invalid(reason: "certificate \(i) (\(c.serial)) is revoked", revoked: true) }
            if i == 0 { continue }  // the leaf signs nothing and says nothing of provisioning
            // Every other certificate signed the one before it: it must be a CA
            // that may sign certificates, with a path length that fits.
            guard c.isCA else { throw Invalid(reason: "certificate \(i) signs another and is not a CA") }
            if let usage = c.keyUsage, usage & keyCertSign == 0 {
                throw Invalid(reason: "certificate \(i) signs another and may not sign certificates")
            }
            if let limit = c.pathLen, limit < i - 1 {
                throw Invalid(reason: "certificate \(i) allows \(limit) CAs below it, the chain has \(i - 1)")
            }
            if c.extensions[oidProvisioning] != nil { rkp = true }
        }
        guard (policy.roots ?? googleRoots).contains(where: { certs.last!.signed(by: Array($0)) }) else {
            throw Invalid(reason: "the chain does not lead to a known root")
        }
        let leaf = certs[0]
        guard leaf.spki == Array(spki) else { throw Invalid(reason: "the leaf certifies another key") }
        guard let ext = leaf.extensions[oidKeyDescription] else { throw Invalid(reason: "the leaf has no key description") }
        let kd: KeyDescription
        do { kd = try KeyDescription(ext) } catch { throw Invalid(reason: "the key description: \(error)") }
        guard kd.challenge == Array(challenge) else { throw Invalid(reason: "another challenge") }
        let serials = certs.map(\.serial)
        if kd.attestationLevel == levelSoftware || kd.keyMintLevel == levelSoftware {
            return Result(store: Records.file, kind: "", rkp: rkp, why: "the Keystore keeps the key in software", serials: serials)
        }
        let kind = kd.attestationLevel == levelStrongBox && kd.keyMintLevel == levelStrongBox ? kindStrongBox : kindTEE
        let why: String
        if let root = kd.root {
            if !root.locked {
                why = "the phone's bootloader is unlocked"
            } else if root.state == bootSelfSigned {
                why = "the phone boots a system signed with its own key"
            } else if root.state != bootVerified {
                why = "the phone's boot is not verified"
            } else if policy.strict && !rkp {
                why = "the chain did not come through Remote Key Provisioning"
            } else {
                why = ""
            }
        } else {
            why = "the key description has no root of trust"
        }
        return Result(store: why.isEmpty ? Records.proven : Records.hardware, kind: kind, rkp: rkp, why: why, serials: serials)
    }

    struct Malformed: Error, CustomStringConvertible {
        let description: String
        init(_ d: String) { description = d }
    }

    /// What check reads of a certificate.
    struct Cert {
        var tbs: [UInt8]
        var signatureAlgorithm: String
        var signature: [UInt8]
        var serial: String
        var spki: [UInt8]
        /// The extensions' values by OID.
        var extensions: [String: [UInt8]] = [:]
        /// BasicConstraints says CA, and its path length when it has one.
        var isCA = false
        var pathLen: Int?
        /// The first byte of the key usage's bits; nil without the extension.
        var keyUsage: UInt8?

        init(_ der: [UInt8]) throws {
            let top = try TLV.read(der, 0)
            guard top.tag == 0x30, top.end == der.count else { throw Malformed("not a certificate") }
            let f = try top.children(der)
            guard f.count == 3 else { throw Malformed("\(f.count) fields") }
            tbs = f[0].full(der)
            signatureAlgorithm = try TLV.oid(try f[1].expect(0x30).children(der).first?.expect(0x06).content(der) ?? [])
            let bits = try f[2].expect(0x03).content(der)
            guard bits.first == 0 else { throw Malformed("a signature with unused bits") }
            signature = Array(bits.dropFirst())
            var t = try f[0].expect(0x30).children(der)
            if t.first.map({ $0.cls == 2 && $0.number == 0 }) == true { t.removeFirst() }
            guard t.count >= 6 else { throw Malformed("a short TBSCertificate") }
            serial = Cert.hex(try t[0].expect(0x02).content(der))
            spki = try t[5].expect(0x30).full(der)
            for e in t.dropFirst(6) where e.cls == 2 && e.number == 3 {
                for x in try (try e.children(der)).first?.expect(0x30).children(der) ?? [] {
                    let parts = try x.expect(0x30).children(der)
                    guard parts.count >= 2 else { throw Malformed("an extension") }
                    extensions[try TLV.oid(try parts[0].expect(0x06).content(der))] = try parts.last!.expect(0x04).content(der)
                }
            }
            if let bc = extensions[oidBasicConstraints] {
                let b = try TLV.read(bc, 0)
                guard b.tag == 0x30, b.end == bc.count else { throw Malformed("basic constraints") }
                for (n, x) in try b.children(bc).enumerated() {
                    switch x.tag {
                    case 0x01 where n == 0:
                        let v = x.content(bc)
                        guard v.count == 1 else { throw Malformed("basic constraints") }
                        isCA = v[0] != 0
                    case 0x02:
                        let v = x.content(bc)
                        guard (1...2).contains(v.count), v[0] & 0x80 == 0 else { throw Malformed("a path length") }
                        pathLen = v.reduce(0) { $0 << 8 | Int($1) }
                    default:
                        throw Malformed("basic constraints")
                    }
                }
                // A path length means something on a CA only.
                if !isCA { pathLen = nil }
            }
            if let ku = extensions[oidKeyUsage] {
                let b = try TLV.read(ku, 0)
                guard b.tag == 0x03, b.end == ku.count else { throw Malformed("key usage") }
                let v = b.content(ku)
                keyUsage = v.count >= 2 ? v[1] : 0
            }
        }

        /// A serial number as Google's revocation list writes it: lowercase
        /// hex without leading zeros.
        static func hex(_ b: [UInt8]) -> String {
            let s = b.map { String(format: "%02x", $0) }.joined().drop(while: { $0 == "0" })
            return s.isEmpty ? "0" : String(s)
        }

        /// Whether the key spki signed this certificate.
        func signed(by spki: [UInt8]) -> Bool {
            guard let key = try? PublicKey(spki) else { return false }
            return key.verifies(signature, of: tbs, algorithm: signatureAlgorithm)
        }
    }

    /// The keys an attestation chain is signed with: P-256, P-384 and RSA.
    enum PublicKey {
        case p256(P256.Signing.PublicKey)
        case p384(P384.Signing.PublicKey)
        case rsa(_RSA.Signing.PublicKey)

        init(_ spki: [UInt8]) throws {
            let top = try TLV.read(spki, 0)
            let alg = try (try top.expect(0x30).children(spki)).first?.expect(0x30).children(spki) ?? []
            guard let oid = alg.first else { throw Malformed("no algorithm") }
            switch try TLV.oid(try oid.expect(0x06).content(spki)) {
            case "1.2.840.10045.2.1":
                guard alg.count == 2 else { throw Malformed("no curve") }
                switch try TLV.oid(try alg[1].expect(0x06).content(spki)) {
                case "1.2.840.10045.3.1.7": self = .p256(try P256.Signing.PublicKey(derRepresentation: spki))
                case "1.3.132.0.34": self = .p384(try P384.Signing.PublicKey(derRepresentation: spki))
                default: throw Malformed("another curve")
                }
            case "1.2.840.113549.1.1.1": self = .rsa(try _RSA.Signing.PublicKey(derRepresentation: spki))
            default: throw Malformed("another key algorithm")
            }
        }

        func verifies(_ sig: [UInt8], of data: [UInt8], algorithm: String) -> Bool {
            switch (self, algorithm) {
            case (.p256(let k), "1.2.840.10045.4.3.2"):
                guard let s = try? P256.Signing.ECDSASignature(derRepresentation: sig) else { return false }
                return k.isValidSignature(s, for: SHA256.hash(data: data))
            case (.p256(let k), "1.2.840.10045.4.3.3"):
                guard let s = try? P256.Signing.ECDSASignature(derRepresentation: sig) else { return false }
                return k.isValidSignature(s, for: SHA384.hash(data: data))
            case (.p384(let k), "1.2.840.10045.4.3.2"):
                guard let s = try? P384.Signing.ECDSASignature(derRepresentation: sig) else { return false }
                return k.isValidSignature(s, for: SHA256.hash(data: data))
            case (.p384(let k), "1.2.840.10045.4.3.3"):
                guard let s = try? P384.Signing.ECDSASignature(derRepresentation: sig) else { return false }
                return k.isValidSignature(s, for: SHA384.hash(data: data))
            case (.rsa(let k), "1.2.840.113549.1.1.11"):
                return k.isValidSignature(_RSA.Signing.RSASignature(rawRepresentation: sig), for: SHA256.hash(data: data), padding: .insecurePKCS1v1_5)
            case (.rsa(let k), "1.2.840.113549.1.1.12"):
                return k.isValidSignature(_RSA.Signing.RSASignature(rawRepresentation: sig), for: SHA384.hash(data: data), padding: .insecurePKCS1v1_5)
            case (.rsa(let k), "1.2.840.113549.1.1.13"):
                return k.isValidSignature(_RSA.Signing.RSASignature(rawRepresentation: sig), for: SHA512.hash(data: data), padding: .insecurePKCS1v1_5)
            default:
                return false
            }
        }
    }

    struct RootOfTrust {
        var locked: Bool
        var state: Int
    }

    /// attestationVersion, attestationSecurityLevel, keyMintVersion,
    /// keyMintSecurityLevel, attestationChallenge, uniqueId,
    /// softwareEnforced, hardwareEnforced; only the hardware-enforced root
    /// of trust counts.
    struct KeyDescription {
        var attestationLevel: Int
        var keyMintLevel: Int
        var challenge: [UInt8]
        var root: RootOfTrust?

        init(_ der: [UInt8]) throws {
            let top = try TLV.read(der, 0)
            guard top.tag == 0x30, top.end == der.count else { throw Malformed("not a sequence") }
            let f = try top.children(der)
            guard f.count >= 8 else { throw Malformed("\(f.count) fields") }
            attestationLevel = try KeyDescription.enumerated(f[1], der)
            keyMintLevel = try KeyDescription.enumerated(f[3], der)
            challenge = try f[4].expect(0x04).content(der)
            for a in try f[7].expect(0x30).children(der) where a.cls == 2 && a.number == tagRootOfTrust {
                let inner = try a.children(der)
                guard inner.count == 1 else { throw Malformed("rootOfTrust") }
                let r = try inner[0].expect(0x30).children(der)
                guard r.count >= 3 else { throw Malformed("rootOfTrust") }
                let locked = try r[1].expect(0x01).content(der)
                guard locked.count == 1 else { throw Malformed("deviceLocked") }
                root = RootOfTrust(locked: locked[0] != 0, state: try KeyDescription.enumerated(r[2], der))
            }
        }

        static func enumerated(_ t: TLV, _ der: [UInt8]) throws -> Int {
            let b = try t.expect(0x0a).content(der)
            guard (1...4).contains(b.count) else { throw Malformed("an enumerated of \(b.count) bytes") }
            return b.reduce(b[0] & 0x80 != 0 ? -1 : 0) { $0 << 8 | Int($1) }
        }
    }

    /// One DER element of a buffer, with the tags above 30 that the
    /// Keystore's authorization lists use: tag is the first byte, cls (0
    /// universal, 2 context-specific) and number the tag itself.
    struct TLV {
        var start: Int
        var tag: UInt8
        var cls: Int
        var number: Int
        var body: Int
        var end: Int

        func content(_ b: [UInt8]) -> [UInt8] { Array(b[body..<end]) }
        func full(_ b: [UInt8]) -> [UInt8] { Array(b[start..<end]) }
        func expect(_ t: UInt8) throws -> TLV {
            guard tag == t else { throw Malformed(String(format: "tag %02x, not %02x", tag, t)) }
            return self
        }

        func children(_ b: [UInt8]) throws -> [TLV] {
            guard tag & 0x20 != 0 else { throw Malformed("a primitive element") }
            var out: [TLV] = []
            var p = body
            while p < end {
                let t = try TLV.read(b, p, limit: end)
                out.append(t)
                p = t.end
            }
            return out
        }

        static func read(_ b: [UInt8], _ start: Int, limit: Int? = nil) throws -> TLV {
            let limit = limit ?? b.count
            var p = start
            func next() throws -> Int {
                guard p < limit else { throw Malformed("truncated") }
                defer { p += 1 }
                return Int(b[p])
            }
            let tag = try next()
            var number = tag & 0x1f
            if number == 0x1f {
                number = 0
                var x: Int
                repeat {
                    x = try next()
                    guard number <= 0xffff else { throw Malformed("a tag too long") }
                    number = number << 7 | x & 0x7f
                } while x & 0x80 != 0
            }
            var n = try next()
            if n & 0x80 != 0 {
                let k = n & 0x7f
                guard (1...3).contains(k) else { throw Malformed("a length of \(k) bytes") }
                n = 0
                for _ in 0..<k { n = n << 8 | (try next()) }
            }
            guard n <= limit - p else { throw Malformed("truncated") }
            return TLV(start: start, tag: UInt8(tag), cls: tag >> 6, number: number, body: p, end: p + n)
        }

        /// An OBJECT IDENTIFIER's content in its dotted form.
        static func oid(_ c: [UInt8]) throws -> String {
            guard let first = c.first else { throw Malformed("an empty OID") }
            var arcs = [Int(first) / 40, Int(first) % 40]
            if first >= 80 { arcs = [2, Int(first) - 80] }
            var v = 0
            for x in c.dropFirst() {
                guard v <= 1 << 48 else { throw Malformed("an OID arc too long") }
                v = v << 7 | Int(x & 0x7f)
                if x & 0x80 == 0 {
                    arcs.append(v)
                    v = 0
                }
            }
            guard c.last.map({ $0 & 0x80 == 0 }) == true else { throw Malformed("a truncated OID") }
            return arcs.map(String.init).joined(separator: ".")
        }
    }
}
