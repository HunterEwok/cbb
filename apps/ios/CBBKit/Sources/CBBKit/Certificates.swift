// SPDX-License-Identifier: AGPL-3.0-only

import Crypto
import Foundation

/// A P-256 key that signs certificates: a software key in tests, a key in
/// the Secure Enclave in the app, which never leaves it.
public protocol CertificateSigner {
    /// The public key as a SubjectPublicKeyInfo, DER.
    var publicKeyDER: Data { get }
    /// An ECDSA signature with SHA-256 over data, DER.
    func signature(for data: Data) throws -> Data
}

/// A software P-256 key as a CertificateSigner.
public struct SoftwareSigner: CertificateSigner, Sendable {
    public let key: P256.Signing.PrivateKey
    public init(_ key: P256.Signing.PrivateKey = .init()) { self.key = key }
    public var publicKeyDER: Data { key.publicKey.derRepresentation }
    public func signature(for data: Data) throws -> Data { try key.signature(for: data).derRepresentation }

    /// An ECDSA signature, DER, of a SHA-256 digest, as the core's member
    /// asks its key for one (the core's sign_digest).
    public func signature(digest: Data) throws -> Data {
        struct Args: Encodable { var pkcs8: Data, digest: Data }
        struct Answer: Decodable { var sig: Data }
        return try Core.run("sign_digest", Args(pkcs8: key.derRepresentation, digest: digest), as: Answer.self).sig
    }
}

/// The group's certificates, with the profiles of docs/protocol.md,
/// section 2, as the Go side issues them (internal/group/cert.go).
public enum GroupCertificates {
    /// How long a member certificate lasts.
    public static let memberYears = 2
    /// How long the group CA lasts.
    public static let caYears = 20
    /// Certificates start this much before now, for clocks a little behind.
    public static let backdate: TimeInterval = 24 * 3600

    static let oidECPublicKey = "1.2.840.10045.2.1"
    static let oidECDSAWithSHA256 = "1.2.840.10045.4.3.2"
    static let oidCommonName = "2.5.4.3"
    static let oidBasicConstraints = "2.5.29.19"
    static let oidKeyUsage = "2.5.29.15"
    static let oidExtKeyUsage = "2.5.29.37"
    static let oidSubjectAltName = "2.5.29.17"
    static let oidSubjectKeyID = "2.5.29.14"
    static let oidAuthorityKeyID = "2.5.29.35"
    static let oidServerAuth = "1.3.6.1.5.5.7.3.1"
    static let oidClientAuth = "1.3.6.1.5.5.7.3.2"

    /// A new group CA certificate for the signer's key: self-signed, a CA
    /// for certificate and CRL signing, valid from a day ago for 20 years.
    /// With path length 0 it is a group CA as a computer makes it; with 1 it
    /// is the root a phone makes, which can certify admin CAs later
    /// (docs/protocol.md, sections 9 and 10).
    public static func groupCA(signer: CertificateSigner, now: Date, pathLength: Int = 0) throws -> Data {
        let day = ISO8601DateFormatter.string(from: now, timeZone: TimeZone(identifier: "UTC")!, formatOptions: [.withFullDate])
        let name = distinguishedName((pathLength == 0 ? "cbb group CA " : "cbb group root ") + day)
        let ski = keyIdentifier(signer.publicKeyDER)
        let extensions = [
            ext(oidBasicConstraints, critical: true, DER.sequence([DER.bool(true), DER.integer(pathLength)])),
            // keyCertSign (bit 5) and cRLSign (bit 6).
            ext(oidKeyUsage, critical: true, DER.bitString([0x06], unused: 1)),
            ext(oidSubjectKeyID, critical: false, DER.octetString(ski)),
        ]
        let notAfter = Calendar.utc.date(byAdding: .year, value: caYears, to: now)!
        return try sign(subject: name, issuer: name, publicKey: signer.publicKeyDER,
                        notBefore: now.addingTimeInterval(-backdate), notAfter: notAfter,
                        extensions: extensions, signer: signer)
    }

    /// A member certificate for a device's public key (a SubjectPublicKeyInfo),
    /// signed by the group CA: the device ID as its CN, cb-<ID>.local as its
    /// one DNS name, for server and client use, from the CA's start until
    /// two years from now or the CA's end, whichever is sooner.
    public static func member(device: String, publicKey: Data, ca: Data, caSigner: CertificateSigner, now: Date) throws -> Data {
        guard isDeviceID(device) else { throw CertificateError.badDeviceID }
        let caInfo = try CertificateInfo(der: ca)
        guard now >= caInfo.notBefore, now < caInfo.notAfter else { throw CertificateError.outsideCALifetime }
        let notAfter = min(Calendar.utc.date(byAdding: .year, value: memberYears, to: now)!, caInfo.notAfter)
        let extensions = [
            // digitalSignature (bit 0).
            ext(oidKeyUsage, critical: true, DER.bitString([0x80], unused: 7)),
            ext(oidExtKeyUsage, critical: false, DER.sequence([DER.oid(oidServerAuth), DER.oid(oidClientAuth)])),
            ext(oidBasicConstraints, critical: true, DER.sequence([])),
            ext(oidSubjectAltName, critical: false, DER.sequence([DER.context(2, constructed: false, Array("cb-\(device).local".utf8))])),
            ext(oidAuthorityKeyID, critical: false, DER.sequence([DER.context(0, constructed: false, keyIdentifier(caSigner.publicKeyDER))])),
        ]
        return try sign(subject: distinguishedName(device), issuer: caInfo.rawSubject, publicKey: publicKey,
                        notBefore: caInfo.notBefore, notAfter: notAfter, extensions: extensions, signer: caSigner)
    }

    /// An admin CA certificate for another admin phone's key (a
    /// SubjectPublicKeyInfo), signed by the group's root: a CA with path
    /// length 0 that issues member certificates and signs records, valid as
    /// long as the root (docs/protocol.md, section 10). device names the
    /// admin phone in its CN.
    public static func adminCA(device: String, publicKey: Data, root: Data, rootSigner: CertificateSigner) throws -> Data {
        guard isDeviceID(device) else { throw CertificateError.badDeviceID }
        let rootInfo = try CertificateInfo(der: root)
        let extensions = [
            ext(oidBasicConstraints, critical: true, DER.sequence([DER.bool(true), DER.integer(0)])),
            ext(oidKeyUsage, critical: true, DER.bitString([0x06], unused: 1)),
            ext(oidSubjectKeyID, critical: false, DER.octetString(keyIdentifier(publicKey))),
            ext(oidAuthorityKeyID, critical: false, DER.sequence([DER.context(0, constructed: false, keyIdentifier(rootSigner.publicKeyDER))])),
        ]
        return try sign(subject: distinguishedName("cbb admin " + device), issuer: rootInfo.rawSubject, publicKey: publicKey,
                        notBefore: rootInfo.notBefore, notAfter: rootInfo.notAfter, extensions: extensions, signer: rootSigner)
    }

    /// The self-signed certificate a joining device presents in pairing, as
    /// Go's joiner makes it: the device ID as its CN, valid from 1970 to
    /// 9999. Nobody trusts it; the QR code's fingerprint names it, and the
    /// pairing exchange binds it.
    public static func selfSigned(device: String, signer: CertificateSigner) throws -> Data {
        guard isDeviceID(device) else { throw CertificateError.badDeviceID }
        let name = distinguishedName(device)
        let extensions = [
            ext(oidKeyUsage, critical: true, DER.bitString([0x80], unused: 7)),
            ext(oidBasicConstraints, critical: true, DER.sequence([])),
        ]
        let end = Calendar.utc.date(from: DateComponents(year: 9999, month: 12, day: 31, hour: 23, minute: 59, second: 59))!
        return try sign(subject: name, issuer: name, publicKey: signer.publicKeyDER, notBefore: Date(timeIntervalSince1970: 0),
                        notAfter: end, extensions: extensions, signer: signer)
    }

    /// Checks an admin CA as Go's checkAdminCA does: a CA with path length 0
    /// that may sign certificates, with a P-256 key, signed by a root whose
    /// path length is at least 1.
    public static func checkAdminCA(_ der: Data, root: Data) throws {
        let c = try ParsedCertificate(der: der), r = try ParsedCertificate(der: root)
        guard c.isCA, c.pathLength == 0, c.canSignCertificates,
              P256.Signing.PublicKey(spki: c.info.publicKey) != nil else { throw VerifyError.notAdminCA }
        // A root without a path length limit is refused, as in Go.
        guard (r.pathLength ?? -1) >= 1 else { throw VerifyError.notAdminCA }
        guard signed(c, by: r.info) else { throw VerifyError.notFromGroupCA }
    }

    /// Checks the new root of a root record as Go's checkRoot does: a
    /// self-signed CA with path length 1 that may sign certificates, with a
    /// P-256 key (docs/protocol.md, section 10, "Roots").
    public static func checkRoot(_ der: Data) throws {
        let c = try ParsedCertificate(der: der)
        guard c.isCA, c.pathLength == 1, c.canSignCertificates,
              P256.Signing.PublicKey(spki: c.info.publicKey) != nil, signed(c, by: c.info) else {
            throw VerifyError.notRoot
        }
    }

    /// Whether the certificate der was signed by the CA issuer.
    static func signed(_ der: Data, by issuer: Data) -> Bool {
        guard let c = try? ParsedCertificate(der: der), let i = try? CertificateInfo(der: issuer) else { return false }
        return signed(c, by: i)
    }

    static func signed(_ cert: ParsedCertificate, by issuer: CertificateInfo) -> Bool {
        guard cert.rawIssuer == issuer.rawSubject,
              let key = P256.Signing.PublicKey(spki: issuer.publicKey),
              let sig = try? P256.Signing.ECDSASignature(derRepresentation: cert.signature),
              cert.signatureAlgorithm == DER.oid(oidECDSAWithSHA256) else { return false }
        return key.isValidSignature(sig, for: cert.tbs)
    }

    /// The group tag: the first 8 bytes of SHA-256 over the group CA
    /// certificate, in hex. Members publish it, and the welcome names it.
    public static func tag(groupCA: Data) -> String {
        SHA256.hash(data: groupCA).prefix(8).map { String(format: "%02x", $0) }.joined()
    }

    /// Whether s is a device ID: 32 lowercase hex characters.
    public static func isDeviceID(_ s: String) -> Bool {
        s.utf8.count == 32 && s.utf8.allSatisfy { (0x30...0x39).contains($0) || (0x61...0x66).contains($0) }
    }

    static func distinguishedName(_ cn: String) -> [UInt8] {
        DER.sequence([DER.set([DER.sequence([DER.oid(oidCommonName), DER.utf8String(cn)])])])
    }

    static func ext(_ oid: String, critical: Bool, _ value: [UInt8]) -> [UInt8] {
        DER.sequence([DER.oid(oid)] + (critical ? [DER.bool(true)] : []) + [DER.octetString(value)])
    }

    /// The key identifier Go uses: SHA-1 over the public key's bit string.
    static func keyIdentifier(_ spki: Data) -> [UInt8] {
        Array(Insecure.SHA1.hash(data: (try? CertificateInfo.subjectPublicKeyBits(spki)) ?? Array(spki)))
    }

    static func sign(subject: [UInt8], issuer: [UInt8], publicKey: Data, notBefore: Date, notAfter: Date,
                     extensions: [[UInt8]], signer: CertificateSigner) throws -> Data {
        var serial = [UInt8](repeating: 0, count: 16)
        var rng = SystemRandomNumberGenerator()
        for i in serial.indices { serial[i] = UInt8.random(in: .min ... .max, using: &rng) }
        serial[0] &= 0x7f
        serial[0] |= 0x01 // non-zero, so the minimal encoding keeps 16 bytes
        let algorithm = DER.sequence([DER.oid(oidECDSAWithSHA256)])
        let tbs = DER.sequence([
            DER.context(0, constructed: true, DER.integer(2)), // v3
            DER.integer(unsigned: serial),
            algorithm,
            issuer,
            DER.sequence([DER.time(notBefore), DER.time(notAfter)]),
            subject,
            Array(publicKey),
            DER.context(3, constructed: true, DER.sequence(extensions)),
        ])
        let sig = try signer.signature(for: Data(tbs))
        return Data(DER.sequence([tbs, algorithm, DER.bitString(Array(sig))]))
    }

    public enum CertificateError: Error { case badDeviceID, outsideCALifetime, malformed }

    /// A member certificate is renewed when less than this much remains.
    public static let renewBefore: TimeInterval = 240 * 24 * 3600

    /// Whether a member certificate is due for renewal, as Go's renewable
    /// decides: less than 240 days left, and its CA lasts longer than it. A
    /// clock before the CA's start is wrong, and nothing is due then.
    public static func isDue(_ cert: Data, groupCA: Data, now: Date) -> Bool {
        guard let c = try? CertificateInfo(der: cert), let ca = try? CertificateInfo(der: groupCA), now >= ca.notBefore else { return false }
        return now > c.notAfter.addingTimeInterval(-renewBefore) && ca.notAfter > c.notAfter
    }

    /// A renewed member certificate for the device and key of cert, which
    /// the group CA issued (or issuer, an admin CA under it), or nil when it
    /// is not due (or not from the CA). The renewed one is from the group CA,
    /// or from adminCA when caSigner holds that admin CA's key, which the
    /// cert message then carries (section 10), so an admin phone renews any
    /// member's certificate, also one another admin issued.
    public static func renewal(of cert: Data, groupCA: Data, issuer: Data? = nil, caSigner: CertificateSigner, adminCA: Data? = nil,
                               now: Date) throws -> Data? {
        guard isDue(cert, groupCA: groupCA, now: now),
              let device = try? verifyMember(cert, groupCA: groupCA, issuer: issuer, now: now) else { return nil }
        return try member(device: device, publicKey: CertificateInfo(der: cert).publicKey, ca: adminCA ?? groupCA, caSigner: caSigner, now: now)
    }

    /// renewal(of:...) for a peer's chain from a TLS handshake, leaf first:
    /// the certificate after the leaf, when there is one, is its issuer.
    public static func renewal(chain: [Data], groupCA: Data, caSigner: CertificateSigner, adminCA: Data? = nil, now: Date) throws -> Data? {
        try renewal(chain: chain, roots: [groupCA], caSigner: caSigner, adminCA: adminCA, now: now)
    }

    /// renewal(chain:...) in a group with several roots, the current one
    /// last (section 10, "Roots"): the certificate may be from any of them,
    /// or from an admin CA under any of them, and the renewed one is from
    /// the current root, or from adminCA.
    public static func renewal(chain: [Data], roots: [Data], caSigner: CertificateSigner, adminCA: Data? = nil, now: Date) throws -> Data? {
        guard let leaf = chain.first, let current = roots.last else { return nil }
        for root in roots {
            let issuer = chain.dropFirst().first { (try? checkAdminCA($0, root: root)) != nil }
            guard let device = try? verifyMember(leaf, groupCA: root, issuer: issuer, now: now) else { continue }
            let ca = adminCA ?? current
            guard isDue(leaf, groupCA: ca, now: now) else { return nil }
            return try member(device: device, publicKey: CertificateInfo(der: leaf).publicKey, ca: ca, caSigner: caSigner, now: now)
        }
        return nil
    }

    public enum VerifyError: Error, Equatable {
        case notFromGroupCA, expired, notYetValid, badName, isCA, notAdminCA, notRoot
    }

    /// Checks a member certificate as Go's checkPeer does (docs/protocol.md,
    /// section 2): signed by the group CA, or by issuer when that is an
    /// admin CA under it, valid at max(now, the CA's start), not a CA, its
    /// CN a device ID and its one DNS name cb-<ID>.local. It returns the
    /// device ID.
    public static func verifyMember(_ der: Data, groupCA: Data, issuer: Data? = nil, now: Date) throws -> String {
        let ca = try CertificateInfo(der: groupCA)
        var signer = ca
        if let issuer {
            try checkAdminCA(issuer, root: groupCA)
            signer = try CertificateInfo(der: issuer)
        }
        let cert = try ParsedCertificate(der: der)
        guard signed(cert, by: signer) else { throw VerifyError.notFromGroupCA }
        let t = max(now, ca.notBefore)
        guard t >= cert.info.notBefore else { throw VerifyError.notYetValid }
        guard t <= cert.info.notAfter else { throw VerifyError.expired }
        guard !cert.isCA else { throw VerifyError.isCA }
        guard let id = cert.info.commonName, isDeviceID(id), cert.dnsNames == ["cb-\(id).local"] else { throw VerifyError.badName }
        return id
    }

    /// Checks a peer's certificate chain from a TLS handshake, leaf first:
    /// the leaf from the group CA, or from the admin CA that follows it.
    /// Other certificates after the leaf are ignored, as Go's verifier
    /// ignores what it does not need.
    public static func verifyMember(chain: [Data], groupCA: Data, now: Date) throws -> String {
        guard let leaf = chain.first else { throw VerifyError.notFromGroupCA }
        if let id = try? verifyMember(leaf, groupCA: groupCA, now: now) { return id }
        for issuer in chain.dropFirst() {
            if let id = try? verifyMember(leaf, groupCA: groupCA, issuer: issuer, now: now) { return id }
        }
        return try verifyMember(leaf, groupCA: groupCA, now: now)
    }

    /// verifyMember(chain:groupCA:now:) in a group with several roots
    /// (section 10, "Roots"): the leaf from any of them, or from an admin
    /// CA under any of them.
    public static func verifyMember(chain: [Data], roots: [Data], now: Date) throws -> String {
        var last: Error = VerifyError.notFromGroupCA
        for root in roots {
            do { return try verifyMember(chain: chain, groupCA: root, now: now) } catch { last = error }
        }
        throw last
    }
}

/// The parts of a certificate that verifying it needs: the signed bytes,
/// the signature, the issuer and the extensions.
struct ParsedCertificate {
    let info: CertificateInfo
    let tbs: [UInt8]
    let signatureAlgorithm: [UInt8] // the OID, encoded
    let signature: [UInt8] // DER
    let rawIssuer: [UInt8]
    let dnsNames: [String]
    let isCA: Bool
    /// The path length limit of a CA; nil without one.
    let pathLength: Int?
    /// Whether key usage allows signing certificates.
    let canSignCertificates: Bool

    init(der: Data) throws {
        info = try CertificateInfo(der: der)
        var r = DERReader(Array(der))
        var cert = try r.read(0x30)
        tbs = try cert.readAny(raw: true).bytes
        var alg = try cert.read(0x30)
        signatureAlgorithm = try alg.readAny(raw: true).bytes
        signature = Array(try cert.read(0x03).bytes.dropFirst()) // the unused-bits byte
        var t = DERReader(tbs)
        var body = try t.read(0x30)
        if body.peek == 0xa0 { _ = try body.readAny() } // version
        _ = try body.read(0x02) // serial
        _ = try body.read(0x30) // algorithm
        rawIssuer = try body.readAny(raw: true).bytes
        _ = try body.read(0x30) // validity
        _ = try body.readAny() // subject
        _ = try body.readAny() // public key
        var names: [String] = []
        var ca = false
        var pathLen: Int?
        var certSign = false
        while let tag = body.peek {
            var e = try body.readAny()
            guard tag == 0xa3 else { continue } // extensions
            var exts = try e.read(0x30)
            while exts.peek != nil {
                var ext = try exts.read(0x30)
                let oid = try ext.readAny(raw: true).bytes
                if ext.peek == 0x01 { _ = try ext.readAny() } // critical
                var value = DERReader(try ext.read(0x04).bytes)
                if oid == DER.oid(GroupCertificates.oidSubjectAltName) {
                    var seq = try value.read(0x30)
                    while let t = seq.peek {
                        let n = try seq.readAny()
                        if t == 0x82 { names.append(String(decoding: n.bytes, as: UTF8.self)) } // dNSName
                    }
                } else if oid == DER.oid(GroupCertificates.oidBasicConstraints) {
                    var seq = try value.read(0x30)
                    if seq.peek == 0x01 { ca = try seq.readAny().bytes != [0] }
                    if seq.peek == 0x02 { pathLen = try seq.readAny().bytes.reduce(0) { $0 << 8 | Int($1) } }
                } else if oid == DER.oid(GroupCertificates.oidKeyUsage) {
                    let bits = try value.read(0x03).bytes
                    certSign = bits.count > 1 && bits[1] & 0x04 != 0 // keyCertSign, bit 5
                }
            }
        }
        (dnsNames, isCA, pathLength, canSignCertificates) = (names, ca, pathLen, certSign)
    }
}

/// What CBBKit reads from a certificate: its subject, validity and
/// public key. It is a minimal DER reader, not a verifier.
public struct CertificateInfo {
    public let rawIssuer: [UInt8]
    public let rawSubject: [UInt8]
    public let notBefore: Date
    public let notAfter: Date
    public let publicKey: Data // SubjectPublicKeyInfo

    public init(der: Data) throws {
        var r = DERReader(Array(der))
        var cert = try r.read(0x30)
        var tbs = try cert.read(0x30)
        if tbs.peek == 0xa0 { _ = try tbs.readAny() } // version
        _ = try tbs.read(0x02) // serial
        _ = try tbs.read(0x30) // algorithm
        rawIssuer = try tbs.readAny(raw: true).bytes
        var validity = try tbs.read(0x30)
        notBefore = try validity.readTime()
        notAfter = try validity.readTime()
        rawSubject = try tbs.readAny(raw: true).bytes
        publicKey = Data(try tbs.readAny(raw: true).bytes)
    }

    /// Whether the certificate names itself as its issuer, as a root does.
    public var selfIssued: Bool { rawIssuer == rawSubject }

    /// The subject's common name, or nil without one.
    public var commonName: String? {
        var r = DERReader(rawSubject)
        guard var name = try? r.read(0x30) else { return nil }
        while name.peek != nil {
            guard var rdn = try? name.read(0x31) else { return nil }
            while rdn.peek != nil {
                guard var atv = try? rdn.read(0x30), let oid = try? atv.readAny(raw: true).bytes,
                      let value = try? atv.readAny() else { return nil }
                if oid == DER.oid(GroupCertificates.oidCommonName) {
                    return String(decoding: value.bytes, as: UTF8.self)
                }
            }
        }
        return nil
    }

    /// The bits of the public key in a SubjectPublicKeyInfo.
    static func subjectPublicKeyBits(_ spki: Data) throws -> [UInt8] {
        var r = DERReader(Array(spki))
        var seq = try r.read(0x30)
        _ = try seq.read(0x30)
        let bits = try seq.read(0x03).bytes
        return Array(bits.dropFirst()) // the unused-bits byte
    }
}

struct DERReader {
    var bytes: [UInt8]
    var pos = 0
    init(_ b: [UInt8]) { bytes = b }

    var peek: UInt8? { pos < bytes.count ? bytes[pos] : nil }

    /// Reads one element; returns its content, or the whole element with raw.
    mutating func readAny(raw: Bool = false) throws -> DERReader {
        guard pos + 2 <= bytes.count else { throw GroupCertificates.CertificateError.malformed }
        let start = pos
        pos += 1
        var n = Int(bytes[pos])
        pos += 1
        if n & 0x80 != 0 {
            let k = n & 0x7f
            guard k > 0, k <= 4, pos + k <= bytes.count else { throw GroupCertificates.CertificateError.malformed }
            n = bytes[pos..<pos + k].reduce(0) { $0 << 8 | Int($1) }
            pos += k
        }
        guard pos + n <= bytes.count else { throw GroupCertificates.CertificateError.malformed }
        defer { pos += n }
        return DERReader(Array(bytes[(raw ? start : pos)..<pos + n]))
    }

    mutating func read(_ tag: UInt8) throws -> DERReader {
        guard peek == tag else { throw GroupCertificates.CertificateError.malformed }
        return try readAny()
    }

    mutating func readTime() throws -> Date {
        let tag = peek
        let s = String(decoding: try readAny().bytes, as: UTF8.self)
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = TimeZone(identifier: "UTC")
        switch tag {
        case 0x17:
            f.dateFormat = "yyMMddHHmmss'Z'"
            // yy from 50 on is 19yy, as RFC 5280 says.
            f.twoDigitStartDate = Date(timeIntervalSince1970: -631_152_000) // 1950-01-01
        case 0x18: f.dateFormat = "yyyyMMddHHmmss'Z'"
        default: throw GroupCertificates.CertificateError.malformed
        }
        guard let d = f.date(from: s) else { throw GroupCertificates.CertificateError.malformed }
        return d
    }
}

extension Calendar {
    static var utc: Calendar {
        var c = Calendar(identifier: .gregorian)
        c.timeZone = TimeZone(identifier: "UTC")!
        return c
    }
}

extension P256.Signing.PublicKey {
    /// A P-256 key from a SubjectPublicKeyInfo in its one DER encoding, or nil.
    /// swift-crypto on Linux reads the key's point without checking the
    /// algorithm's OIDs, which Go and the Kotlin kit refuse to accept.
    init?(spki: Data) {
        guard let key = try? P256.Signing.PublicKey(derRepresentation: spki), key.derRepresentation == spki else { return nil }
        self = key
    }
}
