// SPDX-License-Identifier: AGPL-3.0-only

import Crypto
import Foundation

/// The pairing messages of docs/protocol.md, section 6, encoded as the Go
/// side encodes them: JSON objects whose byte fields are standard base64,
/// in frames of a 4-byte big-endian length.
public enum Pairing {
    /// The ALPN protocol of pairing connections.
    public static let alpn = "cbb-pair/2"
    /// The TLS exporter label for the CPace session ID.
    public static let exporterLabel = "EXPERIMENTAL-cbb-pair-v2"
    /// Frames larger than this are refused.
    public static let maxFrame = 64 << 10
    /// What a Welcome leaves free in its frame for the CA keys and the
    /// framing, as Go's welcomeRoom.
    static let welcomeRoom = 4 << 10
    static let channelPrefix = Array("cbb pair v2\u{0}".utf8)

    /// One frame of the exchange; each uses some of the fields.
    public struct Frame: Codable, Equatable {
        public var msg: Data?
        public var ad: Data?
        public var tag: Data?
        public var welcome: Welcome?
        public var error: String?
        public var ok: Bool?

        public init(msg: Data? = nil, ad: Data? = nil, tag: Data? = nil, welcome: Welcome? = nil, error: String? = nil, ok: Bool? = nil) {
            (self.msg, self.ad, self.tag, self.welcome, self.error, self.ok) = (msg, ad, tag, welcome, error, ok)
        }
    }

    /// What a new device receives: its member certificate, the group CA
    /// and, for a Linux device in a group rooted in a Linux member, the CA
    /// keys. A phone root never sends keys; it may send a joining phone its
    /// admin CA.
    public struct Welcome: Codable, Equatable {
        public var cert: Data
        /// The admin CA that issued cert and the admitting phone's own
        /// certificate; nil when the group CA did.
        public var issuer: Data?
        /// The group's first root, which names it.
        public var groupCA: Data
        /// The roots that took a phone group over from groupCA, in order;
        /// nil when it was never handed over (section 10, "Roots").
        public var roots: [Data]?
        /// The group's records (RecordSet.pathRecords): the joiner checks
        /// roots by them and takes its peers at once; nil when they do not
        /// fit and the group was never handed over.
        public var records: [Member.Record]?
        /// When the admitting member first held each claim of records,
        /// which the new device takes (RecordSet.takeClaimTimes).
        public var claimTimes: [RecordSet.ClaimTime]?
        /// For a phone that joins as an admin: the admin CA the root issued
        /// for the admin key the phone sent in its Info.
        public var adminCA: Data?

        enum CodingKeys: String, CodingKey {
            case cert, issuer, groupCA = "group_ca", roots, records, claimTimes = "claim_times", adminCA = "admin_ca"
        }

        public init(cert: Data, groupCA: Data, issuer: Data? = nil, adminCA: Data? = nil) {
            (self.cert, self.groupCA, self.issuer, self.adminCA) = (cert, groupCA, issuer, adminCA)
        }
    }

    /// The joiner's CPace associated data.
    public struct Info: Codable, Equatable {
        public var name: String
        public var os: String // "linux", "windows", "macos", or "ios", "android", "aurora" or "sailfish" for a phone with the app; "none" for firmware
        /// A phone's admin key, a SubjectPublicKeyInfo, for the admin CA the
        /// root may issue it; only from a phone.
        public var adminKey: Data?
        /// The admin key's signature (ECDSA with SHA-256, DER) over
        /// `Info.adminProofMessage` of this connection's session ID, which
        /// proves the phone holds the key; it comes with adminKey.
        public var adminProof: Data?
        /// `Info.lite` for a lite member, which only dials and never holds
        /// CA keys; nil for a full device.
        public var role: String?
        /// The joiner's public key for sealed messages, which the phone
        /// that admits it puts in its device record (docs/protocol.md,
        /// section 15).
        public var seal: Data?

        /// The role of a lite member.
        public static let lite = "lite"

        enum CodingKeys: String, CodingKey { case name, os, adminKey = "admin_key", adminProof = "admin_proof", role, seal }

        public init(name: String, os: String, adminKey: Data? = nil, role: String? = nil, seal: Data? = nil) {
            (self.name, self.os, self.adminKey, self.role, self.seal) = (name, os, adminKey, role, seal)
        }

        /// What the admin key signs to prove the phone holds it: the label,
        /// a zero byte and sessionID, the TLS exporter's output of the
        /// pairing connection (docs/protocol.md, section 6).
        public static func adminProofMessage(sessionID: [UInt8]) -> Data {
            Data("cbb pairing admin key".utf8) + Data([0]) + Data(sessionID)
        }

        /// This description with the admin key's proof for sessionID, signed
        /// by admin, the key adminKey names.
        public func proving(sessionID: [UInt8], with admin: CertificateSigner) throws -> Info {
            var i = self
            if adminKey != nil { i.adminProof = try admin.signature(for: Self.adminProofMessage(sessionID: sessionID)) }
            return i
        }

        /// Whether adminProof is adminKey's signature for sessionID.
        public func provesAdminKey(sessionID: [UInt8]) -> Bool {
            guard let adminKey, let adminProof, let key = P256.Signing.PublicKey(spki: adminKey),
                  let sig = try? P256.Signing.ECDSASignature(derRepresentation: adminProof) else { return false }
            return key.isValidSignature(sig, for: Self.adminProofMessage(sessionID: sessionID))
        }

        /// The size of a key for sealed messages (an X-Wing public key).
        public static let sealKeySize = 1216

        /// Whether it comes from a phone with the app, an iPhone or an
        /// Android phone, which joins as a phone and may become an admin.
        public var isPhone: Bool { ["ios", "android", "aurora", "sailfish"].contains(os) }

        /// Checks it as the member does: a known OS, a printable name of 1
        /// to 64 bytes, a known role, and an admin key only from a phone, a
        /// P-256 one.
        /// Whether a name may hold s, as Go's unicode.IsPrint says: a
        /// letter, mark, number, punctuation, symbol or the ASCII space; no
        /// control, format, private-use, unassigned or other space.
        static func printable(_ s: Unicode.Scalar) -> Bool {
            if s == " " { return true }
            switch s.properties.generalCategory {
            case .uppercaseLetter, .lowercaseLetter, .titlecaseLetter, .modifierLetter, .otherLetter,
                 .nonspacingMark, .spacingMark, .enclosingMark,
                 .decimalNumber, .letterNumber, .otherNumber,
                 .connectorPunctuation, .dashPunctuation, .openPunctuation, .closePunctuation,
                 .initialPunctuation, .finalPunctuation, .otherPunctuation,
                 .mathSymbol, .currencySymbol, .modifierSymbol, .otherSymbol:
                return true
            default:
                return false
            }
        }

        public var isValid: Bool {
            guard ["linux", "windows", "macos", "ios", "android", "aurora", "sailfish"].contains(os) || (os == "none" && role == Self.lite), !name.isEmpty, name.utf8.count <= 64,
                  name.unicodeScalars.allSatisfy(Self.printable),
                  role == nil || role == Self.lite else { return false }
            if let seal, seal.count != Self.sealKeySize { return false }
            guard (adminKey == nil) == (adminProof == nil) else { return false }
            guard let adminKey else { return true }
            return isPhone && P256.Signing.PublicKey(spki: adminKey) != nil
        }
    }

    /// The member's CPace associated data.
    public struct MemberAD: Codable, Equatable {
        public var device: String
        public var group: String // the group tag

        public init(device: String, group: String) { (self.device, self.group) = (device, group) }
    }

    /// The error codes that travel in frames. Anything else means "refused".
    public enum ErrorCode: String {
        case wrongCode = "wrong-code", closed, busy, expired, tooMany = "too-many", taken, declined, refused
        public init(wire: String) { self = ErrorCode(rawValue: wire) ?? .refused }
    }

    /// The CPace channel identifier: the prefix, then SHA-256 of the
    /// member's and the joiner's certificate, in that order.
    public static func channelID(memberCert: Data, joinerCert: Data) -> [UInt8] {
        channelPrefix + Array(SHA256.hash(data: memberCert)) + Array(SHA256.hash(data: joinerCert))
    }

    /// The fingerprint of a certificate's key, the one form of
    /// docs/protocol.md (Conventions, "Fingerprints"): SHA-256 over its
    /// SubjectPublicKeyInfo in standard base64, as a record's key hash;
    /// empty for bytes that are no certificate. A join QR code carries it.
    public static func fingerprint(cert: Data) -> String {
        guard let info = try? CertificateInfo(der: cert) else { return "" }
        return Data(SHA256.hash(data: info.publicKey)).base64EncodedString()
    }

    /// Encodes a frame: the length, then the JSON.
    public static func encode(_ f: Frame) throws -> Data {
        let body = try JSONEncoder().encode(f)
        guard body.count <= maxFrame else { throw FrameError.tooLarge }
        var n = UInt32(body.count).bigEndian
        return Data(bytes: &n, count: 4) + body
    }

    /// Decodes the body of a frame whose length was read already.
    public static func decode(body: Data) throws -> Frame {
        try JSONDecoder().decode(Frame.self, from: body)
    }

    /// The length a frame header announces, or an error when too large.
    public static func length(header: Data) throws -> Int {
        guard header.count == 4 else { throw FrameError.short }
        let n = header.reduce(0) { $0 << 8 | Int($1) }
        guard n <= maxFrame else { throw FrameError.tooLarge }
        return n
    }

    public enum FrameError: Error { case tooLarge, short }
}

/// What the QR code of cbb pair carries (docs/protocol.md, section 7):
/// cbb://join?code=123456&addr=host:port&fp=...
public struct JoinCode: Equatable {
    public var code: String
    public var addrs: [String]
    public var fingerprint: String

    /// At most this many addresses are kept.
    public static let maxAddrs = 4

    public init(code: String, addrs: [String], fingerprint: String) {
        (self.code, self.addrs, self.fingerprint) = (code, addrs, fingerprint)
    }

    /// The code as the screen shows it, in two groups of three digits, for
    /// a computer of the group to type.
    public var grouped: String {
        code.count == 6 ? "\(code.prefix(3)) \(code.suffix(3))" : code
    }

    /// Parses the text of a join QR code; nil when it is not one. Unknown
    /// fields are ignored, and addresses without a port are dropped.
    public init?(qr text: String) {
        guard let u = URLComponents(string: text.trimmingCharacters(in: .whitespacesAndNewlines)),
              u.scheme?.lowercased() == "cbb", u.host?.lowercased() == "join" else { return nil }
        let items = u.queryItems ?? []
        guard let code = items.first(where: { $0.name == "code" })?.value, !code.isEmpty else { return nil }
        self.code = code
        fingerprint = items.first(where: { $0.name == "fp" })?.value ?? ""
        addrs = items.filter { $0.name == "addr" }.compactMap(\.value).filter(JoinCode.hasPort).prefix(JoinCode.maxAddrs).map { $0 }
    }

    /// Whether a host:port, or [IPv6]:port, has a port.
    static func hasPort(_ a: String) -> Bool {
        guard let i = a.lastIndex(of: ":"), let port = UInt16(a[a.index(after: i)...]), port > 0 else { return false }
        let host = a[..<i]
        if host.hasPrefix("[") { return host.hasSuffix("]") }
        return !host.isEmpty && !host.contains(":")
    }

    /// host and port of "host:port" or "[IPv6]:port".
    public static func split(_ addr: String) -> (String, UInt16)? {
        guard let i = addr.lastIndex(of: ":"), let port = UInt16(addr[addr.index(after: i)...]) else { return nil }
        var host = String(addr[..<i])
        if host.hasPrefix("["), host.hasSuffix("]") { host = String(host.dropFirst().dropLast()) }
        return host.isEmpty ? nil : (host, port)
    }

    /// The addresses to try, IPv4 first: a home network reaches those most
    /// surely, and each that fails costs its timeout.
    public static func ordered(_ addrs: [String]) -> [String] {
        addrs.filter { !$0.hasPrefix("[") } + addrs.filter { $0.hasPrefix("[") }
    }

    /// Whether a host:port, or [IPv6]:port, is on a home network: a private
    /// IPv4 or unique local IPv6 address.
    public static func isHome(_ a: String) -> Bool {
        guard hasPort(a), let (host, _) = split(a) else { return false }
        return a.hasPrefix("[") ? LocalAddresses.isHome(ipv6: host) : LocalAddresses.isHome(ipv4: host)
    }

    /// Whether the code is six digits, as the computer expects.
    public var codeIsValid: Bool { code.count == 6 && code.allSatisfy { $0.isASCII && $0.isNumber } }

    /// The text of the QR code, as cbb pair shows it.
    public var qrText: String {
        // Escaped as Go's phone.JoinQR does: everything but letters, digits
        // and -._~, so a fingerprint's + is never read as a space.
        let unreserved = CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
        func esc(_ s: String) -> String { s.addingPercentEncoding(withAllowedCharacters: unreserved) ?? "" }
        let items = [("code", code)] + addrs.prefix(Self.maxAddrs).map { ("addr", $0) } + [("fp", fingerprint)]
        return "cbb://join?" + items.map { "\($0.0)=\(esc($0.1))" }.joined(separator: "&")
    }

    /// A new six-digit code.
    public static func newCode() -> String {
        String(format: "%06d", Int.random(in: 0..<1_000_000))
    }

    /// host:port, or [IPv6]:port, as a QR code carries an address.
    public static func address(host: String, port: UInt16) -> String {
        host.contains(":") ? "[\(host)]:\(port)" : "\(host):\(port)"
    }
}
