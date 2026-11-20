// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import Crypto
import Foundation

/// Server credentials (docs/protocol.md, section 18), as internal/group
/// makes and checks them. The group lives in periods of about 30 days. For
/// each, its root signs, inside the group, a period credential: a fresh tag
/// for the servers and a fresh period key. Each device signs with its
/// member key the server key it uses with the servers in that period. The
/// servers see only what the period key signs: the hubs' and the members'
/// credentials, padded lists of server key hashes under the period's tag.
public enum ServerCredentials {
    public static let period = "period"
    public static let server = "server"
    public static let hubs = "hubs"
    public static let members = "members"

    /// How long a period lasts, and how old it may get before the root
    /// starts the next.
    public static let periodLifetimeMS: Int64 = 35 * 24 * 3600 * 1000
    public static let periodRenewMS: Int64 = 30 * 24 * 3600 * 1000

    public static let maxHubs = 16
    public static let maxMembers = 256
    public static let maxAdmins = 64
    static let maxBody = 16 << 10
    /// The most credentials a member keeps and sends: the period, the hubs',
    /// the members' and one server credential per member.
    public static let maxCredentials = maxMembers + 3

    public struct Refused: Error, CustomStringConvertible {
        public let description: String
        init(_ s: String) { description = s }
    }

    /// A signed credential body: the body's exact bytes, an ECDSA P-256
    /// signature over them, and the signer's SubjectPublicKeyInfo.
    public struct Credential: Codable, Equatable, Sendable {
        public var body: Data
        public var sig: Data
        public var key: Data

        public init(body: Data, sig: Data, key: Data) { (self.body, self.sig, self.key) = (body, sig, key) }

        /// The hash of the key that signed it.
        public var signer: Data { Data(SHA256.hash(data: key)) }

        /// Checks the signature and returns the body; it checks neither who
        /// signed it nor the group.
        public func open() throws -> Body {
            let b = try Body.parse(body)
            guard let pub = P256.Signing.PublicKey(spki: key) else { throw Refused("the credential's key is not a P-256 key") }
            guard let s = try? P256.Signing.ECDSASignature(derRepresentation: sig), pub.isValidSignature(s, for: body) else {
                throw Refused("the credential's signature does not verify")
            }
            return b
        }
    }

    /// What a credential says.
    public struct Body: Codable, Equatable, Sendable {
        /// Reads and checks a credential's body: its size, the strict form
        /// of signed bodies, then its fields.
        static func parse(_ data: Data) throws -> Body {
            // The core decides whether the body is taken (parse_body).
            if let why = Core.bodyRefusal("credential", data) { throw Refused("the credential is not valid: \(why)") }
            guard data.count <= maxBody else { throw Refused("the credential is too large") }
            do {
                try Strict.check(data, required: ["v", "type", "group", "version", "expires_ms"])
            } catch let e as Strict.Invalid {
                throw Refused("the credential is not valid: \(e.reason)")
            }
            guard let b = try? JSONDecoder().decode(Body.self, from: data), let raw = try? JSONDecoder().decode(Raw.self, from: data),
                  raw.canonical else { throw Refused("the credential does not decode") }
            try b.check()
            return b
        }

        /// The bytes of a body as their strings, to check their form.
        private struct Raw: Decodable {
            var key: String?
            var hubs, admins, members: [String]?

            var canonical: Bool {
                ([key].compactMap { $0 } + (hubs ?? []) + (admins ?? []) + (members ?? [])).allSatisfy { Strict.base64($0) != nil }
            }
        }

        public var v: Int = 1
        public var type: String
        /// The group's own tag in a period or a server credential, the
        /// period's tag in a hubs' or a members' credential.
        public var group: String
        public var version: Int64
        public var expires_ms: Int64
        /// A period's tag, or the period a server credential is for.
        public var tag: String = ""
        /// The period key or the server key (SubjectPublicKeyInfo).
        public var key = Data()
        public var hubs: [Data] = []
        public var admins: [Data] = []
        public var members: [Data] = []

        public init(type: String, group: String, version: Int64, expires_ms: Int64, tag: String = "", key: Data = Data(),
                    hubs: [Data] = [], admins: [Data] = [], members: [Data] = []) {
            (self.type, self.group, self.version, self.expires_ms, self.tag, self.key) = (type, group, version, expires_ms, tag, key)
            (self.hubs, self.admins, self.members) = (hubs, admins, members)
        }

        enum CodingKeys: String, CodingKey { case v, type, group, version, expires_ms, tag, key, hubs, admins, members }

        public init(from d: Decoder) throws {
            let c = try d.container(keyedBy: CodingKeys.self)
            v = try c.decodeIfPresent(Int.self, forKey: .v) ?? 0
            type = try c.decodeIfPresent(String.self, forKey: .type) ?? ""
            group = try c.decodeIfPresent(String.self, forKey: .group) ?? ""
            version = try c.decodeIfPresent(Int64.self, forKey: .version) ?? 0
            expires_ms = try c.decodeIfPresent(Int64.self, forKey: .expires_ms) ?? 0
            tag = try c.decodeIfPresent(String.self, forKey: .tag) ?? ""
            key = try c.decodeIfPresent(Data.self, forKey: .key) ?? Data()
            hubs = try c.decodeIfPresent([Data].self, forKey: .hubs) ?? []
            admins = try c.decodeIfPresent([Data].self, forKey: .admins) ?? []
            members = try c.decodeIfPresent([Data].self, forKey: .members) ?? []
        }

        public func encode(to e: Encoder) throws {
            var c = e.container(keyedBy: CodingKeys.self)
            try c.encode(v, forKey: .v)
            try c.encode(type, forKey: .type)
            try c.encode(group, forKey: .group)
            try c.encode(version, forKey: .version)
            try c.encode(expires_ms, forKey: .expires_ms)
            if !tag.isEmpty { try c.encode(tag, forKey: .tag) }
            if !key.isEmpty { try c.encode(key, forKey: .key) }
            if !hubs.isEmpty { try c.encode(hubs, forKey: .hubs) }
            if !admins.isEmpty { try c.encode(admins, forKey: .admins) }
            if !members.isEmpty { try c.encode(members, forKey: .members) }
        }

        func check() throws {
            guard v == 1 else { throw Refused("unknown credential version \(v)") }
            guard version > 0, expires_ms > 0 else { throw Refused("a credential without a version or an expiry") }
            guard validTag(group) else { throw Refused("a credential's group is not a tag") }
            guard (hubs + admins + members).allSatisfy({ $0.count == 32 }) else { throw Refused("a credential lists a key hash that is not 32 bytes") }
            switch type {
            case period, server:
                guard validTag(tag) else { throw Refused("a credential's period tag is not a tag") }
                guard P256.Signing.PublicKey(spki: key) != nil else { throw Refused("the credential's key is not a P-256 key") }
                guard hubs.count + admins.count + members.count == 0 else { throw Refused("a period or server credential lists keys") }
            case ServerCredentials.hubs:
                guard hubs.count <= maxHubs, admins.count <= maxAdmins else { throw Refused("a hubs' credential lists too many keys") }
                guard tag.isEmpty, key.isEmpty, members.isEmpty else { throw Refused("a hubs' credential carries more than its lists") }
            case ServerCredentials.members:
                guard members.count <= maxMembers else { throw Refused("a members' credential lists too many keys") }
                guard tag.isEmpty, key.isEmpty, hubs.count + admins.count == 0 else { throw Refused("a members' credential carries more than its list") }
            default:
                throw Refused("unknown credential type \"\(type)\"")
            }
        }
    }

    /// Whether s is a tag: 16 lower-case hex characters.
    public static func validTag(_ s: String) -> Bool {
        s.utf8.count == 16 && s.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }

    /// The name of a server key at the relay: its fingerprint, the hash in standard base64.
    public static func pseudonym(_ keyHash: Data) -> String { keyHash.base64EncodedString() }

    /// A fresh tag for the servers: 8 random bytes in hex.
    public static func newPeriodTag() -> String { random(8).map { String(format: "%02x", $0) }.joined() }

    static func random(_ n: Int) -> Data {
        var g = SystemRandomNumberGenerator()
        return Data((0..<n).map { _ in UInt8.random(in: 0...255, using: &g) })
    }

    /// The next version after prev: one more, or the time in seconds if
    /// that is later, so a device that lost its state still goes forward.
    public static func nextVersion(_ prev: Int64, nowMS: Int64) -> Int64 { max(prev + 1, nowMS / 1000) }

    /// What the group's credentials must list, by member key (Go's
    /// Records.CredentialLists).
    public struct Lists: Equatable, Sendable {
        public var hubs: [Data] = []
        public var admins: [Data] = []
        public var members: [Data] = []
    }

    /// The hubs in their order, at most maxHubs; the admins that are not
    /// frozen, other than the root's own device, which holds the period
    /// key; and every device that is not frozen, at most maxMembers.
    public static func lists(_ s: RecordSet) -> Lists {
        var l = Lists()
        let root = s.rootMember()
        let devs = s.devices
        for id in s.hubOrder {
            if l.hubs.count == maxHubs { break }
            if let root, root.device == id {
                l.hubs.append(root.key)
                continue
            }
            l.hubs += devs.filter { $0.id == id }.map(\.key)
        }
        for d in devs where !d.frozen {
            if d.admin, d.id != root?.device, l.admins.count < maxAdmins { l.admins.append(d.key) }
            if l.members.count < maxMembers { l.members.append(d.key) }
        }
        return l
    }

    /// The size a list of n entries is padded to: the next of 4, 8, 16 and on.
    public static func padTo(_ n: Int) -> Int {
        var size = 4
        while size < n { size *= 2 }
        return size
    }

    /// ks with random 32-byte entries up to padTo(ks.count): a key hash
    /// looks random, so the padding cannot be told from a real entry.
    public static func pad(_ ks: [Data]) -> [Data] {
        ks + (0..<(padTo(ks.count) - ks.count)).map { _ in random(32) }
    }

    /// Signs b with key.
    public static func sign(_ b: Body, key: CertificateSigner) throws -> Credential {
        try b.check()
        let data = try JSONEncoder().encode(b)
        _ = try Body.parse(data)
        return Credential(body: data, sig: try key.signature(for: data), key: key.publicKeyDER)
    }

    /// The period credential: the root signs the period's tag and key for
    /// the group tagged groupTag.
    public static func signPeriod(groupTag: String, tag: String, periodKey: Data, version: Int64, nowMS: Int64,
                                  root: CertificateSigner) throws -> Credential {
        try sign(Body(type: period, group: groupTag, version: version, expires_ms: nowMS + periodLifetimeMS, tag: tag, key: periodKey), key: root)
    }

    /// A device's server key for the period p, signed by its member key.
    public static func signServer(_ p: Body, serverKey: Data, version: Int64, member: CertificateSigner) throws -> Credential {
        try sign(Body(type: server, group: p.group, version: version, expires_ms: p.expires_ms, tag: p.tag, key: serverKey), key: member)
    }

    /// The hubs' credential of the period p, signed by the period key.
    public static func signHubs(_ p: Body, hubs: [Data], admins: [Data], version: Int64, periodKey: CertificateSigner) throws -> Credential {
        guard hubs.count <= maxHubs, admins.count <= maxAdmins else { throw Refused("too many hubs or admins") }
        return try sign(Body(type: ServerCredentials.hubs, group: p.tag, version: version, expires_ms: p.expires_ms,
                             hubs: pad(hubs), admins: pad(admins)), key: periodKey)
    }

    /// The members' credential of the period p, signed by the period key or
    /// a listed admin's server key.
    public static func signMembers(_ p: Body, members: [Data], version: Int64, key: CertificateSigner) throws -> Credential {
        guard members.count <= maxMembers else { throw Refused("too many members") }
        return try sign(Body(type: ServerCredentials.members, group: p.tag, version: version, expires_ms: p.expires_ms, members: pad(members)), key: key)
    }

    /// What a server checked of the credentials a device presented (Go's
    /// Presented).
    public struct Presented: Sendable {
        public var tag: String
        public var signer: Data
        public var hubs: Body
        public var members: Body?
        public var period: Body?
        public var periodRoot: Data?
    }

    /// Checks the credentials a device presents a server, as Go's
    /// CheckPresented: one hubs' credential, and with it at most one
    /// members' credential of the same period, which the period key or an
    /// admin that the hubs' credential lists signed, and at most one period
    /// credential whose tag and key are those of the hubs' credential. None
    /// may have expired at nowMS.
    public static func checkPresented(_ cs: [Credential], nowMS: Int64) throws -> Presented {
        let wrong = Refused("the credentials are not a hubs' credential with at most a members' and a period credential")
        guard !cs.isEmpty, cs.count <= 3 else { throw wrong }
        var got: [String: (Body, Credential)] = [:]
        for c in cs {
            let b = try c.open()
            guard nowMS < b.expires_ms else { throw Refused("the \(b.type) credential expired") }
            guard [hubs, members, period].contains(b.type), got[b.type] == nil else { throw wrong }
            got[b.type] = (b, c)
        }
        guard let (hb, hc) = got[hubs] else { throw Refused("no hubs' credential") }
        var p = Presented(tag: hb.group, signer: hc.signer, hubs: hb)
        if let (b, c) = got[members] {
            guard b.group == hb.group else { throw Refused("a members' credential of another period") }
            guard c.key == hc.key || hb.admins.contains(c.signer) else {
                throw Refused("a members' credential that neither the period key nor a listed admin signed")
            }
            p.members = b
        }
        if let (b, c) = got[period] {
            guard b.tag == hb.group, b.key == hc.key else { throw Refused("a period credential of another period") }
            p.period = b
            p.periodRoot = c.key
        }
        return p
    }
}

/// A member's server credentials (Go's group.Credentials): the newest
/// period that the group's current root signed, and for it each member's
/// newest server credential and the newest hubs' and members' credentials.
public struct CredentialStore: Sendable {
    public typealias Credential = ServerCredentials.Credential
    public typealias Body = ServerCredentials.Body

    let groupCA: Data
    private var periodCred: Credential?
    private var servers: [Data: Credential] = [:] // by the member key that signed it
    private var serverOrder: [Data] = []
    private var hubsCred: Credential?
    private var membersCred: Credential?

    public init(groupCA: Data) { self.groupCA = groupCA }

    private static func rank(_ c: Credential) -> Int {
        struct T: Decodable { var type: String? }
        let t = (try? JSONDecoder().decode(T.self, from: c.body))?.type
        return [ServerCredentials.period, ServerCredentials.server, ServerCredentials.hubs, ServerCredentials.members].firstIndex(of: t ?? "") ?? -1
    }

    private func periodOf(_ root: Data) -> Body? {
        guard let p = periodCred, p.key == root else { return nil }
        return try? p.open()
    }

    private static func newer(_ old: Credential?, _ b: Body) -> Bool {
        guard let old, let ob = try? old.open() else { return true }
        return b.version > ob.version
    }

    /// Takes the credentials that are valid for the group and newer than
    /// what it keeps, and returns those it took, with why it dropped the
    /// others. root is the current root's SubjectPublicKeyInfo; isMember
    /// tells whether a key hash is the member key of a device in the group.
    /// A newer period with another tag drops the credentials of the one
    /// before.
    @discardableResult
    public mutating func add(root: Data, isMember: (Data) -> Bool, _ cs: [Credential]) -> (fresh: [Credential], errors: [String]) {
        let tag = GroupCertificates.tag(groupCA: groupCA)
        var fresh: [Credential] = [], errs: [String] = []
        for c in cs.enumerated().sorted(by: { (Self.rank($0.element), $0.offset) < (Self.rank($1.element), $1.offset) }).map(\.element) {
            let b: Body
            do { b = try c.open() } catch { errs.append("\(error)"); continue }
            let p = periodOf(root)
            switch b.type {
            case ServerCredentials.period:
                guard b.group == tag else { errs.append("a period of another group"); continue }
                guard c.key == root else { errs.append("a period that the group's root did not sign"); continue }
                guard Self.newer(p != nil ? periodCred : nil, b) else { continue }
                if p == nil || p?.tag != b.tag {
                    servers = [:]
                    serverOrder = []
                    hubsCred = nil
                    membersCred = nil
                }
                periodCred = c
            case ServerCredentials.server:
                guard let p, b.group == tag, b.tag == p.tag else { continue }
                guard isMember(c.signer) else { errs.append("a server credential that no member signed"); continue }
                let old = servers[c.signer]
                if let old, !Self.newer(old, b) { continue }
                if old == nil, servers.count >= ServerCredentials.maxMembers { errs.append("too many server credentials"); continue }
                if old == nil { serverOrder.append(c.signer) }
                servers[c.signer] = c
            case ServerCredentials.hubs:
                guard let p, b.group == p.tag else { continue }
                guard c.key == p.key else { errs.append("a hubs' credential that the period key did not sign"); continue }
                guard Self.newer(hubsCred, b) else { continue }
                hubsCred = c
            case ServerCredentials.members:
                guard let p, b.group == p.tag else { continue }
                let admin = (try? hubsCred?.open())??.admins.contains(c.signer) ?? false
                guard c.key == p.key || admin else {
                    errs.append("a members' credential that neither the period key nor a listed admin signed")
                    continue
                }
                guard Self.newer(membersCred, b) else { continue }
                membersCred = c
            default:
                continue
            }
            fresh.append(c)
        }
        return (fresh, errs)
    }

    /// Every credential it keeps, the period first.
    public var all: [Credential] {
        [periodCred].compactMap { $0 } + serverOrder.compactMap { servers[$0] } + [hubsCred, membersCred].compactMap { $0 }
    }

    /// The period kept, if the current root signed it.
    public func period(root: Data) -> (Credential, Body)? {
        guard let b = periodOf(root), let c = periodCred else { return nil }
        return (c, b)
    }

    /// The hash of the server key the member key hash member signed for the
    /// period.
    public func server(member: Data) -> Data? {
        guard let c = servers[member], let b = try? c.open() else { return nil }
        return Data(SHA256.hash(data: b.key))
    }

    /// The member key that signed the server key whose hash is k.
    public func memberOfServer(_ k: Data) -> Data? {
        serverOrder.first { m in servers[m].flatMap { try? $0.open() }.map { Data(SHA256.hash(data: $0.key)) == k } ?? false }
    }

    /// The server keys of the member keys ms, in their order, leaving out
    /// those without one.
    public func serverKeys(_ ms: [Data]) -> [Data] { ms.compactMap { server(member: $0) } }

    public var hubs: (Credential, Body)? { hubsCred.flatMap { c in (try? c.open()).map { (c, $0) } } }
    public var members: (Credential, Body)? { membersCred.flatMap { c in (try? c.open()).map { (c, $0) } } }

    /// Whether the root should start a new period: none kept, one older than
    /// periodRenewMS, or one with a server credential that no member of the
    /// group signed any more (a removal).
    public func periodStale(root: Data, isMember: (Data) -> Bool, nowMS: Int64) -> Bool {
        guard let p = periodOf(root) else { return true }
        if nowMS >= p.expires_ms - ServerCredentials.periodLifetimeMS + ServerCredentials.periodRenewMS { return true }
        return servers.keys.contains { !isMember($0) }
    }

    /// Whether a list a credential holds is not the list want: want must be
    /// its first entries, in its order when ordered, and the rest padding.
    public func listStale(_ got: [Data], want: [Data], ordered: Bool) -> Bool {
        if got.count != ServerCredentials.padTo(want.count) { return true }
        if ordered { return zip(got, want).contains { $0 != $1 } }
        let head = Set(got.prefix(want.count))
        return want.contains { !head.contains($0) }
    }

    /// What a device registers with at a relay (docs/protocol.md, section
    /// 18): the hubs' and the members' credentials, then the period; the
    /// group's roots, the group CA first; and the pseudonyms of the group's
    /// devices with the IDs they stand for.
    public struct Registration: Sendable, Equatable {
        public var credentials: [Credential]
        public var roots: [Data]
        public var names: [String: String]
    }

    /// What a hub registers with at its forwarder (docs/protocol.md,
    /// section 18): the hubs' credential, once it lists the hub's server
    /// key, which hashes to mine, and while the period of the current root,
    /// root, lasts; nil until then.
    public func hubRegistration(root: Data, mine: Data, nowMS: Int64) -> [Credential]? {
        guard let (_, p) = period(root: root), nowMS < p.expires_ms, let (hc, hb) = hubs, nowMS < hb.expires_ms, hb.hubs.contains(mine)
        else { return nil }
        return [hc]
    }

    /// The registration with these credentials for the device whose server
    /// key hashes to mine, or nil until the members' credential lists it;
    /// root is the current root's key, records the group's records.
    public func registration(records: RecordSet, root: Data, mine: Data) -> Registration? {
        guard let (pc, _) = period(root: root), let (hc, _) = hubs, let (mc, mb) = members, mb.members.contains(mine) else { return nil }
        var names: [String: String] = [:]
        for d in records.devices {
            for k in d.keys {
                if let s = server(member: k) { names[ServerCredentials.pseudonym(s)] = d.id }
            }
        }
        return Registration(credentials: [hc, mc, pc], roots: [groupCA] + records.roots, names: names)
    }
}

/// A device's keys for the servers, one set per period (Go's
/// group.ServerKeys): its server key, and on the root that started the
/// period, the period key. The app keeps them in the Secure Enclave or the
/// Keystore, without user presence, since they sign in the background.
public protocol PeriodKeys: AnyObject {
    /// The key of kind (serverKey or periodKey) for the period tag, made
    /// when there is none.
    func get(_ kind: String, tag: String) throws -> CertificateSigner
    func has(_ kind: String, tag: String) -> Bool
    /// Drops the keys of every period but tag.
    func keep(_ tag: String)
}

public enum PeriodKeyKind {
    public static let serverKey = "server"
    public static let periodKey = "period"
}

/// Brings a device's server credentials up to date as far as it can, as
/// Go's refreshCredential (docs/protocol.md, section 18).
public enum CredentialRefresh {
    /// Returns what it signed and the store took, for the peers. On the
    /// current root, a new period when the one kept is due or a member that
    /// sent its server key left the group; on every member, its server key
    /// for the period; on the root, the hubs' and the members' credentials
    /// when they list other keys than the records and the server
    /// credentials say; on an admin that the hubs' credential lists, the
    /// members' credential. root is the current root's certificate;
    /// rootSigner, given only on the phone that holds that root, is asked
    /// for its key when a period must be signed, about once a month, and
    /// returns nil while the key cannot sign without asking the user: the
    /// period then waits for the next refresh.
    public static func refresh(_ store: inout CredentialStore, records: RecordSet, groupCA: Data, root: Data, member: CertificateSigner,
                               keys: PeriodKeys, nowMS: Int64, rootSigner: (() throws -> CertificateSigner?)? = nil) throws -> [ServerCredentials.Credential] {
        let rootKey = try CertificateInfo(der: root).publicKey
        let devices = records.devices
        let isMember = { (k: Data) in devices.contains { !$0.frozen && $0.keys.contains(k) } }
        var signed: [ServerCredentials.Credential] = []
        func add(_ c: ServerCredentials.Credential) { signed += store.add(root: rootKey, isMember: isMember, [c]).fresh }

        if let rootSigner, store.periodStale(root: rootKey, isMember: isMember, nowMS: nowMS), let rs = try rootSigner() {
            let tag = ServerCredentials.newPeriodTag()
            let pk = try keys.get(PeriodKeyKind.periodKey, tag: tag)
            let prev = store.period(root: rootKey)?.1.version ?? 0
            add(try ServerCredentials.signPeriod(groupTag: GroupCertificates.tag(groupCA: groupCA), tag: tag, periodKey: pk.publicKeyDER,
                                                 version: ServerCredentials.nextVersion(prev, nowMS: nowMS), nowMS: nowMS, root: rs))
        }
        guard let p = store.period(root: rootKey)?.1 else { return signed }
        keys.keep(p.tag)

        let sk = try keys.get(PeriodKeyKind.serverKey, tag: p.tag)
        let mine = Data(SHA256.hash(data: sk.publicKeyDER))
        if store.server(member: Data(SHA256.hash(data: member.publicKeyDER))) != mine {
            add(try ServerCredentials.signServer(p, serverKey: sk.publicKeyDER, version: ServerCredentials.nextVersion(0, nowMS: nowMS), member: member))
        }

        let l = ServerCredentials.lists(records)
        let hubs = store.serverKeys(l.hubs), admins = store.serverKeys(l.admins), members = store.serverKeys(l.members)
        let hb = store.hubs?.1
        let signer: CertificateSigner
        if rootSigner != nil, keys.has(PeriodKeyKind.periodKey, tag: p.tag) {
            let pk = try keys.get(PeriodKeyKind.periodKey, tag: p.tag)
            if hb == nil || store.listStale(hb!.hubs, want: hubs, ordered: true) || store.listStale(hb!.admins, want: admins, ordered: false) {
                add(try ServerCredentials.signHubs(p, hubs: hubs, admins: admins, version: ServerCredentials.nextVersion(hb?.version ?? 0, nowMS: nowMS),
                                                   periodKey: pk))
            }
            signer = pk
        } else if let hb, hb.admins.contains(mine) {
            signer = sk
        } else {
            return signed
        }
        let mb = store.members?.1
        if mb == nil || store.listStale(mb!.members, want: members, ordered: false) {
            add(try ServerCredentials.signMembers(p, members: members, version: ServerCredentials.nextVersion(mb?.version ?? 0, nowMS: nowMS), key: signer))
        }
        return signed
    }
}
