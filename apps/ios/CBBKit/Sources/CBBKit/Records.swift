// SPDX-License-Identifier: AGPL-3.0-only

import Crypto
import Foundation

/// The group's signed records of version 2 (docs/records-v2.md): what a
/// phone writes into them. The phone signs a record with the root's own key,
/// without a chain, or with its admin key, and the chain holds the admin
/// CA. What the records say comes from the Rust core (RecordSet), never from
/// rules written again here.
public enum Records {
    public static let version = 2
    /// The signature algorithm every record names: ECDSA P-256 with SHA-256.
    public static let alg = "es256"

    /// A record body before the set fills in its group, seq, prev and seen
    /// (RecordSet.sign); the fields depend on its type
    /// (docs/protocol.md, section 10, "Types").
    public struct Body: Encodable, Equatable, Sendable {
        public var v = Records.version
        public var alg = Records.alg
        public var type: String
        /// The signer's key hash.
        public var signer: Data
        public var time_ms: Int64
        // device
        public var device: String?
        public var name: String?
        public var role: String?
        public var os: String?
        public var key: Data?
        public var admin: Data?
        public var powers: [String]?
        public var commands: [String]?
        /// Where the device's keys live: "file", "hardware", "proven" or "rootless".
        public var store: String?
        /// With a checked attestation: the kind of hardware and the hex
        /// SHA-256 of the attestation's leaf.
        public var kind: String?
        public var proof: String?
        public var holds_root: Bool?
        /// The device's public key for sealed messages (section 15).
        public var seal: Data?
        /// A hub that only passes copies on: none is sealed to it (section 4).
        public var forward_only: Bool?
        // revoke, freeze
        public var keys: [Data]?
        // thaw, resolve
        public var records: [Data]?
        // claim
        public var root: Data?
        // recovery: the recovery key's admin CA, DER
        public var cert: Data?
        // settings
        public var takeover_delay_ms: Int64?
        /// Which keys may be the group's root, an admin or a hub: one of Records.keyLevels.
        public var key_level: String?
        // hubs
        public var hubs: [String]?

        public init(type: String, signer: Data, timeMS: Int64) {
            (self.type, self.signer, self.time_ms) = (type, signer, timeMS)
        }

        /// The fields left out when empty, so the core gets no empty one.
        public func encode(to encoder: Encoder) throws {
            var c = encoder.container(keyedBy: Key.self)
            try c.encode(v, forKey: .v)
            try c.encode(alg, forKey: .alg)
            try c.encode(type, forKey: .type)
            try c.encode(signer, forKey: .signer)
            try c.encode(time_ms, forKey: .time_ms)
            func put(_ s: String?, _ k: Key) throws { if let s, !s.isEmpty { try c.encode(s, forKey: k) } }
            func put(_ d: Data?, _ k: Key) throws { if let d, !d.isEmpty { try c.encode(d, forKey: k) } }
            func put<T: Encodable>(_ a: [T]?, _ k: Key) throws { if let a, !a.isEmpty { try c.encode(a, forKey: k) } }
            try put(device, .device)
            try put(name, .name)
            try put(role, .role)
            try put(os, .os)
            try put(key, .key)
            try put(admin, .admin)
            try put(powers, .powers)
            try put(commands, .commands)
            try put(store, .store)
            try put(kind, .kind)
            try put(proof, .proof)
            if holds_root == true { try c.encode(true, forKey: .holds_root) }
            try put(seal, .seal)
            if forward_only == true { try c.encode(true, forKey: .forward_only) }
            // Each key and record once, as the core wants them.
            func once(_ a: [Data]?) -> [Data]? { a.map { a in a.enumerated().filter { a.firstIndex(of: $0.element) == $0.offset }.map(\.element) } }
            try put(once(keys), .keys)
            try put(once(records), .records)
            try put(root, .root)
            try put(cert, .cert)
            if let t = takeover_delay_ms { try c.encode(t, forKey: .takeover_delay_ms) }
            try put(key_level, .key_level)
            try put(hubs, .hubs)
        }

        private enum Key: String, CodingKey {
            case v, alg, type, signer, time_ms, device, name, role, os, key, admin, powers, commands, store, kind, proof, holds_root, seal, forward_only
            case keys, records, root, cert, takeover_delay_ms, key_level, hubs
        }
    }

    /// The powers an admin may have (docs/protocol.md, section 10, "Who signs what"):
    /// what the apps give an admin phone.
    public static let powers = ["admit", "freeze", "hub", "remove", "remove-admins", "renew", "takeover", "thaw"]
    /// The commands an admin may sign.
    public static let commands = ["action", "actions-off", "away-off", "hub", "mode", "mute", "paste", "paste-off", "unmute"]
    /// What the apps give an admin computer under a phone's root.
    public static let computerPowers = ["admit", "freeze", "hub", "remove", "renew"]
    /// What the apps give a watch.
    public static let watchPowers = ["freeze", "remove"]
    public static let watchCommands = ["action", "actions-off", "away-off", "paste-off"]

    /// Whether s is a device ID: 32 of 0-9 and a-f.
    static func isDeviceID(_ s: String?) -> Bool {
        guard let s, s.utf8.count == 32 else { return false }
        return s.utf8.allSatisfy { (0x30...0x39).contains($0) || (0x61...0x66).contains($0) }
    }

    /// The hash that names a key in records: SHA-256 over a
    /// SubjectPublicKeyInfo.
    public static func keyHash(spki: Data) -> Data { Data(SHA256.hash(data: spki)) }

    /// The hash of the key a certificate certifies.
    public static func keyHash(cert: Data) throws -> Data { keyHash(spki: try CertificateInfo(der: cert).publicKey) }

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

    /// A record's ID: SHA-256 over its body.
    public static func id(_ r: Member.Record) -> Data { Data(SHA256.hash(data: r.body)) }

    static func ms(_ d: Date) -> Int64 { Int64((d.timeIntervalSince1970 * 1000).rounded(.down)) }
}

/// The record set a member keeps: the records file of the Rust core
/// (cbb_core::group::Records, docs/core-api.md, "The record set"), which
/// only grows, and what the core says of it. The set asks the core for
/// every answer, so the phones follow the same rules as every member.
public struct RecordSet: Codable, Equatable, Sendable {
    /// The records file, as the core writes it; nil for an empty set.
    public private(set) var file: Data?
    /// The group's first root, which names it; the first add sets it.
    public internal(set) var groupCA: Data?
    /// The group's tag where it is not the group CA's own, for the vectors.
    var tag: String?
    /// What the core said of the set when it last changed or refresh ran.
    public private(set) var view = View()

    /// The member's clock: the wall clock, which the claims' delays count
    /// in; tests set another.
    public var clock: @Sendable () -> Date = { Date() }
    /// The clock in milliseconds when set, in place of clock: a command's
    /// or a vector's time, exactly.
    var nowMS: Int64?

    private enum CodingKeys: String, CodingKey { case file, groupCA }

    public init() {}

    /// A set read back asks the core again, so what it says follows the
    /// rules of this version.
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        file = try c.decodeIfPresent(Data.self, forKey: .file)
        groupCA = try c.decodeIfPresent(Data.self, forKey: .groupCA)
        refresh()
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encodeIfPresent(file, forKey: .file)
        try c.encodeIfPresent(groupCA, forKey: .groupCA)
    }

    public static func == (a: RecordSet, b: RecordSet) -> Bool { a.file == b.file && a.groupCA == b.groupCA }

    /// A device as the list shows it.
    public struct Device: Decodable, Equatable, Sendable, Identifiable {
        public var id: String
        public var name: String
        /// "full", "phone", "lite" or "watch".
        public var role: String
        /// Its operating system; nil when its record does not tell.
        public var os: String?
        /// The member key of its newest counting record.
        public var key: Data
        /// Where its keys live: Records.file, Records.hardware, Records.proven
        /// or Records.rootless.
        public var store = Records.file
        /// The kind of hardware and the hash of the attestation the root
        /// checked, if any.
        public var kind: String?
        public var proof: String?
        /// Its public key for sealed messages, which commands for it are
        /// sealed to; nil when its record has none.
        public var seal: Data?
        /// A hub that only passes copies on, which no copy is sealed to.
        public var forwardOnly = false
        /// An admin now: it has an admin key and is not frozen.
        public var admin = false
        /// The key hash of its admin CA, whether or not it is frozen.
        public var adminKey: Data?
        public var powers: [String] = []
        public var commands: [String] = []
        /// An admin another admin froze: no admin until the freeze ends, and refused.
        public var frozen = false
        /// The IDs of the freezes of a frozen admin, which a thaw names.
        public var freezes: [Data] = []
        /// Every key that a counting device record names for it and that is
        /// not revoked, key among them: what removing it revokes.
        public var keys: [Data] = []

        /// Whether it is an admin with the power p.
        public func may(_ p: String) -> Bool { admin && powers.contains(p) }

        private enum CodingKeys: String, CodingKey {
            case id = "device", name, role, os, key, store, kind, proof, seal, forwardOnly = "forward_only", admin, adminKey = "admin_key", powers, commands, frozen, freezes, keys
        }

        public init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            id = try c.decode(String.self, forKey: .id)
            name = try c.decode(String.self, forKey: .name)
            role = try c.decode(String.self, forKey: .role)
            os = try c.decodeIfPresent(String.self, forKey: .os)
            key = try c.decode(Data.self, forKey: .key)
            store = try c.decodeIfPresent(String.self, forKey: .store) ?? Records.file
            kind = try c.decodeIfPresent(String.self, forKey: .kind)
            proof = try c.decodeIfPresent(String.self, forKey: .proof)
            seal = try c.decodeIfPresent(Data.self, forKey: .seal)
            forwardOnly = try c.decodeIfPresent(Bool.self, forKey: .forwardOnly) ?? false
            admin = try c.decodeIfPresent(Bool.self, forKey: .admin) ?? false
            adminKey = try c.decodeIfPresent(Data.self, forKey: .adminKey)
            powers = try c.decodeIfPresent([String].self, forKey: .powers) ?? []
            commands = try c.decodeIfPresent([String].self, forKey: .commands) ?? []
            frozen = try c.decodeIfPresent(Bool.self, forKey: .frozen) ?? false
            freezes = try c.decodeIfPresent([Data].self, forKey: .freezes) ?? []
            keys = try c.decodeIfPresent([Data].self, forKey: .keys) ?? []
        }
    }

    /// A claim of the state: an admin's handover of the group to its new
    /// root (docs/protocol.md, section 10, "Handing the group over").
    public struct Claim: Decodable, Equatable, Sendable {
        public var record: Data
        public var claimant: Data
        public var root: Data
        /// "pending", "effective", "disputed" or "cancelled".
        public var state: String
        public var left_ms: Int64?
    }

    /// The parts of the group's state (docs/protocol.md, section 10, "The state")
    /// the phones show.
    public struct State: Decodable, Equatable, Sendable {
        public var root_device: String?
        public var roots: [Data] = []
        /// "none", or why the group stops (docs/protocol.md, section 10, "Stopping the exchange").
        public var stop: String = "none"
        public var claims: [Claim]?
        /// The keys the records revoke.
        public var revoked: [Data]?
        /// The conflicts that stop the group until its root decides.
        public var conflicts: [Conflict]?
        /// The devices that get no secrets, and those that get nothing.
        public var no_secrets_to: [String]?
        public var nothing_to: [String]?
        /// The records of a later version the set keeps.
        public var newer: [Data]?
        /// The key hash of the group's recovery key, while one counts.
        public var recovery: Data?
        /// The key level of the current root's newest settings; nil means hardware.
        public var key_level: String?
    }

    /// A conflict of the state: kind is admins, claims or two_histories.
    public struct Conflict: Decodable, Equatable, Sendable {
        public var kind: String
        public var records: [Data]
        public var signers: [Data]
    }

    /// When the set first held a claim, which a Welcome passes on.
    public struct ClaimTime: Codable, Equatable, Sendable {
        public var record: Data
        public var ms: Int64
    }

    /// What the core says of the set (group_view).
    public struct View: Decodable, Equatable, Sendable {
        public var state = State()
        public var devices: [Device] = []
        /// The roots' certificates on the path, the group CA first.
        public var path: [Data] = []
        public struct RootMember: Decodable, Equatable, Sendable { public var device: String, key: Data }
        public var root_member: RootMember?
        public var hub_order: [String] = []
        /// The admin key hash the current root handed the group to
        /// (docs/protocol.md, section 10, "Handing the group over").
        public var handed_to: Data?
        public var digest: String?
        public var claim_times: [ClaimTime]?
        public var known: [String] = []
        public var records = 0
    }

    /// The set's records, as the file holds them.
    public var records: [Member.Record] {
        struct File: Decodable { var records: [Member.Record]? }
        guard let file else { return [] }
        return (try? JSONDecoder().decode(File.self, from: file))?.records ?? []
    }

    private struct SetArgs: Encodable {
        var group_ca: Data
        var group: String?
        var now_ms: Int64
        var file: Data?
    }

    /// The set's arguments for the core, with extra fields.
    private struct Args<E: Encodable>: Encodable {
        var set: SetArgs
        var extra: E
        func encode(to encoder: Encoder) throws {
            try set.encode(to: encoder)
            try extra.encode(to: encoder)
        }
    }

    private struct NoExtra: Encodable { func encode(to encoder: Encoder) throws {} }

    /// Asks the core op with the set's arguments and extra.
    private func ask<E: Encodable, R: Decodable>(_ op: String, _ extra: E, as _: R.Type = R.self) throws -> R {
        guard let ca = groupCA else { throw Core.Mismatch(reason: "the set knows no group yet") }
        return try Core.run(op, Args(set: SetArgs(group_ca: ca, group: tag, now_ms: nowMS ?? Records.ms(clock()), file: file), extra: extra))
    }

    /// Asks the core what the set says again: after the clock moved, as a
    /// claim's delay runs out.
    public mutating func refresh() {
        guard groupCA != nil else { view = View(); return }
        view = (try? ask("group_view", NoExtra())) ?? View()
    }

    /// Adds a record signed under one of the group's roots, unless it holds
    /// it; reports whether it was new.
    @discardableResult
    public mutating func add(_ r: Member.Record, groupCA: Data) -> Bool { !addAll([r], groupCA: groupCA).isEmpty }

    /// Adds records and returns those it did not hold; the core leaves out
    /// records it refuses (docs/records-v2.md).
    @discardableResult
    public mutating func addAll(_ rs: [Member.Record], groupCA: Data) -> [Member.Record] {
        if self.groupCA == nil { self.groupCA = groupCA }
        guard !rs.isEmpty else { return [] }
        struct Extra: Encodable { var records: [Member.Record] }
        struct Out: Decodable { var file: Data, fresh: [Member.Record] }
        guard let out: Out = try? ask("group_add", Extra(records: rs)) else { return [] }
        file = out.file
        refresh()
        return out.fresh
    }

    /// Takes the claim times a Welcome brought: those earlier than the
    /// set's own and not in the future.
    public mutating func takeClaimTimes(_ ts: [ClaimTime]) {
        guard !ts.isEmpty else { return }
        struct Extra: Encodable { var claim_times: [ClaimTime] }
        struct Out: Decodable { var file: Data }
        guard let out: Out = try? ask("group_claim_times", Extra(claim_times: ts)) else { return }
        file = out.file
        refresh()
    }

    /// Signs body as the signer's next record: the core sets the group,
    /// seq and prev, and seen for a removal, freeze or claim, from the set.
    /// The caller adds the record to the set.
    public func sign(_ body: Records.Body, with signer: CertificateSigner, adminCA: Data? = nil) throws -> Member.Record {
        let data = try canonical(body)
        return Member.Record(body: data, sig: try signer.signature(for: data), chain: adminCA.map { [$0] })
    }

    /// The canonical bytes of body as the signer's next record, to sign.
    public func canonical(_ body: Records.Body) throws -> Data {
        struct Extra: Encodable { var body: Records.Body }
        struct Out: Decodable { var body: Data }
        let out: Out = try ask("group_body", Extra(body: body))
        return out.body
    }

    /// The devices list, sorted by name.
    public var devices: [Device] { view.devices }
    /// The roots that took the group over from the group CA, in order; the last is the current root.
    public var roots: [Data] { Array(view.path.dropFirst()) }
    /// The device of the group's root, when the records name it.
    public var rootDevice: String? { view.state.root_device.flatMap { $0.isEmpty ? nil : $0 } }
    /// The device that holds the root key and its member key.
    func rootMember() -> (device: String, key: Data)? { view.root_member.map { ($0.device, $0.key) } }
    /// The devices that may be hubs, in the order members try them.
    public var hubOrder: [String] { view.hub_order }
    /// The admin key hash the current root handed the group to, whose
    /// claim takes effect at once; nil without a handover.
    public var handedTo: Data? { view.handed_to }
    /// Whether the records let the device be the group's hub.
    public func mayHost(_ device: String) -> Bool { view.hub_order.contains(device) }
    /// The digest a hello carries; nil for an empty set.
    public var digest: String? { view.digest }
    /// When the set first held each claim, which a Welcome passes on.
    public var claimTimes: [ClaimTime] { view.claim_times ?? [] }
    /// Whether a device record names device, counted or not: an ID a new device must not take.
    public func knows(_ device: String) -> Bool { view.known.contains(device) }
    /// Why the group stops exchanging, "none" when it does not.
    public var stop: String { view.state.stop }
    /// The claims of the state.
    public var claims: [Claim] { view.state.claims ?? [] }
    /// The keys the records revoke.
    public var revoked: Set<Data> { Set(view.state.revoked ?? []) }
    /// The key hash of the group's recovery key, while one counts.
    public var recovery: Data? { view.state.recovery }
    /// The group's key level (Records.keyLevels): hardware when the root set none.
    public var keyLevel: String { view.state.key_level.flatMap { $0.isEmpty ? nil : $0 } ?? Records.hardware }
    /// The records a new member gets in the Welcome, to check the
    /// Welcome's roots, and a hub shows its forwarder: all of them, since
    /// every member evaluates the whole set.
    public var pathRecords: [Member.Record] { records }
    public var authorityRecords: [Member.Record] { records }

    /// What the set says of a peer's chain.
    public enum Verdict: Equatable, Sendable {
        case ok
        /// No device record that counts names the device yet; its connection carries records only.
        case notListed(String)
        /// The root's own device that a claim took the group over from;
        /// its connection carries records only, so that it may cancel the claim.
        case takenOver(String)
        /// The state stops the exchange with the device (docs/protocol.md,
        /// section 10, "Stopping the exchange"); its connection carries
        /// records only, so that the root's decision reaches every member.
        case stopped(String)
        case refused(String)

        /// Why it is not ok, nil when it is.
        public var why: String? {
            switch self {
            case .ok: nil
            case let .notListed(w), let .takenOver(w), let .stopped(w), let .refused(w): w
            }
        }

        /// Whether the connection carries records only.
        public var recordsOnly: Bool {
            switch self {
            case .notListed, .takenOver, .stopped: true
            default: false
            }
        }
    }

    private struct VerdictOut: Decodable { var verdict: String, why: String? }

    private static func verdict(_ v: VerdictOut) -> Verdict {
        switch v.verdict {
        case "ok": .ok
        case "not_listed": .notListed(v.why ?? "")
        case "taken_over": .takenOver(v.why ?? "")
        case "stopped": .stopped(v.why ?? "")
        default: .refused(v.why ?? "refused")
        }
    }

    /// Whether the set takes a member's chain, leaf first, already verified
    /// to a trusted root; an empty set takes any.
    public func verdict(chain: [Data]) -> Verdict {
        guard groupCA != nil, file != nil else { return .ok }
        struct Extra: Encodable { var chain: [Data] }
        do {
            return Self.verdict(try ask("group_refused", Extra(chain: chain)))
        } catch {
            return .refused("\(error)")
        }
    }

    /// Why the set refuses a member's chain, nil when it takes it; a chain
    /// the state only stops the exchange with is taken, for records only
    /// (stopped(chain:)).
    public func refused(chain: [Data]) -> String? {
        let v = verdict(chain: chain)
        if case .stopped = v { return nil }
        return v.why
    }

    /// Whether the state stops the exchange with this chain's device: its
    /// connection carries records only (docs/protocol.md, section 10,
    /// "Stopping the exchange").
    public func stopped(chain: [Data]) -> Bool {
        if case .stopped = verdict(chain: chain) { return true }
        return false
    }

    /// Whether this member sends device no secret: while the state stops
    /// secrets or everything, or names device among those that get no
    /// secrets or nothing. Such a device gets the mark of a secret, never
    /// its text. A nil device is checked against the stop alone.
    public func noSecrets(to device: String?) -> Bool {
        let st = view.state
        guard st.stop == "none" else { return true }
        guard let device else { return false }
        return (st.no_secrets_to ?? []).contains(device) || (st.nothing_to ?? []).contains(device)
    }

    /// Whether the set takes an admin CA.
    public func verdict(adminCA: Data) -> Verdict {
        guard groupCA != nil, file != nil else { return .ok }
        struct Extra: Encodable { var ca: Data }
        do {
            return Self.verdict(try ask("group_refused_admin_ca", Extra(ca: adminCA)))
        } catch {
            return .refused("\(error)")
        }
    }

    /// Whether the device with the chain is the group's root or an admin, which alone may be a hub.
    public func mayHost(_ device: String, chain: [Data]) -> Bool {
        struct Extra: Encodable { var device: String, chain: [Data] }
        struct Out: Decodable { var admin: Bool }
        return ((try? ask("group_admin_peer", Extra(device: device, chain: chain), as: Out.self))?.admin) ?? false
    }

    /// The admin that took the group over from the root whose own device
    /// has chain, by a claim that took effect.
    public func takenOver(chain: [Data]) -> (device: String, admin: Data)? {
        struct Extra: Encodable { var chain: [Data] }
        struct Claimant: Decodable { var device: String, admin: Data }
        struct Out: Decodable { var claimant: Claimant? }
        guard let c = (try? ask("group_taken_over", Extra(chain: chain), as: Out.self))?.claimant else { return nil }
        return (c.device, c.admin)
    }

    /// A command the core checked for this member.
    public struct CheckedCommand: Decodable, Sendable {
        public var command: Commands.Body
        /// The device that signed it, when the records list it.
        public var signer: Device?
        /// Whether the current root's own key signed it.
        public var root: Bool?
        /// The device the limits count it for.
        public var sender: String
        /// Whether that device's own key signed it.
        public var verified: Bool?
        /// Whether its orders were sealed to this member and opened.
        public var opened: Bool?
    }

    /// Checks command c for the member me (docs/protocol.md, section 15):
    /// an admin of the group that may sign its type signed it, its by is
    /// the signer's device, it is for me in this group and in its
    /// lifetime. A sealed command's orders are opened with secret, this
    /// member's secret for sealed messages; a paste in the open is refused
    /// when this member's device record has a `seal` key. The caller keeps
    /// the replay cache.
    public func check(command c: Member.Record, me: String, secret: Data? = nil) throws -> CheckedCommand {
        guard groupCA != nil else { throw Commands.Refused(reason: "this device has no records of its group yet") }
        struct Extra: Encodable { var command: Member.Record, me: String, secret: Data? }
        do {
            return try ask("group_command", Extra(command: c, me: me, secret: secret))
        } catch let r as Core.Refusal {
            throw Commands.Refused(reason: r.details.map { "\(r.message): \($0)" } ?? r.message)
        }
    }

    /// Seals a copy this member made to the readers the set names
    /// (group_seal_copy, docs/protocol.md, section 4, "Sealing") and signs
    /// it with signer, the member key of cert; key sealed the blob of its
    /// images or files, if it has one.
    public func sealCopy(_ e: Member.Event, cert: Data, issuer: Data?, key: Data?, blob: Media.Blob?, signer: CertificateSigner) throws -> Member.Sealed {
        struct Extra: Encodable {
            var id: String, origin: String, time: Member.Timestamp, cert: Data, issuer: Data?
            var kind: Member.Kind, via: Member.Via, text: String, media: Media.Manifest?, blob: Media.Blob?, key: Data?
        }
        struct Answer: Decodable { var event: Member.Sealed, to_sign: Data }
        let a = try ask("group_seal_copy", Extra(id: e.id, origin: e.origin, time: e.time, cert: cert, issuer: issuer, kind: e.kind, via: e.via,
                                                 text: e.text, media: e.media, blob: blob, key: key), as: Answer.self)
        var s = a.event
        s.sig = try signer.signature(for: a.to_sign)
        return s
    }

    /// Checks a copy's origin and signature against the set, as a member
    /// does before it keeps or passes the copy on (group_check_copy).
    public func checkCopy(_ s: Member.Sealed) throws {
        struct Extra: Encodable { var event: Member.Sealed }
        struct Answer: Decodable {}
        _ = try ask("group_check_copy", Extra(event: s), as: Answer.self)
    }
}
