// SPDX-License-Identifier: AGPL-3.0-only

import Crypto
import Foundation

/// A phone group (docs/protocol.md, sections 9 and 10) as this phone holds
/// it: the group CA, the phone's own member certificate, the computers it
/// admitted and the records. The phone is the root, which made the group,
/// an admin with an admin CA under the root, or a member without either.
/// The keys stay outside: the signing key (the root key, or the admin key)
/// in the Secure Enclave, the member key in the keychain. It is saved as
/// JSON next to the app's other data.
public struct PhoneGroup: Codable, Equatable, Sendable {
    /// This phone's device ID.
    public var device: String
    /// The group root CA, DER; path length 1. The group's first root, which
    /// names it for good.
    public var groupCA: Data
    /// The roots that took the group over from groupCA, in order, DER; the
    /// last is the current root (docs/protocol.md, section 10, "Roots").
    public var roots: [Data] = []
    /// This phone's member certificate, DER, from one of the roots or from
    /// memberIssuer.
    public var memberCert: Data
    /// The admin CA that issued memberCert, which the phone sends after it
    /// in TLS handshakes; nil when the group CA did.
    public var memberIssuer: Data?
    /// Whether this phone holds the current root's key: it made the group,
    /// or took it over.
    public var isRoot = true
    /// This phone's admin CA when it is an admin but not the root.
    public var adminCA: Data?
    public var computers: [Computer]
    /// The group's signed device and revocation records; admin phones sign
    /// them, and they spread to every member.
    public var records = RecordSet()
    /// The admin CAs this phone, as the root, issued to computers, DER, by
    /// device ID: sent again to a computer that offers the same admin key
    /// (section 10, "A computer as admin").
    public var computerAdmins: [String: Data] = [:]
    /// The new root of this admin's claim to take the group over, DER,
    /// while the claim waits (docs/protocol.md, section 10, "Handing the group
    /// over"); its key stays in the Secure Enclave until the claim takes
    /// effect or ends.
    public var claim: Data?
    /// The device of the root that claim takes the group over from, which
    /// the new root removes.
    public var claimedFrom: String?

    enum CodingKeys: String, CodingKey {
        case device, groupCA, roots, memberCert, memberIssuer, isRoot, adminCA, computers, records, computerAdmins, claim, claimedFrom
    }

    init(device: String, groupCA: Data, memberCert: Data, computers: [Computer]) {
        (self.device, self.groupCA, self.memberCert, self.computers) = (device, groupCA, memberCert, computers)
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        device = try c.decode(String.self, forKey: .device)
        groupCA = try c.decode(Data.self, forKey: .groupCA)
        roots = try c.decodeIfPresent([Data].self, forKey: .roots) ?? []
        memberCert = try c.decode(Data.self, forKey: .memberCert)
        memberIssuer = try c.decodeIfPresent(Data.self, forKey: .memberIssuer)
        // Files saved before phones could join belong to a root.
        isRoot = try c.decodeIfPresent(Bool.self, forKey: .isRoot) ?? true
        adminCA = try c.decodeIfPresent(Data.self, forKey: .adminCA)
        computers = try c.decode([Computer].self, forKey: .computers)
        records = try c.decodeIfPresent(RecordSet.self, forKey: .records) ?? RecordSet()
        computerAdmins = try c.decodeIfPresent([String: Data].self, forKey: .computerAdmins) ?? [:]
        claim = try c.decodeIfPresent(Data.self, forKey: .claim)
        claimedFrom = try c.decodeIfPresent(String.self, forKey: .claimedFrom)
    }

    /// Whether this phone may admit devices, renew certificates and remove
    /// devices: the root and the admins.
    public var isAdmin: Bool { isRoot || adminCA != nil }

    /// The certificate chain this phone presents in TLS, leaf first.
    public var memberChain: [Data] { [memberCert] + (memberIssuer.map { [$0] } ?? []) }

    /// The current root: the last of roots, or the group CA.
    public var currentRoot: Data { roots.last ?? groupCA }

    /// Every root the group had, the group CA first: member certificates
    /// and admin CAs from any of them verify.
    public var trusted: [Data] { [groupCA] + roots }

    /// The CA whose key signs for this phone: the current root, or its
    /// admin CA.
    var signingCA: Data { adminCA ?? currentRoot }

    /// A computer this phone admitted.
    public struct Computer: Codable, Equatable, Sendable, Identifiable {
        public var device: String
        public var name: String
        /// "linux", "windows" or "macos", as its pairing Info says.
        public var os: String
        public var cert: Data
        public var admitted: Date
        /// Its addresses on the home network from the QR code, the one that
        /// answered first: dialed when mDNS does not find it, as in another
        /// subnet (docs/protocol.md, section 9). nil in files saved before.
        public var addrs: [String]?
        public var id: String { device }
    }

    /// The home network addresses of the computers this phone admitted, by
    /// device ID, best first.
    public var addresses: [String: [String]] {
        var out: [String: [String]] = [:]
        for c in computers { if let a = c.addrs?.filter(JoinCode.isHome), !a.isEmpty { out[c.device] = a } }
        return out
    }

    /// The group tag the computers publish.
    public var tag: String { GroupCertificates.tag(groupCA: groupCA) }

    /// Creates a group: a root CA for caSigner's key, a member certificate
    /// for this phone's member key (a SubjectPublicKeyInfo), and the phone's
    /// own device record under name, with seal, the phone's public key for
    /// sealed messages (SealKey), when it has one.
    public static func create(caSigner: CertificateSigner, memberKey: Data, name: String = "iPhone", seal: Data? = nil, now: Date) throws -> PhoneGroup {
        let ca = try GroupCertificates.groupCA(signer: caSigner, now: now, pathLength: 1)
        let device = Member.newID()
        let cert = try GroupCertificates.member(device: device, publicKey: memberKey, ca: ca, caSigner: caSigner, now: now)
        var g = PhoneGroup(device: device, groupCA: ca, memberCert: cert, computers: [])
        _ = try g.record(device: device, name: Self.validName(name), role: "phone", os: "ios", key: Records.keyHash(spki: memberKey),
                         store: Records.hardware, seal: seal, caSigner: caSigner, now: now)
        return g
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

    /// The group a phone joins, from the welcome the admitting phone sent
    /// and PairingJoiner checked: a member of it, and an admin when the
    /// welcome carries its admin CA. The records arrive from the computers.
    public static func joined(_ j: PairingJoiner.Joined) -> PhoneGroup {
        var g = PhoneGroup(device: j.device, groupCA: j.welcome.groupCA, memberCert: j.welcome.cert, computers: [])
        (g.memberIssuer, g.isRoot, g.adminCA) = (j.welcome.issuer, false, j.welcome.adminCA)
        // The records that lead to the roots stay with the group, so the
        // roots are those its records name.
        g.records.addAll(j.welcome.records ?? [], groupCA: j.welcome.groupCA)
        g.records.takeClaimTimes(j.welcome.claimTimes ?? [])
        g.roots = g.records.roots
        return g
    }

    /// The group the core made with this phone's root key
    /// (CorePairing.newGroup), or the group a phone joined through the core
    /// (CorePairing.Joining): a member of it, and an admin when the
    /// admitting phone sent its admin CA.
    public static func of(_ c: CorePairing.Group, root: Bool) -> PhoneGroup {
        var g = PhoneGroup(device: c.device, groupCA: c.groupCA, memberCert: c.cert, computers: [])
        (g.memberIssuer, g.isRoot, g.adminCA) = (c.issuer, root, root ? nil : c.adminCA)
        g.records = RecordSet.fromFile(groupCA: c.groupCA, file: c.records)
        // The records that lead to the roots stay with the group, so the
        // roots are those its records name.
        g.roots = g.records.roots.isEmpty ? c.roots : g.records.roots
        return g
    }

    /// Notes a computer the core admitted for this phone (CorePairing): its
    /// name, system and those of addrs that are on a home network, the one
    /// that answered first, for dialing it where mDNS does not find it. One
    /// admitted again replaces its entry. Its record reaches the group from
    /// the member.
    public mutating func noteComputer(device: String, name: String, os: String, addrs: [String], now: Date) {
        computers.removeAll { $0.device == device }
        computers.append(Computer(device: device, name: name, os: os, cert: Data(), admitted: now, addrs: addrs.filter(JoinCode.isHome)))
    }

    /// fileKey: the computer keeps its keys in a file, which a thief with
    /// it can copy and then act as an admin; the user allows it after a
    /// warning (docs/protocol.md, section 17). rootless: the computer is a
    /// rootless install, which is never an admin (D-79).
    public enum Failure: Error, Equatable {
        case cannotRemoveItself, unknownDevice, notAdmin, cannotRemoveRoot, notRoot, notAComputer, frozen, notFrozen, invalidName, fileKey, rootless
        /// An admin, or the root's own device, reads the copies: it is no
        /// hub that only passes them on.
        case readsCopies
        /// The root did not give this admin the power to take the group over.
        case noTakeover
        /// This admin's claim to take the group over waits already.
        case claimWaiting
        /// The root did not hand the group to this phone.
        case notHandedOver
        /// The delay before a claim takes effect is outside 0 to 7 days.
        case invalidDelay
        /// How long an incoming copy stays live is outside 5 s to 1 h.
        case invalidIncoming
        /// A watch's request names a device ID or system that is not a new watch's,
        /// or a device that is not a watch of the group.
        case notAWatch
        /// A watch may not do that to the device (section 10, "Watches").
        case notForWatch
        /// The group has no recovery key to remove.
        case noRecovery
        /// The group's recovery key now is not the one this phone holds.
        case notTheRecoveryKey
        /// The key level is none of Records.keyLevels.
        case invalidKeyLevel
        /// The group's key level does not let the device's keys be an admin
        /// or the root; the root sets another level first.
        case belowKeyLevel
    }

    /// Adds records from other members, then follows the roots they lead
    /// to when they differ from this phone's; returns the new records.
    @discardableResult
    public mutating func add(_ rs: [Member.Record]) -> [Member.Record] {
        let fresh = records.addAll(rs, groupCA: groupCA)
        adoptRoots()
        return fresh
    }

    /// Takes the roots of the records when they differ from roots,
    /// compared by content, so a root the records do not name never stays
    /// trusted; an empty set says nothing yet.
    public mutating func adoptRoots() {
        let path = records.roots
        if !records.records.isEmpty, path != roots { roots = path }
    }

    /// The key hash of the signer's key, which names it in its records.
    static func signer(_ s: CertificateSigner) -> Data { Records.keyHash(spki: s.publicKeyDER) }

    /// The powers and commands the apps give an admin with role
    /// (docs/protocol.md, section 10, "Who signs what").
    static func grants(role: String) -> (powers: [String], commands: [String]) {
        switch role {
        case "phone": (Records.powers, Records.commands)
        case "watch": (Records.watchPowers, Records.watchCommands)
        default: (Records.computerPowers, Records.commands)
        }
    }

    /// Signs body with caSigner, the root's own key or this phone's admin
    /// key, and adds it to the set.
    mutating func sign(_ body: Records.Body, caSigner: CertificateSigner) throws -> Member.Record {
        if records.groupCA == nil { records.groupCA = groupCA }
        let r = try records.sign(body, with: caSigner, adminCA: isRoot ? nil : adminCA)
        records.add(r, groupCA: groupCA)
        return r
    }

    /// Signs and adds a device record. A record that makes an admin gives
    /// it the powers of its role unless powers names them, and the root's
    /// record of its own device says that it holds the root.
    mutating func record(device: String, name: String, role: String, os: String? = nil, key: Data, admin: Data? = nil,
                         powers: [String]? = nil, commands: [String]? = nil, store: String? = nil, kind: String? = nil,
                         proof: String? = nil, seal: Data? = nil, forwardOnly: Bool = false, caSigner: CertificateSigner, now: Date) throws -> Member.Record {
        guard isAdmin else { throw Failure.notAdmin }
        var b = Records.Body(type: "device", signer: Self.signer(caSigner), timeMS: Records.ms(now))
        (b.device, b.name, b.role, b.os, b.key, b.admin) = (device, name, role, os, key, admin)
        (b.store, b.kind, b.proof, b.seal) = (store, kind, proof, seal)
        if forwardOnly { b.forward_only = true }
        if admin != nil {
            let g = Self.grants(role: role)
            (b.powers, b.commands) = (powers ?? g.powers, commands ?? g.commands)
        }
        if isRoot, device == self.device { b.holds_root = true }
        return try sign(b, caSigner: caSigner)
    }

    /// Checks that this admin phone may claim the group when the root
    /// phone lost is gone (docs/protocol.md, section 10, "Handing the group
    /// over"), before the app makes a new root key: the core's member then
    /// signs the claim (CoreMember.claim), which waits the group's delay (72
    /// hours unless the root set another), in which the root cancels it if
    /// it is still in use; claimed(newRoot:lost:) notes it, and
    /// CoreMember.finishTakeover and becameRoot(cert:records:) then make
    /// this phone the root.
    public func checkTakeOver(from lost: String) throws {
        guard adminCA != nil, !isRoot else { throw Failure.notAdmin }
        guard lost == records.rootDevice, lost != device else { throw Failure.notRoot }
        try checkClaim()
    }

    /// Whether the group's root handed the group to this phone's admin key
    /// (`cbb handover`, docs/protocol.md, section 10, "Handing the group
    /// over"), and this phone has not claimed it yet.
    public var handedToMe: Bool {
        guard let adminCA, !isRoot, claim == nil, let to = records.handedTo else { return false }
        return (try? Records.keyHash(cert: adminCA)) == to
    }

    /// Checks that this phone may take the group the root handed to it: a
    /// claim, as in checkTakeOver(from:), that takes effect at once because
    /// the root signed a handover for this phone's admin key. The old
    /// root's device stays in the group.
    public func checkHandedOver() throws {
        guard handedToMe else { throw Failure.notHandedOver }
        try checkClaim()
    }

    /// Checks that this new phone, which Restore made a member of the group
    /// under the recovery key's admin CA, may claim the group with that key
    /// (docs/protocol.md, section 10, "The recovery key"). The lost root's
    /// device goes when the claim takes effect.
    public func checkRecovery() throws {
        guard let adminCA, !isRoot else { throw Failure.notAdmin }
        guard claim == nil else { throw Failure.claimWaiting }
        guard let k = try? Records.keyHash(cert: adminCA), records.recovery == k else { throw Failure.notTheRecoveryKey }
    }

    private func checkClaim() throws {
        guard claim == nil else { throw Failure.claimWaiting }
        guard let me = devices.first(where: { $0.id == device }), me.may("takeover") else { throw Failure.noTakeover }
    }

    /// Notes this phone's claim for newRoot, which the core's member
    /// signed, from the lost root's device lost (nil for a handed group).
    public mutating func claimed(newRoot: Data, lost: String?) {
        (claim, claimedFrom) = (newRoot, lost)
    }

    /// The fields of a record's body that find a claim.
    private struct ClaimBody: Decodable {
        var type: String
        var root: Data?
    }

    /// This phone's claim among rs, the member's records, to send on a
    /// connection the member does not make (a records-only one).
    public func claimRecord(in rs: [Member.Record]) -> Member.Record? {
        guard let c = claim else { return nil }
        return rs.last { r in
            guard let b = try? JSONDecoder().decode(ClaimBody.self, from: r.body) else { return false }
            return b.type == "claim" && b.root == c
        }
    }

    /// The state of this phone's claim, as the records say: "pending",
    /// "effective", "cancelled", "void", "competing" or "disputed"; nil
    /// without one.
    public var claimState: String? {
        guard let claim, let k = try? Records.keyHash(cert: claim) else { return nil }
        return records.claims.last(where: { $0.root == k })?.state
    }

    /// Drops this phone's claim when the root cancelled it or it became
    /// void; reports whether it did.
    @discardableResult
    public mutating func dropEndedClaim() -> Bool {
        guard let st = claimState, st == "cancelled" || st == "void" else { return false }
        (claim, claimedFrom) = (nil, nil)
        return true
    }

    /// Drops this phone's claim, which the core's member said was
    /// cancelled or became void.
    public mutating func dropClaim() {
        (claim, claimedFrom) = (nil, nil)
    }

    /// Makes this phone the root once the core's member finished its claim
    /// (CoreMember.finishTakeover): cert is its member certificate from the
    /// new root, records the member's records, with those the new root
    /// signed. The phone signs with the new root key from then on, holds no
    /// admin CA, and its TLS identity must be made again.
    public mutating func becameRoot(cert: Data, records rs: [Member.Record]) {
        add(rs)
        adoptRoots()
        (isRoot, memberCert, memberIssuer, adminCA) = (true, cert, nil, nil)
        (claim, claimedFrom) = (nil, nil)
    }

    /// Cancels claims, or ends a conflict, as the current root
    /// (docs/protocol.md, section 10, "Chains and numbers"): a resolve that voids the records
    /// with the IDs ids. It returns the record to send.
    public mutating func resolve(_ ids: [Data], rootSigner: CertificateSigner, now: Date) throws -> Member.Record {
        guard isRoot else { throw Failure.notRoot }
        var b = Records.Body(type: "resolve", signer: Self.signer(rootSigner), timeMS: Records.ms(now))
        b.records = ids
        return try sign(b, caSigner: rootSigner)
    }

    /// Sets how long a claim waits before it takes effect (0 to 7 days;
    /// 72 hours without a settings record), as the current root. It
    /// returns the record to send.
    public mutating func setTakeoverDelay(ms: Int64, rootSigner: CertificateSigner, now: Date) throws -> Member.Record {
        guard isRoot else { throw Failure.notRoot }
        guard (0...7 * 24 * 3600 * 1000).contains(ms) else { throw Failure.invalidDelay }
        var b = Records.Body(type: "settings", signer: Self.signer(rootSigner), timeMS: Records.ms(now))
        // The newest settings record counts whole, so this one keeps the level.
        (b.takeover_delay_ms, b.key_level) = (ms, settings(of: Self.signer(rootSigner)).level)
        return try sign(b, caSigner: rootSigner)
    }

    /// The group's key level: which keys may be its root, an admin or a hub.
    public var keyLevel: String { records.keyLevel }

    /// How long a copy from another device stays live after it arrives, in
    /// milliseconds: written to the clipboard until then, never after.
    public var incomingMS: Int64 { records.incomingMS }

    /// Sets how long a copy from another device stays live after it
    /// arrives (5 s to 1 h), as the root or an admin: a copies record
    /// (docs/protocol.md, section 10, "The copies setting"). It returns the
    /// record to send.
    public mutating func setIncoming(ms: Int64, caSigner: CertificateSigner, now: Date) throws -> Member.Record {
        guard isAdmin else { throw Failure.notAdmin }
        guard Records.incomingBounds.contains(ms) else { throw Failure.invalidIncoming }
        var b = Records.Body(type: "copies", signer: Self.signer(caSigner), timeMS: Records.ms(now))
        b.incoming_ms = ms
        return try sign(b, caSigner: caSigner)
    }

    /// Sets the group's key level (Records.keyLevels), as the current root,
    /// keeping the takeover delay; never a level this phone's own key does
    /// not pass. It returns the record to send. The admins whose keys the
    /// new level would not let in stay until the user removes them
    /// (belowKeyLevel lists them).
    public mutating func setKeyLevel(_ level: String, rootSigner: CertificateSigner, now: Date) throws -> Member.Record {
        guard isRoot else { throw Failure.notRoot }
        guard Records.keyLevels.contains(level) else { throw Failure.invalidKeyLevel }
        let own = devices.first { $0.id == device }?.store ?? Records.hardware
        guard Records.levelAllows(level, store: own, consent: true) else { throw Failure.belowKeyLevel }
        var b = Records.Body(type: "settings", signer: Self.signer(rootSigner), timeMS: Records.ms(now))
        (b.takeover_delay_ms, b.key_level) = (settings(of: Self.signer(rootSigner)).delay, level)
        return try sign(b, caSigner: rootSigner)
    }

    /// The admins, other than this phone, whose keys the level would not
    /// let in, by device ID.
    public func belowKeyLevel(_ level: String) -> [String] {
        devices.filter { $0.id != device && $0.adminKey != nil && !Records.levelAllows(level, store: $0.store, consent: true) }
            .map(\.id)
    }

    /// What the newest settings record of the root whose key hash is root
    /// set, so that a new one keeps what it does not change.
    func settings(of root: Data) -> (delay: Int64?, level: String?) {
        var seq: Int64 = -1
        var out: (delay: Int64?, level: String?) = (nil, nil)
        for r in records.authorityRecords {
            guard let o = try? JSONSerialization.jsonObject(with: r.body) as? [String: Any], o["type"] as? String == "settings",
                  let s = o["signer"] as? String, Data(base64Encoded: s) == root,
                  let q = (o["seq"] as? NSNumber)?.int64Value, q > seq else { continue }
            seq = q
            out = ((o["takeover_delay_ms"] as? NSNumber)?.int64Value, o["key_level"] as? String)
        }
        return out
    }

    /// Renews this phone's own member certificate when it is due; reports
    /// whether it did, after which the TLS identity must be made again. An
    /// admin issues it from its own admin CA, a phone without one cannot.
    public mutating func renewOwnCertificate(caSigner: CertificateSigner, now: Date) throws -> Bool {
        guard isAdmin, GroupCertificates.isDue(memberCert, groupCA: signingCA, now: now),
              (try? GroupCertificates.verifyMember(chain: memberChain, roots: trusted, now: now)) == device else { return false }
        memberCert = try GroupCertificates.member(device: device, publicKey: CertificateInfo(der: memberCert).publicKey, ca: signingCA,
                                                  caSigner: caSigner, now: now)
        memberIssuer = adminCA
        return true
    }

    /// A renewed certificate for a peer's chain (leaf first) when it is due
    /// and this phone is an admin: the root issues it from its root, an
    /// admin from its admin CA, which the cert message carries, whoever
    /// issued the old one (as a removed admin did).
    public func renewal(chain: [Data], caSigner: CertificateSigner, now: Date) -> Renewal? {
        guard isAdmin, let cert = try? GroupCertificates.renewal(chain: chain, roots: trusted, caSigner: caSigner, adminCA: adminCA, now: now)
        else { return nil }
        return Renewal(cert: cert, issuer: adminCA)
    }

    /// A renewed member certificate for a peer, DER, and the admin CA that
    /// issued it; nil when a root did. The peer gets it in a cert message
    /// (CoreMember.sendCert).
    public struct Renewal: Equatable, Sendable {
        public var cert: Data
        public var issuer: Data?
        public init(cert: Data, issuer: Data? = nil) { (self.cert, self.issuer) = (cert, issuer) }
    }

    /// The devices of the group, from the records.
    public var devices: [RecordSet.Device] { records.devices }

    /// The key for sealed messages that the device record of device
    /// names, which an admin's commands for it are sealed to (section 15,
    /// "Sealed commands"); nil when it has none.
    func sealKey(of device: String) -> Data? {
        devices.first { $0.id == device }?.seal
    }

    /// A command that sets the sync mode of the member device to (section
    /// 15), signed with this phone's root or admin key; only an admin phone
    /// signs one.
    public func modeCommand(to device: String, mode: String, caSigner: CertificateSigner, now: Date) throws -> Member.Record {
        guard isAdmin else { throw Failure.notAdmin }
        return try Commands.mode(to: device, mode: mode, group: tag, by: self.device, now: now, signer: caSigner, adminCA: adminCA,
                                 seal: sealKey(of: device))
    }

    /// A paste command that puts text where the focus of the member device
    /// to is (section 15; design.md, "Remote paste"), by method "paste" or
    /// "type", then Enter when enter is set; signed as modeCommand.
    public func pasteCommand(to device: String, text: String, method: String, enter: Bool, secret: Bool,
                             caSigner: CertificateSigner, now: Date) throws -> Member.Record {
        guard isAdmin else { throw Failure.notAdmin }
        return try Commands.paste(to: device, text: text, method: method, enter: enter, kind: secret ? "secret" : "text",
                                  group: tag, by: self.device, now: now, signer: caSigner, adminCA: adminCA, seal: sealKey(of: device))
    }

    /// A paste command of the group's copy of images or files copyID,
    /// which this phone made just before (docs/protocol.md, section 15):
    /// the member device fetches it and pastes it with the paste keys.
    public func pasteCopyCommand(to device: String, copyID: String, enter: Bool, caSigner: CertificateSigner, now: Date) throws -> Member.Record {
        guard isAdmin else { throw Failure.notAdmin }
        return try Commands.paste(to: device, text: copyID, method: "paste", enter: enter, kind: "media",
                                  group: tag, by: self.device, now: now, signer: caSigner, adminCA: adminCA, seal: sealKey(of: device))
    }

    /// An action command that runs the quick action name on the member
    /// device, signed with this phone's root or admin key; the member
    /// defines what it does.
    public func actionCommand(to device: String, name: String, caSigner: CertificateSigner, now: Date) throws -> Member.Record {
        guard isAdmin else { throw Failure.notAdmin }
        return try Commands.action(to: device, name: name, group: tag, by: self.device, now: now, signer: caSigner, adminCA: adminCA,
                                   seal: sealKey(of: device))
    }

    /// An actions-off command that turns every quick action off on the
    /// member device.
    public func actionsOffCommand(to device: String, caSigner: CertificateSigner, now: Date) throws -> Member.Record {
        guard isAdmin else { throw Failure.notAdmin }
        return try Commands.actionsOff(to: device, group: tag, by: self.device, now: now, signer: caSigner, adminCA: adminCA,
                                       seal: sealKey(of: device))
    }

    /// A mute command that keeps the copies of the member device from the
    /// whole group for forMS milliseconds, 0 for until an unmute command
    /// (design.md, "Muting a device"); any admin phone signs one.
    public func muteCommand(to device: String, forMS: Int64, caSigner: CertificateSigner, now: Date) throws -> Member.Record {
        guard isAdmin else { throw Failure.notAdmin }
        return try Commands.mute(to: device, forMS: forMS, group: tag, by: self.device, now: now, signer: caSigner, adminCA: adminCA,
                                 seal: sealKey(of: device))
    }

    /// An unmute command that ends an admin's mute of the member device.
    public func unmuteCommand(to device: String, caSigner: CertificateSigner, now: Date) throws -> Member.Record {
        guard isAdmin else { throw Failure.notAdmin }
        return try Commands.unmute(to: device, group: tag, by: self.device, now: now, signer: caSigner, adminCA: adminCA,
                                   seal: sealKey(of: device))
    }

    /// A hub command that makes the admin computer to the group's hub in
    /// place of this phone (section 11, "Moving the hub"), signed with this
    /// phone's root or admin key, with the hub's clients and its forwarder.
    public func hubCommand(to device: String, forwarder: (endpoint: String, pin: String)?, clients: [PhoneHub.Client],
                           caSigner: CertificateSigner, now: Date) throws -> Member.Record {
        guard isAdmin, records.mayHost(device) else { throw Failure.notAdmin }
        return try Commands.hub(to: device, forwarder: forwarder, clients: clients.filter { $0.device != device }, group: tag, by: self.device,
                                now: now, signer: caSigner, adminCA: adminCA, seal: sealKey(of: device))
    }

    /// Removes a device from the group: signs a revocation of every key it
    /// had, and of its admin key for an admin, which every member then
    /// refuses, and returns the record to send. What an admin signed before
    /// stays (docs/protocol.md, section 10, "Removals and freezes keep what the
    /// author saw"). The root phone is taken over instead (CoreMember.claim).
    public mutating func revoke(device: String, caSigner: CertificateSigner, now: Date) throws -> Member.Record {
        guard isAdmin else { throw Failure.notAdmin }
        guard device != self.device else { throw Failure.cannotRemoveItself }
        guard let d = devices.first(where: { $0.id == device }) else { throw Failure.unknownDevice }
        guard device != records.rootDevice else { throw Failure.cannotRemoveRoot }
        var keys = d.keys
        if let admin = d.adminKey, !keys.contains(admin) { keys.append(admin) }
        var b = Records.Body(type: "revoke", signer: Self.signer(caSigner), timeMS: Records.ms(now))
        b.keys = keys
        let r = try sign(b, caSigner: caSigner)
        computers.removeAll { $0.device == device }
        computerAdmins[device] = nil
        return r
    }

    /// Gives a device another name: a device record like its newest one with
    /// that name, which names it everywhere, since the newest record of a
    /// device counts (section 10). An admin renames any device, itself and
    /// the root included. name is trimmed; it must have 1 to 64 bytes and
    /// no control characters.
    /// Signs the device record that makes a computer that is no admin a hub
    /// that only passes the copies on (docs/protocol.md, section 11, "Two
    /// kinds of hub"): `forward_only`, which no key level limits; from then
    /// on no copy is sealed to it. nil when its record says so already.
    public mutating func markForwardOnly(device: String, caSigner: CertificateSigner, now: Date) throws -> Member.Record? {
        guard isAdmin else { throw Failure.notAdmin }
        guard let d = devices.first(where: { $0.id == device }) else { throw Failure.unknownDevice }
        if d.forwardOnly { return nil }
        guard d.role == "full" else { throw Failure.notAComputer }
        guard !d.frozen else { throw Failure.frozen }
        guard d.store != Records.rootless else { throw Failure.rootless }
        guard d.adminKey == nil, device != records.rootDevice else { throw Failure.readsCopies }
        return try record(device: device, name: d.name, role: d.role, os: d.os, key: d.key, store: d.store, kind: d.kind, proof: d.proof,
                          seal: d.seal, forwardOnly: true, caSigner: caSigner, now: now)
    }

    public mutating func rename(device: String, to name: String, caSigner: CertificateSigner, now: Date) throws -> Member.Record {
        guard isAdmin else { throw Failure.notAdmin }
        guard let d = devices.first(where: { $0.id == device }) else { throw Failure.unknownDevice }
        let name = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !name.isEmpty, Self.validName(name) == name else { throw Failure.invalidName }
        return try record(device: device, name: name, role: d.role, os: d.os, key: d.key, admin: d.adminKey,
                          powers: d.adminKey == nil ? nil : d.powers, commands: d.adminKey == nil ? nil : d.commands,
                          store: d.store, kind: d.kind, proof: d.proof, seal: d.seal, forwardOnly: d.forwardOnly, caSigner: caSigner, now: now)
    }

    /// Unfreezes an admin computer that another admin froze (section 10,
    /// rule 4): a thaw record that ends every freeze of it. The root and the
    /// admin phones do it; Remove takes the computer out for good instead.
    public mutating func thaw(device: String, caSigner: CertificateSigner, now: Date) throws -> Member.Record {
        guard isAdmin else { throw Failure.notAdmin }
        guard let d = devices.first(where: { $0.id == device }) else { throw Failure.unknownDevice }
        guard d.frozen, d.adminKey != nil, !d.freezes.isEmpty else { throw Failure.notFrozen }
        var b = Records.Body(type: "thaw", signer: Self.signer(caSigner), timeMS: Records.ms(now))
        b.records = d.freezes
        return try sign(b, caSigner: caSigner)
    }

    /// Makes a computer an admin (section 10, "A computer as admin"): the
    /// root issues an admin CA for the admin key the computer's hello
    /// offered (a SubjectPublicKeyInfo) and signs its device record again,
    /// naming that CA. It returns the admin CA, for the admin message, and
    /// the record to send. Only the root makes admins. keyStore is where
    /// the computer's hello says its keys live; one that keeps them in a
    /// file becomes an admin only with allowFileKey, else Failure.fileKey,
    /// and a rootless install never (Failure.rootless).
    public mutating func makeAdmin(device: String, adminKey: Data, rootSigner: CertificateSigner, now: Date,
                                   keyStore: String? = nil, allowFileKey: Bool = false) throws -> (adminCA: Data, record: Member.Record) {
        guard isRoot else { throw Failure.notRoot }
        guard let d = devices.first(where: { $0.id == device }) else { throw Failure.unknownDevice }
        guard d.role == "full" else { throw Failure.notAComputer }
        guard !d.frozen else { throw Failure.frozen }
        let proven = d.store == Records.proven
        let store = proven ? d.store : Records.store(keyStore, role: d.role)
        guard store != Records.rootless, d.store != Records.rootless else { throw Failure.rootless }
        guard Records.levelAllows(keyLevel, store: store, consent: true) else { throw Failure.belowKeyLevel }
        guard store != Records.file || allowFileKey else { throw Failure.fileKey }
        let ca = try GroupCertificates.adminCA(device: device, publicKey: adminKey, root: currentRoot, rootSigner: rootSigner)
        let r = try record(device: device, name: d.name, role: d.role, os: d.os, key: d.key, admin: Records.keyHash(cert: ca),
                           store: store, kind: proven ? d.kind : nil, proof: proven ? d.proof : nil, seal: d.seal, caSigner: rootSigner, now: now)
        computerAdmins[device] = ca
        return (ca, r)
    }

    /// A new recovery key (docs/protocol.md, section 10, "The recovery
    /// key"): its 32 bytes, the admin CA the root issued it, the
    /// `recovery` record to send and the sheet to print. The app shows the
    /// sheet once and then forgets the key; nothing of it stays here.
    public struct Recovery: Sendable {
        public var key: Data
        public var adminCA: Data
        public var record: Member.Record
        public var sheet: Core.RecoverySheet
    }

    /// Makes the group's recovery key, as the root: a new P-256 key, an
    /// admin CA for it under the current root (its CN names a random ID,
    /// since the key has no device) and the `recovery` record that names
    /// it, which replaces the recovery key before it.
    public mutating func makeRecovery(rootSigner: CertificateSigner, now: Date) throws -> Recovery {
        guard isRoot else { throw Failure.notRoot }
        let key = P256.Signing.PrivateKey()
        let (ca, r) = try recovery(for: key.publicKey.derRepresentation, rootSigner: rootSigner, now: now)
        let sheet = try Core.recoverySheet(key: key.rawRepresentation, cert: ca, group: tag)
        return Recovery(key: key.rawRepresentation, adminCA: ca, record: r, sheet: sheet)
    }

    /// Makes the group's recovery key from a key a YubiKey made (publicKey,
    /// a SubjectPublicKeyInfo; Piv.generate), as the root: its admin CA,
    /// which goes into the YubiKey's slot, and the `recovery` record that
    /// names it.
    public mutating func makeRecoveryOnCard(publicKey: Data, rootSigner: CertificateSigner, now: Date) throws -> (adminCA: Data, record: Member.Record) {
        guard isRoot else { throw Failure.notRoot }
        return try recovery(for: publicKey, rootSigner: rootSigner, now: now)
    }

    private mutating func recovery(for publicKey: Data, rootSigner: CertificateSigner, now: Date) throws -> (adminCA: Data, record: Member.Record) {
        let ca = try GroupCertificates.adminCA(device: Member.newID(), publicKey: publicKey, root: currentRoot, rootSigner: rootSigner)
        var b = Records.Body(type: "recovery", signer: Self.signer(rootSigner), timeMS: Records.ms(now))
        (b.admin, b.cert) = (try Records.keyHash(cert: ca), ca)
        return (ca, try sign(b, caSigner: rootSigner))
    }

    /// Removes the group's recovery key, as the root: a revocation of its
    /// key. It returns the record to send.
    public mutating func removeRecovery(rootSigner: CertificateSigner, now: Date) throws -> Member.Record {
        guard isRoot else { throw Failure.notRoot }
        guard let k = records.recovery else { throw Failure.noRecovery }
        var b = Records.Body(type: "revoke", signer: Self.signer(rootSigner), timeMS: Records.ms(now))
        b.keys = [k]
        return try sign(b, caSigner: rootSigner)
    }

    /// Makes a watch an admin (section 10, "Watches"): the root issues an
    /// admin CA for the key the watch made in its Secure Enclave or
    /// Keystore (adminKey, a SubjectPublicKeyInfo) and signs the watch's
    /// device record, whose key and admin both name that CA, since a watch
    /// has no member key. device is the ID the watch picked, os "watchos"
    /// or "wearos". It returns the admin CA, for the watch, and the record
    /// to send. Only the root does it; the watch checked its passcode and
    /// wrist detection before it made the key.
    public mutating func addWatch(device: String, name: String, os: String, adminKey: Data, rootSigner: CertificateSigner,
                                  now: Date) throws -> (adminCA: Data, record: Member.Record) {
        guard isRoot else { throw Failure.notRoot }
        guard device.count == 32, device.allSatisfy({ $0.isHexDigit && !$0.isUppercase }), os == "watchos" || os == "wearos",
              !devices.contains(where: { $0.id == device }) else { throw Failure.notAWatch }
        let name = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !name.isEmpty, Self.validName(name) == name else { throw Failure.invalidName }
        let ca = try GroupCertificates.adminCA(device: device, publicKey: adminKey, root: currentRoot, rootSigner: rootSigner)
        let key = try Records.keyHash(cert: ca)
        let r = try record(device: device, name: name, role: "watch", os: os, key: key, admin: key, store: Records.hardware,
                           caSigner: rootSigner, now: now)
        return (ca, r)
    }

    /// What a watch of the group may do from its wrist (section 10, "Watches").
    public enum WatchAction: String, Codable, CaseIterable, Sendable {
        case freeze, remove, pasteOff = "paste-off", actionsOff = "actions-off", awayOff = "away-off", action
    }

    /// What a watch may do to device: freeze it when it is an admin
    /// computer, remove it when it is no admin, and send a member the
    /// commands that turn things off or run a quick action. Nothing to the
    /// root, a phone or a watch.
    public func watchActions(for device: String) -> [WatchAction] {
        guard let d = devices.first(where: { $0.id == device }), device != records.rootDevice,
              d.role == "full" || d.role == "lite" else { return [] }
        var out: [WatchAction] = []
        if d.adminKey != nil, d.role == "full", !d.frozen { out.append(.freeze) }
        if d.adminKey == nil, !d.admin { out.append(.remove) }
        return out + [.pasteOff, .actionsOff, .awayOff, .action]
    }

    /// The body the watch with the device ID watch signs for action on
    /// device (name is the quick action's, for action): the phone builds it,
    /// the watch shows what it says and signs it with its admin key, and
    /// watchRecord puts the two together. Any phone of the group builds
    /// it, admin or not: what counts is the watch's signature.
    public func watchBody(_ action: WatchAction, device: String, name: String? = nil, watch: String, now: Date) throws -> Data {
        guard let w = devices.first(where: { $0.id == watch && $0.role == "watch" }), let ca = w.adminKey, w.admin else {
            throw Failure.notAWatch
        }
        guard watchActions(for: device).contains(action), let d = devices.first(where: { $0.id == device }) else {
            throw Failure.notForWatch
        }
        let s = BodyOnly()
        let r: Member.Record
        switch action {
        case .freeze:
            guard let admin = d.adminKey else { throw Failure.notForWatch }
            var b = Records.Body(type: "freeze", signer: ca, timeMS: Records.ms(now))
            b.keys = [admin]
            return try records.canonical(b)
        case .remove:
            var b = Records.Body(type: "revoke", signer: ca, timeMS: Records.ms(now))
            b.keys = d.keys
            return try records.canonical(b)
        case .pasteOff: r = try Commands.pasteOff(to: device, group: tag, by: watch, now: now, signer: s)
        case .actionsOff: r = try Commands.actionsOff(to: device, group: tag, by: watch, now: now, signer: s)
        case .awayOff: r = try Commands.awayOff(to: device, group: tag, by: watch, now: now, signer: s)
        case .action:
            guard let name, Commands.validActionName(name) else { throw Failure.notForWatch }
            r = try Commands.action(to: device, name: name, group: tag, by: watch, now: now, signer: s)
        }
        return r.body
    }

    /// The record or command a watch signed: body, its signature (ECDSA
    /// with SHA-256, DER) and the watch's admin CA.
    public static func watchRecord(body: Data, signature: Data, watchCA: Data) -> Member.Record {
        Member.Record(body: body, sig: signature, chain: [watchCA])
    }

    /// Signs nothing: the watch signs the body elsewhere.
    private struct BodyOnly: CertificateSigner {
        var publicKeyDER: Data { Data() }
        func signature(for data: Data) throws -> Data { Data() }
    }

    /// Checks the attestation a device sent of its member key (section 17,
    /// "Evidence") and, on the root, returns a new device record with what
    /// it shows when that differs from the device's record; nil when there
    /// is nothing to record. chain is the certificate chain the device
    /// presented, leaf first. Throws AndroidAttestation.Invalid for a proof
    /// of nothing.
    public mutating func evidence(device: String, chain: [Data], _ e: Member.Evidence, rootSigner: CertificateSigner, now: Date,
                                  roots: [Data]? = nil, revoked: Set<String> = []) throws -> Member.Record? {
        guard isRoot, let leaf = chain.first, e.format == Member.Evidence.android, e.key == Member.Evidence.member else { return nil }
        let key = try Records.keyHash(cert: leaf)
        guard let d = devices.first(where: { $0.id == device && $0.key == key }) else { return nil }
        if let t = e.groupTag, t != tag { throw AndroidAttestation.Invalid(reason: "an attestation made for another group") }
        let challenge: Data
        do {
            challenge = try Attestation.challenge(groupTag: e.groupTag ?? "", memberKey: Data(), salt: e.salt)
        } catch {
            throw AndroidAttestation.Invalid(reason: "\(error)")
        }
        let r: AndroidAttestation.Result
        do {
            r = try AndroidAttestation.check(chain: e.chain, spki: try CertificateInfo(der: leaf).publicKey, challenge: challenge,
                                             policy: AndroidAttestation.Policy(revoked: revoked, roots: roots))
        } catch let x as AndroidAttestation.Invalid where x.revoked {
            // Revoked: the keys may still be in hardware, as the hello says,
            // but Google no longer vouches for the chain.
            guard d.store == Records.proven else { return nil }
            return try record(device: device, name: d.name, role: d.role, os: d.os, key: d.key, admin: d.adminKey,
                              powers: d.adminKey == nil ? nil : d.powers, commands: d.adminKey == nil ? nil : d.commands,
                              store: Records.hardware, kind: d.kind, proof: nil, seal: d.seal, forwardOnly: d.forwardOnly, caSigner: rootSigner, now: now)
        }
        if d.store == r.store, (d.kind ?? "") == r.kind { return nil }
        guard let first = e.chain.first else { return nil }
        let proof = r.store == Records.proven ? SHA256.hash(data: first).map { String(format: "%02x", $0) }.joined() : nil
        return try record(device: device, name: d.name, role: d.role, os: d.os, key: d.key, admin: d.adminKey,
                          powers: d.adminKey == nil ? nil : d.powers, commands: d.adminKey == nil ? nil : d.commands, store: r.store,
                          kind: r.kind.isEmpty ? nil : r.kind, proof: proof, seal: d.seal, forwardOnly: d.forwardOnly, caSigner: rootSigner, now: now)
    }

    /// The admin CA this phone issued for an admin key a computer offers,
    /// while that computer is still listed as an admin.
    public func computerAdminCA(for adminKey: Data) -> Data? {
        let listed = Set(devices.filter(\.admin).map(\.id))
        return computerAdmins.first { listed.contains($0.key) && (try? CertificateInfo(der: $0.value).publicKey) == adminKey }?.value
    }

    /// Admits a listening device over a pairing connection whose TLS
    /// handshake is done (section 6, "The joiner listens"): joinerCert is
    /// the device's certificate, already checked against the QR code's
    /// fingerprint, and sessionID the TLS exporter's output. The device
    /// gets a member certificate from this phone's CA and the group CA,
    /// never a key. A phone that sent an admin key becomes an admin when
    /// this phone is the root and makeAdmin is set: it gets an admin CA for
    /// that key. On success a computer is in computers, where one admitted
    /// again replaces its entry, and every device has its record. A
    /// computer keeps those of addrs that are on a home network, where the
    /// phone dialed it. With invitation, the device dialed this phone, the
    /// hub, with a remote invitation (section 12): code is unused and the
    /// device never becomes an admin.
    public mutating func admit(over t: FrameTransport, code: String, joinerCert: Data, sessionID: [UInt8],
                               caSigner: CertificateSigner, makeAdmin: Bool = true, addrs: [String] = [],
                               invitation: PairingMember.Invitation? = nil, now: Date) async throws -> PairingMember.Admitted {
        guard isAdmin else { throw Failure.notAdmin }
        let (first, later, root, ca, issuer) = (groupCA, roots, currentRoot, signingCA, adminCA)
        let canMakeAdmins = isRoot && invitation == nil
        let pathRecords = records.pathRecords, claimTimes = records.claimTimes
        var adminKey: Data?
        let admitted = try await PairingMember.admit(
            over: t, code: code, memberCert: memberCert, joinerCert: joinerCert, sessionID: sessionID,
            memberAD: Pairing.MemberAD(device: device, group: tag), taken: { [device, records] in $0 == device || records.knows($0) },
            invitation: invitation
        ) { dev, publicKey, info in
            var w = Pairing.Welcome(cert: try GroupCertificates.member(device: dev, publicKey: publicKey, ca: ca, caSigner: caSigner, now: now),
                                    groupCA: first, issuer: issuer)
            w.roots = later.isEmpty ? nil : later
            // The records let the new device take its peers at once; a
            // group never handed over leaves them out when they do not fit
            // in a frame, and the device gets them from its peers.
            (w.records, w.claimTimes) = (pathRecords.isEmpty ? nil : pathRecords, claimTimes.isEmpty ? nil : claimTimes)
            if later.isEmpty, ((try? JSONEncoder().encode(w))?.count ?? Int.max) > Pairing.maxFrame - Pairing.welcomeRoom {
                (w.records, w.claimTimes) = (nil, nil)
            }
            if info.isPhone, let key = info.adminKey, makeAdmin, canMakeAdmins {
                w.adminCA = try GroupCertificates.adminCA(device: dev, publicKey: key, root: root, rootSigner: caSigner)
                adminKey = key
            }
            return w
        }
        let name = Self.validName(admitted.info.name), key = try Records.keyHash(cert: admitted.cert)
        if admitted.info.isPhone {
            _ = try record(device: admitted.device, name: name, role: "phone", os: admitted.info.os, key: key,
                           admin: adminKey.map(Records.keyHash(spki:)), store: Records.hardware,
                           seal: admitted.info.seal, caSigner: caSigner, now: now)
            return admitted
        }
        computers.removeAll { $0.device == admitted.device }
        computers.append(Computer(device: admitted.device, name: admitted.info.name, os: admitted.info.os, cert: admitted.cert, admitted: now,
                                  addrs: addrs.filter(JoinCode.isHome)))
        _ = try record(device: admitted.device, name: name, role: admitted.info.role == Pairing.Info.lite ? "lite" : "full",
                       os: admitted.info.os, key: key, seal: admitted.info.seal, caSigner: caSigner, now: now)
        return admitted
    }

    /// Reads a saved group; nil when there is none.
    public static func load(from url: URL) throws -> PhoneGroup? {
        guard FileManager.default.fileExists(atPath: url.path) else { return nil }
        return try JSONDecoder().decode(PhoneGroup.self, from: Data(contentsOf: url))
    }

    /// Saves the group in one step, so a crash leaves the old file or the new one.
    public func save(to url: URL) throws {
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try enc.encode(self).write(to: url, options: [.atomic])
    }
}
