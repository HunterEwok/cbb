// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import Crypto
import Foundation

/// Restoring a group on a new phone with the group's recovery key, scanned
/// from the QR code of its sheet (docs/protocol.md, section 10, "The
/// recovery key"). The recovery key issues this phone a member certificate
/// under its own admin CA; a computer of the group takes it on a connection
/// that carries records only and sends the group's first root in its hello.
/// The phone checks the records, then claims the group for a new root of
/// its own through the core's member; the claim waits the group's delay,
/// unless the root cancels it, and CoreMember.finishTakeover and
/// PhoneGroup.becameRoot then make the phone the root. The recovery key
/// is not kept: the claim is the one thing it signs.
public struct Restore: Sendable {
    public enum Kind: Sendable {
        /// The key was typed: a new phone needs the QR code, which carries
        /// the key's admin CA.
        case needsQR
        /// The computer is of another group than the sheet.
        case otherGroup
        /// The group has no recovery key now, or another one: the root
        /// removed or replaced this one.
        case notTheKey
        /// The computer's answer or certificate does not fit the group's
        /// records.
        case notAMember
    }

    public struct Failure: Error, CustomStringConvertible {
        public let kind: Kind
        public let message: String
        public var description: String { message }

        public init(kind: Kind, message: String) {
            (self.kind, self.message) = (kind, message)
        }
    }

    public static let needsQRMessage = "scan the QR code of the recovery sheet: on a new phone the typed key is not enough"
    public static let notTheKeyMessage = "this is not the group's recovery key now: the root removed it or made a new one"

    /// How long the computer stays quiet before the exchange counts as
    /// done, in seconds; it closes after 5 s.
    public static let quiet: Double = 2
    /// How long the computer's hello takes at most, in seconds, as a TLS
    /// handshake does.
    static let helloWait: Double = 10
    /// The most records one exchange takes: the core's set keeps no more.
    static let maxRecords = 4096

    /// The recovery key as a signer: a software key from the sheet, or the
    /// key on a YubiKey.
    private let signer: any CertificateSigner & Sendable
    /// The key hash of the admin CA's key, which the records name.
    private let admin: Data
    /// The group's tag from the sheet's QR code; nil from a YubiKey.
    private let groupTag: String?
    /// The recovery key's admin CA, DER, from the QR code or the YubiKey's slot.
    public let adminCA: Data
    /// This phone's new device ID.
    public let device: String
    /// This phone's member certificate, from the recovery key's admin CA.
    public let memberCert: Data
    /// The chain this phone presents in TLS, leaf first.
    public var chain: [Data] { [memberCert, adminCA] }

    /// memberKey is this phone's member key, a SubjectPublicKeyInfo; the
    /// key itself stays in the keychain.
    public init(key: Core.RecoveredKey, memberKey: Data, now: Date) throws {
        guard let ca = key.cert else { throw Failure(kind: .needsQR, message: Self.needsQRMessage) }
        guard let k = try? P256.Signing.PrivateKey(rawRepresentation: key.key), k.publicKey.x963Representation == key.public else {
            throw Failure(kind: .needsQR, message: "the recovery key is not a P-256 key")
        }
        guard (try? Records.keyHash(cert: ca)) == key.admin else { throw Failure(kind: .needsQR, message: "the sheet's admin CA is for another key") }
        try self.init(signer: SoftwareSigner(k), adminCA: ca, admin: key.admin, groupTag: key.group, memberKey: memberKey, now: now)
    }

    /// Restores with the recovery key on a YubiKey: signer is the key in
    /// the slot whose certificate, adminCA, is the key's admin CA
    /// (Piv.recoveryKeys). The card signs this phone's member certificate
    /// here and, held again, the claim.
    public init(card signer: Piv.Signer, adminCA: Data, memberKey: Data, now: Date) throws {
        guard let info = try? CertificateInfo(der: adminCA) else { throw Failure(kind: .notTheKey, message: "the YubiKey's certificate does not parse") }
        guard info.publicKey == signer.publicKeyDER else { throw Failure(kind: .notTheKey, message: "the YubiKey's certificate is for another key") }
        try self.init(signer: signer, adminCA: adminCA, admin: Records.keyHash(spki: info.publicKey), groupTag: nil, memberKey: memberKey, now: now)
    }

    private init(signer: any CertificateSigner & Sendable, adminCA: Data, admin: Data, groupTag: String?, memberKey: Data, now: Date) throws {
        (self.signer, self.adminCA, self.admin, self.groupTag) = (signer, adminCA, admin, groupTag)
        device = Member.newID()
        memberCert = try GroupCertificates.member(device: device, publicKey: memberKey, ca: adminCA, caSigner: signer, now: now)
    }

    /// What a computer sent on a records-only connection.
    public struct Fetched: Sendable {
        /// The group's first root, DER, from the computer's hello.
        public var groupCA: Data?
        public var records: [Member.Record]
        /// The computer's certificate chain from the TLS handshake.
        public var peerChain: [Data]
    }

    /// Checks what a computer of the group sent (fetched), and returns the
    /// group as this phone holds it before its claim: a member whose
    /// certificate the recovery key issued, its records and roots. The
    /// group's first root must carry the sheet's tag, the records must name
    /// the recovery key in their state and lead to a root that issued its
    /// admin CA, and the computer's certificate must verify to a root on
    /// the path and name a device the records list.
    public func group(_ fetched: Fetched, now: Date) throws -> PhoneGroup {
        guard let groupCA = fetched.groupCA else { throw Failure(kind: .notAMember, message: "the computer did not send the group's first root") }
        if let tag = groupTag, tag != GroupCertificates.tag(groupCA: groupCA) {
            throw Failure(kind: .otherGroup, message: "the computer is of another group than the sheet")
        }
        do {
            try GroupCertificates.checkRoot(groupCA)
        } catch {
            throw Failure(kind: .notAMember, message: "the group's first root is not a root: \(error)")
        }
        var g = PhoneGroup(device: device, groupCA: groupCA, memberCert: memberCert, computers: [])
        (g.isRoot, g.memberIssuer, g.adminCA) = (false, adminCA, adminCA)
        g.records.addAll(fetched.records, groupCA: groupCA)
        g.adoptRoots()
        guard g.records.recovery == admin, !g.records.revoked.contains(admin) else {
            throw Failure(kind: .notTheKey, message: Self.notTheKeyMessage)
        }
        guard g.trusted.contains(where: { (try? GroupCertificates.checkAdminCA(adminCA, root: $0)) != nil }) else {
            throw Failure(kind: .notTheKey, message: "no root of the group issued the recovery key's admin CA")
        }
        let peer: String
        do {
            peer = try GroupCertificates.verifyMember(chain: fetched.peerChain, roots: g.trusted, now: now)
        } catch {
            throw Failure(kind: .notAMember, message: "the computer's certificate is not from the group: \(error)")
        }
        guard g.devices.contains(where: { $0.id == peer }), g.records.verdict(chain: fetched.peerChain) == .ok else {
            throw Failure(kind: .notAMember, message: "the records do not list the computer")
        }
        return g
    }

    /// Claims group, which group(_:now:) returned, for newRoot, a root CA
    /// for a new key of this phone (CoreMember.rootCA), with the recovery
    /// key, through member, the core's member running as this phone, which
    /// adds the claim to its records and sends it. with is the recovery key
    /// again, as a YubiKey held to the phone a second time gives it.
    public func claim(_ group: inout PhoneGroup, member: CoreMember, newRoot: Data, with: (any CertificateSigner)? = nil) throws {
        let s: any CertificateSigner = with ?? signer
        guard s.publicKeyDER == signer.publicKeyDER else {
            throw Failure(kind: .notTheKey, message: "this is another key than the one that issued this phone's certificate")
        }
        try group.checkRecovery()
        try member.claim(.recover, rootCA: newRoot, public: s.publicKeyDER, ca: adminCA, sign: { try s.signature(digest: $0) })
        group.claimed(newRoot: newRoot, lost: group.records.rootDevice)
    }

    /// Exchanges records with a computer on a connection that carries
    /// records only (docs/protocol.md, section 10, "Records only"): this
    /// phone's hello without a digest, so the computer sends all its
    /// records; then send, once the computer's hello came; then whatever
    /// arrives until it is quiet for quiet seconds. It closes t.
    public static func exchange(_ t: ClosableTransport, name: String, os: String, now: Date, send: [Member.Record] = [],
                                quiet: Double = Restore.quiet) async throws -> Fetched {
        defer { t.close() }
        let inbox = Inbox()
        try await t.write(Member.encode(.hello(.phone, Member.Hello(wallMS: Records.ms(now), name: name, os: os))))
        let reader = Task {
            do {
                while true {
                    let (n, binary) = try Member.header(try await t.read(exactly: 4))
                    let body = try await t.read(exactly: n)
                    if !binary { inbox.put(.success(try Member.decode(body: body))) }
                }
            } catch {
                inbox.put(.failure(error))
            }
        }
        defer { reader.cancel() }
        var groupCA: Data?
        var hello = false
        var records: [Member.Record] = []
        while true {
            let m = await inbox.next(within: hello ? quiet : helloWait)
            switch m {
            case nil:
                guard hello else { throw Failure(kind: .notAMember, message: "the computer sent no hello") }
                return Fetched(groupCA: groupCA, records: records, peerChain: t.peerChain)
            case let .failure(e)?:
                guard hello else { throw Failure(kind: .notAMember, message: "the computer closed the connection: \(e)") }
                return Fetched(groupCA: groupCA, records: records, peerChain: t.peerChain)
            case let .success(msg)?:
                if !hello {
                    guard case let .hello(_, h) = msg else { throw Failure(kind: .notAMember, message: "the computer did not start with a hello") }
                    (hello, groupCA) = (true, h.groupCA)
                    for chunk in Member.Record.chunks(send) { try await t.write(Member.encode(.records(chunk))) }
                } else if case let .records(rs) = msg, records.count + rs.count <= maxRecords {
                    records += rs
                }
            }
        }
    }

    /// The messages a reader took, for one waiter at a time.
    private final class Inbox: @unchecked Sendable {
        private let lock = NSLock()
        private var items: [Result<Member.Message, Error>] = []
        private var waiter: CheckedContinuation<Result<Member.Message, Error>?, Never>?
        private var turn = 0

        func put(_ r: Result<Member.Message, Error>) {
            let w: CheckedContinuation<Result<Member.Message, Error>?, Never>? = lock.withLock {
                guard let w = waiter else {
                    items.append(r)
                    return nil
                }
                waiter = nil
                return w
            }
            w?.resume(returning: r)
        }

        /// The next message, or nil after seconds without one.
        func next(within seconds: Double) async -> Result<Member.Message, Error>? {
            await withCheckedContinuation { c in
                let ready: Result<Member.Message, Error>?? = lock.withLock {
                    if !items.isEmpty { return .some(items.removeFirst()) }
                    waiter = c
                    turn += 1
                    return .none
                }
                if let r = ready {
                    c.resume(returning: r)
                    return
                }
                let mine = lock.withLock { turn }
                Task {
                    try? await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000))
                    let w: CheckedContinuation<Result<Member.Message, Error>?, Never>? = self.lock.withLock {
                        guard self.turn == mine, let w = self.waiter else { return nil }
                        self.waiter = nil
                        return w
                    }
                    w?.resume(returning: nil)
                }
            }
        }
    }
}
