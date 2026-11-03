// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

@testable import CBBKit
import Foundation
import XCTest

/// Restoring a group on a new phone with the recovery key
/// (docs/protocol.md, section 10, "The recovery key"): the root phone is
/// lost, and a new phone scans the sheet, takes the records from a
/// computer of the group and claims the group.
final class RestoreTests: XCTestCase {
    /// When the group was made: long enough ago that a claim made then
    /// took effect by now.
    let t0 = Date().addingTimeInterval(-100 * 3600)

    struct Group {
        let rootKey = SoftwareSigner()
        var root: PhoneGroup
        var computer = RootTests.Computer()
        var recovery: PhoneGroup.Recovery

        init(t0: Date) throws {
            root = try PhoneGroup.create(caSigner: rootKey, memberKey: SoftwareSigner().publicKeyDER, name: "Lost", now: t0)
            root.records.clock = { t0 }
            computer.cert = try GroupCertificates.member(device: computer.device, publicKey: computer.key.publicKeyDER, ca: root.groupCA,
                                                         caSigner: rootKey, now: t0)
            _ = try root.record(device: computer.device, name: "one", role: "full", key: computer.keyHash, caSigner: rootKey, now: t0)
            recovery = try root.makeRecovery(rootSigner: rootKey, now: t0)
        }

        func sheet() throws -> Core.RecoveredKey {
            guard case let .key(k) = try Core.readRecoverySheet(recovery.sheet.qr) else { throw XCTSkip("the QR code is refused") }
            return k
        }
    }

    /// Plays the computer's side of a records-only connection, as Go's
    /// node does with a device no record names: its hello with groupCA,
    /// then its records, then whatever arrives until the phone closes.
    func computer(_ records: [Member.Record], groupCA: Data?, chain: [Data]) -> (Pipe, Task<[Member.Record], Error>) {
        let (phone, pc) = Pipe.pair()
        phone.chain = chain
        let got = Task {
            try await pc.write(Member.encode(.hello(.full, Member.Hello(wallMS: 0, name: "one", os: "linux", groupCA: groupCA))))
            func next() async throws -> Member.Message {
                let (n, _) = try Member.header(try await pc.read(exactly: 4))
                return try Member.decode(body: try await pc.read(exactly: n))
            }
            guard case let .hello(_, h) = try await next() else { throw POSIXError(.EPROTO) }
            XCTAssertNil(h.records, "the phone holds no records yet")
            for c in Member.Record.chunks(records) { try await pc.write(Member.encode(.records(c))) }
            var got: [Member.Record] = []
            while let m = try? await next() {
                if case let .records(rs) = m { got += rs }
            }
            return got
        }
        return (phone, got)
    }

    func testRestores() async throws {
        let g = try Group(t0: t0)
        let memberKey = SoftwareSigner()
        let r = try Restore(key: try g.sheet(), memberKey: memberKey.publicKeyDER, now: t0)
        XCTAssertEqual(r.chain, [r.memberCert, g.recovery.adminCA])

        let (phone, pc) = computer(g.root.records.records, groupCA: g.root.groupCA, chain: [g.computer.cert])
        let fetched = try await Restore.exchange(phone, name: "New", os: "ios", now: t0, quiet: 0.3)
        _ = try await pc.value
        var group = try r.group(fetched, now: t0)
        group.records.clock = { self.t0 }
        XCTAssertFalse(group.isRoot)
        XCTAssertEqual(group.tag, g.root.tag)
        XCTAssertFalse(group.devices.contains { $0.id == r.device }, "no record names the new phone yet")
        guard case .notListed = group.records.verdict(chain: r.chain) else { return XCTFail("the computers take its chain for records only") }

        let newRootKey = SoftwareSigner()
        let newRoot = try GroupCertificates.groupCA(signer: newRootKey, now: t0, pathLength: 1)
        let claim = try r.claim(&group, newRoot: newRoot, now: t0)
        XCTAssertEqual(group.claimState, "pending")
        XCTAssertTrue(try group.finishTakeOver(rootSigner: newRootKey, now: t0).isEmpty, "the claim waits")

        // The claim reaches the computer on the next exchange.
        let (phone2, pc2) = computer(g.root.records.records, groupCA: g.root.groupCA, chain: [g.computer.cert])
        _ = try await Restore.exchange(phone2, name: "New", os: "ios", now: t0, send: [claim], quiet: 0.3)
        let sent = try await pc2.value
        XCTAssertEqual(sent, [claim])

        // Once the delay ran out, the phone is the root.
        group.records.clock = { Date() }
        let rs = try group.finishTakeOver(rootSigner: newRootKey, now: Date(), name: "New")
        XCTAssertTrue(group.isRoot)
        XCTAssertNil(group.memberIssuer)
        XCTAssertNil(group.adminCA)
        XCTAssertEqual(group.records.rootDevice, r.device)
        XCTAssertEqual(group.devices.map(\.name).sorted(), ["New", "one"], "the lost root's device goes")
        XCTAssertFalse(rs.isEmpty)
        XCTAssertEqual(try GroupCertificates.verifyMember(chain: group.memberChain, roots: [newRoot], now: Date()), r.device)
        XCTAssertEqual(try CertificateInfo(der: r.memberCert).publicKey, try CertificateInfo(der: group.memberCert).publicKey, "the same member key")
        XCTAssertEqual(group.records.verdict(chain: group.memberChain), .ok)
    }

    /// The same with the recovery key on a YubiKey: the card signs the
    /// member certificate, then, held again, the claim.
    func testRestoresWithCard() async throws {
        var g = try Group(t0: t0)
        let card = FakePivCard()
        try Piv.select(card)
        try Piv.verify(card, pin: "123456")
        try Piv.authenticate(card)
        let slot = try Piv.freeSlot(card)
        let (ca, _) = try g.root.makeRecoveryOnCard(publicKey: try Piv.generate(card, slot: slot), rootSigner: g.rootKey, now: t0)
        try Piv.putCertificate(card, slot: slot, cert: ca)

        try Piv.select(card)
        let keys = try Piv.recoveryKeys(card)
        XCTAssertEqual(keys.count, 1)
        let spki = try CertificateInfo(der: keys[0].cert).publicKey
        let r = try Restore(card: Piv.Signer(card: card, slot: keys[0].slot, publicKeyDER: spki, pin: "123456"), adminCA: keys[0].cert,
                            memberKey: SoftwareSigner().publicKeyDER, now: t0)
        let (phone, pc) = computer(g.root.records.records, groupCA: g.root.groupCA, chain: [g.computer.cert])
        let fetched = try await Restore.exchange(phone, name: "New", os: "ios", now: t0, quiet: 0.3)
        _ = try await pc.value
        var group = try r.group(fetched, now: t0)
        group.records.clock = { self.t0 }
        let newRoot = try GroupCertificates.groupCA(signer: SoftwareSigner(), now: t0, pathLength: 1)
        XCTAssertThrowsError(try r.claim(&group, newRoot: newRoot, now: t0, with: SoftwareSigner()))
        try Piv.select(card)
        _ = try r.claim(&group, newRoot: newRoot, now: t0, with: Piv.Signer(card: card, slot: keys[0].slot, publicKeyDER: spki, pin: "123456"))
        XCTAssertEqual(group.claimState, "pending")
        XCTAssertEqual(card.signed, 2)
    }

    func testRefusesWhatDoesNotFit() async throws {
        var g = try Group(t0: t0)
        let memberKey = SoftwareSigner().publicKeyDER

        // A typed key carries no admin CA.
        guard case let .key(typed) = try Core.readRecoverySheet(g.recovery.sheet.text) else { return XCTFail("the text is refused") }
        do {
            _ = try Restore(key: typed, memberKey: memberKey, now: t0)
            XCTFail("a typed key restored")
        } catch let e as Restore.Failure {
            XCTAssertEqual(e.kind, .needsQR)
        }

        func refused(_ records: [Member.Record], groupCA: Data?, chain: [Data], key: Core.RecoveredKey) async throws -> Restore.Kind? {
            let r = try Restore(key: key, memberKey: memberKey, now: t0)
            let (phone, pc) = computer(records, groupCA: groupCA, chain: chain)
            let f = try await Restore.exchange(phone, name: "New", os: "ios", now: t0, quiet: 0.3)
            _ = try await pc.value
            do {
                _ = try r.group(f, now: t0)
                return nil
            } catch let e as Restore.Failure {
                return e.kind
            }
        }
        let sheet = try g.sheet()
        let mine = [g.computer.cert]
        var kind = try await refused(g.root.records.records, groupCA: nil, chain: mine, key: sheet)
        XCTAssertEqual(kind, .notAMember, "no group CA")

        let other = try Group(t0: t0)
        kind = try await refused(other.root.records.records, groupCA: other.root.groupCA, chain: [other.computer.cert], key: sheet)
        XCTAssertEqual(kind, .otherGroup)

        let stranger = try GroupCertificates.member(device: SyncEngine.newID(), publicKey: SoftwareSigner().publicKeyDER, ca: other.root.groupCA,
                                                    caSigner: other.rootKey, now: t0)
        kind = try await refused(g.root.records.records, groupCA: g.root.groupCA, chain: [stranger], key: sheet)
        XCTAssertEqual(kind, .notAMember, "a computer of another group")
        let unlisted = try GroupCertificates.member(device: SyncEngine.newID(), publicKey: SoftwareSigner().publicKeyDER, ca: g.root.groupCA,
                                                    caSigner: g.rootKey, now: t0)
        kind = try await refused(g.root.records.records, groupCA: g.root.groupCA, chain: [unlisted], key: sheet)
        XCTAssertEqual(kind, .notAMember, "a computer the records do not list")

        // The root made a new recovery key: the old sheet no longer counts.
        _ = try g.root.makeRecovery(rootSigner: g.rootKey, now: t0.addingTimeInterval(1))
        kind = try await refused(g.root.records.records, groupCA: g.root.groupCA, chain: mine, key: sheet)
        XCTAssertEqual(kind, .notTheKey)
    }
}
