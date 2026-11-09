// SPDX-License-Identifier: AGPL-3.0-only

@testable import CBBKit
import Foundation
import XCTest

/// A computer as admin (docs/protocol.md, section 10): the root phone
/// certifies the admin key that a computer's hello offers.
final class ComputerAdminTests: XCTestCase {
    let t0 = Date()
    /// Later than t0, so that the admin record replaces the computer's first.
    var t1: Date { t0.addingTimeInterval(1) }

    /// The root phone's group with one computer, pi, in its list.
    func group() throws -> (g: PhoneGroup, root: SoftwareSigner, pi: String, piKey: Data) {
        let root = SoftwareSigner()
        var g = try PhoneGroup.create(caSigner: root, memberKey: SoftwareSigner().publicKeyDER, now: t0)
        let pi = Member.newID()
        let cert = try GroupCertificates.member(device: pi, publicKey: SoftwareSigner().publicKeyDER, ca: g.groupCA, caSigner: root, now: t0)
        let key = try Records.keyHash(cert: cert)
        _ = try g.record(device: pi, name: "pi", role: "member", caps: Records.caps, key: key, caSigner: root, now: t0)
        // Its computers keep their keys in files, which the level files lets in.
        _ = try g.setKeyLevel(Records.levelFiles, rootSigner: root, now: t0)
        return (g, root, pi, key)
    }

    /// The key level decides who may be an admin; the root sets it, keeping
    /// the takeover delay, and never above its own key.
    func testKeyLevel() throws {
        let root = SoftwareSigner()
        var g = try PhoneGroup.create(caSigner: root, memberKey: SoftwareSigner().publicKeyDER, now: t0)
        XCTAssertEqual(g.keyLevel, Records.hardware)
        let pi = Member.newID()
        let cert = try GroupCertificates.member(device: pi, publicKey: SoftwareSigner().publicKeyDER, ca: g.groupCA, caSigner: root, now: t0)
        _ = try g.record(device: pi, name: "pi", role: "member", caps: Records.caps, key: try Records.keyHash(cert: cert), caSigner: root, now: t0)
        let adminKey = SoftwareSigner().publicKeyDER
        // At the level hardware a key in a file is no admin, even with the consent.
        XCTAssertThrowsError(try g.makeAdmin(device: pi, adminKey: adminKey, rootSigner: root, now: t1, keyStore: Records.file, allowFileKey: true)) {
            XCTAssertEqual($0 as? PhoneGroup.Failure, .belowKeyLevel)
        }
        // At the level proven, a key in hardware without a proof is not either.
        XCTAssertThrowsError(try g.setKeyLevel(Records.proven, rootSigner: root, now: t1)) {
            XCTAssertEqual($0 as? PhoneGroup.Failure, .belowKeyLevel, "the root's own key is not proven")
        }
        XCTAssertThrowsError(try g.setKeyLevel("any", rootSigner: root, now: t1)) {
            XCTAssertEqual($0 as? PhoneGroup.Failure, .invalidKeyLevel)
        }
        _ = try g.setTakeoverDelay(ms: 3_600_000, rootSigner: root, now: t1)
        _ = try g.setKeyLevel(Records.levelFiles, rootSigner: root, now: t1)
        XCTAssertEqual(g.keyLevel, Records.levelFiles)
        XCTAssertEqual(g.settings(of: PhoneGroup.signer(root)).delay, 3_600_000, "the level keeps the delay")
        _ = try g.makeAdmin(device: pi, adminKey: adminKey, rootSigner: root, now: t1, keyStore: Records.file, allowFileKey: true)
        XCTAssertEqual(g.belowKeyLevel(Records.hardware), [pi])
        XCTAssertEqual(g.belowKeyLevel(Records.levelFiles), [])
        _ = try g.setTakeoverDelay(ms: 0, rootSigner: root, now: t1)
        XCTAssertEqual(g.keyLevel, Records.levelFiles, "the delay keeps the level")
        var member = g
        member.isRoot = false
        XCTAssertThrowsError(try member.setKeyLevel(Records.hardware, rootSigner: root, now: t1)) {
            XCTAssertEqual($0 as? PhoneGroup.Failure, .notRoot)
        }
    }

    func testWire() throws {
        let key = SoftwareSigner().publicKeyDER
        let hello = Member.Message.hello(.member, Member.Hello(wallMS: 1, name: "pi", adminKey: key))
        let body = Data(try Member.encode(hello).dropFirst(4))
        XCTAssertTrue(String(decoding: body, as: UTF8.self).contains("\"admin_key\""))
        XCTAssertEqual(try Member.decode(body: body), hello)
        let admin = Member.Message.admin(Data([1, 2, 3]))
        let adminBody = Data(try Member.encode(admin).dropFirst(4))
        XCTAssertEqual(String(decoding: adminBody, as: UTF8.self), #"{"admin_ca":"AQID","t":"admin"}"#)
        XCTAssertEqual(try Member.decode(body: adminBody), admin)
        guard case let .hello(_, h) = try Member.decode(body: Data(#"{"t":"hello","role":"member","hello":{"wall_ms":0}}"#.utf8)) else {
            return XCTFail("not a hello")
        }
        XCTAssertNil(h.adminKey)
    }

    func testRename() throws {
        let t = try group()
        var g = t.g
        let (ca, _) = try g.makeAdmin(device: t.pi, adminKey: SoftwareSigner().publicKeyDER, rootSigner: t.root, now: t1, allowFileKey: true)
        let r = try g.rename(device: t.pi, to: "  living room pi ", caSigner: t.root, now: t1.addingTimeInterval(1))
        XCTAssertTrue(g.records.records.contains(r))
        let d = try XCTUnwrap(g.devices.first { $0.id == t.pi })
        XCTAssertEqual(d.name, "living room pi")
        XCTAssertTrue(d.admin)
        XCTAssertEqual(d.adminKey, try Records.keyHash(cert: ca))
        XCTAssertEqual(d.key, t.piKey)
        XCTAssertEqual(d.role, "member")
        XCTAssertThrowsError(try g.rename(device: t.pi, to: " ", caSigner: t.root, now: t1)) {
            XCTAssertEqual($0 as? PhoneGroup.Failure, .invalidName)
        }
        XCTAssertThrowsError(try g.rename(device: t.pi, to: String(repeating: "x", count: 65), caSigner: t.root, now: t1)) {
            XCTAssertEqual($0 as? PhoneGroup.Failure, .invalidName)
        }
        XCTAssertThrowsError(try g.rename(device: Member.newID(), to: "x", caSigner: t.root, now: t1)) {
            XCTAssertEqual($0 as? PhoneGroup.Failure, .unknownDevice)
        }
    }

    func testMakeAdmin() throws {
        let t = try group()
        var g = t.g
        let (root, pi, piKey) = (t.root, t.pi, t.piKey)
        let adminKey = SoftwareSigner()
        // A computer whose keys sit in a file, or that does not say, needs
        // the user's consent.
        for store in [nil, Records.file] {
            XCTAssertThrowsError(try g.makeAdmin(device: pi, adminKey: adminKey.publicKeyDER, rootSigner: root, now: t1, keyStore: store)) {
                XCTAssertEqual($0 as? PhoneGroup.Failure, .fileKey)
            }
        }
        // A rootless install never, even with the consent (D-79).
        XCTAssertThrowsError(try g.makeAdmin(device: pi, adminKey: adminKey.publicKeyDER, rootSigner: root, now: t1,
                                             keyStore: Records.rootless, allowFileKey: true)) {
            XCTAssertEqual($0 as? PhoneGroup.Failure, .rootless)
        }
        XCTAssertEqual(Records.store(Records.rootless, role: "member"), Records.rootless)
        let (ca, r) = try g.makeAdmin(device: pi, adminKey: adminKey.publicKeyDER, rootSigner: root, now: t1, allowFileKey: true)
        XCTAssertEqual(try CertificateInfo(der: ca).publicKey, adminKey.publicKeyDER)
        let d = try XCTUnwrap(g.devices.first { $0.id == pi })
        XCTAssertTrue(d.admin)
        XCTAssertEqual(d.store, Records.file)
        XCTAssertEqual(g.devices.first { $0.id == g.device }?.store, Records.hardware)
        XCTAssertEqual(d.adminKey, try Records.keyHash(cert: ca))
        XCTAssertEqual(d.key, piKey)
        XCTAssertTrue(g.records.records.contains(r))
        XCTAssertEqual(g.computerAdminCA(for: adminKey.publicKeyDER), ca)
        XCTAssertNil(g.computerAdminCA(for: SoftwareSigner().publicKeyDER))

        let url = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString + ".json")
        defer { try? FileManager.default.removeItem(at: url) }
        try g.save(to: url)
        XCTAssertEqual(try PhoneGroup.load(from: url)?.computerAdmins, g.computerAdmins)

        XCTAssertThrowsError(try g.makeAdmin(device: g.device, adminKey: SoftwareSigner().publicKeyDER, rootSigner: root, now: t0, allowFileKey: true)) {
            XCTAssertEqual($0 as? PhoneGroup.Failure, .alreadyAdmin, "the root is more than an admin")
        }
        XCTAssertThrowsError(try g.makeAdmin(device: pi, adminKey: SoftwareSigner().publicKeyDER, rootSigner: root, now: t0, allowFileKey: true)) {
            XCTAssertEqual($0 as? PhoneGroup.Failure, .alreadyAdmin)
        }
        XCTAssertThrowsError(try g.makeAdmin(device: Member.newID(), adminKey: adminKey.publicKeyDER, rootSigner: root, now: t0, allowFileKey: true)) {
            XCTAssertEqual($0 as? PhoneGroup.Failure, .unknownDevice)
        }
        var notRoot = g
        notRoot.isRoot = false
        XCTAssertThrowsError(try notRoot.makeAdmin(device: pi, adminKey: adminKey.publicKeyDER, rootSigner: root, now: t0, allowFileKey: true)) {
            XCTAssertEqual($0 as? PhoneGroup.Failure, .notRoot)
        }

        // The admin computer admits the deck; removing the computer keeps it.
        let deck = Member.newID()
        let deckCert = try GroupCertificates.member(device: deck, publicKey: SoftwareSigner().publicKeyDER, ca: ca, caSigner: adminKey, now: t0)
        g.add([try g.records.sign(.device(deck, name: "deck", role: "member", key: Records.keyHash(cert: deckCert), signer: adminKey, now: t0),
                                  with: adminKey, adminCA: ca)])
        XCTAssertTrue(g.devices.contains { $0.id == deck })
        _ = try g.revoke(device: pi, caSigner: root, now: t0)
        XCTAssertEqual(Set(g.devices.map(\.id)), [g.device, deck])
        XCTAssertNil(g.computerAdmins[pi])
        XCTAssertNil(g.computerAdminCA(for: adminKey.publicKeyDER))
    }

    /// A phone joins as a member, and the root makes it an admin later
    /// with the admin key its hello offers (section 10, "Making a device an
    /// admin"); the phone takes the admin CA only for its own key and
    /// device, from the current root.
    func testMakePhoneAdmin() throws {
        let t = try group()
        var g = t.g
        let phone = Member.newID()
        let cert = try GroupCertificates.member(device: phone, publicKey: SoftwareSigner().publicKeyDER, ca: g.groupCA, caSigner: t.root, now: t0)
        _ = try g.record(device: phone, name: "iPhone", role: "phone", os: "ios", key: try Records.keyHash(cert: cert), store: Records.hardware,
                         caSigner: t.root, now: t0)
        // A key the group already names is refused: the root's, or another device's.
        for taken in [t.root.publicKeyDER] {
            XCTAssertThrowsError(try g.makeAdmin(device: phone, adminKey: taken, rootSigner: t.root, now: t1)) {
                XCTAssertEqual($0 as? PhoneGroup.Failure, .keyTaken)
            }
        }
        let adminKey = SoftwareSigner()
        // The phone's store is its record's, whatever the hello says.
        let (ca, r) = try g.makeAdmin(device: phone, adminKey: adminKey.publicKeyDER, rootSigner: t.root, now: t1, keyStore: Records.file)
        XCTAssertTrue(g.records.records.contains(r))
        let d = try XCTUnwrap(g.devices.first { $0.id == phone })
        XCTAssertTrue(d.admin)
        XCTAssertEqual(d.role, "phone")
        XCTAssertEqual(d.store, Records.hardware)
        XCTAssertEqual(Set(d.powers), Set(Records.powers))
        XCTAssertEqual(g.computerAdminCA(for: adminKey.publicKeyDER), ca, "the root sends it again while the phone offers the key")

        // The member phone's side.
        var member = g
        (member.isRoot, member.device, member.adminCA) = (false, phone, nil)
        XCTAssertThrowsError(try member.takeAdminCA(ca, adminKey: SoftwareSigner().publicKeyDER)) {
            XCTAssertEqual($0 as? PhoneGroup.Failure, .notThisAdminCA, "another key")
        }
        var other = member
        other.device = Member.newID()
        XCTAssertThrowsError(try other.takeAdminCA(ca, adminKey: adminKey.publicKeyDER)) {
            XCTAssertEqual($0 as? PhoneGroup.Failure, .notThisAdminCA, "another device")
        }
        let foreign = try GroupCertificates.adminCA(device: phone, publicKey: adminKey.publicKeyDER,
                                                    root: try PhoneGroup.create(caSigner: SoftwareSigner(), memberKey: SoftwareSigner().publicKeyDER,
                                                                                now: t0).groupCA,
                                                    rootSigner: SoftwareSigner())
        XCTAssertThrowsError(try member.takeAdminCA(foreign, adminKey: adminKey.publicKeyDER)) {
            XCTAssertEqual($0 as? PhoneGroup.Failure, .notThisAdminCA, "another root")
        }
        XCTAssertFalse(member.isAdmin)
        try member.takeAdminCA(ca, adminKey: adminKey.publicKeyDER)
        XCTAssertTrue(member.isAdmin)
        XCTAssertEqual(member.adminCA, ca)
        XCTAssertThrowsError(try member.takeAdminCA(ca, adminKey: adminKey.publicKeyDER)) {
            XCTAssertEqual($0 as? PhoneGroup.Failure, .alreadyAdmin)
        }
    }

    /// The root makes a watch an admin (section 10, "Watches"): its record
    /// names the admin CA as key and admin, it may freeze but admits
    /// nobody, and removing it takes it out of the list.
    func testAddWatch() throws {
        let t = try group()
        var g = t.g
        let watchKey = SoftwareSigner(), watch = Member.newID()
        for (id, os) in [("ABC", "watchos"), (watch.uppercased(), "watchos"), (watch, "ios"), (g.device, "watchos")] {
            XCTAssertThrowsError(try g.addWatch(device: id, name: "Watch", os: os, adminKey: watchKey.publicKeyDER, rootSigner: t.root, now: t1)) {
                XCTAssertEqual($0 as? PhoneGroup.Failure, .notAWatch, "\(id) \(os)")
            }
        }
        var notRoot = g
        notRoot.isRoot = false
        XCTAssertThrowsError(try notRoot.addWatch(device: watch, name: "Watch", os: "watchos", adminKey: watchKey.publicKeyDER,
                                                  rootSigner: t.root, now: t1)) { XCTAssertEqual($0 as? PhoneGroup.Failure, .notRoot) }
        let (ca, r) = try g.addWatch(device: watch, name: " My watch ", os: "watchos", adminKey: watchKey.publicKeyDER, rootSigner: t.root, now: t1)
        XCTAssertEqual(try CertificateInfo(der: ca).publicKey, watchKey.publicKeyDER)
        XCTAssertTrue(g.records.records.contains(r))
        let d = try XCTUnwrap(g.devices.first { $0.id == watch })
        let key = try Records.keyHash(cert: ca)
        XCTAssertEqual(d.name, "My watch")
        XCTAssertEqual(d.role, "watch")
        XCTAssertEqual(d.os, "watchos")
        XCTAssertEqual(d.store, Records.hardware)
        XCTAssertEqual(d.key, key)
        XCTAssertEqual(d.adminKey, key)
        XCTAssertTrue(d.admin)
        XCTAssertEqual(d.powers, Records.watchPowers)
        XCTAssertFalse(g.records.mayHost(watch))

        // A device record the watch signs admits nobody.
        let deck = Member.newID()
        let deckCert = try GroupCertificates.member(device: deck, publicKey: SoftwareSigner().publicKeyDER, ca: ca, caSigner: watchKey, now: t0)
        g.add([try g.records.sign(.device(deck, name: "deck", role: "member", key: Records.keyHash(cert: deckCert), signer: watchKey, now: t1),
                                  with: watchKey, adminCA: ca)])
        XCTAssertFalse(g.devices.contains { $0.id == deck })
        XCTAssertNotNil(g.records.refused(chain: [deckCert, ca]))

        _ = try g.revoke(device: watch, caSigner: t.root, now: t1.addingTimeInterval(1))
        XCTAssertFalse(g.devices.contains { $0.id == watch })
        XCTAssertTrue(g.records.revoked.contains(key))
    }

    /// The watch's emergency actions (section 10, "Watches"): the phone builds
    /// the body, the watch signs it, and what it signed counts as the rules
    /// say.
    func testWatchActions() throws {
        let t = try group()
        var g = t.g
        _ = try g.makeAdmin(device: t.pi, adminKey: SoftwareSigner().publicKeyDER, rootSigner: t.root, now: t1, allowFileKey: true)
        let deck = Member.newID()
        let deckCert = try GroupCertificates.member(device: deck, publicKey: SoftwareSigner().publicKeyDER, ca: g.groupCA, caSigner: t.root, now: t0)
        _ = try g.record(device: deck, name: "deck", role: "member", caps: Records.caps, key: Records.keyHash(cert: deckCert), caSigner: t.root, now: t0)
        let watchKey = SoftwareSigner(), watch = Member.newID()
        let (ca, _) = try g.addWatch(device: watch, name: "Watch", os: "watchos", adminKey: watchKey.publicKeyDER, rootSigner: t.root, now: t1)

        XCTAssertEqual(g.watchActions(for: t.pi), [.freeze, .pasteOff, .actionsOff, .awayOff, .action])
        XCTAssertEqual(g.watchActions(for: deck), [.remove, .pasteOff, .actionsOff, .awayOff, .action])
        XCTAssertEqual(g.watchActions(for: g.device), [])
        XCTAssertEqual(g.watchActions(for: watch), [])
        XCTAssertThrowsError(try g.watchBody(.remove, device: t.pi, watch: watch, now: t1)) {
            XCTAssertEqual($0 as? PhoneGroup.Failure, .notForWatch)
        }
        XCTAssertThrowsError(try g.watchBody(.freeze, device: t.pi, watch: deck, now: t1)) {
            XCTAssertEqual($0 as? PhoneGroup.Failure, .notAWatch)
        }
        func signed(_ a: PhoneGroup.WatchAction, _ device: String, name: String? = nil) throws -> Member.Record {
            let body = try g.watchBody(a, device: device, name: name, watch: watch, now: t1.addingTimeInterval(1))
            return PhoneGroup.watchRecord(body: body, signature: try watchKey.signature(for: body), watchCA: ca)
        }

        // A command reaches pi and counts there.
        let now = Records.ms(t1.addingTimeInterval(2))
        for a in [PhoneGroup.WatchAction.pasteOff, .actionsOff, .awayOff] {
            XCTAssertNoThrow(try Commands.verify(try signed(a, t.pi), records: g.records, me: t.pi, nowMS: now), a.rawValue)
        }
        XCTAssertNoThrow(try Commands.verify(try signed(.action, t.pi, name: "lock"), records: g.records, me: t.pi, nowMS: now))

        // The freeze and the removal count.
        // One at a time: two bodies built from the same set would carry
        // one number, which stops the watch's records (two histories).
        XCTAssertEqual(g.add([try signed(.freeze, t.pi)]).count, 1)
        XCTAssertEqual(g.add([try signed(.remove, deck)]).count, 1)
        XCTAssertTrue(try XCTUnwrap(g.devices.first { $0.id == t.pi }).frozen)
        XCTAssertFalse(g.devices.contains { $0.id == deck })
    }

    /// Reads the next message from the phone, at most ten tries, until one
    /// is what want accepts.
    func next(from t: Pipe, _ want: (Member.Message) -> Bool) async throws -> Member.Message? {
        for _ in 0..<10 {
            let n = try Member.length(header: try await t.read(exactly: 4))
            let m = try Member.decode(body: try await t.read(exactly: n))
            if want(m) { return m }
        }
        return nil
    }

    /// The root sends a device the admin CA it issued, and the device's app
    /// gets it.
    func testNodeSendsTheAdminCA() async throws {
        let t = try CoreGroup(test: self)
        let (phone, other) = (t.phones[0], t.phones[1])
        try await t.connect(1, to: 0)
        XCTAssertTrue(try phone.member.sendAdminCA(to: other.device, ca: Data([7, 7])))
        let (from, ca) = try await other.next("the admin CA") { e -> (String, Data)? in
            if case let .message(f, .admin(ca)) = e { return (f, ca) }
            return nil
        }
        XCTAssertEqual(from, phone.device)
        XCTAssertEqual(ca, Data([7, 7]))
        XCTAssertFalse(try phone.member.sendAdminCA(to: Member.newID(), ca: Data([8])), "a device not connected gets nothing")
    }

    /// Writes the root's admin CA for a computer's admin key and the records
    /// that list it as an admin, for the Go side (internal/group,
    /// TestSwiftComputerAdmin), when CBB_INTEROP_OUT names a
    /// directory.
    func testComputerAdminForGo() throws {
        guard let dir = ProcessInfo.processInfo.environment["CBB_INTEROP_OUT"] else { return }
        let t = try group()
        var g = t.g
        let (root, pi) = (t.root, t.pi)
        let adminKey = SoftwareSigner()
        let (ca, _) = try g.makeAdmin(device: pi, adminKey: adminKey.publicKeyDER, rootSigner: root, now: t1, allowFileKey: true)
        struct Out: Encodable {
            var group_ca: Data
            var device: String
            var admin_key: Data
            var admin_ca: Data
            var records: [Member.Record]
        }
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        let out = Out(group_ca: g.groupCA, device: pi, admin_key: adminKey.publicKeyDER, admin_ca: ca, records: g.records.records)
        try (enc.encode(out) + Data("\n".utf8)).write(to: URL(fileURLWithPath: dir).appendingPathComponent("swift-computer-admin.json"))
    }
}
