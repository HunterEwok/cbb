// SPDX-License-Identifier: AGPL-3.0-only

@testable import CBBKit
import Foundation
import XCTest

/// Handing the group over (docs/protocol.md, section 10, "Handing the group over"):
/// the root phone is lost, and admin phone B claims the group for a new
/// root through its member in the Rust core, which takes effect after the
/// delay; the tests that need it to take effect set the delay to 0.
final class RootTests: XCTestCase {
    /// When the group was made, for the certificates of the computers and
    /// the stolen root key.
    let t0 = Date().addingTimeInterval(-3600)

    /// A computer: its device ID, key and member certificate.
    struct Computer {
        let device = Member.newID()
        let key = SoftwareSigner()
        var cert = Data()
        var keyHash: Data { (try? Records.keyHash(cert: cert)) ?? Data() }
    }

    /// The group before the loss: the root phone, which admitted computer
    /// one itself, and admin phone B, which admitted computer two; B's
    /// member runs in the Rust core, in dir.
    struct Group {
        var root: PhoneGroup, b: PhoneGroup
        let rootKey: SoftwareSigner, adminKey: SoftwareSigner, newRootKey = SoftwareSigner()
        /// B's admin CA, under the old root.
        let adminCA: Data
        let one: Computer, two: Computer
        let member: CoreMember

        init(now: Date, dir: URL) throws {
            let rootKey = SoftwareSigner(), adminKey = SoftwareSigner()
            var root = try PhoneGroup.create(caSigner: rootKey, memberKey: SoftwareSigner().publicKeyDER, name: "Lost", now: now)
            let bDevice = Member.newID(), bKey = SoftwareSigner()
            let adminCA = try GroupCertificates.adminCA(device: bDevice, publicKey: adminKey.publicKeyDER, root: root.groupCA,
                                                        rootSigner: rootKey)
            let bCert = try GroupCertificates.member(device: bDevice, publicKey: bKey.publicKeyDER, ca: root.groupCA, caSigner: rootKey, now: now)
            _ = try root.record(device: bDevice, name: "B", role: "phone", key: Records.keyHash(cert: bCert),
                                admin: Records.keyHash(cert: adminCA), caSigner: rootKey, now: now)
            var one = Computer(), two = Computer()
            one.cert = try GroupCertificates.member(device: one.device, publicKey: one.key.publicKeyDER, ca: root.groupCA,
                                                    caSigner: rootKey, now: now)
            _ = try root.record(device: one.device, name: "one", role: "full", key: one.keyHash, caSigner: rootKey, now: now)
            var b = PhoneGroup(device: bDevice, groupCA: root.groupCA, memberCert: bCert, computers: [])
            (b.isRoot, b.adminCA) = (false, adminCA)
            b.add(root.records.records)
            two.cert = try GroupCertificates.member(device: two.device, publicKey: two.key.publicKeyDER, ca: adminCA, caSigner: adminKey, now: now)
            _ = try b.record(device: two.device, name: "two", role: "full", key: two.keyHash, caSigner: adminKey, now: now)
            root.add(b.records.records)
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            member = try CoreMember(.init(dir: dir, name: "B", osVersion: "26", version: "0.6.0", device: bDevice, publicKeyDER: bKey.publicKeyDER,
                                          seal: CoreGroup.seal, cert: bCert, issuer: nil, groupCA: root.groupCA, roots: root.trusted)) {
                try bKey.signature(digest: $0)
            }
            try member.addRecords(b.records.records)
            (self.root, self.b, self.rootKey, self.adminKey, self.adminCA, self.one, self.two) = (root, b, rootKey, adminKey, adminCA, one, two)
        }

        /// Hands records the root signed to B and its member.
        mutating func fromRoot(_ rs: Member.Record...) throws {
            b.add(rs)
            try member.addRecords(rs)
        }

        /// A root CA for B's new root key, from the member.
        func newRoot() throws -> Data {
            let k = newRootKey
            return try member.rootCA(public: k.publicKeyDER) { try k.signature(digest: $0) }
        }

        /// B claims the group from the lost root phone for newRoot, as the
        /// app does.
        mutating func claim(_ newRoot: Data) throws {
            try b.checkTakeOver(from: root.device)
            let k = adminKey
            try member.claim(.takeOver, rootCA: newRoot, public: k.publicKeyDER, ca: adminCA, sign: { try k.signature(digest: $0) }, lost: root.device)
            b.claimed(newRoot: newRoot, lost: root.device)
            b.add(try member.records())
        }

        /// Asks B's member to finish the claim for newRoot, and makes B the
        /// root once it did.
        mutating func finish(_ newRoot: Data) throws -> CoreMember.Takeover {
            let k = newRootKey
            let f = try member.finishTakeover(rootCA: newRoot, public: k.publicKeyDER, name: "B", store: Records.hardware, seal: nil) {
                try k.signature(digest: $0)
            }
            if f.state == "effective" {
                b.becameRoot(cert: try XCTUnwrap(f.cert), records: try member.records())
            } else {
                b.add(try member.records())
            }
            return f
        }

        /// B's claim record, as its member signed it.
        func claimRecord() throws -> Member.Record {
            try XCTUnwrap(try member.records().first { RootTests.type(of: $0) == "claim" })
        }
    }

    /// The type of a record's body.
    static func type(of r: Member.Record) -> String? {
        (try? JSONSerialization.jsonObject(with: r.body) as? [String: Any])?["type"] as? String
    }

    /// A group whose member stops, and whose folder goes, when the test ends.
    func group(now: Date? = nil) throws -> Group {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("cbb-root-\(UUID().uuidString)")
        let g = try Group(now: now ?? t0, dir: dir)
        let m = g.member
        addTeardownBlock {
            m.stop()
            try? FileManager.default.removeItem(at: dir)
        }
        return g
    }

    /// B's claim, and B as the root once it took effect at once: the
    /// records the takeover added, the claim among them.
    func takeOver(_ g: inout Group) throws -> [Member.Record] {
        try g.fromRoot(try g.root.setTakeoverDelay(ms: 0, rootSigner: g.rootKey, now: Date()))
        let before = Set(g.b.records.records.map(Records.id))
        let newRoot = try g.newRoot()
        try g.claim(newRoot)
        XCTAssertEqual(try g.finish(newRoot).state, "effective")
        return g.b.records.records.filter { !before.contains(Records.id($0)) }
    }

    /// The new root signs the old root's settings again, since the state
    /// counts only the current root's: the group keeps its delay and level.
    func testTakeOverKeepsSettings() throws {
        var g = try group()
        try g.fromRoot(try g.root.setKeyLevel(Records.levelFiles, rootSigner: g.rootKey, now: Date()))
        XCTAssertEqual(g.b.keyLevel, Records.levelFiles)
        let after = try takeOver(&g)
        XCTAssertTrue(g.b.isRoot)
        XCTAssertEqual(g.b.keyLevel, Records.levelFiles)
        let mine = g.b.settings(of: PhoneGroup.signer(g.newRootKey))
        XCTAssertEqual(mine.delay, 0)
        XCTAssertEqual(mine.level, Records.levelFiles)
        XCTAssertEqual(after.filter { Self.type(of: $0) == "settings" }.count, 1)
    }

    /// Every record the set holds goes to a forwarder, which sees the same
    /// roots and the lost phone removed.
    func testAuthorityRecords() throws {
        var g = try group()
        let rs = try takeOver(&g)
        let after = g.b.records.authorityRecords
        let ids = Set(after.map(Records.id))
        XCTAssertTrue(rs.allSatisfy { ids.contains(Records.id($0)) }, "the takeover's records")
        XCTAssertEqual(ids.count, after.count)
        var forwarder = RecordSet()
        forwarder.clock = { self.t0 }
        forwarder.addAll(after.shuffled(), groupCA: g.root.groupCA)
        forwarder.clock = { Date() }
        forwarder.refresh()
        XCTAssertEqual(forwarder.roots, g.b.roots)
        XCTAssertNotNil(forwarder.refused(chain: [g.root.memberCert]))
    }

    /// The root hands the group to B (cbb handover): B's claim takes
    /// effect at once, and the old root's device stays in the group as a
    /// member.
    func testHandedOver() throws {
        let now = Date()
        var g = try group()
        XCTAssertFalse(g.b.handedToMe)
        var h = Records.Body(type: "handover", signer: PhoneGroup.signer(g.rootKey), timeMS: Records.ms(now))
        h.admin = try Records.keyHash(cert: g.adminCA)
        try g.fromRoot(try g.root.sign(h, caSigner: g.rootKey))
        XCTAssertTrue(g.b.handedToMe)
        XCTAssertFalse(g.root.handedToMe, "the root is no admin to hand the group to")
        try g.b.checkHandedOver()
        let newRoot = try g.newRoot()
        let k = g.adminKey
        try g.member.claim(.takeHandedOver, rootCA: newRoot, public: k.publicKeyDER, ca: g.adminCA, sign: { try k.signature(digest: $0) })
        g.b.claimed(newRoot: newRoot, lost: nil)
        g.b.add(try g.member.records())
        XCTAssertFalse(g.b.handedToMe, "it claimed the group")
        XCTAssertEqual(g.b.claimState, "effective", "a handed group needs no wait")
        XCTAssertEqual(try g.finish(newRoot).state, "effective")
        XCTAssertTrue(g.b.isRoot)
        XCTAssertEqual(g.b.records.rootDevice, g.b.device)
        XCTAssertNil(g.b.records.handedTo, "the new root handed nothing")
        XCTAssertEqual(g.b.devices.map(\.name).sorted(), ["B", "Lost", "one", "two"])
        XCTAssertNil(g.b.records.refused(chain: [g.root.memberCert]), "the old root stays a member")

        // A handover to another admin key is not this phone's.
        var other = try group()
        var o = Records.Body(type: "handover", signer: PhoneGroup.signer(other.rootKey), timeMS: Records.ms(now))
        o.admin = Records.keyHash(spki: SoftwareSigner().publicKeyDER)
        try other.fromRoot(try other.root.sign(o, caSigner: other.rootKey))
        XCTAssertFalse(other.b.handedToMe)
        XCTAssertThrowsError(try other.b.checkHandedOver()) {
            XCTAssertEqual($0 as? PhoneGroup.Failure, .notHandedOver)
        }
        let ok = other.adminKey
        XCTAssertThrowsError(try other.member.claim(.takeHandedOver, rootCA: try other.newRoot(), public: ok.publicKeyDER, ca: other.adminCA,
                                                    sign: { try ok.signature(digest: $0) })) {
            XCTAssertTrue($0 is Core.Refusal, "\($0)")
        }
    }

    func testTakeOver() throws {
        var g = try group()
        let lost = g.root.device
        XCTAssertEqual(g.b.records.rootDevice, lost)
        let rs = try takeOver(&g)
        let types = rs.map { Self.type(of: $0) }
        XCTAssertTrue(types.contains("claim") && types.contains("device") && types.contains("revoke"),
                      "the claim, B's own device and the removal of the lost phone: \(types)")
        XCTAssertTrue(g.b.isRoot)
        XCTAssertNil(g.b.adminCA)
        XCTAssertNil(g.b.claim)
        XCTAssertEqual(g.b.roots.count, 1)
        XCTAssertEqual(g.b.records.roots, g.b.roots)
        XCTAssertEqual(g.b.tag, g.root.tag, "the group keeps its tag")
        XCTAssertEqual(g.b.records.rootDevice, g.b.device)
        XCTAssertEqual(g.b.devices.map(\.name), ["B", "one", "two"])
        let set = g.b.records
        XCTAssertNotNil(set.refused(chain: [g.root.memberCert]), "the lost phone")
        XCTAssertNil(set.refused(chain: [g.one.cert]), "the computer the old root admitted")
        XCTAssertNil(set.refused(chain: [g.two.cert, g.adminCA]), "the computer B admitted")
        XCTAssertNil(set.refused(chain: g.b.memberChain), "B itself")
        XCTAssertEqual(try GroupCertificates.verifyMember(g.b.memberCert, groupCA: g.b.currentRoot, now: Date()), g.b.device,
                       "B's certificate is from the new root")

        // A computer that gets the records in any order, and the claim
        // times with them, sees the same.
        var computer = RecordSet()
        computer.addAll(g.b.records.records.shuffled(), groupCA: g.root.groupCA)
        computer.takeClaimTimes(g.b.records.claimTimes)
        XCTAssertEqual(computer.digest, g.b.records.digest)
        XCTAssertEqual(computer.roots, g.b.roots)
        XCTAssertEqual(computer.devices.map(\.name), ["B", "one", "two"])

        // The new root admits and renews.
        let now = Date()
        var three = Computer()
        three.cert = try GroupCertificates.member(device: three.device, publicKey: three.key.publicKeyDER, ca: g.b.currentRoot,
                                                  caSigner: g.newRootKey, now: now)
        XCTAssertEqual(try GroupCertificates.verifyMember(chain: [three.cert], roots: g.b.trusted, now: now), three.device)
        _ = try g.b.record(device: three.device, name: "three", role: "full", key: three.keyHash, caSigner: g.newRootKey, now: now)
        XCTAssertNil(g.b.records.refused(chain: [three.cert]))
        let later = now.addingTimeInterval(500 * 24 * 3600)
        let renewed = try XCTUnwrap(g.b.renewal(chain: [g.one.cert], caSigner: g.newRootKey, now: later)).cert
        XCTAssertEqual(try GroupCertificates.verifyMember(renewed, groupCA: g.b.currentRoot, now: later), g.one.device)
    }

    /// Without a delay of the root's, the claim waits 72 hours, and the
    /// member signs nothing meanwhile.
    func testClaimWaits() throws {
        var g = try group()
        let newRoot = try g.newRoot()
        try g.claim(newRoot)
        XCTAssertEqual(g.b.claimState, "pending")
        let f = try g.finish(newRoot)
        XCTAssertEqual(f.state, "pending")
        XCTAssertGreaterThan(f.leftMS, 71 * 3600 * 1000, "the group's delay")
        XCTAssertNil(f.cert)
        XCTAssertFalse(g.b.isRoot)
        XCTAssertEqual(g.b.records.rootDevice, g.root.device)
    }

    /// The root cancels a claim while it waits, and the claimant stays an admin.
    func testClaimCancelled() throws {
        var g = try group()
        let newRoot = try g.newRoot()
        try g.claim(newRoot)
        XCTAssertThrowsError(try g.b.checkTakeOver(from: g.root.device)) {
            XCTAssertEqual($0 as? PhoneGroup.Failure, .claimWaiting)
        }
        let claim = try g.claimRecord()
        g.root.add([claim])
        XCTAssertEqual(g.root.records.claims.map(\.state), ["pending"])
        try g.fromRoot(try g.root.resolve([Records.id(claim)], rootSigner: g.rootKey, now: Date()))
        XCTAssertEqual(try g.finish(newRoot).state, "cancelled")
        XCTAssertTrue(g.b.dropEndedClaim())
        XCTAssertNil(g.b.claim, "a cancelled claim is dropped")
        XCTAssertFalse(g.b.isRoot)
        XCTAssertEqual(g.b.records.rootDevice, g.root.device)
    }

    /// The root and an admin set how long a copy from another device stays
    /// live; the root's record beats an admin's.
    func testIncoming() throws {
        var g = try group()
        XCTAssertEqual(g.b.incomingMS, Records.defaultIncomingMS)
        XCTAssertThrowsError(try g.root.setIncoming(ms: 4_000, caSigner: g.rootKey, now: Date())) {
            XCTAssertEqual($0 as? PhoneGroup.Failure, .invalidIncoming)
        }
        let byAdmin = try g.b.setIncoming(ms: 90_000, caSigner: g.adminKey, now: Date())
        g.root.add([byAdmin])
        XCTAssertEqual(g.root.incomingMS, 90_000)
        let byRoot = try g.root.setIncoming(ms: 30_000, caSigner: g.rootKey, now: Date())
        g.b.add([byRoot])
        XCTAssertEqual(g.b.incomingMS, 30_000)
    }

    /// The root sets how long a claim waits.
    func testTakeoverDelay() throws {
        var g = try group()
        XCTAssertThrowsError(try g.root.setTakeoverDelay(ms: 8 * 24 * 3600 * 1000, rootSigner: g.rootKey, now: Date())) {
            XCTAssertEqual($0 as? PhoneGroup.Failure, .invalidDelay)
        }
        XCTAssertThrowsError(try g.b.setTakeoverDelay(ms: 0, rootSigner: g.adminKey, now: Date())) {
            XCTAssertEqual($0 as? PhoneGroup.Failure, .notRoot)
        }
        try g.fromRoot(try g.root.setTakeoverDelay(ms: 0, rootSigner: g.rootKey, now: Date()))
        let newRoot = try g.newRoot()
        try g.claim(newRoot)
        XCTAssertEqual(try g.finish(newRoot).state, "effective", "no delay")
        XCTAssertTrue(g.b.isRoot)
    }

    func testOldRootKeyAfterTakeOver() throws {
        var g = try group()
        _ = try takeOver(&g)
        var set = g.b.records
        // Whoever has the lost phone's root key signs a computer, an admin
        // CA, a device record and a claim: none counts.
        var stolen = Computer()
        stolen.cert = try GroupCertificates.member(device: stolen.device, publicKey: stolen.key.publicKeyDER, ca: g.root.groupCA,
                                                   caSigner: g.rootKey, now: t0)
        let thiefKey = SoftwareSigner()
        let thiefCA = try GroupCertificates.adminCA(device: Member.newID(), publicKey: thiefKey.publicKeyDER, root: g.root.groupCA,
                                                    rootSigner: g.rootKey)
        let viaThief = try GroupCertificates.member(device: Member.newID(), publicKey: SoftwareSigner().publicKeyDER, ca: thiefCA,
                                                    caSigner: thiefKey, now: t0)
        XCTAssertNotNil(set.refused(chain: [stolen.cert]))
        XCTAssertNotNil(set.refused(chain: [viaThief, thiefCA]))
        let otherRoot = try GroupCertificates.groupCA(signer: SoftwareSigner(), now: t0, pathLength: 1)
        var claim = Records.Body(type: "claim", signer: Records.keyHash(spki: thiefKey.publicKeyDER), timeMS: Records.ms(Date()))
        claim.root = otherRoot
        set.add(try set.sign(.device(stolen.device, name: "stolen", role: "full", key: stolen.keyHash, signer: g.rootKey, now: Date()),
                             with: g.rootKey), groupCA: g.root.groupCA)
        set.add(try set.sign(claim, with: thiefKey, adminCA: thiefCA), groupCA: g.root.groupCA)
        XCTAssertEqual(set.devices.map(\.name), ["B", "one", "two"])
        XCTAssertEqual(set.roots, g.b.roots)
        XCTAssertNotNil(set.refused(chain: [stolen.cert]))
    }

    func testTakeOverRefused() throws {
        let g = try group()
        XCTAssertThrowsError(try g.b.checkTakeOver(from: g.one.device)) {
            XCTAssertEqual($0 as? PhoneGroup.Failure, .notRoot)
        }
        XCTAssertThrowsError(try g.root.checkTakeOver(from: g.root.device)) {
            XCTAssertEqual($0 as? PhoneGroup.Failure, .notAdmin)
        }
        // The member refuses a claim from a device that does not hold the root too.
        let k = g.adminKey
        XCTAssertThrowsError(try g.member.claim(.takeOver, rootCA: try g.newRoot(), public: k.publicKeyDER, ca: g.adminCA,
                                                sign: { try k.signature(digest: $0) }, lost: g.one.device)) {
            XCTAssertTrue($0 is Core.Refusal, "\($0)")
        }
        // A claim that hands the group to a computer's group CA, or to no
        // root at all, never takes effect.
        let pcCA = try GroupCertificates.groupCA(signer: SoftwareSigner(), now: t0)
        for root in [pcCA, try XCTUnwrap(g.b.adminCA)] {
            var set = g.b.records
            var claim = Records.Body(type: "claim", signer: Records.keyHash(spki: g.adminKey.publicKeyDER), timeMS: Records.ms(t0))
            claim.root = root
            set.add(try set.sign(claim, with: g.adminKey, adminCA: g.b.adminCA), groupCA: g.root.groupCA)
            set.clock = { Date() }
            set.refresh()
            XCTAssertEqual(set.roots, [])
        }
    }

    /// A welcome after the takeover names the new root and carries the
    /// claim times, and a phone that joins checks it.
    func testWelcomeAfterTakeOver() throws {
        var g = try group()
        _ = try takeOver(&g)
        let t0 = Date()
        let joiner = Member.newID(), key = SoftwareSigner()
        let selfSigned = try GroupCertificates.selfSigned(device: joiner, signer: key)
        var w = Pairing.Welcome(cert: try GroupCertificates.member(device: joiner, publicKey: key.publicKeyDER, ca: g.b.currentRoot,
                                                                   caSigner: g.newRootKey, now: t0), groupCA: g.b.groupCA)
        (w.roots, w.records, w.claimTimes) = (g.b.roots, g.b.records.pathRecords, g.b.records.claimTimes)
        let j = PairingJoiner.Joined(device: joiner, welcome: w, member: .init(device: g.b.device, group: g.b.tag))
        let info = Pairing.Info(name: "C", os: "ios")
        XCTAssertNoThrow(try PairingJoiner.check(j, info: info, memberCert: g.b.memberCert, joinerCert: selfSigned, now: t0))
        var bad = j
        bad.welcome.roots = nil
        XCTAssertThrowsError(try PairingJoiner.check(bad, info: info, memberCert: g.b.memberCert, joinerCert: selfSigned, now: t0))
        // A root that no record leads to, as one an admin made up and named
        // in the Welcome, is refused.
        var made = j
        made.welcome.records = nil
        XCTAssertThrowsError(try PairingJoiner.check(made, info: info, memberCert: g.b.memberCert, joinerCert: selfSigned, now: t0))
        XCTAssertEqual(PhoneGroup.joined(j).roots, g.b.roots)
    }

    /// The set over testdata/interop/v2-records.json gives each case's
    /// state, as Go's internal/authority does.
    /// Runs the cases of testdata/interop/v2-records.json whose names start
    /// with one of the prefixes (all of them for nil) through the set: the
    /// core gives each case's state, the same as Go and the lite member.
    /// Answers how many cases ran.
    @discardableResult
    func v2Cases(_ prefixes: [String]? = nil, file: StaticString = #filePath, line: UInt = #line,
                 check: ((String, RecordSet) -> Void)? = nil) throws -> Int {
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<6 { url.deleteLastPathComponent() }
        struct V: Decodable {
            struct Case: Decodable {
                var name: String, group_ca: Data, group: String, now_ms: Int64, records: [Member.Record], state: String
                var first_seen: [RecordSet.ClaimTime]?
                var time_unknown: Bool?
            }
            var cases: [Case]
        }
        let v = try JSONDecoder().decode(V.self, from: Data(contentsOf: url.appendingPathComponent("testdata/interop/v2-records.json")))
        var n = 0
        for c in v.cases where c.time_unknown != true {
            if let prefixes, !prefixes.contains(where: { c.name.hasPrefix($0) }) { continue }
            var set = RecordSet()
            set.tag = c.group
            set.nowMS = c.now_ms
            let fresh = set.addAll(c.records, groupCA: c.group_ca)
            guard fresh.count == c.records.count else { continue } // records the set does not keep
            set.takeClaimTimes(c.first_seen ?? [])
            let want = try JSONDecoder().decode(RecordSet.State.self, from: Data(c.state.utf8))
            XCTAssertEqual(set.view.state, want, c.name, file: file, line: line)
            check?(c.name, set)
            n += 1
        }
        XCTAssertGreaterThan(n, 0, "no case of \(prefixes ?? [])", file: file, line: line)
        return n
    }

    func testV2Vectors() throws {
        XCTAssertGreaterThan(try v2Cases(), 10)
    }

    /// The alerts say each case's stop, conflicts and claims that wait or
    /// stop the group, with the records a resolve names and the devices
    /// involved.
    func testAlerts() throws {
        var kinds = Set<GroupAlert.Kind>()
        try v2Cases { name, set in
            let st = set.view.state
            let alerts = set.alerts
            kinds.formUnion(alerts.map(\.kind))
            XCTAssertEqual(alerts.contains { $0.kind == .stopped }, st.stop == "full", name)
            XCTAssertEqual(alerts.contains { $0.kind == .secretsStopped }, st.stop == "secrets", name)
            for c in st.conflicts ?? [] {
                let a = alerts.first { $0.records == c.records && [.twoHistories, .admins, .claims].contains($0.kind) }
                XCTAssertNotNil(a, "\(name): \(c.kind)")
                if c.kind == "two_histories" { XCTAssertFalse(a?.names.isEmpty ?? true, "\(name): who signed two histories") }
            }
            let waiting = (st.claims ?? []).filter { $0.state == "pending" }.count
            XCTAssertEqual(alerts.filter { $0.kind == .claimPending }.count, waiting, name)
        }
        XCTAssertTrue(kinds.isSuperset(of: [.stopped, .twoHistories, .claimPending]), "\(kinds)")
    }

    // The cases of Go's records of version 1 had these tests; each now runs
    // the cases of version 2 on the same subject.

    func testGoAuthority() throws {
        try v2Cases(["basic", "record of a later version", "ignored records", "checkpoint"])
    }

    func testGoAdminPowers() throws {
        try v2Cases(["powers"])
    }

    func testGoEnvelopes() throws {
        try v2Cases(["one record under two admin CAs", "two histories", "times at the ends"])
    }

    func testGoFreeze() throws {
        try v2Cases(["freeze and thaw", "freezes crossed"])
    }

    func testGoHandover() throws {
        try v2Cases(["claim waits and takes effect", "settings delay", "claim disputed"])
    }

    func testGoHubOrder() throws {
        try v2Cases(["hubs table"])
    }

    func testGoRemovedAdmin() throws {
        try v2Cases(["root removal cuts an admin", "removed admin's device", "removed admin's claim"])
    }

    func testGoRemovedAdmins() throws {
        try v2Cases(["admin removals"])
    }

    func testGoRootMember() throws {
        try v2Cases(["removed phone after a takeover", "chain of claims"])
    }

    func testGoTakeover() throws {
        try v2Cases(["two claims", "claim after removal", "claim while another waits", "stranger's claim", "claimed root signs early"])
    }

    /// A watch's records count only for its powers: removing an admin is
    /// not one of them, so a revocation of an admin's key that a watch
    /// signs counts for nothing, while the root's does.
    func testGoWatch() throws {
        var g = try group()
        let watchKey = SoftwareSigner(), watch = Member.newID()
        let (ca, _) = try g.root.addWatch(device: watch, name: "Watch", os: "watchos", adminKey: watchKey.publicKeyDER,
                                          rootSigner: g.rootKey, now: t0.addingTimeInterval(1))
        XCTAssertEqual(g.root.devices.first { $0.id == watch }?.powers, Records.watchPowers)
        XCTAssertFalse(Records.watchPowers.contains("remove-admins"))
        let adminKey = try Records.keyHash(cert: g.adminCA)
        try g.root.records.signed(.revoke([adminKey], signer: watchKey, now: t0.addingTimeInterval(2)), watchKey, adminCA: ca,
                                  groupCA: g.root.groupCA)
        XCTAssertFalse(g.root.records.revoked.contains(adminKey))
        XCTAssertTrue(g.root.devices.contains { $0.id == g.b.device })
        try g.root.records.signed(.revoke([adminKey], signer: g.rootKey, now: t0.addingTimeInterval(3)), g.rootKey,
                                  groupCA: g.root.groupCA)
        XCTAssertTrue(g.root.records.revoked.contains(adminKey))
    }

    /// Writes swift-root.json for internal/group's TestSwiftRoot: a takeover
    /// as the core's member signs it for this kit.
    func testTakeOverForGo() throws {
        guard let dir = ProcessInfo.processInfo.environment["CBB_INTEROP_OUT"] else { return }
        var g = try group()
        _ = try takeOver(&g)
        struct Out: Encodable {
            var group_ca: Data
            var records: [Member.Record]
            var claim_times: [RecordSet.ClaimTime]
            var roots: [Data]
            var devices: [String]
            var digest: String
            var lost, kept: Data // member certificates: the lost phone's, and the computer the old root admitted
        }
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        let out = Out(group_ca: g.root.groupCA, records: g.b.records.records.reversed(), claim_times: g.b.records.claimTimes, roots: g.b.roots,
                      devices: g.b.devices.map(\.id), digest: g.b.records.digest ?? "", lost: g.root.memberCert, kept: g.one.cert)
        try (enc.encode(out) + Data("\n".utf8)).write(to: URL(fileURLWithPath: dir).appendingPathComponent("swift-root.json"))
    }
}
