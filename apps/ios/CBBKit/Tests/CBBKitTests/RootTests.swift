// SPDX-License-Identifier: AGPL-3.0-only

@testable import CBBKit
import Foundation
import XCTest

/// Handing the group over (docs/protocol.md, section 10, "Handing the group over"):
/// the root phone is lost, and admin phone B claims the group for a new
/// root, which takes effect after the delay.
final class RootTests: XCTestCase {
    /// When the group was made: long enough ago that a claim made then
    /// took effect by now.
    let t0 = Date().addingTimeInterval(-100 * 3600)

    /// A computer: its device ID, key and member certificate.
    struct Computer {
        let device = SyncEngine.newID()
        let key = SoftwareSigner()
        var cert = Data()
        var keyHash: Data { (try? Records.keyHash(cert: cert)) ?? Data() }
    }

    /// The group before the loss: the root phone, which admitted computer
    /// one itself, and admin phone B, which admitted computer two.
    struct Group {
        var root: PhoneGroup, b: PhoneGroup
        let rootKey: SoftwareSigner, adminKey: SoftwareSigner, newRootKey = SoftwareSigner()
        /// B's admin CA, under the old root.
        let adminCA: Data
        let one: Computer, two: Computer

        init(now: Date) throws {
            let rootKey = SoftwareSigner(), adminKey = SoftwareSigner()
            var root = try PhoneGroup.create(caSigner: rootKey, memberKey: SoftwareSigner().publicKeyDER, name: "Lost", now: now)
            let bDevice = SyncEngine.newID(), bKey = SoftwareSigner()
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
            // The members held every record since now.
            root.records.clock = { now }
            b.records.clock = { now }
            (b.isRoot, b.adminCA) = (false, adminCA)
            b.add(root.records.records)
            two.cert = try GroupCertificates.member(device: two.device, publicKey: two.key.publicKeyDER, ca: adminCA, caSigner: adminKey, now: now)
            _ = try b.record(device: two.device, name: "two", role: "full", key: two.keyHash, caSigner: adminKey, now: now)
            root.add(b.records.records)
            root.records.clock = { Date() }
            (self.root, self.b, self.rootKey, self.adminKey, self.adminCA, self.one, self.two) = (root, b, rootKey, adminKey, adminCA, one, two)
        }
    }

    /// What a phone hub shows its forwarder: the records of the root's own
    /// device and of the admins, and every record that is no device record,
    /// never the records that name the computers.
    /// B's claim, made at t0, and B as the root once it took effect.
    func takeOver(_ g: inout Group) throws -> (claim: Member.Record, records: [Member.Record]) {
        let newRoot = try GroupCertificates.groupCA(signer: g.newRootKey, now: t0, pathLength: 1)
        let claim = try g.b.takeOver(from: g.root.device, adminSigner: g.adminKey, newRoot: newRoot, now: t0)
        XCTAssertEqual(g.b.claimState, "pending")
        XCTAssertFalse(g.b.isRoot)
        XCTAssertTrue(try g.b.finishTakeOver(rootSigner: g.newRootKey, now: t0).isEmpty, "the claim waits")
        g.b.records.clock = { Date() }
        let rs = try g.b.finishTakeOver(rootSigner: g.newRootKey, now: Date())
        return (claim, rs)
    }

    /// The new root signs the old root's settings again, since the state
    /// counts only the current root's: the group keeps its delay and level.
    func testTakeOverKeepsSettings() throws {
        var g = try Group(now: t0)
        let rs = [try g.root.setTakeoverDelay(ms: 3_600_000, rootSigner: g.rootKey, now: t0),
                  try g.root.setKeyLevel(Records.levelFiles, rootSigner: g.rootKey, now: t0)]
        g.b.add(rs)
        XCTAssertEqual(g.b.keyLevel, Records.levelFiles)
        let (_, after) = try takeOver(&g)
        XCTAssertTrue(g.b.isRoot)
        XCTAssertEqual(g.b.keyLevel, Records.levelFiles)
        let mine = g.b.settings(of: PhoneGroup.signer(g.newRootKey))
        XCTAssertEqual(mine.delay, 3_600_000)
        XCTAssertEqual(mine.level, Records.levelFiles)
        XCTAssertEqual(after.filter { (try? JSONSerialization.jsonObject(with: $0.body) as? [String: Any])?["type"] as? String == "settings" }.count, 1)
    }

    /// Every record the set holds goes to a forwarder, which sees the same
    /// roots and the lost phone removed.
    func testAuthorityRecords() throws {
        var g = try Group(now: t0)
        let (claim, rs) = try takeOver(&g)
        let after = g.b.records.authorityRecords
        let ids = Set(after.map(Records.id))
        XCTAssertTrue((rs + [claim]).allSatisfy { ids.contains(Records.id($0)) }, "the takeover's records")
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
        var g = try Group(now: now)
        XCTAssertFalse(g.b.handedToMe)
        var h = Records.Body(type: "handover", signer: PhoneGroup.signer(g.rootKey), timeMS: Records.ms(now))
        h.admin = try Records.keyHash(cert: g.adminCA)
        g.b.add([try g.root.sign(h, caSigner: g.rootKey)])
        XCTAssertTrue(g.b.handedToMe)
        XCTAssertFalse(g.root.handedToMe, "the root is no admin to hand the group to")
        let newRoot = try GroupCertificates.groupCA(signer: g.newRootKey, now: now, pathLength: 1)
        _ = try g.b.takeHandedOver(adminSigner: g.adminKey, newRoot: newRoot, now: now)
        XCTAssertFalse(g.b.handedToMe, "it claimed the group")
        XCTAssertEqual(g.b.claimState, "effective", "a handed group needs no wait")
        let rs = try g.b.finishTakeOver(rootSigner: g.newRootKey, now: now)
        XCTAssertEqual(rs.count, 1, "B's own device; nothing removed")
        XCTAssertTrue(g.b.isRoot)
        XCTAssertEqual(g.b.records.rootDevice, g.b.device)
        XCTAssertNil(g.b.records.handedTo, "the new root handed nothing")
        XCTAssertEqual(g.b.devices.map(\.name).sorted(), ["B", "Lost", "one", "two"])
        XCTAssertNil(g.b.records.refused(chain: [g.root.memberCert]), "the old root stays a member")

        // A handover to another admin key is not this phone's.
        var other = try Group(now: now)
        var o = Records.Body(type: "handover", signer: PhoneGroup.signer(other.rootKey), timeMS: Records.ms(now))
        o.admin = Records.keyHash(spki: SoftwareSigner().publicKeyDER)
        other.b.add([try other.root.sign(o, caSigner: other.rootKey)])
        XCTAssertFalse(other.b.handedToMe)
        XCTAssertThrowsError(try other.b.takeHandedOver(adminSigner: other.adminKey, newRoot: newRoot, now: now)) {
            XCTAssertEqual($0 as? PhoneGroup.Failure, .notHandedOver)
        }
    }

    func testTakeOver() throws {
        var g = try Group(now: t0)
        let lost = g.root.device
        XCTAssertEqual(g.b.records.rootDevice, lost)
        let (_, rs) = try takeOver(&g)
        XCTAssertEqual(rs.count, 2, "B's own device and the removal of the lost phone")
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

        // A computer that gets the records in any order, and the claim
        // times with them, sees the same.
        var computer = RecordSet()
        computer.addAll(g.b.records.records.shuffled(), groupCA: g.root.groupCA)
        computer.takeClaimTimes(g.b.records.claimTimes)
        XCTAssertEqual(computer.digest, g.b.records.digest)
        XCTAssertEqual(computer.roots, g.b.roots)
        XCTAssertEqual(computer.devices.map(\.name), ["B", "one", "two"])
        // Without them, it waits the delay itself.
        var late = RecordSet()
        late.addAll(g.b.records.records, groupCA: g.root.groupCA)
        XCTAssertEqual(late.roots, [])
        XCTAssertEqual(late.claims.map(\.state), ["pending"])

        // The new root admits and renews.
        var three = Computer()
        three.cert = try GroupCertificates.member(device: three.device, publicKey: three.key.publicKeyDER, ca: g.b.currentRoot,
                                                  caSigner: g.newRootKey, now: t0)
        XCTAssertEqual(try GroupCertificates.verifyMember(chain: [three.cert], roots: g.b.trusted, now: t0), three.device)
        _ = try g.b.record(device: three.device, name: "three", role: "full", key: three.keyHash, caSigner: g.newRootKey, now: Date())
        XCTAssertNil(g.b.records.refused(chain: [three.cert]))
        let later = t0.addingTimeInterval(500 * 24 * 3600)
        let renewed = try XCTUnwrap(g.b.renewal(chain: [g.one.cert], caSigner: g.newRootKey, now: later)).cert
        XCTAssertEqual(try GroupCertificates.verifyMember(renewed, groupCA: g.b.currentRoot, now: later), g.one.device)
    }

    /// The root cancels a claim while it waits, and the claimant stays an admin.
    func testClaimCancelled() throws {
        var g = try Group(now: t0)
        let newRoot = try GroupCertificates.groupCA(signer: g.newRootKey, now: t0, pathLength: 1)
        let claim = try g.b.takeOver(from: g.root.device, adminSigner: g.adminKey, newRoot: newRoot, now: t0)
        XCTAssertThrowsError(try g.b.takeOver(from: g.root.device, adminSigner: g.adminKey, newRoot: newRoot, now: t0)) {
            XCTAssertEqual($0 as? PhoneGroup.Failure, .claimWaiting)
        }
        g.root.add([claim])
        XCTAssertEqual(g.root.records.claims.map(\.state), ["pending"])
        let cancel = try g.root.resolve([Records.id(claim)], rootSigner: g.rootKey, now: Date())
        g.b.add([cancel])
        g.b.records.clock = { Date() }
        XCTAssertTrue(try g.b.finishTakeOver(rootSigner: g.newRootKey, now: Date()).isEmpty)
        XCTAssertNil(g.b.claim, "a cancelled claim is dropped")
        XCTAssertFalse(g.b.isRoot)
        XCTAssertEqual(g.b.records.rootDevice, g.root.device)
    }

    /// The root sets how long a claim waits.
    func testTakeoverDelay() throws {
        var g = try Group(now: t0)
        XCTAssertThrowsError(try g.root.setTakeoverDelay(ms: 8 * 24 * 3600 * 1000, rootSigner: g.rootKey, now: Date())) {
            XCTAssertEqual($0 as? PhoneGroup.Failure, .invalidDelay)
        }
        XCTAssertThrowsError(try g.b.setTakeoverDelay(ms: 0, rootSigner: g.adminKey, now: Date())) {
            XCTAssertEqual($0 as? PhoneGroup.Failure, .notRoot)
        }
        let r = try g.root.setTakeoverDelay(ms: 0, rootSigner: g.rootKey, now: Date())
        g.b.add([r])
        g.b.records.clock = { Date() }
        let newRoot = try GroupCertificates.groupCA(signer: g.newRootKey, now: t0, pathLength: 1)
        _ = try g.b.takeOver(from: g.root.device, adminSigner: g.adminKey, newRoot: newRoot, now: Date())
        XCTAssertFalse(try g.b.finishTakeOver(rootSigner: g.newRootKey, now: Date()).isEmpty, "no delay")
        XCTAssertTrue(g.b.isRoot)
    }

    func testOldRootKeyAfterTakeOver() throws {
        var g = try Group(now: t0)
        _ = try takeOver(&g)
        var set = g.b.records
        // Whoever has the lost phone's root key signs a computer, an admin
        // CA, a device record and a claim: none counts.
        var stolen = Computer()
        stolen.cert = try GroupCertificates.member(device: stolen.device, publicKey: stolen.key.publicKeyDER, ca: g.root.groupCA,
                                                   caSigner: g.rootKey, now: t0)
        let thiefKey = SoftwareSigner()
        let thiefCA = try GroupCertificates.adminCA(device: SyncEngine.newID(), publicKey: thiefKey.publicKeyDER, root: g.root.groupCA,
                                                    rootSigner: g.rootKey)
        let viaThief = try GroupCertificates.member(device: SyncEngine.newID(), publicKey: SoftwareSigner().publicKeyDER, ca: thiefCA,
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
        var g = try Group(now: t0)
        let newRoot = try GroupCertificates.groupCA(signer: g.newRootKey, now: t0, pathLength: 1)
        XCTAssertThrowsError(try g.b.takeOver(from: g.one.device, adminSigner: g.adminKey, newRoot: newRoot, now: t0)) {
            XCTAssertEqual($0 as? PhoneGroup.Failure, .notRoot)
        }
        XCTAssertThrowsError(try g.root.takeOver(from: g.root.device, adminSigner: g.rootKey, newRoot: newRoot, now: t0)) {
            XCTAssertEqual($0 as? PhoneGroup.Failure, .notAdmin)
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
        var g = try Group(now: t0)
        _ = try takeOver(&g)
        let joiner = SyncEngine.newID(), key = SoftwareSigner()
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
        // in the Welcome, is refused; so is one whose claim still waits
        // for the joiner, without the claim times.
        var made = j
        made.welcome.records = nil
        XCTAssertThrowsError(try PairingJoiner.check(made, info: info, memberCert: g.b.memberCert, joinerCert: selfSigned, now: t0))
        var early = j
        early.welcome.claimTimes = nil
        XCTAssertThrowsError(try PairingJoiner.check(early, info: info, memberCert: g.b.memberCert, joinerCert: selfSigned, now: t0))
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
        var g = try Group(now: t0)
        let watchKey = SoftwareSigner(), watch = SyncEngine.newID()
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
    /// as this kit signs it.
    func testTakeOverForGo() throws {
        guard let dir = ProcessInfo.processInfo.environment["CBB_INTEROP_OUT"] else { return }
        var g = try Group(now: t0)
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
