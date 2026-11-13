// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

@testable import CBBKit
import Crypto
import Foundation
import XCTest

final class CredentialsTests: XCTestCase {
    typealias Credential = ServerCredentials.Credential

    /// Reads testdata/interop/v2-credentials.json, from Go's
    /// TestGoCredentialVectors.
    func testGoCredentials() throws {
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<6 { url.deleteLastPathComponent() }
        struct Lists: Decodable {
            var Hubs: [Data]
            var Admins: [Data]
            var Members: [Data]
        }
        struct Bad: Decodable {
            var name: String
            var set: [Credential]
        }
        struct V: Decodable {
            var group_ca: Data
            var records: [Member.Record]
            var lists: Lists
            var period: Credential
            var servers: [Credential]
            var hubs: Credential
            var members: Credential
            var now_ms: Int64
            var pseudonym: String
            var bad: [Bad]
        }
        let v = try JSONDecoder().decode(V.self, from: Data(contentsOf: url.appendingPathComponent("testdata/interop/v2-credentials.json")))
        var s = RecordSet()
        _ = s.addAll(v.records, groupCA: v.group_ca)
        let l = ServerCredentials.lists(s)
        XCTAssertEqual(l.hubs, v.lists.Hubs)
        XCTAssertEqual(l.admins, v.lists.Admins)
        XCTAssertEqual(l.members, v.lists.Members)

        let root = try CertificateInfo(der: v.group_ca).publicKey
        let devices = s.devices
        let isMember = { (k: Data) in devices.contains { $0.keys.contains(k) } }
        var store = CredentialStore(groupCA: v.group_ca)
        let (fresh, errs) = store.add(root: root, isMember: isMember, [v.period, v.hubs, v.members] + v.servers)
        XCTAssertEqual(errs, [])
        XCTAssertEqual(fresh.count, 3 + v.servers.count)
        let hb = try XCTUnwrap(store.hubs).1
        XCTAssertEqual(ServerCredentials.pseudonym(hb.hubs[0]), v.pseudonym)
        XCTAssertEqual(store.serverKeys(l.hubs), Array(hb.hubs.prefix(l.hubs.count)))
        XCTAssertFalse(store.listStale(hb.hubs, want: store.serverKeys(l.hubs), ordered: true))
        XCTAssertFalse(store.listStale(hb.admins, want: store.serverKeys(l.admins), ordered: false))
        // Again: nothing new.
        XCTAssertEqual(store.add(root: root, isMember: isMember, [v.period, v.hubs]).fresh.count, 0)

        let p = try ServerCredentials.checkPresented([v.hubs, v.members, v.period], nowMS: v.now_ms)
        XCTAssertNotNil(p.members)
        XCTAssertNotNil(p.period)
        for b in v.bad {
            XCTAssertThrowsError(try ServerCredentials.checkPresented(b.set, nowMS: v.now_ms), b.name)
        }
        var forged = v.hubs
        forged.body[10] ^= 1
        XCTAssertThrowsError(try forged.open())
    }

    /// Credentials the kit signs, as a root phone does for its period, are
    /// what the store and a server take.
    func testSigned() throws {
        let rootKey = SoftwareSigner()
        let ca = try GroupCertificates.groupCA(signer: rootKey, now: Date(timeIntervalSince1970: 1_790_000_000))
        let tag = GroupCertificates.tag(groupCA: ca)
        let now: Int64 = 1_792_000_000_000
        let periodKey = SoftwareSigner(), member = SoftwareSigner(), server = SoftwareSigner()
        let period = try ServerCredentials.signPeriod(groupTag: tag, tag: ServerCredentials.newPeriodTag(), periodKey: periodKey.publicKeyDER,
                                                      version: 1, nowMS: now, root: rootKey)
        let p = try period.open()
        let srv = try ServerCredentials.signServer(p, serverKey: server.publicKeyDER, version: 1, member: member)
        let serverHash = Data(SHA256.hash(data: server.publicKeyDER))
        let hubs = try ServerCredentials.signHubs(p, hubs: [serverHash], admins: [], version: 2, periodKey: periodKey)
        let members = try ServerCredentials.signMembers(p, members: [serverHash], version: 3, key: periodKey)
        XCTAssertEqual(try hubs.open().hubs.count, 4)
        XCTAssertEqual(try hubs.open().admins.count, 4)

        var store = CredentialStore(groupCA: ca)
        let memberHash = Data(SHA256.hash(data: member.publicKeyDER))
        let isMember = { (k: Data) in k == memberHash }
        let (fresh, errs) = store.add(root: rootKey.publicKeyDER, isMember: isMember, [members, hubs, srv, period])
        XCTAssertEqual(errs, [])
        XCTAssertEqual(fresh.count, 4)
        XCTAssertEqual(store.server(member: memberHash), serverHash)
        XCTAssertEqual(store.memberOfServer(serverHash), memberHash)
        XCTAssertFalse(store.periodStale(root: rootKey.publicKeyDER, isMember: isMember, nowMS: now + 1000))
        XCTAssertTrue(store.periodStale(root: rootKey.publicKeyDER, isMember: isMember, nowMS: now + ServerCredentials.periodRenewMS))
        // A removal: the member that signed a server key is gone.
        XCTAssertTrue(store.periodStale(root: rootKey.publicKeyDER, isMember: { _ in false }, nowMS: now + 1000))
        XCTAssertNotNil(try ServerCredentials.checkPresented([hubs, members], nowMS: now + 1000).members)

        // A period another key signed is not the group's.
        let stranger = try ServerCredentials.signPeriod(groupTag: tag, tag: ServerCredentials.newPeriodTag(), periodKey: periodKey.publicKeyDER,
                                                        version: 9, nowMS: now, root: SoftwareSigner())
        XCTAssertEqual(store.add(root: rootKey.publicKeyDER, isMember: { _ in true }, [stranger]).errors.count, 1)
        // A newer period with another tag drops the rest.
        let next = try ServerCredentials.signPeriod(groupTag: tag, tag: ServerCredentials.newPeriodTag(), periodKey: periodKey.publicKeyDER,
                                                    version: 5, nowMS: now, root: rootKey)
        XCTAssertEqual(store.add(root: rootKey.publicKeyDER, isMember: { _ in true }, [next]).fresh.count, 1)
        XCTAssertNil(store.hubs)
        XCTAssertNil(store.server(member: memberHash))
        XCTAssertEqual(store.all.count, 1)
        XCTAssertEqual(ServerCredentials.nextVersion(5, nowMS: now), now / 1000)
    }

    /// Keys in memory, as the app keeps them in the Secure Enclave.
    final class Keys: PeriodKeys {
        var keys: [String: SoftwareSigner] = [:]
        func get(_ kind: String, tag: String) throws -> CertificateSigner {
            if let k = keys["\(kind) \(tag)"] { return k }
            let k = SoftwareSigner()
            keys["\(kind) \(tag)"] = k
            return k
        }
        func has(_ kind: String, tag: String) -> Bool { keys["\(kind) \(tag)"] != nil }
        func keep(_ tag: String) { keys = keys.filter { $0.key.hasSuffix(" \(tag)") } }
    }

    /// A root phone starts a period, signs its own server key and the
    /// lists, and asks for the root key only for the period.
    func testRootStartsAPeriod() throws {
        let t0 = Date(timeIntervalSince1970: 1_792_000_000)
        let rootKey = SoftwareSigner(), member = SoftwareSigner()
        let g = try PhoneGroup.create(caSigner: rootKey, memberKey: member.publicKeyDER, name: "Root", now: t0)
        var store = CredentialStore(groupCA: g.groupCA)
        let keys = Keys()
        var asked = 0
        let root = { () -> CertificateSigner? in asked += 1; return rootKey }
        let now = Int64(t0.timeIntervalSince1970 * 1000)
        let signed = try CredentialRefresh.refresh(&store, records: g.records, groupCA: g.groupCA, root: g.currentRoot, member: member,
                                                   keys: keys, nowMS: now, rootSigner: root)
        XCTAssertEqual(try signed.map { try $0.open().type }, ["period", "server", "hubs", "members"])
        XCTAssertEqual(asked, 1)
        let tag = try XCTUnwrap(store.period(root: rootKey.publicKeyDER)).1.tag
        let mine = Data(SHA256.hash(data: try keys.get(PeriodKeyKind.serverKey, tag: tag).publicKeyDER))
        XCTAssertTrue(try XCTUnwrap(store.members).1.members.contains(mine))
        // What it registers with at a relay.
        let reg = try XCTUnwrap(store.registration(records: g.records, root: rootKey.publicKeyDER, mine: mine))
        XCTAssertEqual(try reg.credentials.map { try $0.open().type }, ["hubs", "members", "period"])
        XCTAssertEqual(reg.roots, [g.groupCA])
        XCTAssertEqual(reg.names, [ServerCredentials.pseudonym(mine): try XCTUnwrap(g.records.devices.first).id])
        XCTAssertNotNil(try ServerCredentials.checkPresented(reg.credentials, nowMS: now).period)
        XCTAssertNil(store.registration(records: g.records, root: rootKey.publicKeyDER, mine: Data(SHA256.hash(data: SoftwareSigner().publicKeyDER))))
        // What a hub registers with at its forwarder: the hubs' credential,
        // only while it lists the hub and lasts.
        let hubs = try XCTUnwrap(store.hubs)
        let listed = try XCTUnwrap(hubs.1.hubs.first)
        XCTAssertEqual(store.hubRegistration(root: rootKey.publicKeyDER, mine: listed, nowMS: now), [hubs.0])
        XCTAssertNil(store.hubRegistration(root: rootKey.publicKeyDER, mine: Data(SHA256.hash(data: SoftwareSigner().publicKeyDER)), nowMS: now))
        XCTAssertNil(store.hubRegistration(root: rootKey.publicKeyDER, mine: listed, nowMS: hubs.1.expires_ms))
        XCTAssertNil(store.hubRegistration(root: SoftwareSigner().publicKeyDER, mine: listed, nowMS: now))
        // Nothing changed: nothing to sign, no Face ID.
        XCTAssertEqual(try CredentialRefresh.refresh(&store, records: g.records, groupCA: g.groupCA, root: g.currentRoot, member: member,
                                                     keys: keys, nowMS: now + 1000, rootSigner: root).count, 0)
        XCTAssertEqual(asked, 1)
        // A month on: a new period, and the keys of the one before are gone.
        let later = try CredentialRefresh.refresh(&store, records: g.records, groupCA: g.groupCA, root: g.currentRoot, member: member,
                                                  keys: keys, nowMS: now + ServerCredentials.periodRenewMS, rootSigner: root)
        XCTAssertEqual(try later.first?.open().type, "period")
        XCTAssertEqual(asked, 2)
        XCTAssertEqual(keys.keys.count, 2)
        // A root whose key cannot sign now keeps the period, and still signs the lists.
        let waiting = try CredentialRefresh.refresh(&store, records: g.records, groupCA: g.groupCA, root: g.currentRoot, member: member,
                                                    keys: keys, nowMS: now + 2 * ServerCredentials.periodRenewMS, rootSigner: { nil })
        XCTAssertFalse(try waiting.contains { try $0.open().type == "period" })
        // Without the root key, and with a server key of its own, it signs only that.
        var other = CredentialStore(groupCA: g.groupCA)
        other.add(root: rootKey.publicKeyDER, isMember: { _ in true }, store.all)
        let alone = try CredentialRefresh.refresh(&other, records: g.records, groupCA: g.groupCA, root: g.currentRoot, member: member,
                                                  keys: Keys(), nowMS: now + ServerCredentials.periodRenewMS + 1000)
        XCTAssertEqual(try alone.map { try $0.open().type }, ["server"])
    }

    /// A message with credentials comes back the same.
    func testCredentialsMessage() throws {
        let c = try ServerCredentials.sign(ServerCredentials.Body(type: ServerCredentials.hubs, group: "0123456789abcdef", version: 1, expires_ms: 1,
                                                                  hubs: ServerCredentials.pad([])), key: SoftwareSigner())
        let m = Member.Message.credentials([c])
        let f = try Member.encode(m)
        XCTAssertEqual(try Member.decode(body: Data(f.dropFirst(4))), m)
    }
}
