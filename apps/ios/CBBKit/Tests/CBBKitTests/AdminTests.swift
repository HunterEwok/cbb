// SPDX-License-Identifier: AGPL-3.0-only

@testable import CBBKit
import Foundation
import XCTest

/// Admin CAs under a phone's root (docs/protocol.md, section 10): the
/// certificates they issue and the records they sign.
final class AdminTests: XCTestCase {
    struct Group {
        let t0 = Date()
        let root = SoftwareSigner(), admin = SoftwareSigner()
        let rootCA: Data, adminCA: Data, adminDevice = Member.newID()

        init() throws {
            rootCA = try GroupCertificates.groupCA(signer: root, now: t0, pathLength: 1)
            adminCA = try GroupCertificates.adminCA(device: adminDevice, publicKey: admin.publicKeyDER, root: rootCA, rootSigner: root)
        }

        var tag: String { GroupCertificates.tag(groupCA: rootCA) }

        /// A member certificate from the admin CA, or from the root.
        func member(byAdmin: Bool = true) throws -> (device: String, key: SoftwareSigner, cert: Data) {
            let key = SoftwareSigner(), dev = Member.newID()
            let cert = try GroupCertificates.member(device: dev, publicKey: key.publicKeyDER, ca: byAdmin ? adminCA : rootCA,
                                                    caSigner: byAdmin ? admin : root, now: t0)
            return (dev, key, cert)
        }
    }

    func testAdminCA() throws {
        let g = try Group()
        XCTAssertNoThrow(try GroupCertificates.checkAdminCA(g.adminCA, root: g.rootCA))
        let m = try g.member()
        XCTAssertEqual(try GroupCertificates.verifyMember(m.cert, groupCA: g.rootCA, issuer: g.adminCA, now: g.t0), m.device)
        XCTAssertEqual(try GroupCertificates.verifyMember(chain: [m.cert, g.adminCA], groupCA: g.rootCA, now: g.t0), m.device)
        XCTAssertThrowsError(try GroupCertificates.verifyMember(m.cert, groupCA: g.rootCA, now: g.t0), "without its issuer")
        XCTAssertThrowsError(try GroupCertificates.verifyMember(chain: [m.cert], groupCA: g.rootCA, now: g.t0))
        let byRoot = try g.member(byAdmin: false)
        XCTAssertEqual(try GroupCertificates.verifyMember(chain: [byRoot.cert], groupCA: g.rootCA, now: g.t0), byRoot.device)

        // A member certificate is no admin CA, and a computer's group CA
        // (path length 0) certifies none.
        XCTAssertThrowsError(try GroupCertificates.checkAdminCA(byRoot.cert, root: g.rootCA))
        XCTAssertThrowsError(try GroupCertificates.verifyMember(m.cert, groupCA: g.rootCA, issuer: byRoot.cert, now: g.t0))
        let flat = try GroupCertificates.groupCA(signer: g.root, now: g.t0)
        let under = try GroupCertificates.adminCA(device: g.adminDevice, publicKey: g.admin.publicKeyDER, root: flat, rootSigner: g.root)
        XCTAssertThrowsError(try GroupCertificates.checkAdminCA(under, root: flat))
        // Another group's admin CA does not count.
        let other = try Group()
        XCTAssertThrowsError(try GroupCertificates.checkAdminCA(other.adminCA, root: g.rootCA))
    }

    func testRecordsThroughAdminCA() throws {
        let g = try Group()
        let pc = try g.member(), phone = try g.member(byAdmin: false)
        let adminKey = try Records.keyHash(cert: g.adminCA)
        var set = RecordSet()
        try set.signed(.device(g.adminDevice, name: "Second", role: "phone", key: Records.keyHash(spki: g.admin.publicKeyDER),
                               admin: adminKey, signer: g.root, now: g.t0), g.root, groupCA: g.rootCA)
        try set.signed(.device(pc.device, name: "Desk", role: "full", key: Records.keyHash(cert: pc.cert), signer: g.admin, now: g.t0),
                       g.admin, adminCA: g.adminCA, groupCA: g.rootCA)
        try set.signed(.device(phone.device, name: "Phone", role: "phone", key: Records.keyHash(cert: phone.cert), signer: g.root, now: g.t0),
                       g.root, groupCA: g.rootCA)
        XCTAssertEqual(set.records.count, 3)
        XCTAssertEqual(set.devices.map(\.name), ["Desk", "Phone", "Second"])
        XCTAssertEqual(set.devices.first { $0.name == "Second" }?.admin, true)
        XCTAssertNil(set.refused(chain: [pc.cert, g.adminCA]))

        // Signed by the admin key without its chain, or with a chain that
        // is not an admin CA, a record is refused.
        let x = try Records.Body.device(pc.device, name: "X", role: "full", key: Records.keyHash(cert: pc.cert), signer: g.admin, now: g.t0)
        XCTAssertFalse(set.add(try set.sign(x, with: g.admin), groupCA: g.rootCA))
        let y = try Records.Body.device(pc.device, name: "X", role: "full", key: Records.keyHash(cert: pc.cert), signer: pc.key, now: g.t0)
        XCTAssertFalse(set.add(try set.sign(y, with: pc.key, adminCA: pc.cert), groupCA: g.rootCA))
        XCTAssertEqual(set.records.count, 3)

        // The admin phone is lost: the root removes its admin key and its
        // key. What it signed before stays (docs/protocol.md, section 10, "Removals
        // and freezes keep what the author saw").
        // The admin's member key is its admin key here.
        try set.signed(.revoke([adminKey, Records.keyHash(spki: g.admin.publicKeyDER)], signer: g.root, now: g.t0), g.root, groupCA: g.rootCA)
        XCTAssertEqual(set.devices.map(\.name), ["Desk", "Phone"])
        XCTAssertNil(set.refused(chain: [pc.cert, g.adminCA]))
        // Records the lost admin signs after that count for nothing.
        let late = try g.member()
        try set.signed(.device(late.device, name: "Late", role: "full", key: Records.keyHash(cert: late.cert), signer: g.admin, now: g.t0),
                       g.admin, adminCA: g.adminCA, groupCA: g.rootCA)
        XCTAssertEqual(set.devices.map(\.name), ["Desk", "Phone"])
        XCTAssertNotNil(set.refused(chain: [late.cert, g.adminCA]))
    }

    func testRenewalOfAdminIssued() throws {
        let g = try Group()
        let m = try g.member()
        let later = g.t0.addingTimeInterval(500 * 24 * 3600)
        XCTAssertNil(try GroupCertificates.renewal(of: m.cert, groupCA: g.rootCA, caSigner: g.root, now: later), "without its issuer")
        let renewed = try XCTUnwrap(GroupCertificates.renewal(of: m.cert, groupCA: g.rootCA, issuer: g.adminCA, caSigner: g.root, now: later))
        XCTAssertEqual(try GroupCertificates.verifyMember(renewed, groupCA: g.rootCA, now: later), m.device)
    }

    func testWelcomeIssuer() throws {
        let g = try Group()
        let m = try g.member()
        let f = Pairing.Frame(welcome: Pairing.Welcome(cert: m.cert, groupCA: g.rootCA, issuer: g.adminCA))
        let json = try JSONSerialization.jsonObject(with: Pairing.encode(f).dropFirst(4)) as? [String: Any]
        let w = try XCTUnwrap(json?["welcome"] as? [String: Any])
        XCTAssertEqual(w["issuer"] as? String, g.adminCA.base64EncodedString())
        let plain = try Pairing.encode(Pairing.Frame(welcome: Pairing.Welcome(cert: m.cert, groupCA: g.rootCA)))
        XCTAssertFalse(String(decoding: plain, as: UTF8.self).contains("issuer"))
    }

    /// Writes swift-admin.json for internal/group's TestSwiftAdmin.
    func testAdminForGo() throws {
        guard let dir = ProcessInfo.processInfo.environment["CBB_INTEROP_OUT"] else { return }
        let g = try Group()
        let pc = try g.member()
        let adminKey = try Records.keyHash(cert: g.adminCA)
        var set = RecordSet()
        try set.signed(.device(g.adminDevice, name: "Second", role: "phone", key: Records.keyHash(spki: g.admin.publicKeyDER),
                               admin: adminKey, signer: g.root, now: g.t0), g.root, groupCA: g.rootCA)
        try set.signed(.device(pc.device, name: "Desk", role: "full", key: Records.keyHash(cert: pc.cert), signer: g.admin, now: g.t0),
                       g.admin, adminCA: g.adminCA, groupCA: g.rootCA)
        let records = set.records
        struct Out: Encodable {
            var group_ca, admin_ca, cert, key: Data
            var device: String
            var records: [Member.Record]
            var devices: [String]
            var digest: String
        }
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        let out = Out(group_ca: g.rootCA, admin_ca: g.adminCA, cert: pc.cert, key: pc.key.key.derRepresentation, device: pc.device,
                      records: records, devices: set.devices.map(\.id), digest: set.digest ?? "")
        try (enc.encode(out) + Data("\n".utf8)).write(to: URL(fileURLWithPath: dir).appendingPathComponent("swift-admin.json"))
    }
}
