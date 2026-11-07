// SPDX-License-Identifier: AGPL-3.0-only

@testable import CBBKit
import Foundation
import XCTest

final class RenewalTests: XCTestCase {
    let day: TimeInterval = 24 * 3600

    func testWhenDue() throws {
        let t0 = Date()
        let ca = SoftwareSigner()
        let g = try PhoneGroup.create(caSigner: ca, memberKey: SoftwareSigner().publicKeyDER, now: t0)
        XCTAssertFalse(GroupCertificates.isDue(g.memberCert, groupCA: g.groupCA, now: t0))
        XCTAssertFalse(GroupCertificates.isDue(g.memberCert, groupCA: g.groupCA, now: t0.addingTimeInterval(365 * day)))
        let later = t0.addingTimeInterval(500 * day) // less than 240 of the 730 days left
        XCTAssertTrue(GroupCertificates.isDue(g.memberCert, groupCA: g.groupCA, now: later))
        XCTAssertFalse(GroupCertificates.isDue(g.memberCert, groupCA: g.groupCA, now: Date(timeIntervalSince1970: 0)), "a clock before the CA")

        let renewed = try XCTUnwrap(GroupCertificates.renewal(of: g.memberCert, groupCA: g.groupCA, caSigner: ca, now: later))
        XCTAssertEqual(try GroupCertificates.verifyMember(renewed, groupCA: g.groupCA, now: later), g.device)
        XCTAssertEqual(try CertificateInfo(der: renewed).publicKey, try CertificateInfo(der: g.memberCert).publicKey)
        XCTAssertGreaterThan(try CertificateInfo(der: renewed).notAfter, try CertificateInfo(der: g.memberCert).notAfter)
        XCTAssertNil(try GroupCertificates.renewal(of: renewed, groupCA: g.groupCA, caSigner: ca, now: later))

        // Another group's certificate is not renewed.
        let other = try PhoneGroup.create(caSigner: SoftwareSigner(), memberKey: SoftwareSigner().publicKeyDER, now: t0)
        XCTAssertNil(try GroupCertificates.renewal(of: other.memberCert, groupCA: g.groupCA, caSigner: ca, now: later))

        var mine = g
        XCTAssertFalse(try mine.renewOwnCertificate(caSigner: ca, now: t0))
        XCTAssertTrue(try mine.renewOwnCertificate(caSigner: ca, now: later))
        XCTAssertNotEqual(mine.memberCert, g.memberCert)
    }

    /// An admin phone renews a peer's certificate from the chain its hello
    /// event carries, and the peer's app gets the renewed one to keep.
    func testNodeSendsRenewal() async throws {
        let t = try CoreGroup(test: self)
        let (phone, peer) = (t.phones[0], t.phones[1])
        try await t.connect(1, to: 0)
        let p = try await phone.peer(peer.device)
        XCTAssertEqual(p.chain.first, peer.cert)
        // A certificate for the same key, as a renewal issues it once one is due.
        XCTAssertEqual(try GroupCertificates.verifyMember(chain: p.chain, roots: t.g.trusted, now: Date()), peer.device)
        let renewed = try GroupCertificates.member(device: peer.device, publicKey: peer.key.publicKeyDER, ca: t.g.groupCA, caSigner: t.ca,
                                                   now: Date().addingTimeInterval(3600))
        XCTAssertNotEqual(renewed, peer.cert)
        XCTAssertTrue(try phone.member.sendCert(to: peer.device, cert: renewed, issuer: nil))
        let kept = try await peer.next("the renewed certificate") { if case let .identity(c, _, _) = $0, c == renewed { return c }; return nil }
        XCTAssertEqual(try GroupCertificates.verifyMember(kept, groupCA: t.g.groupCA, now: Date()), peer.device)
    }

    /// Writes a member's key, certificate and the renewal the phone issues
    /// for the Go side (internal/group, TestSwiftRenewal), which must keep
    /// it with Identity.WithCert, when CBB_INTEROP_OUT names a
    /// directory.
    func testRenewalForGo() throws {
        guard let dir = ProcessInfo.processInfo.environment["CBB_INTEROP_OUT"] else { return }
        let t0 = Date()
        let ca = SoftwareSigner()
        let g = try PhoneGroup.create(caSigner: ca, memberKey: SoftwareSigner().publicKeyDER, now: t0)
        let key = SoftwareSigner()
        let pc = Member.newID()
        let cert = try GroupCertificates.member(device: pc, publicKey: key.publicKeyDER, ca: g.groupCA, caSigner: ca, now: t0)
        let renewed = try XCTUnwrap(GroupCertificates.renewal(of: cert, groupCA: g.groupCA, caSigner: ca, now: t0.addingTimeInterval(500 * day)))
        // An admin phone renews the same certificate from its admin CA,
        // which the cert message carries.
        let adminKey = SoftwareSigner()
        let adminCA = try GroupCertificates.adminCA(device: Member.newID(), publicKey: adminKey.publicKeyDER, root: g.groupCA,
                                                    rootSigner: ca)
        let byAdmin = try XCTUnwrap(GroupCertificates.renewal(chain: [cert], groupCA: g.groupCA, caSigner: adminKey, adminCA: adminCA,
                                                              now: t0.addingTimeInterval(500 * day)))
        struct Out: Encodable { var device: String; var group_ca, key, cert, renewed, admin_ca, admin_renewed: Data }
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        let out = Out(device: pc, group_ca: g.groupCA, key: key.key.derRepresentation, cert: cert, renewed: renewed,
                      admin_ca: adminCA, admin_renewed: byAdmin)
        try (enc.encode(out) + Data("\n".utf8)).write(to: URL(fileURLWithPath: dir).appendingPathComponent("swift-renewal.json"))
    }
}
