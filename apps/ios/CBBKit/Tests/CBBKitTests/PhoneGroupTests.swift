// SPDX-License-Identifier: AGPL-3.0-only

@testable import CBBKit
import Foundation
import XCTest

final class PhoneGroupTests: XCTestCase {
    func testCreateSaveLoad() throws {
        let now = Date()
        let ca = SoftwareSigner()
        let g = try PhoneGroup.create(caSigner: ca, memberKey: SoftwareSigner().publicKeyDER, now: now)
        XCTAssertEqual(try GroupCertificates.verifyMember(g.memberCert, groupCA: g.groupCA, now: now), g.device)
        let root = try ParsedCertificate(der: g.groupCA)
        XCTAssertTrue(root.isCA)
        XCTAssertTrue(try CertificateInfo(der: g.groupCA).commonName?.hasPrefix("cbb group root ") == true)
        XCTAssertEqual(g.tag.count, 16)

        let url = FileManager.default.temporaryDirectory.appendingPathComponent("cb-\(Member.newID())/group.json")
        XCTAssertNil(try PhoneGroup.load(from: url))
        var saved = g
        saved.computers.append(.init(device: Member.newID(), name: "pi", os: "linux", cert: Data([1]), admitted: now))
        // A computer in another subnet is dialed at its home network addresses from the QR code.
        let zero = Member.newID()
        saved.computers.append(.init(device: zero, name: "rpi0w", os: "linux", cert: Data([2]), admitted: now,
                                     addrs: ["192.168.20.5:8764", "203.0.113.7:8764", "[fd00::5]:8764", "[2001:db8::5]:8764"]))
        XCTAssertEqual(saved.addresses, [zero: ["192.168.20.5:8764", "[fd00::5]:8764"]])
        try saved.save(to: url)
        XCTAssertEqual(try PhoneGroup.load(from: url), saved)
    }
}
