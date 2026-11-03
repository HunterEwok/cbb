// SPDX-License-Identifier: AGPL-3.0-only

@testable import ClipboardBridgeKit
import Crypto
import Foundation
import XCTest

final class CertificateTests: XCTestCase {
    /// Splits a certificate into the signed part, and checks the signature
    /// with the CA's public key.
    func verify(_ cert: Data, with caKey: Data) throws -> Bool {
        var r = DERReader(Array(cert))
        var outer = try r.read(0x30)
        let tbs = try outer.readAny(raw: true).bytes
        _ = try outer.read(0x30)
        let sig = Array(try outer.read(0x03).bytes.dropFirst())
        let key = try P256.Signing.PublicKey(derRepresentation: caKey)
        return key.isValidSignature(try P256.Signing.ECDSASignature(derRepresentation: sig), for: Data(tbs))
    }

    func testGroupCAAndMember() throws {
        let now = Date(timeIntervalSince1970: 1_790_000_000) // 2026-09
        let caSigner = SoftwareSigner()
        let ca = try GroupCertificates.groupCA(signer: caSigner, now: now, pathLength: 1)
        let caInfo = try CertificateInfo(der: ca)
        XCTAssertTrue(try verify(ca, with: caSigner.publicKeyDER))
        XCTAssertEqual(caInfo.notBefore, now.addingTimeInterval(-GroupCertificates.backdate))
        XCTAssertEqual(caInfo.publicKey, caSigner.publicKeyDER)

        let device = SoftwareSigner()
        let id = "0123456789abcdef0123456789abcdef"
        let member = try GroupCertificates.member(device: id, publicKey: device.publicKeyDER, ca: ca, caSigner: caSigner, now: now)
        let info = try CertificateInfo(der: member)
        XCTAssertTrue(try verify(member, with: caSigner.publicKeyDER))
        XCTAssertFalse(try verify(member, with: SoftwareSigner().publicKeyDER))
        XCTAssertEqual(info.notBefore, caInfo.notBefore)
        XCTAssertEqual(info.notAfter, Calendar.utc.date(byAdding: .year, value: 2, to: now))
        XCTAssertEqual(info.publicKey, device.publicKeyDER)

        XCTAssertThrowsError(try GroupCertificates.member(device: "nope", publicKey: device.publicKeyDER, ca: ca, caSigner: caSigner, now: now))
        XCTAssertThrowsError(try GroupCertificates.member(device: id, publicKey: device.publicKeyDER, ca: ca, caSigner: caSigner,
                                                          now: now.addingTimeInterval(-3 * 24 * 3600)))
        writeInterop(ca: ca, member: member, device: id, key: device.key)
    }

    func testDERTime() {
        XCTAssertEqual(DER.time(Date(timeIntervalSince1970: 0)), DER.tlv(0x17, Array("700101000000Z".utf8)))
        XCTAssertEqual(DER.time(Date(timeIntervalSince1970: 2_524_608_000)), DER.tlv(0x18, Array("20500101000000Z".utf8)))
    }

    func testDERInteger() {
        XCTAssertEqual(DER.integer(0), [0x02, 0x01, 0x00])
        XCTAssertEqual(DER.integer(128), [0x02, 0x02, 0x00, 0x80])
        XCTAssertEqual(DER.integer(unsigned: [0, 0, 1]), [0x02, 0x01, 0x01])
        XCTAssertEqual(DER.oid("1.2.840.10045.4.3.2"), [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02])
    }

    /// With CBB_WRITE_INTEROP set, writes the certificates for the Go
    /// test that checks them (internal/group, TestSwiftCertificates).
    func writeInterop(ca: Data, member: Data, device: String, key: P256.Signing.PrivateKey) {
        guard ProcessInfo.processInfo.environment["CBB_WRITE_INTEROP"] != nil else { return }
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<6 { url.deleteLastPathComponent() }
        let obj: [String: String] = [
            "group_ca": ca.base64EncodedString(),
            "member": member.base64EncodedString(),
            "device": device,
            "member_key": key.rawRepresentation.base64EncodedString(),
            "note": "written by ClipboardBridgeKit's CertificateTests with CBB_WRITE_INTEROP=1; test keys only",
        ]
        let data = try! JSONSerialization.data(withJSONObject: obj, options: [.prettyPrinted, .sortedKeys])
        try! (data + Data("\n".utf8)).write(to: url.appendingPathComponent("testdata/interop/swift-certs.json"))
    }
}
