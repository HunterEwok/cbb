// SPDX-License-Identifier: AGPL-3.0-only

@testable import CBBKit
import Foundation
import XCTest

/// SplitMix64: a fixed seed, so that a failure repeats.
struct SeededGenerator: RandomNumberGenerator {
    var state: UInt64
    mutating func next() -> UInt64 {
        state &+= 0x9e37_79b9_7f4a_7c15
        var z = state
        z = (z ^ (z >> 30)) &* 0xbf58_476d_1ce4_e5b9
        z = (z ^ (z >> 27)) &* 0x94d0_49bb_1331_11eb
        return z ^ (z >> 31)
    }
}

/// Mutates a member certificate, its admin CA and the root at random and
/// checks that the kit's own DER reader fails only with its own errors and
/// never lets a changed signed part through. The Kotlin kit has the same test
/// (CertificatesFuzzTest).
final class CertificateFuzzTests: XCTestCase {
    let now = Date(timeIntervalSince1970: 1_790_000_000) // 2026-09
    let id = "0123456789abcdef0123456789abcdef"
    var root = Data(), admin = Data(), member = Data()

    override func setUpWithError() throws {
        let rootSigner = SoftwareSigner(), adminSigner = SoftwareSigner()
        root = try GroupCertificates.groupCA(signer: rootSigner, now: now, pathLength: 1)
        admin = try GroupCertificates.adminCA(device: "fedcba9876543210fedcba9876543210", publicKey: adminSigner.publicKeyDER,
                                              root: root, rootSigner: rootSigner)
        member = try GroupCertificates.member(device: id, publicKey: SoftwareSigner().publicKeyDER, ca: admin,
                                              caSigner: adminSigner, now: now)
    }

    /// One random change: a bit, a byte with a telling value, a cut, a byte out or in, or bytes after the end.
    func mutate(_ der: Data, _ r: inout SeededGenerator) -> Data {
        var b = Array(der)
        let i = Int.random(in: 0..<b.count, using: &r)
        switch Int.random(in: 0..<6, using: &r) {
        case 0: b[i] ^= 1 << UInt8.random(in: 0..<8, using: &r)
        case 1: b[i] = [0x00, 0x01, 0x7f, 0x80, 0x81, 0x84, 0xff].randomElement(using: &r)!
        case 2: b = Array(b[..<i])
        case 3: b.remove(at: i)
        case 4: b.insert(UInt8.random(in: 0...255, using: &r), at: i)
        default: b += (0..<Int.random(in: 1...8, using: &r)).map { _ in UInt8.random(in: 0...255, using: &r) }
        }
        return Data(b)
    }

    func tbs(_ der: Data) throws -> [UInt8] { try ParsedCertificate(der: der).tbs }

    /// Runs block on a mutant; only the kit's own errors may come out of it.
    func expected<T>(_ mutant: Data, _ block: () throws -> T) -> T? {
        do {
            return try block()
        } catch is GroupCertificates.VerifyError {
            return nil
        } catch is GroupCertificates.CertificateError {
            return nil
        } catch {
            XCTFail("\(error) on \(hex(Array(mutant)))")
            return nil
        }
    }

    // Lengths near the limits of the reader's bounds check.
    func testHugeLengths() {
        for len in ["847fffffff", "84ffffffff", "8480000000", "847ffffffe"] {
            let der = Data(unhex("30\(len)00"))
            var r = DERReader(Array(der))
            _ = expected(der) { try r.readAny() }
            _ = expected(der) { try CertificateInfo(der: der) }
            _ = expected(der) { try GroupCertificates.verifyMember(der, groupCA: root, issuer: admin, now: now) }
        }
    }

    func testMutatedMemberCertificates() throws {
        var r = SeededGenerator(state: 20_261_025)
        for _ in 0..<3000 {
            let m = mutate(member, &r)
            _ = expected(m) { try CertificateInfo(der: m).commonName }
            _ = expected(m) { try ParsedCertificate(der: m) }
            if let got = expected(m, { try GroupCertificates.verifyMember(m, groupCA: root, issuer: admin, now: now) }) {
                XCTAssertEqual(got, id, hex(Array(m)))
                XCTAssertEqual(try tbs(m), try tbs(member), hex(Array(m)))
            }
            if expected(m, { try GroupCertificates.verifyMember(chain: [m, admin], roots: [root], now: now) }) != nil {
                XCTAssertEqual(try tbs(m), try tbs(member), hex(Array(m)))
            }
        }
    }

    func testMutatedAdminCAs() throws {
        var r = SeededGenerator(state: 20_261_026)
        for _ in 0..<3000 {
            let a = mutate(admin, &r)
            if expected(a, { try GroupCertificates.checkAdminCA(a, root: root) }) != nil {
                XCTAssertEqual(try tbs(a), try tbs(admin), hex(Array(a)))
            }
            if let got = expected(a, { try GroupCertificates.verifyMember(member, groupCA: root, issuer: a, now: now) }) {
                XCTAssertEqual(got, id, hex(Array(a)))
                XCTAssertEqual(try tbs(a), try tbs(admin), hex(Array(a)))
            }
        }
    }

    func testMutatedRoots() throws {
        var r = SeededGenerator(state: 20_261_027)
        for _ in 0..<2000 {
            let x = mutate(root, &r)
            if expected(x, { try GroupCertificates.checkRoot(x) }) != nil {
                XCTAssertEqual(try tbs(x), try tbs(root), hex(Array(x)))
            }
            // A root is a trust anchor, as in Go: only its name and key count, not its own signature.
            if expected(x, { try GroupCertificates.verifyMember(chain: [member, admin], roots: [x], now: now) }) != nil {
                XCTAssertEqual(try CertificateInfo(der: x).rawSubject, try CertificateInfo(der: root).rawSubject, hex(Array(x)))
                XCTAssertEqual(try CertificateInfo(der: x).publicKey, try CertificateInfo(der: root).publicKey, hex(Array(x)))
            }
        }
    }
}
