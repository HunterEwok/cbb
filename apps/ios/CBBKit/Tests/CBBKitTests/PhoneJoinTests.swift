// SPDX-License-Identifier: AGPL-3.0-only

@testable import CBBKit
import Foundation
import XCTest

/// A second phone joins a phone group and becomes an admin (docs/protocol.md,
/// sections 6 and 10), then admits, renews and is removed.
final class PhoneJoinTests: XCTestCase {
    let t0 = Date()
    let sid = (0..<32).map { _ in UInt8.random(in: .min ... .max) }

    /// A device that listens for pairing: its device ID, member key and
    /// self-signed certificate.
    struct Listener {
        let device = SyncEngine.newID()
        let key = SoftwareSigner()
        let cert: Data
        init() throws { cert = try GroupCertificates.selfSigned(device: device, signer: key) }
    }

    /// Runs one pairing: the admitting phone dials the listener, which
    /// answers with joinerCode (code when nil).
    /// With admin, the key info's adminKey names, the joiner proves it for
    /// the session.
    func pair(_ admitter: PhoneGroup, signer: CertificateSigner, _ l: Listener, info: Pairing.Info, admin: CertificateSigner? = nil,
              code: String = "123456", joinerCode: String? = nil, makeAdmin: Bool = true, now: Date? = nil)
        async -> (member: Result<(PhoneGroup, PairingMember.Admitted), Error>, joiner: Result<PairingJoiner.Joined, Error>) {
        let now = now ?? t0
        let (m, j) = Pipe.pair()
        let sid = sid
        let info = (try? admin.map { try info.proving(sessionID: sid, with: $0) }) ?? info
        let memberSide = Task { () async throws -> (PhoneGroup, PairingMember.Admitted) in
            var g = admitter
            let a = try await g.admit(over: m, code: code, joinerCert: l.cert, sessionID: sid, caSigner: signer, makeAdmin: makeAdmin, now: now)
            return (g, a)
        }
        let joined: Result<PairingJoiner.Joined, Error>
        do {
            joined = .success(try await PairingJoiner.accept(over: j, code: joinerCode ?? code, info: info, memberCert: admitter.memberCert,
                                                             joinerCert: l.cert, sessionID: sid, now: now) { _ in })
        } catch {
            joined = .failure(error)
        }
        j.close()
        let member: Result<(PhoneGroup, PairingMember.Admitted), Error>
        do { member = .success(try await memberSide.value) } catch { member = .failure(error) }
        return (member, joined)
    }

    func testSecondPhoneBecomesAdmin() async throws {
        let rootKey = SoftwareSigner(), seal = try CommandTests.sealPublic()
        var root = try PhoneGroup.create(caSigner: rootKey, memberKey: SoftwareSigner().publicKeyDER, name: "First", seal: seal, now: t0)
        XCTAssertEqual(root.records.rootDevice, root.device)
        XCTAssertEqual(root.devices.first { $0.id == root.device }?.seal, seal, "the root phone's own key for sealed messages")

        // The second phone joins with an admin key and gets its admin CA.
        let second = try Listener(), adminKey = SoftwareSigner()
        let r = await pair(root, signer: rootKey, second, info: .init(name: "Second", os: "ios", adminKey: adminKey.publicKeyDER, seal: seal),
                           admin: adminKey)
        let joined = try r.joiner.get()
        let (rootAfter, admitted) = try r.member.get()
        root = rootAfter
        XCTAssertTrue(admitted.confirmed)
        XCTAssertEqual(joined.device, second.device)
        let adminCA = try XCTUnwrap(joined.welcome.adminCA)
        XCTAssertNoThrow(try GroupCertificates.checkAdminCA(adminCA, root: root.groupCA))
        XCTAssertTrue(root.computers.isEmpty, "a phone is no computer")
        let listed = try XCTUnwrap(root.devices.first { $0.id == second.device })
        XCTAssertEqual(listed.role, "phone")
        XCTAssertTrue(listed.admin)
        XCTAssertEqual(listed.seal, seal, "a phone's key for sealed messages, from its pairing")

        var admin = PhoneGroup.joined(joined)
        XCTAssertFalse(admin.isRoot)
        XCTAssertTrue(admin.isAdmin)
        XCTAssertEqual(admin.tag, root.tag)
        XCTAssertEqual(admin.memberChain, [joined.welcome.cert])
        // The records reach it through the computers.
        for rec in root.records.records { admin.records.add(rec, groupCA: admin.groupCA) }
        XCTAssertEqual(admin.records.rootDevice, root.device)

        // The admin admits a computer from its own admin CA.
        let pc = try Listener()
        let r2 = await pair(admin, signer: adminKey, pc, info: .init(name: "pi", os: "linux"))
        let pcJoined = try r2.joiner.get()
        (admin, _) = try r2.member.get()
        XCTAssertEqual(pcJoined.welcome.issuer, adminCA)
        XCTAssertNil(pcJoined.welcome.adminCA)
        XCTAssertEqual(try GroupCertificates.verifyMember(chain: [pcJoined.welcome.cert, adminCA], groupCA: root.groupCA, now: t0), pc.device)
        XCTAssertEqual(admin.computers.map(\.device), [pc.device])
        for rec in admin.records.records { root.records.add(rec, groupCA: root.groupCA) }
        XCTAssertTrue(root.devices.contains { $0.id == pc.device }, "a record signed through the admin CA counts")
        // The root and the admin may be the hub away from home; a plain member may not.
        XCTAssertTrue(root.records.mayHost(root.device))
        XCTAssertTrue(root.records.mayHost(second.device))
        XCTAssertFalse(root.records.mayHost(pc.device))
        // By key: the root's own chain and the admin's, not another device's under their IDs.
        XCTAssertTrue(root.records.mayHost(root.device, chain: root.memberChain))
        XCTAssertTrue(root.records.mayHost(second.device, chain: admin.memberChain))
        XCTAssertFalse(root.records.mayHost(pc.device, chain: [pcJoined.welcome.cert, adminCA]), "a chain whose key no admin record names")
        XCTAssertFalse(root.records.mayHost(root.device, chain: admin.memberChain))

        // Renewals: an admin renews what it issued, the root renews any.
        let later = t0.addingTimeInterval(500 * 24 * 3600)
        let pcChain = [pcJoined.welcome.cert, adminCA]
        let byAdmin = try XCTUnwrap(admin.renewal(chain: pcChain, caSigner: adminKey, now: later))
        XCTAssertEqual(byAdmin.issuer, adminCA)
        XCTAssertEqual(try GroupCertificates.verifyMember(byAdmin.cert, groupCA: root.groupCA, issuer: adminCA, now: later), pc.device)
        // An admin renews what the root issued too, from its own admin CA.
        let rootsOne = try XCTUnwrap(admin.renewal(chain: [root.memberCert], caSigner: adminKey, now: later))
        XCTAssertEqual(try GroupCertificates.verifyMember(rootsOne.cert, groupCA: root.groupCA, issuer: adminCA, now: later), root.device)
        let byRoot = try XCTUnwrap(root.renewal(chain: pcChain, caSigner: rootKey, now: later)).cert
        XCTAssertEqual(try GroupCertificates.verifyMember(byRoot, groupCA: root.groupCA, now: later), pc.device)
        XCTAssertTrue(try admin.renewOwnCertificate(caSigner: adminKey, now: later))
        XCTAssertEqual(admin.memberIssuer, adminCA)
        XCTAssertEqual(try GroupCertificates.verifyMember(chain: admin.memberChain, groupCA: root.groupCA, now: later), admin.device)

        // The admin cannot remove the root; the root removes the admin and
        // every listed device stays: the computer it admitted, and the root,
        // whose certificate it renewed (docs/protocol.md, section 10, "Removals and
        // freezes keep what the author saw").
        XCTAssertThrowsError(try admin.revoke(device: root.device, caSigner: adminKey, now: t0)) {
            XCTAssertEqual($0 as? PhoneGroup.Failure, .cannotRemoveRoot)
        }
        let revocation = try root.revoke(device: second.device, caSigner: rootKey, now: t0)
        struct Keys: Decodable { var type: String, keys: [Data]? }
        let body = try JSONDecoder().decode(Keys.self, from: revocation.body)
        XCTAssertEqual(body.type, "revoke")
        XCTAssertEqual(Set(body.keys ?? []), [listed.key, try Records.keyHash(cert: adminCA)])
        XCTAssertFalse(root.devices.contains { $0.id == second.device })
        XCTAssertTrue(root.devices.contains { $0.id == pc.device })
        XCTAssertNil(root.records.refused(chain: pcChain))
        XCTAssertNil(root.records.refused(chain: [rootsOne.cert, adminCA]), "the root's certificate the removed admin renewed")
        XCTAssertNotNil(root.records.refused(chain: [joined.welcome.cert]))
    }

    func testPhoneWithoutAdmin() async throws {
        let rootKey = SoftwareSigner()
        let root = try PhoneGroup.create(caSigner: rootKey, memberKey: SoftwareSigner().publicKeyDER, now: t0)
        let l = try Listener()
        let third = SoftwareSigner()
        let r = await pair(root, signer: rootKey, l, info: .init(name: "Third", os: "ios", adminKey: third.publicKeyDER), admin: third,
                           makeAdmin: false)
        let joined = try r.joiner.get()
        XCTAssertNil(joined.welcome.adminCA)
        let (after, _) = try r.member.get()
        XCTAssertEqual(after.devices.first { $0.id == l.device }?.admin, false)
        var g = PhoneGroup.joined(joined)
        XCTAssertFalse(g.isAdmin)
        XCTAssertThrowsError(try g.revoke(device: root.device, caSigner: rootKey, now: t0)) {
            XCTAssertEqual($0 as? PhoneGroup.Failure, .notAdmin)
        }
        XCTAssertFalse(try g.renewOwnCertificate(caSigner: rootKey, now: t0.addingTimeInterval(500 * 24 * 3600)))

        // An admin that is not the root makes no admins.
        let adminKey = SoftwareSigner(), l2 = try Listener()
        let r2 = await pair(root, signer: rootKey, l2, info: .init(name: "Admin", os: "ios", adminKey: adminKey.publicKeyDER), admin: adminKey)
        let admin = PhoneGroup.joined(try r2.joiner.get())
        let l3 = try Listener()
        let fourth = SoftwareSigner()
        let r3 = await pair(admin, signer: adminKey, l3, info: .init(name: "Fourth", os: "android", adminKey: fourth.publicKeyDER), admin: fourth)
        XCTAssertNil(try r3.joiner.get().welcome.adminCA)
    }

    /// A phone that offers an admin key it does not prove is refused
    /// before any admin CA is made.
    func testAdminKeyWithoutProof() async throws {
        let rootKey = SoftwareSigner()
        let root = try PhoneGroup.create(caSigner: rootKey, memberKey: SoftwareSigner().publicKeyDER, now: t0)
        var info = Pairing.Info(name: "Other", os: "ios", adminKey: SoftwareSigner().publicKeyDER)
        info.adminProof = Data([1])
        let r = await pair(root, signer: rootKey, try Listener(), info: info)
        XCTAssertThrowsError(try r.member.get()) { XCTAssertEqual($0 as? PairingMember.Failure, .refused(.refused)) }
        XCTAssertThrowsError(try r.joiner.get())
    }

    func testWrongCode() async throws {
        let rootKey = SoftwareSigner()
        let root = try PhoneGroup.create(caSigner: rootKey, memberKey: SoftwareSigner().publicKeyDER, now: t0)
        let r = await pair(root, signer: rootKey, try Listener(), info: .init(name: "Second", os: "ios"), joinerCode: "654321")
        XCTAssertThrowsError(try r.joiner.get()) { XCTAssertEqual($0 as? PairingJoiner.Failure, .refused(.wrongCode)) }
        XCTAssertThrowsError(try r.member.get()) { XCTAssertEqual($0 as? PairingMember.Failure, .refused(.wrongCode)) }
    }

    func testJoinerRefusesAWelcomeForAnotherKey() async throws {
        let rootKey = SoftwareSigner()
        let root = try PhoneGroup.create(caSigner: rootKey, memberKey: SoftwareSigner().publicKeyDER, now: t0)
        let l = try Listener()
        let (m, j) = Pipe.pair()
        let (sid, t0) = (sid, t0)
        let memberSide = Task {
            try await PairingMember.admit(over: m, code: "123456", memberCert: root.memberCert, joinerCert: l.cert, sessionID: sid,
                                          memberAD: .init(device: root.device, group: root.tag)) { dev, _, _ in
                Pairing.Welcome(cert: try GroupCertificates.member(device: dev, publicKey: SoftwareSigner().publicKeyDER, ca: root.groupCA,
                                                                   caSigner: rootKey, now: t0), groupCA: root.groupCA)
            }
        }
        do {
            _ = try await PairingJoiner.accept(over: j, code: "123456", info: .init(name: "Second", os: "ios"), memberCert: root.memberCert,
                                               joinerCert: l.cert, sessionID: sid, now: t0) { _ in XCTFail("stored a bad welcome") }
            XCTFail("took a certificate for another key")
        } catch {
            guard case .badWelcome = error as? PairingJoiner.Failure else { return XCTFail("\(error)") }
        }
        let admitted = try await memberSide.value
        XCTAssertFalse(admitted.confirmed)
    }

    /// A self-signed certificate with a P-384 key for the device ID
    /// 0123456789abcdef0123456789abcdef.
    static let p384Cert = Data(base64Encoded: "MIIB6DCCAW6gAwIBAgIUAZv1zxaQendV3vrzM9UqL0xFbGQwCgYIKoZIzj0EAwIwKzEpMCcGA1UEAwwgMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWYwHhcNMjYxMDMxMDgwMTA3WhcNMzYxMDI4MDgwMTA3WjArMSkwJwYDVQQDDCAwMTIzNDU2Nzg5YWJjZGVmMDEyMzQ1Njc4OWFiY2RlZjB2MBAGByqGSM49AgEGBSuBBAAiA2IABGPVHQzOkUL3/eN4mcZqO6tU7B6YS8I21tzGWFeoddh3g8gFJ+lvOeXnWNDs5Kb4ewC4C7xajcObF96dLzHm4iJLndLCPs6Ry8yp+n1Qq2iNjfdEP6DbDovujn61huXGe6NTMFEwHQYDVR0OBBYEFOiZlbxuz4DpfnxiZUCH1Uk1ltN+MB8GA1UdIwQYMBaAFOiZlbxuz4DpfnxiZUCH1Uk1ltN+MA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDaAAwZQIxAL+QMr4a6NK+ye/WnoyqP6zSKvX2m36eBB4JLFFWRDXxvuDkkxbOyY1qZTgnAIK79AIwe1vxP94FlJL73T9uTn9I9VolozxxhdFHmsM+uW9t+sFJU14EH1l/ci4PaH7hPKkz")!

    /// A transport that only shows a TLS handshake's certificates.
    final class Certs: FrameTransport {
        let peerChain: [Data]
        init(_ chain: [Data]) { peerChain = chain }
        func write(_ data: Data) async throws { throw CancellationError() }
        func read(exactly n: Int) async throws -> Data { throw CancellationError() }
    }

    func testMemberRefusesAJoinerKeyOrChainAsAComputerDoes() async throws {
        let root = try PhoneGroup.create(caSigner: SoftwareSigner(), memberKey: SoftwareSigner().publicKeyDER, now: t0)
        let l = try Listener()
        for (t, cert, why) in [(Certs([Self.p384Cert]), Self.p384Cert, "the joining device's key is not a P-256 key"),
                               (Certs([l.cert, root.memberCert]), l.cert, "the joining device must send exactly one certificate")] {
            do {
                _ = try await PairingMember.admit(over: t, code: "123456", memberCert: root.memberCert, joinerCert: cert, sessionID: sid,
                                                  memberAD: .init(device: root.device, group: root.tag)) { _, _, _ in
                    throw CancellationError()
                }
                XCTFail("admitted: \(why)")
            } catch {
                XCTAssertEqual(error as? PairingMember.Failure, .badJoiner(why))
            }
        }
    }

    func testInfo() throws {
        let signer = SoftwareSigner(), key = signer.publicKeyDER
        let proved = try Pairing.Info(name: "iPhone", os: "ios", adminKey: key).proving(sessionID: sid, with: signer)
        XCTAssertTrue(proved.isValid)
        XCTAssertFalse(Pairing.Info(name: "iPhone", os: "ios", adminKey: key).isValid, "an admin key comes with its proof")
        XCTAssertTrue(proved.provesAdminKey(sessionID: sid))
        XCTAssertFalse(proved.provesAdminKey(sessionID: Array(repeating: 0, count: 32)), "a proof for another session")
        var other = proved
        other.adminKey = SoftwareSigner().publicKeyDER
        XCTAssertFalse(other.provesAdminKey(sessionID: sid), "a proof by another key")
        XCTAssertTrue(Pairing.Info(name: "iPhone", os: "ios").isValid)
        XCTAssertFalse(Pairing.Info(name: "pi", os: "linux", adminKey: key).isValid, "only a phone sends an admin key")
        XCTAssertFalse(Pairing.Info(name: "iPhone", os: "ios", adminKey: Data([1, 2, 3])).isValid)
        XCTAssertTrue(Pairing.Info(name: "pc", os: "windows").isValid, "a Windows PC joins as a computer")
        XCTAssertTrue(Pairing.Info(name: "Café — Büro 1", os: "linux").isValid)
        for bad in ["a\u{7}b", "evil\u{202E}gpj", "a\u{200B}b", "a\u{E000}b", "a\u{A0}b", "a\u{2028}b"] {
            XCTAssertFalse(Pairing.Info(name: bad, os: "linux").isValid, "a name is printable, as in Go: \(bad.unicodeScalars.map { String($0.value, radix: 16) })")
        }
        XCTAssertFalse(Pairing.Info(name: "mac", os: "darwin").isValid)
        XCTAssertFalse(Pairing.Info(name: "pi", os: "none").isValid)
        var pixel = proved
        pixel.os = "android"
        XCTAssertTrue(pixel.isValid, "an Android phone joins as a phone")
        XCTAssertTrue(Pairing.Info(name: "router", os: "linux", role: Pairing.Info.lite).isValid, "a lite member")
        XCTAssertFalse(Pairing.Info(name: "router", os: "linux", role: "full").isValid)
        // A computer's Info is encoded as before, without the admin key.
        let json = String(decoding: try JSONEncoder().encode(Pairing.Info(name: "pi", os: "linux")), as: UTF8.self)
        XCTAssertFalse(json.contains("admin_key"))

        let l = try Listener()
        let info = try CertificateInfo(der: l.cert)
        XCTAssertEqual(info.commonName, l.device)
        XCTAssertEqual(info.publicKey, l.key.publicKeyDER)
        XCTAssertEqual(info.notBefore, Date(timeIntervalSince1970: 0))
    }

    func testJoinCodeText() {
        let jc = JoinCode(code: "246802", addrs: ["192.168.1.20:8767", JoinCode.address(host: "fd00::5", port: 8767)], fingerprint: "ab+c/d=")
        XCTAssertEqual(jc.addrs[1], "[fd00::5]:8767")
        XCTAssertEqual(JoinCode(qr: jc.qrText), jc)
        XCTAssertTrue(jc.qrText.hasPrefix("cbb://join?code=246802&addr=192.168.1.20%3A8767&"))
        XCTAssertTrue(jc.qrText.hasSuffix("&fp=ab%2Bc%2Fd%3D"))
        XCTAssertEqual(jc.grouped, "246 802")
        XCTAssertEqual(Discovery.joinerTXT(fingerprint: "ab+c/d="), ["v": "1", "j": "1", "f": "ab+c/d="])
        for _ in 0..<20 { XCTAssertTrue(JoinCode(code: JoinCode.newCode(), addrs: [], fingerprint: "").codeIsValid) }
    }

    func testHomeAddresses() {
        for a in ["10.0.0.2", "172.16.1.1", "172.31.255.1", "192.168.1.20"] { XCTAssertTrue(LocalAddresses.isHome(ipv4: a), a) }
        for a in ["8.8.8.8", "172.32.0.1", "169.254.1.1", "127.0.0.1", "100.64.0.1", "1.2.3"] { XCTAssertFalse(LocalAddresses.isHome(ipv4: a), a) }
        XCTAssertTrue(LocalAddresses.isHome(ipv6: "fd12:3456::1"))
        XCTAssertFalse(LocalAddresses.isHome(ipv6: "fe80::1%en0"))
        XCTAssertFalse(LocalAddresses.isHome(ipv6: "2001:db8::1"))
        XCTAssertLessThanOrEqual(LocalAddresses.current().count, JoinCode.maxAddrs)
    }

    func testOldFileIsARoot() throws {
        let g = try PhoneGroup.create(caSigner: SoftwareSigner(), memberKey: SoftwareSigner().publicKeyDER, now: t0)
        var json = try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder().encode(g)) as? [String: Any])
        json["isRoot"] = nil
        let old = try JSONDecoder().decode(PhoneGroup.self, from: JSONSerialization.data(withJSONObject: json))
        XCTAssertTrue(old.isRoot)
        XCTAssertTrue(old.isAdmin)
        XCTAssertEqual(old.memberChain, [g.memberCert])
    }
}
