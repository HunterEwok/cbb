// SPDX-License-Identifier: AGPL-3.0-only

@testable import CBBKit
import Foundation
import XCTest

/// The phone that is the hub admits a device that dialed it with a remote
/// invitation (docs/protocol.md, section 12): the device confirms the secret
/// first, then the admin confirms the device. Go's
/// TestSwiftHubAdmitsInvitedGoJoiner runs the window against cbb's joiner.
final class InvitationTests: XCTestCase {
    let t0 = Date()
    let sid = (0..<32).map { _ in UInt8.random(in: .min ... .max) }
    let secret = Data((0..<16).map { _ in UInt8.random(in: .min ... .max) })

    /// What the invited joiner gets: the welcome, or the member's error.
    enum Outcome: Equatable {
        case welcome
        case refused(String)
    }

    /// The joining side as cbb pair -invite runs it, over t: it sends its
    /// CPace message, its tag after the member's message, and takes the
    /// welcome with the member's tag.
    func join(over t: FrameTransport, secret: Data, memberCert: Data, joinerCert: Data) async throws -> Outcome {
        let ad = try JSONEncoder().encode(Pairing.Info(name: "pi", os: "linux"))
        var st = try CPace(role: .initiator, password: Array(secret),
                           channelID: Pairing.channelID(memberCert: memberCert, joinerCert: joinerCert), sessionID: sid, ad: Array(ad))
        try await t.writeFrame(Pairing.Frame(msg: Data(st.message), ad: ad))
        let reply = try await t.readFrame()
        if let e = reply.error { return .refused(e) }
        XCTAssertNil(reply.tag, "the hub confirmed the secret before the device did")
        _ = try st.finish(peerMessage: Array(reply.msg!), peerAD: Array(reply.ad!))
        try await t.writeFrame(Pairing.Frame(tag: Data(st.confirmationTag!)))
        let final = try await t.readFrame()
        if let e = final.error { return .refused(e) }
        try st.verify(peerTag: Array(try XCTUnwrap(final.tag)))
        XCTAssertNotNil(final.welcome)
        try await t.writeFrame(Pairing.Frame(ok: true))
        return .welcome
    }

    final class Asked: @unchecked Sendable {
        let lock = NSLock()
        var requests: [PairingMember.Request] = []
    }

    func run(joinerSecret: Data, answer: Bool) async throws -> (Outcome, Result<(PhoneGroup, PairingMember.Admitted), Error>, Asked, Data) {
        let rootKey = SoftwareSigner()
        let root = try PhoneGroup.create(caSigner: rootKey, memberKey: SoftwareSigner().publicKeyDER, now: t0)
        let joiner = SyncEngine.newID(), joinerCert = try GroupCertificates.selfSigned(device: joiner, signer: SoftwareSigner())
        let (m, j) = Pipe.pair()
        let asked = Asked()
        let invitation = PairingMember.Invitation(secret: secret) { req in
            asked.lock.withLock { asked.requests.append(req) }
            return answer
        }
        let (sid, t0) = (sid, t0)
        let memberSide = Task { () async throws -> (PhoneGroup, PairingMember.Admitted) in
            var g = root
            let a = try await g.admit(over: m, code: "", joinerCert: joinerCert, sessionID: sid, caSigner: rootKey, invitation: invitation, now: t0)
            return (g, a)
        }
        let outcome = try await join(over: j, secret: joinerSecret, memberCert: root.memberCert, joinerCert: joinerCert)
        j.close()
        let member: Result<(PhoneGroup, PairingMember.Admitted), Error>
        do { member = .success(try await memberSide.value) } catch { member = .failure(error) }
        return (outcome, member, asked, joinerCert)
    }

    func testAdmitted() async throws {
        let (outcome, member, asked, joinerCert) = try await run(joinerSecret: secret, answer: true)
        XCTAssertEqual(outcome, .welcome)
        let (g, admitted) = try member.get()
        XCTAssertTrue(admitted.confirmed)
        XCTAssertEqual(g.computers.map(\.device), [admitted.device])
        XCTAssertEqual(asked.requests.map(\.fingerprint), [Pairing.fingerprint(cert: joinerCert)])
        XCTAssertEqual(asked.requests.first?.device, admitted.device)
    }

    func testDeclined() async throws {
        let (outcome, member, asked, _) = try await run(joinerSecret: secret, answer: false)
        XCTAssertEqual(outcome, .refused("declined"))
        XCTAssertThrowsError(try member.get()) { XCTAssertEqual($0 as? PairingMember.Failure, .refused(.declined)) }
        XCTAssertEqual(asked.requests.count, 1)
    }

    func testWrongSecret() async throws {
        let (outcome, member, asked, _) = try await run(joinerSecret: Data(count: 16), answer: true)
        XCTAssertEqual(outcome, .refused("wrong-code"))
        XCTAssertThrowsError(try member.get()) { XCTAssertEqual($0 as? PairingMember.Failure, .refused(.wrongCode)) }
        XCTAssertTrue(asked.requests.isEmpty, "the admin was asked about a device that does not know the secret")
    }
}
