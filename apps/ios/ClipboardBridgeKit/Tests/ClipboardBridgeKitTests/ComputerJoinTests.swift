// SPDX-License-Identifier: AGPL-3.0-only

@testable import ClipboardBridgeKit
import Foundation
import XCTest

/// A phone dials a computer's pairing window (docs/protocol.md, section 6,
/// "A phone joins a computer's group"): this phone confirms the code
/// first, so every failure after that spends it. The whole exchange with a
/// real window runs in Go's TestSwiftJoinsComputerRoot.
final class ComputerJoinTests: XCTestCase {
    let sid = (0..<32).map { _ in UInt8.random(in: .min ... .max) }

    /// Plays the computer's window with the code it shows: it answers the
    /// phone's key without a tag, reads the phone's confirmation and hands
    /// it to last, which writes the final frame. Returns what the phone
    /// threw.
    func join(windowCode: String, last: @escaping @Sendable (CPace, Data, Pipe) async throws -> Void) async throws -> Error {
        let phone = try PhoneJoinTests.Listener(), computer = try PhoneJoinTests.Listener()
        let (m, j) = Pipe.pair()
        let sid = sid, computerCert = computer.cert, phoneCert = phone.cert, device = computer.device
        let window = Task {
            let first = try await m.readFrame()
            let adb = try JSONEncoder().encode(Pairing.MemberAD(device: device, group: "a group"))
            var st = try CPace(role: .responder, password: Array(windowCode.utf8),
                               channelID: Pairing.channelID(memberCert: computerCert, joinerCert: phoneCert),
                               sessionID: sid, ad: Array(adb))
            _ = try st.finish(peerMessage: Array(first.msg!), peerAD: Array(first.ad!))
            try await m.writeFrame(Pairing.Frame(msg: Data(st.message), ad: adb))
            try await last(st, try await m.readFrame().tag!, m)
        }
        let info = Pairing.Info(name: "Phone", os: "ios", adminKey: SoftwareSigner().publicKeyDER)
        do {
            _ = try await PairingJoiner.join(over: j, code: "123456", info: info, memberCert: computer.cert, joinerCert: phone.cert,
                                             sessionID: sid, now: Date()) { _ in XCTFail("stored") }
            XCTFail("joined")
        } catch {
            j.close()
            try await window.value
            return error
        }
        throw PairingJoiner.Failure.protocolError("unreachable")
    }

    func testWrongCodeIsSpent() async throws {
        let e = try await join(windowCode: "654321") { st, ta, m in
            XCTAssertNil(try? st.verify(peerTag: Array(ta)), "the computer took a wrong code")
            try await m.writeFrame(Pairing.Frame(error: Pairing.ErrorCode.wrongCode.rawValue))
        }
        XCTAssertEqual((e as? PairingJoiner.Spent)?.underlying as? PairingJoiner.Failure, .refused(.wrongCode))
    }

    func testComputerMustProveTheCode() async throws {
        // A window that does not know the code sends its own tag anyway.
        let e = try await join(windowCode: "654321") { st, _, m in
            try await m.writeFrame(Pairing.Frame(tag: Data(st.confirmationTag!)))
        }
        XCTAssertNotNil(e as? PairingJoiner.Spent, "\(e)")
        // And one without any tag.
        let f = try await join(windowCode: "123456") { _, _, m in try await m.writeFrame(Pairing.Frame(ok: true)) }
        XCTAssertNotNil(f as? PairingJoiner.Spent, "\(f)")
    }
}
