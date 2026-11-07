// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

@testable import CBBKit
import Foundation
import XCTest

/// The phone's member in the Rust core (CoreMember): two phones of one
/// group, one listening as the hub, the other dialing the address it was
/// handed, sync, follow the button's rule and answer commands.
final class CoreMemberTests: XCTestCase {
    func testSyncsTheButtonAndCommands() async throws {
        let t = try CoreGroup(test: self)
        let (a, b) = (t.phones[0], t.phones[1])
        try await t.connect(1, to: 0)
        // B heard of A with A's chain.
        let peer = try await b.peer(a.device)
        XCTAssertEqual(peer.chain.first, t.g.memberCert)
        XCTAssertEqual(peer.name, "Root phone")
        XCTAssertEqual(peer.role, "phone")
        XCTAssertTrue(peer.servesMedia)
        let up = try await b.member.wait(timeout: .seconds(10))
        XCTAssertTrue(up)
        XCTAssertEqual(b.member.connected(), [a.device])

        // B's text reaches A, waits there for the button, and once taken
        // neither waits nor goes back.
        try b.member.copy("from phone B")
        let copy = try await a.copy("from phone B")
        XCTAssertEqual(copy.origin, b.device)
        XCTAssertEqual(copy.key, "from phone B")
        XCTAssertEqual(try a.member.waiting()?.id, copy.id)
        XCTAssertEqual(try a.member.current()?.id, copy.id)
        try a.member.took(copy.id)
        XCTAssertNil(try a.member.waiting())
        XCTAssertFalse(try a.member.sends(board: "from phone B"))
        XCTAssertTrue(try a.member.sends(board: "copied on A"))

        // The root's command for B goes to B's app, whose answer comes back.
        let c = try t.g.modeCommand(to: b.device, mode: "receive", caSigner: t.ca, now: Date())
        async let result = a.member.command(c)
        let (token, from, got) = try await b.next("the command") { e -> (UInt64, String, Member.Record)? in
            if case let .command(token, from, cmd) = e { return (token, from, cmd) }
            return nil
        }
        XCTAssertEqual(from, a.device)
        XCTAssertEqual(got, c)
        try b.member.answer(token, result: .init(id: "", status: "done"))
        let r = try await result
        XCTAssertTrue(r.done, "\(r)")
        XCTAssertEqual(r.id, Commands.id(of: c))
        XCTAssertThrowsError(try b.member.answer(token, result: .init(id: "", status: "done")), "a second answer finds no command")

        // A tunnel key goes into the hellos; one of the wrong size does not.
        try b.member.setTunnelKey(Data(repeating: 1, count: 32), psk: Data(repeating: 2, count: 32))
        try b.member.setTunnelKey(nil, psk: nil)
        XCTAssertThrowsError(try b.member.setTunnelKey(Data(repeating: 1, count: 3), psk: Data(repeating: 2, count: 32)))
        try b.member.setEvidence([])
        XCTAssertFalse(try a.member.records().isEmpty)
        // A device let go is dialed again.
        try b.member.disconnect(a.device)
        let again = try await b.member.wait(timeout: .seconds(10))
        XCTAssertTrue(again)
    }

    /// A command the app does not answer is refused after ten seconds; the
    /// pause closes every connection.
    func testPausesAndRefusesUnansweredCommands() async throws {
        let t = try CoreGroup(test: self)
        let (a, b) = (t.phones[0], t.phones[1])
        try await t.connect(1, to: 0)
        try b.member.pause()
        try await b.until("the pause") { b.member.connected().isEmpty }
        try b.member.resume()
        let up = try await b.member.wait(timeout: .seconds(10))
        XCTAssertTrue(up)
        let c = try t.g.modeCommand(to: b.device, mode: "send", caSigner: t.ca, now: Date())
        let r = try await a.member.command(c, timeout: .seconds(20))
        XCTAssertEqual(r.status, "refused")
        XCTAssertEqual(r.reason, "the app did not answer")
    }

    func testRefusesWhatItDoesNotKnowAndStops() throws {
        let t = try CoreGroup(test: self)
        let a = t.phones[0]
        XCTAssertThrowsError(try a.member.run("no such op", Optional<Int>.none, as: Int.self)) { e in
            XCTAssertTrue(e is Core.Refusal, "\(e)")
        }
        XCTAssertNil(try a.member.current())
        XCTAssertEqual(try a.member.peers(), [])
        a.member.stop()
        XCTAssertThrowsError(try a.member.current()) { XCTAssertTrue($0 is CoreMember.Stopped) }
    }

    func testRefusesABadStart() throws {
        let k = SoftwareSigner()
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("cbb-core-bad-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: dir) }
        let bad = try CoreMember.Config(dir: dir, name: "x", device: "nope", publicKeyDER: k.publicKeyDER, seal: CoreGroup.seal,
                                        cert: Data([1, 2, 3]), issuer: nil, groupCA: Data([4]), roots: [])
        XCTAssertThrowsError(try CoreMember(bad) { try k.signature(digest: $0) }) { XCTAssertTrue($0 is Core.Refusal, "\($0)") }
    }

    /// The core's events read as the kit's.
    func testReadsTheEvents() throws {
        func e(_ json: String) -> CoreMember.Event? { CoreMember.event(Data(json.utf8)) }
        guard case let .write(text, kind, ttl)? = e(#"{"type":"write","text":"hi","kind":"secret","ttl_ms":5000}"#) else { return XCTFail() }
        XCTAssertEqual(text, "hi")
        XCTAssertEqual(kind, .secret)
        XCTAssertEqual(ttl, 5000)
        guard case let .message(from, .admin(ca))? = e(#"{"type":"message","from":"d","message":{"t":"admin","admin_ca":"AQI="}}"#) else {
            return XCTFail()
        }
        XCTAssertEqual(from, "d")
        XCTAssertEqual(ca, Data([1, 2]))
        guard case .message(_, .other("future"))? = e(#"{"type":"message","from":"d","message":{"t":"future"}}"#) else { return XCTFail() }
        guard case let .copy(c)? = e(#"{"type":"copy","copy":{"id":"i","origin":"o","age_ms":3,"kind":"text","via":"copy","text":"t","media":null,"unread":false,"key":"t"}}"#) else {
            return XCTFail()
        }
        XCTAssertEqual(c.event.id, "i")
        XCTAssertEqual(c.event.ageMS, 3)
        XCTAssertNil(e(#"{"type":"from the future"}"#))
        guard case .log? = e("not json") else { return XCTFail() }
    }
}
