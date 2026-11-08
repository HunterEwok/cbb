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

    /// A blind relay's port serves a call only when the app names its
    /// caller and the call's certificate names the same device; the relay's
    /// and the tunnel's ports are on the loopback address only.
    func testRelayServesOnlyTheAnnouncedCaller() async throws {
        let t = try CoreGroup(test: self)
        let (a, b) = (t.phones[0], t.phones[1])
        let port = try b.member.listen(.relay)
        XCTAssertEqual(try b.member.listen(.relay), port, "a port already open stays")
        try a.member.found("relay", addrs: ["127.0.0.1:\(port)"], device: b.device)
        // A call the relay announced from another device is closed.
        let first = try await b.next("the first call") { e -> (UInt64, UInt16, String)? in
            if case let .caller(token, port, device) = e { return (token, port, device) }
            return nil
        }
        XCTAssertEqual(first.2, a.device)
        try b.member.caller(first.0, device: Member.newID())
        try await Task.sleep(nanoseconds: 300_000_000)
        XCTAssertEqual(b.member.connected(), [])
        XCTAssertThrowsError(try b.member.caller(first.0, device: a.device), "a call is named once")
        // The next one, which the relay announced from the device its
        // certificate names, is served.
        let second = try await b.next("the second call") { e -> UInt64? in
            if case let .caller(token, _, _) = e, token != first.0 { return token }
            return nil
        }
        try b.member.caller(second, device: a.device)
        try await b.until("the announced caller connected") { b.member.connected() == [a.device] }
        // On another address than the loopback one, the relay's and the
        // tunnel's ports take nothing.
        let tunnel = try b.member.listen(.tunnel)
        for host in LocalAddresses.current().filter({ !$0.contains(":") }) {
            for p in [port, tunnel] { XCTAssertFalse(Self.connects(host, p), "\(host):\(p) took a connection") }
        }
        XCTAssertTrue(Self.connects("127.0.0.1", tunnel))
        // Closed, the port takes nothing once the listener's thread let go.
        try b.member.unlisten(.relay)
        try await b.until("the relay's port closed") { !Self.connects("127.0.0.1", port) }
    }

    /// Whether a TCP connection to host:port is taken.
    static func connects(_ host: String, _ port: UInt16) -> Bool {
        #if os(Linux)
        let fd = socket(AF_INET, Int32(SOCK_STREAM.rawValue), 0)
        #else
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        #endif
        guard fd >= 0 else { return false }
        defer { close(fd) }
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        inet_pton(AF_INET, host, &addr.sin_addr)
        return withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) == 0 }
        }
    }

    /// A hub share goes to the one peer the app names; from a device that
    /// may not be a hub, the member drops it.
    func testSendsAHubShareToOnePeer() async throws {
        let t = try CoreGroup(3, test: self)
        let (root, b, c) = (t.phones[0], t.phones[1], t.phones[2])
        try await t.connect(1, to: 0)
        try await t.connect(2, to: 0)
        let share = Member.HubShare(serving: true)
        XCTAssertEqual(try root.member.sendHubs(share, to: b.device), [b.device])
        _ = try await b.next("the share") { if case let .message(_, .hubs(h)) = $0 { return h }; return nil }
        // C, no hub, sends one to the root, which drops it.
        XCTAssertEqual(try c.member.sendHubs(share, to: root.device), [root.device])
        try c.member.copy("after the share")
        _ = try await root.copy("after the share")
        XCTAssertTrue(root.all { if case .message(_, .hubs) = $0 { return true }; return nil }.isEmpty)
        XCTAssertTrue(c.all { if case .message(_, .hubs) = $0 { return true }; return nil }.isEmpty, "C was not named")
    }

    /// A mode change connects again so the hellos say it, and the member
    /// dials its peer again at once, however many changes come in a row.
    func testReconnectsAtOnceAfterAModeChange() async throws {
        let t = try CoreGroup(test: self)
        let (a, b) = (t.phones[0], t.phones[1])
        try await t.connect(1, to: 0)
        // Sync off says "own" in the hellos, on says "shared".
        for (i, on) in [false, true, false, true].enumerated() {
            let mode = on ? "shared" : "own"
            try b.member.setSync(on: on)
            let start = Date()
            try await b.until("the peer's hello with mode \(mode), change \(i + 1)") {
                try a.member.peers().contains { $0.device == b.device && $0.mode == mode }
            }
            XCTAssertLessThan(Date().timeIntervalSince(start), 3, "change \(i + 1) took \(Date().timeIntervalSince(start)) s")
        }
    }

    /// Calls from other threads while the member stops answer or fail, and
    /// never reach freed memory: an event's handler that called the member
    /// as the app restarted it crashed the Android app.
    func testStopsWhileCalled() throws {
        let t = try CoreGroup(test: self)
        let m = t.phones[0].member
        let done = DispatchGroup()
        let calls = NSLock()
        var n = 0
        for _ in 0..<4 {
            DispatchQueue.global().async(group: done) {
                for _ in 0..<2_000 {
                    _ = try? m.current()
                    _ = try? m.peers()
                    calls.withLock { n += 1 }
                }
            }
        }
        Thread.sleep(forTimeInterval: 0.02)
        m.stop()
        done.wait()
        XCTAssertEqual(calls.withLock { n }, 8_000)
        XCTAssertThrowsError(try m.current()) { XCTAssertTrue($0 is CoreMember.Stopped) }
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
