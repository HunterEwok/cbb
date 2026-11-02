// SPDX-License-Identifier: AGPL-3.0-only

@testable import ClipboardBridgeKit
import Foundation
#if canImport(Network)
import Network
#endif
import XCTest

final class DiscoveryTests: XCTestCase {
    let dev = "0123456789abcdef0123456789abcdef"

    func testTXT() {
        XCTAssertEqual(Discovery.member(instance: dev, txt: ["v=1", "g=0011223344556677", "p=1"]),
                       FoundMember(device: dev, group: "0011223344556677", pairing: true))
        // Keys without regard to case, the value after the first "=", the
        // first of a repeated key.
        XCTAssertEqual(Discovery.member(instance: dev, txt: ["G=a=b", "g=other", "x"]),
                       FoundMember(device: dev, group: "a=b", pairing: false))
        XCTAssertEqual(Discovery.member(instance: dev, txt: [])?.group, nil)
        XCTAssertEqual(Discovery.member(instance: dev, txt: ["g": "77", "p": "0"]), FoundMember(device: dev, group: "77"))
        XCTAssertNil(Discovery.member(instance: "printer", txt: ["g=77"]))
        XCTAssertNil(Discovery.member(instance: dev.uppercased(), txt: ["g=77"]))
    }

    func testWithKnown() {
        let other = "fedcba9876543210fedcba9876543210"
        let found: Set = [FoundMember(device: dev, group: "g1", pairing: true)]
        // A member browsing finds stays as found; one it does not find is
        // added by its known address.
        XCTAssertEqual(Discovery.withKnown(found, known: [dev, other], group: "g1"), found.union([FoundMember(device: other, group: "g1")]))
        XCTAssertEqual(Discovery.withKnown(found, known: [], group: "g1"), found)
        XCTAssertTrue(JoinCode.isHome("10.1.2.3:8764"))
        XCTAssertFalse(JoinCode.isHome("100.64.0.1:8764"))
        XCTAssertFalse(JoinCode.isHome("[fd00::5]"))
    }

    /// A Linux member as a MemberNode at the other end of a pipe, which
    /// ends the connection after its hello.
    final class Peers: @unchecked Sendable {
        let lock = NSLock()
        var dials: [String] = []
        func dialed(_ d: String) { lock.withLock { dials.append(d) } }
        var count: Int { lock.withLock { dials.count } }
    }

    func testDialer() async throws {
        let phone = MemberNode(engine: SyncEngine(device: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", clock: HybridClock()), name: "iPhone")
        await phone.send(text: "from the phone", kind: .text)
        let peers = Peers()
        let pi = MemberNode(engine: SyncEngine(device: dev, clock: HybridClock()), name: "pi", role: .full)
        let d = MemberDialer(node: phone, group: "g1", firstWait: 0.05, maxWait: 0.2) { m in
            peers.dialed(m.device)
            let (mine, theirs) = Pipe.pair()
            // The pi serves the connection, then hangs up after a moment.
            Task {
                try? await Task.sleep(nanoseconds: 30_000_000)
                theirs.close()
            }
            Task { try? await pi.serve(theirs) }
            return mine
        }
        let other = FoundMember(device: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", group: "another group")
        await d.update([FoundMember(device: dev, group: "g1"), other])
        // It dials again after each end, and the pi got the phone's text.
        try await waitUntil { peers.count >= 3 }
        let piText = await pi.usable?.text
        XCTAssertEqual(piText, "from the phone")
        XCTAssertFalse(peers.lock.withLock { peers.dials.contains(other.device) }, "dialed a member of another group")
        // A member no longer found is not dialed again.
        await d.update([])
        try await waitUntil { await d.dialing.isEmpty }
        let n = peers.count
        try await Task.sleep(nanoseconds: 300_000_000)
        XCTAssertEqual(peers.count, n)
        // Found again, it is dialed again; stop ends that.
        await d.update([FoundMember(device: dev, group: "g1")])
        try await waitUntil { peers.count > n }
        await d.stop()
        let dialing = await d.dialing
        XCTAssertTrue(dialing.isEmpty)
    }

    func testDialsAtMostMaxDialed() async throws {
        let phone = MemberNode(engine: SyncEngine(device: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", clock: HybridClock()), name: nil)
        let d = MemberDialer(node: phone, group: "g1", firstWait: 10, maxWait: 10) { _ in throw POSIXError(.ECONNREFUSED) }
        let many = Set((0..<200).map { FoundMember(device: String(repeating: "0", count: 29) + String(format: "%03d", $0), group: "g1") })
        await d.update(many)
        let dialing = await d.dialing
        XCTAssertEqual(dialing.count, MemberDialer.maxDialed)
        await d.stop()
    }

    func testDialFailuresBackOff() async throws {
        let phone = MemberNode(engine: SyncEngine(device: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", clock: HybridClock()), name: nil)
        let peers = Peers()
        let d = MemberDialer(node: phone, group: "g1", firstWait: 0.05, maxWait: 0.4) { m in
            peers.dialed(m.device)
            throw POSIXError(.ECONNREFUSED)
        }
        await d.update([FoundMember(device: dev, group: "g1")])
        try await Task.sleep(nanoseconds: 700_000_000)
        await d.stop()
        // 0.05 + 0.1 + 0.2 + 0.4 ... : about five tries in 0.7 s, not dozens.
        XCTAssertGreaterThanOrEqual(peers.count, 3)
        XCTAssertLessThanOrEqual(peers.count, 6)
    }

    /// hurry dials a member at once instead of after its wait, and the task
    /// it replaces ends without taking the member from the new one.
    func testHurry() async throws {
        let phone = MemberNode(engine: SyncEngine(device: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", clock: HybridClock()), name: nil)
        let peers = Peers()
        let d = MemberDialer(node: phone, group: "g1", firstWait: 30, maxWait: 30) { m in
            peers.dialed(m.device)
            throw POSIXError(.ECONNREFUSED)
        }
        await d.update([FoundMember(device: dev, group: "g1")])
        try await waitUntil { peers.count == 1 }
        // The next try would come after 30 s; hurry makes it now.
        await d.hurry()
        try await waitUntil { peers.count == 2 }
        await d.hurry()
        try await waitUntil { peers.count == 3 }
        let dialing = await d.dialing
        XCTAssertEqual(dialing, [dev])
        await d.stop()
        // A stopped dialer does not hurry.
        await d.hurry()
        try await Task.sleep(nanoseconds: 100_000_000)
        XCTAssertEqual(peers.count, 3)
    }

    /// A hurry while a dial is under way: the connection that dial makes is
    /// closed, and the new task keeps the member.
    func testHurryWhileDialing() async throws {
        let phone = MemberNode(engine: SyncEngine(device: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", clock: HybridClock()), name: nil)
        let peers = Peers()
        let pi = MemberNode(engine: SyncEngine(device: dev, clock: HybridClock()), name: "pi", role: .full)
        let d = MemberDialer(node: phone, group: "g1", firstWait: 30, maxWait: 30) { m in
            peers.dialed(m.device)
            let first = peers.count == 1
            // The first dial takes a while, long enough for a hurry, and
            // does not notice that its task was cancelled.
            if first {
                await withCheckedContinuation { (c: CheckedContinuation<Void, Never>) in
                    DispatchQueue.global().asyncAfter(deadline: .now() + 0.2) { c.resume() }
                }
            }
            let (mine, theirs) = Pipe.pair()
            Task { try? await pi.serve(theirs) }
            return mine
        }
        await d.update([FoundMember(device: dev, group: "g1")])
        try await waitUntil { peers.count == 1 }
        await d.hurry()
        try await waitUntil { peers.count == 2 }
        try await Task.sleep(nanoseconds: 400_000_000)
        let dialing = await d.dialing
        XCTAssertEqual(dialing, [dev])
        await d.stop()
    }

    #if canImport(Network) && os(macOS)
    /// Publishes a service as a Linux member does and finds it with
    /// BonjourBrowser, through the system's mDNSResponder.
    func testBonjourBrowser() async throws {
        let device = SyncEngine.newID()
        let listener = try NWListener(using: .tcp)
        listener.service = NWListener.Service(name: device, type: Discovery.serviceType, domain: "local.",
                                              txtRecord: NWTXTRecord(["v": "1", "g": "0011223344556677"]))
        listener.newConnectionHandler = { $0.cancel() }
        listener.start(queue: .main)
        defer { listener.cancel() }
        let seen = Seen()
        let browser = BonjourBrowser { seen.set($0) }
        browser.start()
        defer { browser.stop() }
        for _ in 0..<200 where !seen.has(device) {
            try await Task.sleep(nanoseconds: 50_000_000)
        }
        XCTAssertEqual(seen.get(device), FoundMember(device: device, group: "0011223344556677"))
        XCTAssertNotNil(browser.endpoint(of: device))
        // Browsing again from the start finds it again.
        seen.set([])
        browser.restart()
        for _ in 0..<200 where !seen.has(device) {
            try await Task.sleep(nanoseconds: 50_000_000)
        }
        XCTAssertTrue(seen.has(device))
        // Stopped, it does not start again on restart.
        browser.stop()
        browser.restart()
        XCTAssertNil(browser.endpoint(of: "none"))
    }

    final class Seen: @unchecked Sendable {
        let lock = NSLock()
        var members: Set<FoundMember> = []
        func set(_ m: Set<FoundMember>) { lock.withLock { members = m } }
        func get(_ d: String) -> FoundMember? { lock.withLock { members.first { $0.device == d } } }
        func has(_ d: String) -> Bool { get(d) != nil }
    }
    #endif

    func waitUntil(_ cond: @escaping () async -> Bool) async throws {
        for _ in 0..<300 {
            if await cond() { return }
            try await Task.sleep(nanoseconds: 10_000_000)
        }
        XCTFail("timed out")
    }
}
