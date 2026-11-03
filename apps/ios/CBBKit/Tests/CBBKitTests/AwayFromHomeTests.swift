// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import Foundation
import XCTest
@testable import CBBKit

/// Sync away from home on the phone: the kept state and the loop that
/// reaches the hub through the tunnel while it is away.
final class AwayFromHomeTests: XCTestCase {
    let hub = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    let offer = Member.TunnelOffer(hubKey: Data(repeating: 2, count: 32), psk: Data(repeating: 3, count: 32),
                                   endpoints: ["203.0.113.7:8764", "[2001:db8::7]:8764"])

    func testStateRoundTrips() throws {
        let key = Data(repeating: 1, count: 32)
        let off = AwayState(key: key)
        XCTAssertEqual(off.psk.count, 32)
        XCTAssertEqual(AwayState.decode(try off.encoded()), off)
        let pc = "dddddddddddddddddddddddddddddddd"
        let on = off.with(hub, offer: offer).with(pc, offer: offer)
        XCTAssertEqual(AwayState.decode(try on.encoded()), on)
        XCTAssertEqual(on.hubs.map(\.device), [hub, pc])
        XCTAssertEqual(on.offer(hub), offer)
        XCTAssertEqual(on.without(hub).hubs.map(\.device), [pc])
        // An obfuscated hub's settings are kept with its offer.
        var hidden = offer
        hidden.obfuscation = Member.Obfuscation(jc: 4, jmin: 50, jmax: 300, s1: 20, s2: 40, s3: 16, s4: 24,
                                                h1: "100-200", h2: "300-400", h3: "500-600", h4: "700-800",
                                                headerProtectionKey: Data(repeating: 8, count: 32))
        let kept = off.with(hub, offer: hidden)
        XCTAssertEqual(AwayState.decode(try kept.encoded()), kept)
        // So is the way over VLESS.
        var tunneled = offer
        tunneled.vless = Member.VLESS(endpoint: "203.0.113.9:443", publicKey: Data(repeating: 9, count: 32),
                                      shortID: "0123456789abcdef", serverName: "www.example.com",
                                      id: "5f0c1e2d-3b4a-4c5d-8e6f-7a8b9c0d1e2f")
        let overVLESS = off.with(hub, offer: tunneled)
        XCTAssertEqual(AwayState.decode(try overVLESS.encoded()), overVLESS)
        // And the hub's key for the next period, tried right after its key now.
        var next = offer
        next.nextKey = Data(repeating: 7, count: 32)
        let withNext = off.with(hub, offer: next)
        XCTAssertEqual(AwayState.decode(try withNext.encoded()), withNext)
        let tried = AwayFromHome.hubsToTry([hub], withNext)
        XCTAssertEqual(tried.map(\.device), [hub, hub])
        XCTAssertEqual(tried[1].offer.hubKey, next.nextKey)
        XCTAssertNil(tried[1].offer.nextKey)
        // A short key, a short preshared key and a bad offer are not states.
        XCTAssertNil(AwayState.decode(try AwayState(key: Data(count: 31)).encoded()))
        XCTAssertNil(AwayState.decode(try AwayState(key: key, psk: Data(count: 31)).encoded()))
        XCTAssertNil(AwayState.decode(try off.with(hub, offer: Member.TunnelOffer(hubKey: Data(count: 31), psk: Data(count: 32))).encoded()))
        XCTAssertNil(AwayState.decode(Data("{".utf8)))
    }

    /// The state of the first versions, one hub's offer and no preshared
    /// key of the phone's own, is not read.
    func testReadsTheOneHubOfEarlierVersions() throws {
        let key = Data(repeating: 1, count: 32)
        let old = #"{"key":"\#(key.base64EncodedString())","hub":"\#(hub)","offer":\#(String(decoding: try JSONEncoder().encode(offer), as: UTF8.self))}"#
        XCTAssertNil(AwayState.decode(Data(old.utf8)))
        XCTAssertNil(AwayState.decode(Data(#"{"key":"\#(key.base64EncodedString())"}"#.utf8)))
    }

    final class FakeTunnel: OpenTunnel, @unchecked Sendable {
        let port: UInt16
        let first: String
        let obfuscation: String
        let vless: String
        let hubKey: Data
        private let lock = NSLock()
        private var _endpoints: [String]
        private var _closed = false
        init(port: UInt16, endpoint: String, obfuscation: String = "", vless: String = "", hubKey: Data = Data()) {
            (self.port, self.first, self.obfuscation, self.vless, self._endpoints) = (port, endpoint, obfuscation, vless, [endpoint])
            self.hubKey = hubKey
        }
        var endpoints: [String] { lock.withLock { _endpoints } }
        var closed: Bool { lock.withLock { _closed } }
        func setEndpoint(_ endpoint: String) throws { lock.withLock { _endpoints.append(endpoint) } }
        func close() { lock.withLock { _closed = true } }
    }

    final class FakeTunnels: Tunnels, @unchecked Sendable {
        private let lock = NSLock()
        private var _started: [FakeTunnel] = []
        var started: [FakeTunnel] { lock.withLock { _started } }
        func newKey() throws -> Data { Data(repeating: 7, count: 32) }
        func publicKey(_ privateKey: Data) throws -> Data { Data(privateKey.map { $0 &+ 1 }) }
        func start(privateKey: Data, psk: Data, hubKey: Data, device: String, hub: String, endpoint: String,
                   obfuscation: String, vless: String) throws -> OpenTunnel {
            lock.withLock {
                let t = FakeTunnel(port: UInt16(40_000 + _started.count), endpoint: endpoint, obfuscation: obfuscation, vless: vless,
                                   hubKey: hubKey)
                _started.append(t)
                return t
            }
        }
    }

    /// Shared values the fakes set and the test reads.
    final class Box<T>: @unchecked Sendable {
        private let lock = NSLock()
        private var value: T
        init(_ v: T) { value = v }
        var current: T { lock.withLock { value } }
        func set(_ v: T) { lock.withLock { value = v } }
        func update(_ f: (inout T) -> Void) { lock.withLock { f(&value) } }
    }

    private func eventually(_ what: String, _ check: @Sendable () async -> Bool) async throws {
        let deadline = Date().addingTimeInterval(5)
        while !(await check()) {
            if Date() > deadline { return XCTFail(what) }
            try await Task.sleep(for: .milliseconds(5))
        }
    }

    private static let short = (first: Duration.milliseconds(10), max: Duration.milliseconds(20), home: Duration.milliseconds(10))

    /// With VLESS the hub's endpoints are tried in AmneziaWG first and
    /// VLESS after them; without AmneziaWG settings only VLESS, never plain
    /// WireGuard.
    func testTriesAmneziaWGBeforeVLESS() async throws {
        let vless = Member.VLESS(endpoint: "203.0.113.9:443", publicKey: Data(repeating: 9, count: 32),
                                 shortID: "ab", serverName: "www.example.com",
                                 id: "5f0c1e2d-3b4a-4c5d-8e6f-7a8b9c0d1e2f")
        let obf = Member.Obfuscation(jc: 4, jmin: 50, jmax: 300, s1: 20, s2: 40, s3: 16, s4: 24,
                                     h1: "100-200", h2: "300-400", h3: "500-600", h4: "700-800",
                                     headerProtectionKey: Data(repeating: 8, count: 32))
        for (obfuscation, ways) in [(obf as Member.Obfuscation?, [false, false, true, false]), (nil, [true, true])] {
            let tunnels = FakeTunnels()
            let hub = hub
            let a = AwayFromHome(
                device: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", tunnels: tunnels, state: nil,
                save: { _ in }, atHome: { _ in false },
                dial: { _, _ in throw POSIXError(.ECONNREFUSED) },
                serve: { _, _ in },
                mayHost: { $0 == hub }, order: { [hub] },
                firstWait: Self.short.first, maxWait: Self.short.max, homeCheck: Self.short.home)
            await a.start()
            try await a.turnOn()
            var o = offer
            (o.obfuscation, o.vless) = (obfuscation, vless)
            await a.keep(from: hub, offer: o)
            try await eventually("the tunnels") { tunnels.started.count >= ways.count }
            XCTAssertEqual(tunnels.started.prefix(ways.count).map { !$0.vless.isEmpty }, ways)
            await a.stop()
        }
    }

    func testReachesTheHubOnlyWhileItIsAway() async throws {
        let tunnels = FakeTunnels()
        let saved = Box<AwayState?>(nil)
        let home = Box(false)
        let answers = Box(false)
        let dialed = Box<[UInt16]>([])
        let served = Box(0)
        let release = Box(0)
        let hub = hub
        let a = AwayFromHome(
            device: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", tunnels: tunnels, state: nil,
            save: { saved.set($0) },
            atHome: { _ in home.current },
            dial: { port, h in
                XCTAssertEqual(h, hub)
                dialed.update { $0.append(port) }
                guard answers.current else { throw POSIXError(.ECONNREFUSED) }
                return Pipe()
            },
            serve: { _, _ in
                let mine = served.current
                served.set(mine + 1)
                // Runs until the test lets it end, as a connection does.
                while release.current <= mine { try await Task.sleep(for: .milliseconds(2)) }
            },
            mayHost: { $0 == hub },
            order: { [hub] },
            firstWait: Self.short.first, maxWait: Self.short.max, homeCheck: Self.short.home)
        await a.start()

        // Off: no key for the hellos, no tunnel.
        let isOn = await a.isOn
        let none = await a.publicKey
        XCTAssertFalse(isOn)
        XCTAssertNil(none)
        try await eventually("off") { await a.status == .off }

        try await a.turnOn()
        let key = await a.publicKey
        XCTAssertEqual(key, Data(repeating: 8, count: 32))
        XCTAssertNotNil(saved.current)
        try await eventually("waiting for the hub") { await a.status == .waitingForHub }
        XCTAssertTrue(tunnels.started.isEmpty)

        // An offer from a device that is neither the root nor an admin is ignored.
        await a.keep(from: "cccccccccccccccccccccccccccccccc", offer: offer)
        XCTAssertEqual(saved.current?.hubs, [])
        // The hub's answer, from a peer the node named: away, the tunnel starts on its first endpoint.
        await a.keep(from: nil, offer: offer)
        await a.keep(from: hub, offer: offer)
        XCTAssertEqual(saved.current?.offer(hub), offer)
        let psk = await a.psk
        XCTAssertEqual(psk, saved.current?.psk)
        try await eventually("a tunnel") { tunnels.started.count == 1 }
        let t = tunnels.started[0]
        XCTAssertEqual(t.first, offer.endpoints[0])
        XCTAssertEqual(t.obfuscation, "")
        XCTAssertEqual(t.vless, "")
        // No answer: the next endpoint, on a new tunnel.
        let second = offer.endpoints[1]
        try await eventually("the next endpoint") { tunnels.started.count >= 2 }
        XCTAssertEqual(dialed.current.first, t.port)
        XCTAssertTrue(t.closed)
        XCTAssertEqual(tunnels.started[1].first, second)

        answers.set(true)
        try await eventually("served") { served.current == 1 }
        let connected = await a.status
        XCTAssertEqual(connected, .connected)

        // At home the tunnel closes and the phone dials the hub directly.
        home.set(true)
        release.set(1)
        try await eventually("at home") { await a.status == .atHome }
        let served1 = tunnels.started.last!
        XCTAssertTrue(served1.closed)

        // Away again: a new tunnel.
        let before = tunnels.started.count
        home.set(false)
        try await eventually("a new tunnel served") { served.current == 2 }
        XCTAssertEqual(tunnels.started.count, before + 1)

        // Off: the tunnel closes and the state is forgotten.
        try await a.turnOff()
        release.set(2)
        XCTAssertTrue(tunnels.started.last!.closed)
        XCTAssertNil(saved.current)
        let gone = await a.publicKey
        XCTAssertNil(gone)
        try await eventually("off again") { await a.status == .off }
        await a.stop()
    }

    func testANewOfferStartsAgain() async throws {
        let tunnels = FakeTunnels()
        let release = Box(0)
        let a = AwayFromHome(
            device: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", tunnels: tunnels,
            state: AwayState(key: Data(repeating: 1, count: 32)).with(hub, offer: offer), save: { _ in },
            atHome: { _ in false }, dial: { _, _ in Pipe() },
            serve: { _, _ in while release.current == 0 { try await Task.sleep(for: .milliseconds(2)) } },
            mayHost: { _ in true }, order: { [self.hub, "dddddddddddddddddddddddddddddddd"] },
            firstWait: Self.short.first, maxWait: Self.short.max, homeCheck: Self.short.home)
        await a.start()
        try await eventually("connected") { await a.status == .connected }
        let t = tunnels.started[0]
        // The same offer again changes nothing, nor does another admin's; a new one closes the tunnel and starts with it.
        await a.keep(from: hub, offer: offer)
        await a.keep(from: "dddddddddddddddddddddddddddddddd",
                     offer: Member.TunnelOffer(hubKey: offer.hubKey, psk: Data(repeating: 4, count: 32), endpoints: ["203.0.113.7:8764"]))
        XCTAssertFalse(t.closed)
        await a.keep(from: hub, offer: Member.TunnelOffer(hubKey: offer.hubKey, psk: offer.psk, endpoints: ["198.51.100.9:8764"]))
        XCTAssertTrue(t.closed)
        release.set(1)
        try await eventually("a new tunnel") { tunnels.started.count == 2 }
        XCTAssertEqual(tunnels.started[1].first, "198.51.100.9:8764")
        await a.stop()
        try await eventually("stopped") { await a.status == .off }
    }

    /// A hub that offers its next key is tried with each key at each of
    /// its endpoints in turn: the key it serves with now may answer only at
    /// the second endpoint, as a hub at home does from away through its
    /// forwarder.
    func testEachKeyTriesEachEndpoint() async throws {
        let tunnels = FakeTunnels()
        let served = Box(0)
        let next = Data(repeating: 9, count: 32)
        let both = Member.TunnelOffer(hubKey: offer.hubKey, psk: offer.psk, endpoints: offer.endpoints, nextKey: next)
        let a = AwayFromHome(
            device: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", tunnels: tunnels,
            state: AwayState(key: Data(repeating: 1, count: 32)).with(hub, offer: both), save: { _ in },
            atHome: { _ in false },
            dial: { port, _ in
                guard let t = tunnels.started.first(where: { $0.port == port }),
                      t.hubKey == both.hubKey, t.first == both.endpoints[1] else { throw POSIXError(.ECONNREFUSED) }
                return Pipe()
            },
            serve: { _, _ in
                served.update { $0 += 1 }
                try await Task.sleep(for: .seconds(60))
            },
            mayHost: { _ in true }, order: { [self.hub] },
            firstWait: Self.short.first, maxWait: Self.short.max, homeCheck: Self.short.home)
        await a.start()
        // Only the key now at the second endpoint answers.
        try await eventually("served") { served.current == 1 }
        XCTAssertTrue(tunnels.started.contains { $0.hubKey == next })
        await a.stop()
    }

    /// Every hub's offer is kept, its own or passed on by another hub, and
    /// one marked moved makes the phone forget the sender's
    /// (docs/protocol.md, section 11, "Several hubs").
    func testKeepsEveryHubsOffer() async throws {
        let pc = "dddddddddddddddddddddddddddddddd"
        let admins = Box<Set<String>>([hub, pc])
        let saved = Box<AwayState?>(nil)
        let hub = hub
        let a = AwayFromHome(
            device: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", tunnels: FakeTunnels(),
            state: AwayState(key: Data(repeating: 1, count: 32)).with(hub, offer: offer), save: { saved.set($0) },
            atHome: { _ in true }, dial: { _, _ in Pipe() }, serve: { _, _ in },
            mayHost: { admins.current.contains($0) }, order: { [hub, pc] })
        let pcOffer = Member.TunnelOffer(hubKey: Data(repeating: 5, count: 32), psk: Data(repeating: 6, count: 32), endpoints: ["203.0.113.5:8764"])
        // Another hub's own offer is kept beside the first's.
        await a.keep(from: pc, offer: pcOffer)
        XCTAssertEqual(saved.current?.hubs.map(\.device), [hub, pc])
        let first = await a.hub
        XCTAssertEqual(first, hub)
        let listed = await a.hubs
        XCTAssertEqual(listed, [hub, pc])
        // Passed on by the hub, without the hub field, in place of the earlier one.
        let passed = Member.TunnelOffer(hubKey: pcOffer.hubKey, psk: offer.psk, endpoints: ["203.0.113.6:8764"])
        await a.keep(from: hub, offer: passed.with(psk: passed.psk, hub: pc))
        XCTAssertEqual(saved.current?.offer(pc), passed)
        // The hub moves to the computer: its own offer goes.
        await a.keep(from: hub, offer: pcOffer.with(psk: pcOffer.psk, hub: pc, moved: true))
        XCTAssertEqual(saved.current?.hubs.map(\.device), [pc])
        XCTAssertEqual(saved.current?.offer(pc), pcOffer)
        // An offer naming a device that is no admin, or from one, is ignored, as is this phone's own.
        await a.keep(from: pc, offer: pcOffer.with(psk: pcOffer.psk, hub: "cccccccccccccccccccccccccccccccc"))
        await a.keep(from: "cccccccccccccccccccccccccccccccc", offer: offer)
        await a.keep(from: pc, offer: offer.with(psk: offer.psk, hub: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
        admins.set([hub])
        await a.keep(from: pc, offer: offer)
        XCTAssertEqual(saved.current?.hubs.map(\.device), [pc])
        XCTAssertEqual(saved.current?.offer(pc), pcOffer)
    }

    /// The first hub in the order that answers is used; on a lower one the
    /// connection ends after the up check, and the phone goes back up to
    /// the first once it answers.
    func testUsesTheFirstHubThatAnswers() async throws {
        let pc = "dddddddddddddddddddddddddddddddd"
        let pcOffer = Member.TunnelOffer(hubKey: Data(repeating: 5, count: 32), psk: Data(repeating: 6, count: 32), endpoints: ["203.0.113.5:8764"])
        let pcUp = Box(false)
        let served = Box<[String]>([])
        let a = AwayFromHome(
            device: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", tunnels: FakeTunnels(),
            state: AwayState(key: Data(repeating: 1, count: 32)).with(hub, offer: offer).with(pc, offer: pcOffer), save: { _ in },
            atHome: { _ in false },
            dial: { _, h in
                if h == pc && !pcUp.current { throw POSIXError(.ECONNREFUSED) }
                return Pipe()
            },
            serve: { t, h in
                served.update { $0.append(h) }
                // Until the connection closes.
                while !(t as! Pipe).isClosed { try await Task.sleep(for: .milliseconds(2)) }
            },
            mayHost: { _ in true }, order: { [pc, self.hub] },
            firstWait: Self.short.first, maxWait: Self.short.max, homeCheck: Self.short.home, upCheck: .milliseconds(100))
        await a.start()
        try await eventually("the second hub") { served.current == [hub] }
        let second = await a.hub
        XCTAssertEqual(second, hub)
        let (inUse, hubs) = (await a.inUse, await a.hubs)
        XCTAssertEqual(inUse, hub)
        XCTAssertEqual(hubs, [pc, hub])
        pcUp.set(true)
        try await eventually("back to the first") { served.current == [hub, pc] }
        let first = await a.hub
        XCTAssertEqual(first, pc)
        // On the first hub there is no up check.
        try await Task.sleep(for: .milliseconds(300))
        XCTAssertEqual(served.current, [hub, pc])
        await a.stop()
    }

    /// A phone hub, there only while its app is open, is tried every few
    /// moments however long it was away; a computer waits longer each time.
    func testAPhoneHubIsTriedOften() async throws {
        for phone in [true, false] {
            let dialed = Box(0)
            let a = AwayFromHome(
                device: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", tunnels: FakeTunnels(),
                state: AwayState(key: Data(repeating: 1, count: 32)).with(hub, offer: offer), save: { _ in },
                atHome: { _ in false },
                dial: { _, _ in
                    dialed.update { $0 += 1 }
                    throw POSIXError(.ECONNREFUSED)
                },
                serve: { _, _ in },
                mayHost: { _ in true }, order: { [self.hub] },
                firstWait: .milliseconds(10), maxWait: .seconds(3600), isPhone: { _ in phone }, phoneWait: .milliseconds(20),
                homeCheck: Self.short.home)
            await a.start()
            if phone {
                // Every 20 ms; a slow runner gets there later, but gets there.
                try await eventually("a phone hub tried often") { dialed.current >= 6 }
            } else {
                // 10, 20, 40, 80 and 160 ms, then an hour.
                try await Task.sleep(for: .milliseconds(400))
                XCTAssertLessThanOrEqual(dialed.current, 6)
            }
            await a.stop()
        }
    }
}
