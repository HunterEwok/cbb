// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

@testable import CBBKit
import Foundation
import XCTest

/// The phone at a blind relay: its settings, the link it starts, the
/// connections the relay joins, and whose each call is.
final class RelayOnPhoneTests: XCTestCase {
    let phone = String(repeating: "8", count: 32), pc = String(repeating: "1", count: 32), tv = String(repeating: "f", count: 32)
    let pin = String(repeating: "A", count: 43) + "="

    final class FakeLink: RelayLink, @unchecked Sendable {
        let args: [String]
        let memberPort: UInt16
        weak var events: RelayLinkEvents?
        var records: String
        var closed = false

        init(args: [String], memberPort: UInt16, records: String, events: RelayLinkEvents) {
            (self.args, self.memberPort, self.records, self.events) = (args, memberPort, records, events)
        }
        /// The creds of each setCredentials, "" back to the member certificate.
        var credentials: [String] = []
        func setRecords(_ records: String) throws { self.records = records }
        func setCredentials(serverKey: Data, sign: @escaping @Sendable (Data) throws -> Data, creds: String, roots: String, names: String) throws {
            credentials.append(creds)
        }
        func close() { closed = true }
    }

    final class FakeLinks: RelayLinks, @unchecked Sendable {
        var started: [FakeLink] = []
        var keys = 0
        func newKey() throws -> Data {
            keys += 1
            return Data(repeating: UInt8(keys), count: 32)
        }
        func start(privateKey: Data, device: String, endpoint: String, pin: String, chain: [Data],
                   sign: @escaping @Sendable (Data) throws -> Data, records: String, memberPort: UInt16,
                   events: RelayLinkEvents) throws -> RelayLink {
            let l = FakeLink(args: [privateKey.base64EncodedString(), device, endpoint, pin], memberPort: memberPort, records: records, events: events)
            started.append(l)
            return l
        }
    }

    final class Saved: @unchecked Sendable {
        var settings: RelaySettings?
        var served: [String] = []
        var near: Set<String> = []
    }

    func relay(_ links: FakeLinks, _ saved: Saved, settings: RelaySettings? = nil) -> RelayOnPhone {
        RelayOnPhone(device: phone, links: links, settings: settings, save: { saved.settings = $0 },
                     dial: { port, _ in
                         let (a, _) = Pipe.pair()
                         a.peerCertificate = Data("\(port)".utf8)
                         return a
                     },
                     serve: { t, peer in saved.served.append("\(peer) \(String(decoding: t.peerCertificate ?? Data(), as: UTF8.self))") },
                     elsewhere: { saved.near.contains($0) })
    }

    func group() -> HubOnPhone.Group {
        HubOnPhone.Group(memberPort: 4242, chain: [Data([1, 1, 1])], sign: { $0 }, records: [])
    }

    func testSettingsRoundTrip() throws {
        let s = RelaySettings(key: Data(repeating: 1, count: 32), relay: .init(endpoint: "203.0.113.9:8764", pin: pin))
        XCTAssertEqual(RelaySettings.decode(try s.encoded()), s)
        XCTAssertNil(RelaySettings.decode(Data("{}".utf8)))
        var bad = s
        bad.relay.pin = "nope"
        XCTAssertNil(RelaySettings.decode(try bad.encoded()))
    }

    func testTurnOnStartsOnlyWithARelay() throws {
        let links = FakeLinks(), saved = Saved()
        let r = relay(links, saved)
        r.start(group())
        XCTAssertTrue(links.started.isEmpty, "off: no link")
        XCTAssertEqual(r.status(paused: false).0, .off)
        XCTAssertThrowsError(try r.turnOn(endpoint: "cbb.tools:8764", pin: pin))
        XCTAssertThrowsError(try r.turnOn(endpoint: "203.0.113.9:8764", pin: "short"))
        XCTAssertNil(saved.settings)

        try r.turnOn(endpoint: " 203.0.113.9:8764 ", pin: pin)
        XCTAssertEqual(saved.settings?.relay, .init(endpoint: "203.0.113.9:8764", pin: pin))
        XCTAssertEqual(r.status(paused: true).0, .paused)
        r.start(group())
        r.start(group())
        XCTAssertEqual(links.started.count, 1, "a running link is not started again")
        let l = try XCTUnwrap(links.started.first)
        XCTAssertEqual(l.args, [Data(repeating: 1, count: 32).base64EncodedString(), phone, "203.0.113.9:8764", pin])
        XCTAssertEqual(l.memberPort, 4242)
        XCTAssertEqual(r.status(paused: false).0, .connecting)

        // Another relay keeps the key and starts again.
        try r.turnOn(endpoint: "198.51.100.7:8764", pin: pin)
        XCTAssertTrue(l.closed)
        XCTAssertEqual(saved.settings?.key, Data(repeating: 1, count: 32))
        r.start(group())
        XCTAssertEqual(links.started.count, 2)

        try r.turnOff()
        XCTAssertNil(saved.settings)
        XCTAssertTrue(links.started[1].closed)
        XCTAssertEqual(r.status(paused: false).0, .off)
    }

    func testCredentialsGoToTheLinkOnce() throws {
        let links = FakeLinks(), saved = Saved()
        let r = relay(links, saved, settings: RelaySettings(key: Data(repeating: 1, count: 32),
                                                            relay: HubState.Forwarder(endpoint: "203.0.113.9:8764", pin: pin)))
        let reg = CredentialStore.Registration(credentials: [], roots: [Data([1])], names: ["ab": pc])
        r.setCredentials(RelayOnPhone.Credentials(serverKey: Data([2]), sign: { $0 }, registration: reg))
        r.start(group())
        let l = try XCTUnwrap(links.started.first)
        XCTAssertEqual(l.credentials, ["[]"], "kept for the link when it starts")
        r.setCredentials(RelayOnPhone.Credentials(serverKey: Data([2]), sign: { $0 }, registration: reg))
        XCTAssertEqual(l.credentials.count, 1, "the same again: no new registration")
        r.setCredentials(nil)
        XCTAssertEqual(l.credentials, ["[]", ""])
        r.stop()
        r.start(group())
        XCTAssertEqual(links.started.last?.credentials, [], "back with the member certificate: nothing to hand over")
    }

    func testReports() throws {
        let links = FakeLinks(), saved = Saved()
        let r = relay(links, saved, settings: RelaySettings(key: Data(repeating: 1, count: 32), relay: .init(endpoint: "203.0.113.9:8764", pin: pin)))
        r.start(group())
        r.changed(#"{"connected":true,"online":["\#(pc)"],"through":1}"#)
        let (st, rp, _) = r.status(paused: false)
        XCTAssertEqual(st, .connected)
        XCTAssertEqual(rp, .init(connected: true, online: [pc], through: 1))
        r.changed(#"{"connected":false,"online":[],"through":0,"error":"the relay refused: too many groups"}"#)
        let (st2, _, why) = r.status(paused: false)
        XCTAssertEqual(st2, .failed)
        XCTAssertEqual(why, "the relay refused: too many groups")
        r.changed("not json") // logged, the last report stays
        XCTAssertEqual(r.status(paused: false).0, .failed)
    }

    func testCallersAreTakenOnce() {
        let r = relay(FakeLinks(), Saved())
        r.calling(peer: pc, localPort: 50_001)
        r.calling(peer: tv, localPort: 50_002)
        XCTAssertNil(r.caller(port: 50_003), "a connection the relay did not announce")
        XCTAssertEqual(r.caller(port: 50_002), tv)
        XCTAssertNil(r.caller(port: 50_002), "taken once")
        XCTAssertEqual(r.caller(port: 50_001), pc)
        // The oldest go when many never come.
        for p in 0..<(RelayOnPhone.maxCalls + 5) { r.calling(peer: pc, localPort: UInt16(40_000 + p)) }
        XCTAssertNil(r.caller(port: 40_000))
        XCTAssertEqual(r.caller(port: UInt16(40_000 + RelayOnPhone.maxCalls + 4)), pc)
    }

    func testDialedConnectionsAreServed() async throws {
        let saved = Saved()
        saved.near = [pc]
        let r = relay(FakeLinks(), saved)
        XCTAssertFalse(r.wanted(peer: pc), "found at home: dialed directly")
        XCTAssertTrue(r.wanted(peer: tv))
        r.dial(peer: tv, port: 50_100)
        for _ in 0..<100 where saved.served.isEmpty { try await Task.sleep(for: .milliseconds(10)) }
        XCTAssertEqual(saved.served, ["\(tv) 50100"])
    }
}
