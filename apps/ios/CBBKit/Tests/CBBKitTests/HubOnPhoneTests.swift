// SPDX-License-Identifier: AGPL-3.0-only

@testable import CBBKit
import Foundation
import XCTest

/// The phone as the group's hub: its state, the forwarder it registers
/// with, its home networks, and the clients it hands its tunnel.
final class HubOnPhoneTests: XCTestCase {
    let phone = String(repeating: "a", count: 32), pc = String(repeating: "b", count: 32), tv = String(repeating: "c", count: 32)
    let pin = String(repeating: "A", count: 43) + "="

    final class FakeHub: HubTunnel, @unchecked Sendable {
        let memberPort: UInt16
        var held: String
        var registered: [String]?
        var obfuscation = ""
        var vlessID = ""
        var shown = ""
        var report = "{}"
        var closed = false

        init(memberPort: UInt16, clients: String) { (self.memberPort, held) = (memberPort, clients) }
        func setClients(_ json: String) throws { held = json }
        func register(endpoint: String, pin: String, chain: [Data], sign: @escaping @Sendable (Data) throws -> Data, records: String, vlessID: String) throws {
            registered = [endpoint, pin]
            shown = records
            self.vlessID = vlessID
        }
        func setRecords(_ records: String) throws { shown = records }
        var credentials: [String] = []
        func setCredentials(serverKey: Data, sign: @escaping @Sendable (Data) throws -> Data, creds: String) throws {
            credentials.append(creds)
        }
        var ways: String?
        func setProjectWays(_ ways: String) throws { self.ways = ways }
        func status() -> String { report }
        var invited: [String]?
        func invite(group: String, endpoints: String, lifetime: Int, guestPort: UInt16, vless: String) throws -> HubGuest {
            invited = [group, endpoints, "\(lifetime)", "\(guestPort)"]
            return Guest()
        }
        func close() { closed = true }
    }

    final class Guest: HubGuest, @unchecked Sendable {
        let text = "cbb://invite#x", secret = Data(count: 16), expires = Date()
        func admitted() {}
        func close() {}
    }

    final class FakeTunnels: HubTunnels, @unchecked Sendable {
        var started: [FakeHub] = []
        func newKey() throws -> Data { Data(repeating: 7, count: 32) }
        func publicKey(_ privateKey: Data) throws -> Data { Data(repeating: 8, count: 32) }
        var made = 0
        func start(privateKey: Data, device: String, memberPort: UInt16, obfuscation: String, clients: String) throws -> HubTunnel {
            let h = FakeHub(memberPort: memberPort, clients: clients)
            h.obfuscation = obfuscation
            started.append(h)
            return h
        }
        func newObfuscation() throws -> Member.Obfuscation {
            made += 1
            return Member.Obfuscation(jc: 4, jmin: 50, jmax: 300, s1: 20, s2: 30, s3: 17, s4: 18,
                                      h1: "5-100", h2: "200-300", h3: "400-500", h4: "600-700", headerProtectionKey: Data(repeating: 9, count: 32))
        }
        func newVLESSID() throws -> String { "00000000-0000-4000-8000-000000000000" }
    }

    final class Saved: @unchecked Sendable {
        var state: HubState?
    }

    func group(_ records: [Member.Record] = []) -> HubOnPhone.Group {
        HubOnPhone.Group(memberPort: 4242, chain: [Data([1, 1, 1])], sign: { $0 }, records: records)
    }

    func testStateRoundTrips() throws {
        let s = HubState(key: Data(repeating: 1, count: 32), on: true, forwarder: .init(endpoint: "203.0.113.9:8764", pin: pin),
                         homes: ["192.168.0.1 192.168.0.0/24"],
                         clients: [PhoneHub.Client(device: pc, key: Data(repeating: 2, count: 32), psk: Data(repeating: 3, count: 32))])
        XCTAssertEqual(HubState.decode(try s.encoded()), s)
        XCTAssertNil(HubState.decode(Data("{}".utf8)))
        XCTAssertNil(HubState.decode(Data(#"{"key":"AAAA","on":false,"homes":[],"clients":[]}"#.utf8)))
    }

    func testForwarderInput() {
        XCTAssertTrue(HubState.validPin(pin))
        XCTAssertTrue(HubState.validPin(HubState.Forwarder.projectPin))
        XCTAssertTrue(HubState.Forwarder(endpoint: "198.51.100.20:8764", pin: HubState.Forwarder.projectPin).isProject)
        XCTAssertFalse(HubState.Forwarder(endpoint: "198.51.100.20:8764", pin: pin).isProject)
        XCTAssertTrue(HubState.validPin(String(repeating: "a+/9", count: 10) + "abc="))
        XCTAssertFalse(HubState.validPin("sha256:" + String(repeating: "A", count: 43) + "="))
        XCTAssertFalse(HubState.validPin(String(repeating: "A", count: 43)))
        XCTAssertFalse(HubState.validPin(String(repeating: "a-_9", count: 10) + "abc="))
        XCTAssertFalse(HubState.validPin(String(repeating: "A", count: 42) + "B="))
        XCTAssertEqual(HubState.endpoint(" 203.0.113.9:8764 "), "203.0.113.9:8764")
        XCTAssertEqual(HubState.endpoint("[2001:db8::9]:8764"), "[2001:db8::9]:8764")
        XCTAssertNil(HubState.endpoint("203.0.113.9"))
        XCTAssertNil(HubState.endpoint("203.0.113.9:0"))
        XCTAssertNil(HubState.endpoint("cbb.tools:8764"))
        XCTAssertNil(HubState.endpoint("1.2.3:8764"))
    }

    func testNetworkKeys() {
        XCTAssertEqual(HubState.networkKey(gateway: "192.168.0.1", address: "192.168.0.57", prefixLength: 24), "192.168.0.1 192.168.0.0/24")
        XCTAssertEqual(HubState.networkKey(gateway: "192.168.0.1", address: "192.168.1.57", prefixLength: 23), "192.168.0.1 192.168.0.0/23")
        XCTAssertEqual(HubState.networkKey(gateway: "192.168.0.1", address: "10.1.2.3", prefixLength: 32), "192.168.0.1 10.1.2.3/32")
        XCTAssertNil(HubState.networkKey(gateway: nil, address: "192.168.0.57", prefixLength: 24))
        XCTAssertNil(HubState.networkKey(gateway: "192.168.0.1", address: "192.168.0.57", prefixLength: 33))
    }

    /// On with a forwarder: it offers the forwarder's endpoint, keeps the
    /// clients, and hands them and the records to the tunnel.
    func testServesWithAForwarder() throws {
        let saved = Saved(), tunnels = FakeTunnels()
        let h = HubOnPhone(device: phone, tunnels: tunnels, state: nil, save: { saved.state = $0 })
        XCTAssertFalse(h.isOn)
        XCTAssertNil(h.offer(device: pc, key: Data(repeating: 2, count: 32)))
        try h.turnOn(home: "192.168.0.1 192.168.0.0/24")
        XCTAssertTrue(h.isOn)
        XCTAssertThrowsError(try h.invite(group: "tag", lifetime: 3600, guestPort: 5555)) {
            XCTAssertEqual($0 as? HubOnPhone.Failure, .notRunning)
        }
        XCTAssertTrue(h.isHome("192.168.0.1 192.168.0.0/24"))
        XCTAssertFalse(h.isHome("10.0.0.1 10.0.0.0/24"))
        XCTAssertFalse(h.isHome(nil))
        // At home only: no offer, nothing to register.
        XCTAssertEqual(h.status(paused: false).0, .homeOnly)
        XCTAssertNil(h.offer(device: pc, key: Data(repeating: 2, count: 32)))
        h.start(group())
        XCTAssertTrue(tunnels.started.isEmpty)

        XCTAssertThrowsError(try h.setForwarder(.init(endpoint: "203.0.113.9:8764", pin: "pin")))
        try h.setForwarder(.init(endpoint: "203.0.113.9:8764", pin: pin))
        let o = try XCTUnwrap(h.offer(device: pc, key: Data(repeating: 2, count: 32)))
        XCTAssertEqual(o.endpoints, ["203.0.113.9:8764"])
        XCTAssertEqual(o.hubKey, Data(repeating: 8, count: 32))
        XCTAssertEqual(saved.state?.clients.map(\.device), [pc])
        XCTAssertEqual(h.status(paused: true).0, .paused)

        h.start(group([Member.Record(body: Data([1]), sig: Data([2]))]))
        let t = try XCTUnwrap(tunnels.started.first)
        XCTAssertEqual(tunnels.started.count, 1)
        XCTAssertEqual(t.memberPort, 4242)
        XCTAssertTrue(t.held.contains(pc))
        XCTAssertEqual(t.registered?.first, "203.0.113.9:8764")
        XCTAssertTrue(t.shown.contains("\"body\""))
        XCTAssertNil(t.ways, "a forwarder of the user's own got the project's ways in")
        h.start(group()) // running already
        XCTAssertEqual(tunnels.started.count, 1)
        XCTAssertEqual(h.status(paused: false).0, .registering)
        t.report = #"{"registered":true,"seen":"198.51.100.1:5555"}"#
        XCTAssertEqual(h.status(paused: false).0, .registered)
        t.report = #"{"error":"the forwarder refused it"}"#
        XCTAssertEqual(h.status(paused: false).0, .failed)
        XCTAssertEqual(h.status(paused: false).1, "the forwarder refused it")

        // An invitation goes through the running tunnel, with the forwarder as the hub's address.
        _ = try h.invite(group: "tag", lifetime: 3600, guestPort: 5555)
        XCTAssertEqual(t.invited, ["tag", #"["203.0.113.9:8764"]"#, "3600", "5555"])

        // A new client reaches the running tunnel, and the hub shares again
        // for it; one it knows already is no news. A removed one leaves it.
        var admitted = 0
        _ = h.offers(device: tv, key: Data(repeating: 4, count: 32), admitted: { admitted += 1 })
        _ = h.offers(device: tv, key: Data(repeating: 4, count: 32), admitted: { admitted += 1 })
        XCTAssertEqual(admitted, 1)
        XCTAssertTrue(t.held.contains(tv))
        XCTAssertEqual(h.prune { $0 != pc }, [pc])
        XCTAssertFalse(t.held.contains(pc))
        XCTAssertEqual(saved.state?.clients.map(\.device), [tv])
        h.setRecords([])
        XCTAssertEqual(t.shown, "[]")

        // A new forwarder stops the tunnel; turning it off stops it and keeps the clients.
        try h.setForwarder(.init(endpoint: "203.0.113.10:8764", pin: pin))
        XCTAssertTrue(t.closed)
        h.start(group())
        try h.turnOff()
        XCTAssertTrue(tunnels.started.last?.closed == true)
        XCTAssertEqual(h.status(paused: false).0, .off)
        XCTAssertEqual(HubOnPhone(device: phone, tunnels: FakeTunnels(), state: saved.state, save: { _ in }).clients, [tv])
    }

    /// The project's forwarder: the hub gets the entry points' ways in
    /// over VLESS, or none for the built-in one.
    func testProjectWays() throws {
        let tunnels = FakeTunnels()
        let h = HubOnPhone(device: phone, tunnels: tunnels, state: nil, save: { _ in })
        try h.turnOn(home: "192.168.0.1 192.168.0.0/24")
        try h.setForwarder(.init(endpoint: "203.0.113.9:8764", pin: HubState.Forwarder.projectPin))
        h.start(group())
        XCTAssertEqual(try XCTUnwrap(tunnels.started.last).ways, "")
        try h.turnOff()
        try h.turnOn(home: "192.168.0.1 192.168.0.0/24")
        var g = group()
        g.ways = [Releases.EntryVLESS(transport: "xhttp", server_name: "cbb.tools", port: 443, path: "/aNewWayInHere")]
        h.start(g)
        let ways = try XCTUnwrap(tunnels.started.last?.ways)
        XCTAssertTrue(ways.contains("aNewWayInHere"), ways)
    }

    /// The period's hubs' credential: set before the tunnel starts, it
    /// reaches the tunnel once it runs; the same again is no news, a new
    /// one reaches it, and none takes the hub back to its certificate.
    func testRegistersWithTheHubsCredential() throws {
        let tunnels = FakeTunnels()
        let h = HubOnPhone(device: phone, tunnels: tunnels, state: nil, save: { _ in })
        try h.turnOn(home: "192.168.0.1 192.168.0.0/24")
        try h.setForwarder(.init(endpoint: "203.0.113.9:8764", pin: pin))
        let one = ServerCredentials.Credential(body: Data([1]), sig: Data([2]), key: Data([3]))
        let two = ServerCredentials.Credential(body: Data([4]), sig: Data([5]), key: Data([6]))
        h.setCredentials(.init(serverKey: Data([9]), sign: { $0 }, credentials: [one]))
        h.start(group())
        let t = try XCTUnwrap(tunnels.started.last)
        XCTAssertEqual(t.credentials.count, 1)
        XCTAssertTrue(t.credentials[0].contains("\"body\""), t.credentials[0])
        h.setCredentials(.init(serverKey: Data([9]), sign: { $0 }, credentials: [one]))
        XCTAssertEqual(t.credentials.count, 1, "the same credential went to the tunnel again")
        h.setCredentials(.init(serverKey: Data([9]), sign: { $0 }, credentials: [two]))
        XCTAssertEqual(t.credentials.count, 2)
        h.setCredentials(nil)
        XCTAssertEqual(t.credentials.last, "")

        // A new tunnel takes what is set now, and none is no news to it.
        try h.turnOff()
        try h.turnOn(home: "192.168.0.1 192.168.0.0/24")
        h.start(group())
        XCTAssertEqual(try XCTUnwrap(tunnels.started.last).credentials, [])
    }

    /// The tunnel hides as the user chose: the AmneziaWG settings go to the
    /// tunnel and into the offers and stay while it stays on; VLESS keeps
    /// them, and waits for the forwarder's way there before it offers
    /// anything.
    func testDisguise() throws {
        let saved = Saved(), tunnels = FakeTunnels()
        let h = HubOnPhone(device: phone, tunnels: tunnels, state: nil, save: { saved.state = $0 })
        try h.turnOn(home: nil)
        try h.setForwarder(.init(endpoint: "203.0.113.9:8764", pin: pin))
        XCTAssertEqual(h.disguise, .plain)
        try h.setDisguise(.obfuscate)
        try h.setDisguise(.obfuscate)
        XCTAssertEqual(h.disguise, .obfuscate)
        XCTAssertEqual(tunnels.made, 1)
        let obf = try XCTUnwrap(saved.state?.obfuscation)
        XCTAssertEqual(h.offer(device: pc, key: Data(repeating: 2, count: 32))?.obfuscation, obf)
        h.start(group())
        let t = try XCTUnwrap(tunnels.started.last)
        XCTAssertEqual(try JSONDecoder().decode(Member.Obfuscation.self, from: Data(t.obfuscation.utf8)), obf)
        XCTAssertEqual(t.vlessID, "")

        try h.setDisguise(.vless)
        XCTAssertTrue(t.closed)
        XCTAssertEqual(saved.state?.obfuscation, obf)
        XCTAssertEqual(saved.state?.vlessID, "00000000-0000-4000-8000-000000000000")
        XCTAssertNil(h.offer(device: pc, key: Data(repeating: 2, count: 32)))
        h.start(group())
        let v = try XCTUnwrap(tunnels.started.last)
        XCTAssertEqual(try JSONDecoder().decode(Member.Obfuscation.self, from: Data(v.obfuscation.utf8)), obf)
        XCTAssertEqual(v.vlessID, "00000000-0000-4000-8000-000000000000")
        v.report = #"{"registered":true,"vless":{"transport":"xhttp","endpoint":"203.0.113.9:443","server_name":"cbb.tools","path":"/banMEJvnYJJap8S/AbCdEfGhIjKlMnOpQr","id":"00000000-0000-4000-8000-000000000000"}}"#
        XCTAssertEqual(h.status(paused: false).0, .registered)
        XCTAssertEqual(h.offer(device: pc, key: Data(repeating: 2, count: 32))?.vless?.endpoint, "203.0.113.9:443")

        try h.setDisguise(.plain)
        XCTAssertEqual(h.disguise, .plain)
        XCTAssertNil(saved.state?.vlessID)
        XCTAssertNil(saved.state?.obfuscation)
        XCTAssertNil(h.offer(device: pc, key: Data(repeating: 2, count: 32))?.vless)
    }

    func testRemembersAFewHomes() throws {
        let saved = Saved()
        let h = HubOnPhone(device: phone, tunnels: FakeTunnels(), state: nil, save: { saved.state = $0 })
        try h.turnOn(home: nil)
        for i in 1...(HubState.maxHomes + 2) { try h.addHome("home \(i)") }
        XCTAssertEqual(saved.state?.homes.count, HubState.maxHomes)
        XCTAssertFalse(h.isHome("home 1"))
        XCTAssertTrue(h.isHome("home \(HubState.maxHomes + 2)"))
    }
}
