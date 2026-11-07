// SPDX-License-Identifier: AGPL-3.0-only

import Foundation
import XCTest
@testable import CBBKit

/// The phone as the group's hub: admitting clients by their tunnel keys,
/// and the offer a hello's tunnel key gets.
final class PhoneHubTests: XCTestCase {
    private func key(_ b: UInt8) -> Data { Data(repeating: b, count: 32) }

    func testAdmitsAsAComputersHub() throws {
        let hub = PhoneHub(publicKey: key(1))
        let (a, b) = (Member.newID(), Member.newID())
        let first = try hub.admit(device: a, key: key(2))
        XCTAssertTrue(first.changed)
        XCTAssertEqual(first.client.psk.count, 32)

        // The same key keeps its preshared key; a new key gets a new one.
        let same = try hub.admit(device: a, key: key(2))
        XCTAssertFalse(same.changed)
        XCTAssertEqual(same.client.psk, first.client.psk)
        let renewed = try hub.admit(device: a, key: key(3))
        XCTAssertNotEqual(renewed.client.psk, first.client.psk)
        XCTAssertEqual(hub.clients.count, 1)

        // Another device's key, the hub's own, no key, and a bad device are refused.
        XCTAssertThrowsError(try hub.admit(device: b, key: key(3))) { XCTAssertEqual($0 as? PhoneHub.Refused, .keyOfAnother(a)) }
        XCTAssertThrowsError(try hub.admit(device: b, key: key(1)))
        XCTAssertThrowsError(try hub.admit(device: b, key: key(0)))
        XCTAssertThrowsError(try hub.admit(device: b, key: Data(count: 31)))
        XCTAssertThrowsError(try hub.admit(device: "B", key: key(4)))

        // The clients go to cbbtun as JSON and come back from it.
        _ = try hub.admit(device: b, key: key(4))
        XCTAssertEqual(try PhoneHub.clients(json: try hub.clientsJSON()), hub.clients.map(\.shared))
        XCTAssertEqual(try PhoneHub.clients(json: ""), [])
        XCTAssertThrowsError(try PhoneHub.clients(json: "{}"))

        XCTAssertEqual(hub.prune { $0.device != a }, [a])
        XCTAssertEqual(hub.clients.map(\.device), [b])
    }

    func testKeepsAtMost256Clients() throws {
        let hub = PhoneHub(publicKey: key(1))
        for i in 0..<PhoneHub.maxClients {
            var k = key(7)
            (k[0], k[1]) = (UInt8(i & 0xff), UInt8(i >> 8))
            _ = try hub.admit(device: Member.newID(), key: k)
        }
        XCTAssertThrowsError(try hub.admit(device: Member.newID(), key: key(9))) { XCTAssertEqual($0 as? PhoneHub.Refused, .tooManyClients) }
    }

    func testOffersWaitForVLESS() throws {
        let hub = PhoneHub(publicKey: key(1))
        hub.endpoints = ["203.0.113.1:8764"]
        let c = try hub.admit(device: Member.newID(), key: key(2)).client
        let o = try XCTUnwrap(hub.offer(for: c))
        XCTAssertTrue(o.isValid)
        XCTAssertEqual(o.endpoints, ["203.0.113.1:8764"])
        hub.vlessOnly = true
        XCTAssertNil(hub.offer(for: c))
        hub.vless = Member.VLESS(endpoint: "203.0.113.1:443", publicKey: key(3), shortID: "ab", serverName: "example.com", id: UUID().uuidString)
        XCTAssertEqual(hub.offer(for: c)?.vless, hub.vless)
    }

    /// The client's own preshared key, the clients other hubs share, and
    /// their offers passed on (section 11, "Several hubs").
    func testSharesWithTheOtherHubs() throws {
        let hub = PhoneHub(publicKey: key(1))
        hub.endpoints = ["203.0.113.1:8764"]
        let a = Member.newID(), b = Member.newID(), other = Member.newID()

        // A client's own preshared key; an older one's stays when it offers none.
        XCTAssertEqual(try hub.admit(device: a, key: key(2), psk: key(3)).client.psk, key(3))
        XCTAssertFalse(try hub.admit(device: a, key: key(2)).changed)
        XCTAssertTrue(try hub.admit(device: a, key: key(2), psk: key(4)).changed)
        XCTAssertEqual(hub.clients.map(\.psk), [key(4)])

        // A shared client is taken, and takes new keys, but one met here stays.
        XCTAssertTrue(try hub.take(PhoneHub.Client(device: b, key: key(5), psk: key(6))))
        XCTAssertFalse(try hub.take(PhoneHub.Client(device: b, key: key(5), psk: key(6))))
        XCTAssertTrue(try hub.take(PhoneHub.Client(device: b, key: key(7), psk: key(6))))
        XCTAssertFalse(try hub.take(PhoneHub.Client(device: a, key: key(9), psk: key(9))))
        XCTAssertThrowsError(try hub.take(PhoneHub.Client(device: other, key: key(7), psk: key(6))))
        XCTAssertThrowsError(try hub.take(PhoneHub.Client(device: other, key: key(1), psk: key(6))))
        XCTAssertTrue(try hub.admit(device: b, key: key(7), psk: key(6)).changed, "met now")
        XCTAssertTrue(hub.clients.allSatisfy(\.met))
        let kept = try JSONDecoder().decode([PhoneHub.Client].self, from: JSONEncoder().encode(hub.clients))
        XCTAssertEqual(kept, hub.clients)
        XCTAssertFalse(try PhoneHub.clients(json: hub.clientsJSON()).contains(where: \.met), "cbbtun gets no met")

        // Another hub's offer goes to the clients with their own preshared keys.
        XCTAssertTrue(hub.setOther(other, offer: Member.TunnelOffer(hubKey: key(10), psk: Data(), endpoints: ["198.51.100.1:8764"])))
        XCTAssertFalse(hub.setOther(other, offer: Member.TunnelOffer(hubKey: key(10), psk: Data(), endpoints: ["198.51.100.1:8764"])))
        let offers = hub.offers(for: hub.clients[0])
        XCTAssertEqual(offers.map(\.hub), [nil, other])
        XCTAssertEqual(offers[1].psk, key(4))
        XCTAssertTrue(offers.allSatisfy(\.isValid))
        XCTAssertTrue(hub.setOther(other, offer: nil))
        XCTAssertEqual(hub.offers(for: hub.clients[0]).count, 1)

        // What it shares goes through a frame and back, and Go's reads.
        let share = try XCTUnwrap(hub.share())
        XCTAssertEqual(try Member.decode(body: Data(Member.encode(.hubs(share)).dropFirst(4))), .hubs(share))
        let go = #"{"t":"hubs","hubs":{"serving":true,"offer":{"hub_key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=","psk":null},"# +
            #""clients":[{"device":"\#(a)","key":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=","psk":"AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM="}]}}"#
        guard case let .hubs(got) = try Member.decode(body: Data(go.utf8)) else { return XCTFail("no hubs") }
        XCTAssertTrue(got.serving)
        XCTAssertEqual(got.clients.map(\.psk), [key(3)])
    }

    /// The phone as the hub answers a client's tunnel key, as its hello
    /// offers it, with its own offer under the client's preshared key.
    func testNodeAnswersTheTunnelKey() async throws {
        let t = try CoreGroup(test: self)
        let (phone, client) = (t.phones[0], t.phones[1])
        let hub = PhoneHub(publicKey: key(1))
        hub.endpoints = ["203.0.113.1:8764"]
        try client.member.setTunnelKey(key(2), psk: key(7))
        try await t.connect(1, to: 0)
        let p = try await phone.peer(client.device)
        guard let k = p.tunnelKey else { return XCTFail("the hello offers no key") }
        for o in hub.offers(device: p.device, key: k, psk: p.tunnelPSK) { try phone.member.sendTunnel(to: p.device, offer: o) }
        let offer = try await client.next("the hub's offer") { if case let .tunnel(_, o) = $0 { return o }; return nil }
        XCTAssertEqual(offer.psk, key(7), "the client's own preshared key")
        XCTAssertEqual(offer.hubKey, key(1))
        XCTAssertEqual(offer.endpoints, ["203.0.113.1:8764"])
        XCTAssertEqual(hub.clients.map(\.device), [client.device])
        XCTAssertEqual(hub.share()?.clients.map(\.device), [client.device])
    }
}
