// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import Foundation
import XCTest
@testable import CBBKit

/// The tunnel key in the phone's hello and the hub's offer for it
/// (docs/protocol.md, section 11).
final class TunnelTests: XCTestCase {
    func testOfferChecksAsGo() {
        let (k, p) = (Data(repeating: 2, count: 32), Data(repeating: 3, count: 32))
        XCTAssertTrue(Member.TunnelOffer(hubKey: k, psk: p, endpoints: ["192.0.2.1:8764", "[2001:db8::1]:65535"]).isValid)
        XCTAssertFalse(Member.TunnelOffer(hubKey: Data(count: 32), psk: p).isValid, "a hub key of zeros")
        XCTAssertFalse(Member.TunnelOffer(hubKey: k, psk: Data(count: 32)).isValid, "a preshared key of zeros")
        for e in ["192.0.2.1:0", "192.0.2.1", "192.0.2.1:65536", "192.0.2.1:+1", ":8764x", "[2001:db8::1]"] {
            XCTAssertFalse(Member.TunnelOffer(hubKey: k, psk: p, endpoints: [e]).isValid, e)
        }
    }

    /// The phone's hello offers the tunnel key the app set, and the root's
    /// offer for it reaches the app; a phone that turned it off offers none.
    func testNodeOffersTheTunnelKeyAndKeepsTheOffer() async throws {
        let t = try CoreGroup(test: self)
        let (hub, phone) = (t.phones[0], t.phones[1])
        let key = Data(repeating: 1, count: 32), psk = Data(repeating: 4, count: 32)
        try phone.member.setTunnelKey(key, psk: psk)
        try await t.connect(1, to: 0)
        let p = try await hub.peer(phone.device)
        XCTAssertEqual(p.tunnelKey, key)
        XCTAssertEqual(p.tunnelPSK, psk)
        // The root's offer reaches the app as it came.
        let good = Member.TunnelOffer(hubKey: Data(repeating: 2, count: 32), psk: Data(repeating: 3, count: 32), endpoints: ["192.0.2.1:8764"])
        XCTAssertTrue(try hub.member.sendTunnel(to: phone.device, offer: good))
        let (from, offer) = try await phone.next("the offer") { if case let .tunnel(f, o) = $0 { return (f, o) }; return nil }
        XCTAssertEqual(from, hub.device)
        XCTAssertEqual(offer, good)

        // The next connection offers no key once it is off.
        try phone.member.setTunnelKey(nil, psk: nil)
        try phone.member.disconnect(hub.device)
        try await hub.until("a hello without the key") {
            try hub.member.peers().contains { $0.device == phone.device && $0.tunnelKey == nil }
        }
    }
}
