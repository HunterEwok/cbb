// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import Foundation
import XCTest
@testable import CBBKit

/// The hub's offer for a phone's tunnel key as the 0.5 member's wire
/// carries it (docs/protocol.md, section 11).
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
}
