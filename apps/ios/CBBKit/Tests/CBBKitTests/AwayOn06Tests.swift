// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

@testable import CBBKit
import Foundation
import XCTest

/// The cards' states on a group of 0.6, from where the Live member says
/// sync away from home stands.
final class AwayOn06Tests: XCTestCase {
    let hubID = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"

    func testAwayStatus() {
        XCTAssertEqual(AwayOn06.awayStatus(nil) { _ in false }, .off)
        XCTAssertEqual(AwayOn06.awayStatus(.init()) { _ in false }, .waitingForHub)
        XCTAssertEqual(AwayOn06.awayStatus(.init(hubDevice: hubID)) { $0 == self.hubID }, .atHome)
        XCTAssertEqual(AwayOn06.awayStatus(.init(hubDevice: hubID)) { _ in false }, .connecting)
        XCTAssertEqual(AwayOn06.awayStatus(.init(hubDevice: hubID, through: true)) { _ in false }, .connected)
    }

    func testRelayStatus() {
        XCTAssertEqual(AwayOn06.relayStatus(nil).0, .off)
        XCTAssertEqual(AwayOn06.relayStatus(.init()).0, .off)
        let r = CoreMember.RelayState(endpoint: "203.0.113.9:8764")
        XCTAssertEqual(AwayOn06.relayStatus(.init(relay: r)).0, .connecting)
        XCTAssertEqual(AwayOn06.relayStatus(.init(relay: .init(endpoint: r.endpoint, connected: true))).0, .connected)
        let (s, e) = AwayOn06.relayStatus(.init(relay: .init(endpoint: r.endpoint, error: "timed out", detail: "udp")))
        XCTAssertEqual(s, .failed)
        XCTAssertEqual(e, "timed out (udp)")
    }

    /// away_status as the member answers it: fields it leaves out read as
    /// false, zero and empty.
    func testAwayStateReadsTheMembersAnswer() throws {
        let json = #"{"hub":true,"port":8764,"clients":2,"obfuscated":true,"endpoints":["192.0.2.1:8764"],"keys_in_file":true,"#
            + #""forwarder":{"endpoint":"203.0.113.9:8764","registered":true},"relay":{"endpoint":"203.0.113.10:8764","online":["x"]}}"#
        let a = try JSONDecoder().decode(CoreMember.AwayState.self, from: Data(json.utf8))
        XCTAssertTrue(a.hub && a.isOn && a.obfuscated)
        XCTAssertFalse(a.vless || a.through || a.standby)
        XCTAssertEqual(a.port, 8764)
        XCTAssertEqual(a.clients, 2)
        XCTAssertEqual(a.endpoints, ["192.0.2.1:8764"])
        XCTAssertEqual(a.forwarder?.registered, true)
        XCTAssertEqual(a.relay?.online, ["x"])
        XCTAssertEqual(a.relay?.connected, false)
        let failed = try JSONDecoder().decode(CoreMember.AwayState.self, from: Data(#"{"error":"off","detail":"why"}"#.utf8))
        XCTAssertFalse(failed.isOn)
    }

    func testPeriodsDecode() throws {
        let both = try JSONDecoder().decode(CoreMember.Periods.self, from: Data(#"{"away":null,"period_due":true,"period_overdue":true}"#.utf8))
        XCTAssertEqual(both, .init(due: true, overdue: true))
        XCTAssertEqual(try JSONDecoder().decode(CoreMember.Periods.self, from: Data(#"{"away":null}"#.utf8)), .init())
    }
}
