// SPDX-License-Identifier: AGPL-3.0-only

@testable import CBBKit
import Foundation
import XCTest

/// A forwarder's or a relay's address and key as the user gives them.
final class HubStateTests: XCTestCase {
    let pin = String(repeating: "A", count: 43) + "="

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
}
