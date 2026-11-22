// SPDX-License-Identifier: AGPL-3.0-only

@testable import CBBKit
import Foundation
import XCTest

/// What a hello says about a device is shown, never trusted: the kit
/// drops what does not fit.
final class MemberTests: XCTestCase {
    func testDeviceInfoCleaned() {
        let bad = Member.DeviceInfo(form: "toaster", osVersion: String(repeating: "9", count: 33), version: "1\n2", mac: "A4:83:E7:01:02:0F")
        XCTAssertNil(bad.cleaned)
        XCTAssertEqual(Member.DeviceInfo(form: "phone", mac: "nope").cleaned, Member.DeviceInfo(form: "phone"))
    }

    func testSyncModes() {
        XCTAssertTrue(Member.receives(nil) && Member.sends(nil), "a device without a mode shares")
        XCTAssertTrue(Member.receives("receive") && !Member.sends("receive"))
        XCTAssertTrue(!Member.receives("send") && Member.sends("send"))
        XCTAssertTrue(!Member.receives("own") && !Member.sends("own"))
        XCTAssertEqual(Member.modes, ["own", "shared", "receive", "send"])
    }
}
