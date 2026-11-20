// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import XCTest
@testable import CBBKit

final class TunnelSettingsTests: XCTestCase {
    /// The group path of a VLESS user ID is the forwarder's and the Rust
    /// member's (section 13, "VLESS").
    func testGroupPathOfAUserID() {
        XCTAssertEqual(Member.VLESS.groupPath("6f1c2b9e-3d4a-4f5b-8c7d-0e1f2a3b4c5d"), "FAf82MUKFMjUNz3SkIYXXw")
        XCTAssertEqual(Member.VLESS.groupPath("0b6e7f10-2a3b-4c5d-9e8f-112233445566"), "mefvDB5qwj9eeFnyKOOk4A")
    }

    /// Only a UUID of version 4 in lowercase is a VLESS user ID.
    func testUserIDs() {
        XCTAssertTrue(Member.VLESS.isUserID("0b6e7f10-2a3b-4c5d-9e8f-112233445566"))
        for bad in ["", "0b6e7f10-2a3b-3c5d-9e8f-112233445566", "0b6e7f10-2a3b-4c5d-7e8f-112233445566",
                    "0B6E7F10-2A3B-4C5D-9E8F-112233445566", "0b6e7f102a3b-4c5d-9e8f-1122334455667", "0b6e7f10-2a3b-4c5d-9e8f-11223344556"] {
            XCTAssertFalse(Member.VLESS.isUserID(bad), bad)
        }
    }
}
