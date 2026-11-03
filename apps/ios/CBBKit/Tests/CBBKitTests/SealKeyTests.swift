// SPDX-License-Identifier: AGPL-3.0-only

#if canImport(Security)
import Foundation
import XCTest
@testable import CBBKit

/// The phone's own key for sealed messages: kept on first use, the same
/// after, a new one after it is removed.
final class SealKeyTests: XCTestCase {
    func testSecretKeptAndRemoved() throws {
        let account = "test-\(UUID().uuidString)"
        defer { SealKey.remove(account: account) }
        let first: Data
        do {
            first = try SealKey.secret(account: account)
        } catch SealKey.Failure.keychain(let s) {
            throw XCTSkip("no keychain here (\(s))")
        }
        XCTAssertEqual(first.count, 32)
        XCTAssertEqual(try SealKey.secret(account: account), first)
        XCTAssertEqual(try SealKey.publicKey(account: account).count, 1216)
        XCTAssertFalse(String(describing: SealKey.Failure.keychain(-25300)).isEmpty)
        XCTAssertFalse(String(describing: SealKey.Failure.random(-1)).isEmpty)
        SealKey.remove(account: account)
        XCTAssertNotEqual(try SealKey.secret(account: account), first)
    }
}
#endif
