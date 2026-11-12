// SPDX-License-Identifier: AGPL-3.0-only

import Foundation
import XCTest
@testable import CBBKit

/// Push's calls from the kit: the keys, the platform's limits, a group's
/// registration (a new send key with each token, a higher seq each time, the
/// previous key kept for late bodies) and the extension's refusal of a body
/// no key opens.
final class PushTests: XCTestCase {
    func testKeysAndLimits() throws {
        let a = try Push.newKeys(), b = try Push.newKeys()
        XCTAssertEqual(a.key.count, 32)
        XCTAssertFalse(a.sendKey.isEmpty)
        XCTAssertNotEqual(a.key, b.key)
        XCTAssertNotEqual(a.sendKey, b.sendKey)
        let apns = try Push.limits(env: Push.Env.apns)
        XCTAssertTrue(apns.known)
        XCTAssertEqual(apns.kinds, Push.Kinds([.copies, .events]).rawValue)
        XCTAssertFalse(try Push.limits(env: 200).known)
    }

    func testRegistrationMovesForward() throws {
        let k = try Push.newKeys()
        let token = Data(repeating: 7, count: 32)
        let now = Date(timeIntervalSince1970: 1_800_000_000)
        let r = try Push.registration(savedSeq: nil, now: now, kinds: [.copies], env: Push.Env.apns, token: token,
                                      key: k.key, sendKey: k.sendKey)
        XCTAssertEqual(r.seq, 1_800_000_000_000)
        // Restored from a backup with an older seq: still forward of the clock.
        let back = try Push.registration(savedSeq: 5, now: now, kinds: [.copies], env: Push.Env.apns, token: token,
                                         key: k.key, sendKey: k.sendKey)
        XCTAssertEqual(back.seq, r.seq)
        let next = try Push.registration(savedSeq: r.seq, now: now, kinds: [.copies], env: Push.Env.apns, token: token,
                                         key: k.key, sendKey: k.sendKey)
        XCTAssertEqual(next.seq, r.seq + 1)
        let off = try Push.registration(savedSeq: next.seq, now: now, kinds: [], env: nil, token: nil, key: nil, sendKey: nil)
        XCTAssertEqual(off.seq, next.seq + 1)
        XCTAssertLessThan(off.frame.count, r.frame.count)
        // A key that is not 32 bytes is refused with code 18.
        XCTAssertThrowsError(try Push.registration(savedSeq: nil, kinds: [.copies], env: Push.Env.apns, token: token,
                                                   key: Data(count: 31), sendKey: k.sendKey)) { e in
            XCTAssertEqual((e as? Core.Refusal)?.code, 18)
        }
    }

    func testABodyNoKeyOpensIsRefused() throws {
        let c = Push.Context(keys: [Push.KeyAndSeq(key: try Push.newKeys().key, seq: 1)], me: Data(count: 16))
        XCTAssertThrowsError(try Push.open(Data(count: 2972), in: c)) { e in
            XCTAssertEqual((e as? Core.Refusal)?.code, 18)
        }
    }

    #if canImport(Security)
    func testTheVaultKeepsAGroupsKeys() throws {
        let vault = PushVault(accessGroup: nil, service: "tools.cbb.push.test-\(UUID().uuidString)")
        let group = "g1"
        defer { try? vault.save(group, nil) }
        let me = Data(repeating: 1, count: 16)
        let token = Data(repeating: 7, count: 32)
        let first: Push.Registration
        do {
            first = try vault.register(group, me: me, token: token, env: Push.Env.apns, kinds: [.copies, .events])
        } catch PushVault.Failure.keychain(let s) {
            throw XCTSkip("no keychain here (\(s))")
        }
        let g1 = try vault.load(group)
        XCTAssertEqual(g1.seq, first.seq)
        XCTAssertEqual(g1.frame, first.frame)
        XCTAssertEqual(g1.keys.count, 1)
        XCTAssertEqual(try vault.groups(), [group])
        XCTAssertNotNil(g1.context)
        // The same token: the same send key and push key, a higher seq, the
        // key under the previous seq kept.
        let second = try vault.register(group, me: me, token: token, env: Push.Env.apns, kinds: [.copies, .events])
        let g2 = try vault.load(group)
        XCTAssertGreaterThan(second.seq, first.seq)
        XCTAssertEqual(g2.sendKey, g1.sendKey)
        XCTAssertEqual(g2.keys.map(\.key), [g1.keys[0].key, g1.keys[0].key])
        XCTAssertEqual(g2.keys.map(\.seq), [second.seq, first.seq])
        // A new token: a new send key. A new key on demand: the previous kept.
        try vault.register(group, me: me, token: Data(repeating: 8, count: 32), env: Push.Env.apns, kinds: [.copies],
                           newKey: true)
        let g3 = try vault.load(group)
        XCTAssertNotEqual(g3.sendKey, g2.sendKey)
        XCTAssertNotEqual(g3.keys[0].key, g2.keys[0].key)
        XCTAssertEqual(g3.keys.count, 2)
        // Off: the frame says so, the seq still moves.
        let off = try vault.register(group, me: me, token: nil, env: nil, kinds: [])
        XCTAssertGreaterThan(off.seq, g3.seq ?? 0)
        XCTAssertEqual(try vault.load(group).kinds, 0)
    }
    #endif
}
