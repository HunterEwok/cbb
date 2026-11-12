// SPDX-License-Identifier: AGPL-3.0-only

import Foundation
import XCTest
@testable import CBBKit

/// Push's calls from the kit: the keys, the platform's limits, a group's
/// registration (one send key per token for every group, a slot per group,
/// a new registration only when something in it changed, the previous key
/// kept for late bodies but not after a membership change), the push
/// service's challenge, the extension opening a real copy across a rotation
/// of the sealing key, and what the extension's keychain group holds.
final class PushTests: XCTestCase {
    func testKeysAndLimits() throws {
        let a = try Push.newKeys(), b = try Push.newKeys()
        XCTAssertEqual(a.key.count, 32)
        XCTAssertFalse(a.sendKey.isEmpty)
        XCTAssertNotEqual(a.key, b.key)
        XCTAssertNotEqual(a.sendKey, b.sendKey)
        XCTAssertEqual(a.slot.count, 16)
        XCTAssertNotEqual(a.slot, b.slot)
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
                                      key: k.key, sendKey: k.sendKey, slot: k.slot)
        XCTAssertEqual(r.seq, 1_800_000_000_000)
        // Restored from a backup with an older seq: still forward of the clock.
        let back = try Push.registration(savedSeq: 5, now: now, kinds: [.copies], env: Push.Env.apns, token: token,
                                         key: k.key, sendKey: k.sendKey, slot: k.slot)
        XCTAssertEqual(back.seq, r.seq)
        let next = try Push.registration(savedSeq: r.seq, now: now, kinds: [.copies], env: Push.Env.apns, token: token,
                                         key: k.key, sendKey: k.sendKey, slot: k.slot)
        XCTAssertEqual(next.seq, r.seq + 1)
        let off = try Push.registration(savedSeq: next.seq, now: now, kinds: [], env: nil, token: nil, key: nil, sendKey: nil,
                                        slot: nil)
        XCTAssertEqual(r.keyHint?.count, 8)
        XCTAssertNil(off.keyHint)
        XCTAssertEqual(off.seq, next.seq + 1)
        XCTAssertLessThan(off.frame.count, r.frame.count)
        // A key that is not 32 bytes is refused with code 18.
        XCTAssertThrowsError(try Push.registration(savedSeq: nil, kinds: [.copies], env: Push.Env.apns, token: token,
                                                   key: Data(count: 31), sendKey: k.sendKey, slot: k.slot)) { e in
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
    private func vault() -> PushVault {
        PushVault(accessGroup: nil, service: "tools.cbb.push.test-\(UUID().uuidString)")
    }

    private func clean(_ vault: PushVault) {
        for g in (try? vault.groups()) ?? [] { try? vault.save(g, nil) }
        try? vault.save(sender: nil)
    }

    func testTheVaultRegistersOnlyWhatChanged() throws {
        let vault = vault()
        defer { clean(vault) }
        let me = Data(repeating: 1, count: 16)
        let token = Data(repeating: 7, count: 32)
        let devices = PushVault.Devices(members: [me, Data(repeating: 2, count: 16), Data(repeating: 3, count: 16)], root: me)
        let first: Push.Registration?
        do {
            first = try vault.register("g1", me: me, token: token, env: Push.Env.apns, kinds: [.copies, .events],
                                       devices: devices)
        } catch PushVault.Failure.keychain(let s) {
            throw XCTSkip("no keychain here (\(s))")
        }
        let g1 = try vault.load("g1")
        XCTAssertEqual(g1.seq, first?.seq)
        XCTAssertEqual(g1.frame, first?.frame)
        XCTAssertEqual(g1.keys.count, 1)
        XCTAssertEqual(g1.slot?.count, 16)
        XCTAssertEqual(try vault.groups(), ["g1"])
        XCTAssertNotNil(g1.context(hintsOnly: false))
        let sender = try vault.sender()
        XCTAssertEqual(sender.keyHint, first?.keyHint)
        XCTAssertNil(sender.challenge)
        // The app ran again with nothing new: no new registration.
        XCTAssertNil(try vault.register("g1", me: me, token: token, env: Push.Env.apns, kinds: [.copies, .events],
                                        devices: devices))
        XCTAssertEqual(try vault.load("g1"), g1)
        // A member asked for it again: the same keys, a higher seq.
        let renewed = try XCTUnwrap(try vault.register("g1", me: me, token: token, env: Push.Env.apns,
                                                       kinds: [.copies, .events], reasons: .renew, devices: devices))
        XCTAssertGreaterThan(renewed.seq, g1.seq ?? 0)
        XCTAssertEqual(try vault.load("g1").keys.map(\.key), [g1.keys[0].key, g1.keys[0].key])
        XCTAssertEqual(try vault.group(slot: g1.slot!), "g1")

        // A second group: the same send key, its own slot and push key.
        let other = try XCTUnwrap(try vault.register("g2", me: me, token: token, env: Push.Env.apns, kinds: [.copies]))
        let g2 = try vault.load("g2")
        XCTAssertEqual(other.keyHint, first?.keyHint)
        XCTAssertNotEqual(g2.slot, g1.slot)
        XCTAssertNotEqual(g2.keys[0].key, g1.keys[0].key)

        // The push service's challenge: one for another key is dropped; one
        // for this send key is kept and every group registers again with it.
        let value = Data(repeating: 9, count: 16)
        XCTAssertFalse(try vault.keep(challenge: value + Data(repeating: 0, count: 8)))
        XCTAssertFalse(try vault.keep(challenge: Data(count: 23)))
        XCTAssertTrue(try vault.keep(challenge: value + sender.keyHint!))
        XCTAssertFalse(try vault.keep(challenge: value + sender.keyHint!), "the same one twice changes nothing")
        XCTAssertEqual(try vault.sender().challenge, value)
        let withChallenge = try XCTUnwrap(try vault.register("g1", me: me, token: token, env: Push.Env.apns,
                                                             kinds: [.copies, .events], devices: devices))
        XCTAssertGreaterThan(withChallenge.seq, renewed.seq)
        XCTAssertEqual(try vault.load("g1").registered?.challenge, value)

        // A device removed: a new push key, and the previous one is not kept.
        let before = try vault.load("g1")
        let fewer = PushVault.Devices(members: [me, Data(repeating: 2, count: 16)], root: me)
        XCTAssertNotNil(try vault.register("g1", me: me, token: token, env: Push.Env.apns, kinds: [.copies, .events],
                                           devices: fewer))
        let after = try vault.load("g1")
        XCTAssertEqual(after.keys.count, 1)
        XCTAssertNotEqual(after.keys[0].key, before.keys[0].key)
        XCTAssertEqual(after.members, fewer.members)
        XCTAssertGreaterThanOrEqual(after.keyDrawnMS ?? 0, before.keyDrawnMS ?? 0)
        // A device added changes no key: the registration stays.
        XCTAssertNil(try vault.register("g1", me: me, token: token, env: Push.Env.apns, kinds: [.copies, .events],
                                        devices: devices))
        XCTAssertEqual(try vault.load("g1").keys, after.keys)

        // A new token: a new send key for every group, its challenge gone.
        try vault.register("g1", me: me, token: Data(repeating: 8, count: 32), env: Push.Env.apns, kinds: [.copies])
        let s3 = try vault.sender()
        XCTAssertNotEqual(s3.sendKey, sender.sendKey)
        XCTAssertNil(s3.challenge)
        XCTAssertEqual(try vault.load("g1").slot, g1.slot, "the slot stays with the group")
        // Off: the frame says so, the seq still moves; off again is nothing new.
        let off = try XCTUnwrap(try vault.register("g1", me: me, token: nil, env: nil, kinds: []))
        XCTAssertGreaterThan(off.seq, withChallenge.seq)
        XCTAssertEqual(try vault.load("g1").kinds, 0)
        XCTAssertNil(try vault.register("g1", me: me, token: nil, env: nil, kinds: []))
        // On again: a new push key, nothing from before kept.
        try vault.register("g1", me: me, token: Data(repeating: 8, count: 32), env: Push.Env.apns, kinds: [.copies])
        XCTAssertEqual(try vault.load("g1").keys.count, 1)
        try vault.forget("g1")
        try vault.forget("g2")
        XCTAssertEqual(try vault.sender(), PushVault.Sender(), "the sender goes with the last group")
    }

    /// testdata/interop/push-open.json, from the Rust core's push tests: the
    /// extension opens a real copy to its text with the secrets the app left
    /// it, and after a rotation the new epoch's copy and no longer the copy
    /// of the epoch that left the window.
    func testARealCopyShowsAcrossARotation() throws {
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<6 { url.deleteLastPathComponent() }
        struct Body: Decodable {
            var body: Data
            var now_ms: UInt64
            var text: String
        }
        struct Step: Decodable {
            var name: String
            var sealing: [Push.Sealing]
            var opens: [String]
        }
        struct V: Decodable {
            var key: Data
            var seq: UInt64
            var me: Data
            var window_ms: UInt64
            var origins: [Push.Origin]
            var bodies: [String: Body]
            var steps: [Step]
        }
        let v = try JSONDecoder().decode(V.self, from: Data(contentsOf: url.appendingPathComponent("testdata/interop/push-open.json")))
        XCTAssertEqual(v.steps.count, 3)
        let vault = vault()
        defer { clean(vault) }
        var g = PushVault.Group()
        g.keys = [Push.KeyAndSeq(key: v.key, seq: v.seq)]
        g.me = v.me
        do {
            try vault.save("g", g)
        } catch PushVault.Failure.keychain(let s) {
            throw XCTSkip("no keychain here (\(s))")
        }
        for step in v.steps {
            // The app writes what opens a copy on every rotation.
            try vault.opening("g", sealing: step.sealing, origins: v.origins, windowMS: v.window_ms, halted: false)
            let c = try XCTUnwrap(try vault.load("g").context(hintsOnly: false))
            XCTAssertEqual(c.sealing, step.sealing, step.name)
            for (name, b) in v.bodies.sorted(by: { $0.key < $1.key }) {
                let o = try Push.open(b.body, in: c, now: Date(timeIntervalSince1970: Double(b.now_ms) / 1000))
                if step.opens.contains(name) {
                    XCTAssertEqual(o.kind, "copy", "\(step.name) \(name)")
                    XCTAssertEqual(o.text, b.text, "\(step.name) \(name)")
                } else {
                    XCTAssertEqual(o.kind, "waits", "\(step.name) \(name)")
                    XCTAssertNil(o.text, "\(step.name) \(name)")
                }
            }
            // Halted, or after a membership change: never the text.
            var held = c
            held.hintsOnly = true
            let first = try XCTUnwrap(v.bodies["first"])
            XCTAssertNil(try Push.open(first.body, in: held, now: Date(timeIntervalSince1970: Double(first.now_ms) / 1000)).text)
        }
    }

    /// The shared keychain group holds what opens a body and a copy, and no
    /// key that signs a record: every item the vault wrote has only the
    /// push fields, the extension's entitlements name only the push group,
    /// and the member key's group (where new keys go) is another one.
    func testTheSharedGroupHoldsNoSigningKey() throws {
        let vault = vault()
        defer { clean(vault) }
        let me = Data(repeating: 1, count: 16)
        do {
            try vault.register("g1", me: me, token: Data(repeating: 7, count: 32), env: Push.Env.apns,
                               kinds: [.copies, .events], devices: PushVault.Devices(members: [me], root: me))
        } catch PushVault.Failure.keychain(let s) {
            throw XCTSkip("no keychain here (\(s))")
        }
        try vault.opening("g1", sealing: [Push.Sealing(epoch: 1, secret: Data(count: 32))],
                          origins: [Push.Origin(key: Data(count: 70), rights: 1)], windowMS: 120_000, halted: false)
        let allowed: Set<String> = [
            // Sender
            "token", "env", "sendKey", "keyHint", "challenge",
            // Group
            "keys", "key", "seq", "slot", "kinds", "frame", "registered", "keyDrawnMS", "me", "members", "root",
            "origins", "rights", "frozen", "sealing", "epoch", "secret", "tooOld", "halted", "windowMS",
        ]
        func names(_ v: Any) -> Set<String> {
            if let d = v as? [String: Any] { return d.reduce(into: Set(d.keys)) { $0.formUnion(names($1.value)) } }
            if let a = v as? [Any] { return a.reduce(into: Set<String>()) { $0.formUnion(names($1)) } }
            return []
        }
        let items = try vault.items()
        XCTAssertEqual(items.count, 2, "one group and the sender")
        for item in items {
            let found = names(try JSONSerialization.jsonObject(with: item))
            XCTAssertTrue(found.isSubset(of: allowed), "unexpected fields: \(found.subtracting(allowed))")
        }

        var root = URL(fileURLWithPath: #filePath)
        for _ in 0..<6 { root.deleteLastPathComponent() }
        func groups(_ path: String) throws -> [String] {
            let d = try Data(contentsOf: root.appendingPathComponent(path))
            let p = try PropertyListSerialization.propertyList(from: d, format: nil) as? [String: Any]
            return p?["keychain-access-groups"] as? [String] ?? []
        }
        XCTAssertEqual(try groups("apps/ios/NotificationService/NotificationService.entitlements"),
                       ["$(AppIdentifierPrefix)tools.cbb.push"])
        let app = try groups("apps/ios/CBB/CBB.entitlements")
        XCTAssertEqual(app.first, "$(AppIdentifierPrefix)tools.cbb.shared", "new keys go to the first group, not push's")
        XCTAssertTrue(app.contains("$(AppIdentifierPrefix)tools.cbb.push"))
        // Only push's code names the push group.
        let sources = root.appendingPathComponent("apps/ios")
        let files = FileManager.default.enumerator(at: sources, includingPropertiesForKeys: nil)?
            .compactMap { $0 as? URL }.filter { $0.pathExtension == "swift" && !$0.path.contains("/.build/") } ?? []
        for f in files where !["PushVault.swift", "PushSetup.swift", "NotificationService.swift", "PushTests.swift"].contains(f.lastPathComponent) {
            let text = try String(contentsOf: f, encoding: .utf8)
            XCTAssertFalse(text.contains("CBBPushKeychain") || text.contains("tools.cbb.push"), f.lastPathComponent)
        }
    }

    func testAHintsOnlyMarkLastsUntilItsChangeIsApplied() throws {
        let defaults = try XCTUnwrap(UserDefaults(suiteName: "push-marks-\(UUID().uuidString)"))
        let gone = Data(repeating: 2, count: 16), me = Data(repeating: 1, count: 16)
        var g = PushVault.Group()
        g.members = [me, gone]
        g.root = me
        g.keyDrawnMS = 1_000
        XCTAssertFalse(PushMarks.hintsOnly("g", g, in: defaults))
        // A removal the app has not applied yet: hints only.
        PushMarks.mark("g", event: 2, device: gone, now: Date(timeIntervalSince1970: 2), in: defaults)
        XCTAssertTrue(PushMarks.hintsOnly("g", g, in: defaults))
        XCTAssertFalse(PushMarks.hintsOnly("other", g, in: defaults))
        PushMarks.spend("g", g, in: defaults)
        XCTAssertTrue(PushMarks.hintsOnly("g", g, in: defaults), "not applied: the mark stays")
        // Applied, with its new key: spent.
        g.members = [me]
        g.keyDrawnMS = 3_000
        XCTAssertFalse(PushMarks.hintsOnly("g", g, in: defaults))
        PushMarks.spend("g", g, in: defaults)
        // A removal the phone applied before the event came: nothing.
        PushMarks.mark("g", event: 2, device: gone, now: Date(timeIntervalSince1970: 9), in: defaults)
        XCTAssertFalse(PushMarks.hintsOnly("g", g, in: defaults))
        PushMarks.spend("g", g, in: defaults)
        // A new root the app knows already: nothing; one it does not: hints.
        g.members = [me, gone]
        PushMarks.mark("g", event: 4, device: me, now: Date(timeIntervalSince1970: 9), in: defaults)
        XCTAssertFalse(PushMarks.hintsOnly("g", g, in: defaults))
        PushMarks.mark("g", event: 4, device: gone, now: Date(timeIntervalSince1970: 9), in: defaults)
        XCTAssertTrue(PushMarks.hintsOnly("g", g, in: defaults))
        // Applied: the new root and its new key, and the mark for the old
        // root does not come back.
        g.root = gone
        g.keyDrawnMS = 9_500
        XCTAssertFalse(PushMarks.hintsOnly("g", g, in: defaults))
        // A stop: until a key drawn after it.
        PushMarks.mark("g", event: 6, device: nil, now: Date(timeIntervalSince1970: 10), in: defaults)
        XCTAssertTrue(PushMarks.hintsOnly("g", g, in: defaults))
        g.keyDrawnMS = 11_000
        XCTAssertFalse(PushMarks.hintsOnly("g", g, in: defaults))
    }
    #endif
}
