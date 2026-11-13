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
        let face = Data(repeating: 4, count: 16)
        let now = Date(timeIntervalSince1970: 1_800_000_000)
        func reg(_ highest: UInt64?, restart: Bool = false, at: Date = now) throws -> Push.Registration {
            try Push.registration(highestSeq: highest, restart: restart, now: at, kinds: [.copies], env: Push.Env.apns,
                                  token: token, key: k.key, sendKey: k.sendKey, slot: k.slot, face: face)
        }
        let r = try reg(nil)
        XCTAssertEqual(r.seq, 1_800_000_000_000)
        XCTAssertEqual(r.highest, r.seq)
        // Restored from a backup with an older seq: still forward of the clock.
        let back = try reg(5)
        XCTAssertEqual(back.seq, r.seq)
        let next = try reg(r.seq)
        XCTAssertEqual(next.seq, r.seq + 1)
        let off = try Push.registration(highestSeq: next.highest, now: now, kinds: [], env: nil, token: nil, key: nil,
                                        sendKey: nil, slot: nil, face: nil)
        XCTAssertEqual(r.keyHint?.count, 8)
        XCTAssertNil(off.keyHint)
        XCTAssertEqual(off.seq, next.seq + 1)
        XCTAssertLessThan(off.frame.count, r.frame.count)
        // Saved while the clock was two days ahead: the number stays above
        // it until a member says the service found it ahead; then it starts
        // again from the clock, and so does the highest, which the phone's
        // clock finds ahead too. A restart the clock disagrees with keeps it.
        let ahead = try reg(r.seq + 2 * 86_400_000)
        XCTAssertEqual(ahead.seq, r.seq + 2 * 86_400_000 + 1)
        let restarted = try reg(ahead.highest, restart: true)
        XCTAssertEqual(restarted.seq, r.seq)
        XCTAssertEqual(restarted.highest, r.seq)
        let falseAhead = try reg(r.seq + 1000, restart: true)
        XCTAssertEqual(falseAhead.seq, r.seq)
        XCTAssertEqual(falseAhead.highest, r.seq + 1000)
        // Another face signs other bytes.
        let other = try Push.registration(highestSeq: r.seq, now: now, kinds: [.copies], env: Push.Env.apns, token: token,
                                          key: k.key, sendKey: k.sendKey, slot: k.slot, face: Data(repeating: 5, count: 16))
        XCTAssertNotEqual(other.frame, next.frame)
        // A key that is not 32 bytes, a face that is not 16 or none: code 18.
        for (key, face) in [(Data(count: 31), face), (k.key, Data(count: 15)), (k.key, nil)] as [(Data, Data?)] {
            XCTAssertThrowsError(try Push.registration(highestSeq: nil, kinds: [.copies], env: Push.Env.apns, token: token,
                                                       key: key, sendKey: k.sendKey, slot: k.slot, face: face)) { e in
                XCTAssertEqual((e as? Core.Refusal)?.code, 18)
            }
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
        let face = Data(repeating: 4, count: 16)
        let devices = PushVault.Devices(members: [me, Data(repeating: 2, count: 16), Data(repeating: 3, count: 16)], root: me)
        let first: Push.Registration?
        do {
            first = try vault.register("g1", me: me, token: token, env: Push.Env.apns, kinds: [.copies, .events],
                                       face: face, devices: devices)
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
                                        face: face, devices: devices))
        XCTAssertEqual(try vault.load("g1"), g1)
        // A member asked for it again: the same keys, a higher seq.
        let renewed = try XCTUnwrap(try vault.register("g1", me: me, token: token, env: Push.Env.apns,
                                                       kinds: [.copies, .events], face: face, reasons: .renew, devices: devices))
        XCTAssertGreaterThan(renewed.seq, g1.seq ?? 0)
        XCTAssertEqual(try vault.load("g1").keys.map(\.key), [g1.keys[0].key, g1.keys[0].key])
        XCTAssertEqual(try vault.group(slot: g1.slot!), "g1")

        // A second group: the same send key, its own slot and push key.
        let other = try XCTUnwrap(try vault.register("g2", me: me, token: token, env: Push.Env.apns, kinds: [.copies],
                                                     face: face))
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
                                                             kinds: [.copies, .events], face: face, devices: devices))
        XCTAssertGreaterThan(withChallenge.seq, renewed.seq)
        XCTAssertEqual(try vault.load("g1").registered?.challenge, value)

        // A device removed: a new push key, and the previous one is not kept.
        let before = try vault.load("g1")
        let fewer = PushVault.Devices(members: [me, Data(repeating: 2, count: 16)], root: me)
        XCTAssertNotNil(try vault.register("g1", me: me, token: token, env: Push.Env.apns, kinds: [.copies, .events],
                                           face: face, devices: fewer))
        let after = try vault.load("g1")
        XCTAssertEqual(after.keys.count, 1)
        XCTAssertNotEqual(after.keys[0].key, before.keys[0].key)
        XCTAssertEqual(after.members, fewer.members)
        XCTAssertGreaterThanOrEqual(after.keyDrawnMS ?? 0, before.keyDrawnMS ?? 0)
        // A device added changes no key: the registration stays.
        XCTAssertNil(try vault.register("g1", me: me, token: token, env: Push.Env.apns, kinds: [.copies, .events],
                                        face: face, devices: devices))
        XCTAssertEqual(try vault.load("g1").keys, after.keys)

        // A new face for the push service: a new registration naming it, the
        // same push key; no face at all registers nothing.
        let moved = Data(repeating: 6, count: 16)
        let onNewFace = try XCTUnwrap(try vault.register("g1", me: me, token: token, env: Push.Env.apns,
                                                         kinds: [.copies, .events], face: moved, devices: devices))
        XCTAssertEqual(try vault.load("g1").registered?.face, moved)
        XCTAssertEqual(try vault.load("g1").keys.first?.key, after.keys[0].key)
        XCTAssertThrowsError(try vault.register("g1", me: me, token: token, env: Push.Env.apns, kinds: [.copies, .events],
                                                devices: devices)) { e in
            guard case PushVault.Failure.noFace = e else { return XCTFail("\(e)") }
        }
        XCTAssertEqual(try vault.load("g1").seq, onNewFace.seq, "nothing saved without a face")
        // A member said the number was ahead, and the phone's clock agrees:
        // one registration from the clock, which becomes the highest, so the
        // next of the phone's own is in time too.
        var g = try vault.load("g1")
        let past = UInt64(Date().timeIntervalSince1970 * 1000) + 3 * 86_400_000
        g.highest = past
        g.seq = past
        try vault.save("g1", g)
        let restarted = try XCTUnwrap(try vault.register("g1", me: me, token: token, env: Push.Env.apns,
                                                         kinds: [.copies, .events], face: moved,
                                                         reasons: [.renew, .ahead], devices: devices))
        XCTAssertLessThan(restarted.seq, past)
        XCTAssertEqual(try vault.load("g1").highest, restarted.seq)
        XCTAssertEqual(try vault.load("g1").seq, restarted.seq)
        let renewedAgain = try XCTUnwrap(try vault.register("g1", me: me, token: token, env: Push.Env.apns,
                                                            kinds: [.copies, .events], face: moved, reasons: .renew,
                                                            devices: devices))
        XCTAssertLessThan(renewedAgain.seq, past)
        XCTAssertGreaterThan(renewedAgain.seq, restarted.seq)

        // A new token: a new send key for every group, its challenge gone.
        try vault.register("g1", me: me, token: Data(repeating: 8, count: 32), env: Push.Env.apns, kinds: [.copies], face: face)
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
        try vault.register("g1", me: me, token: Data(repeating: 8, count: 32), env: Push.Env.apns, kinds: [.copies], face: face)
        XCTAssertEqual(try vault.load("g1").keys.count, 1)
        // Leaving every group drops the groups and keeps the sender: a group
        // joined later registers under the same send key and challenge.
        let kept = try vault.sender()
        XCTAssertTrue(try vault.keep(challenge: value + kept.keyHint!))
        try vault.forget("g1")
        try vault.forget("g2")
        XCTAssertEqual(try vault.groups(), [])
        XCTAssertNil(try? vault.load("g1").slot)
        let g3 = try XCTUnwrap(try vault.register("g3", me: me, token: Data(repeating: 8, count: 32), env: Push.Env.apns,
                                                  kinds: [.copies], face: face))
        XCTAssertEqual(g3.keyHint, kept.keyHint)
        XCTAssertEqual(try vault.sender().sendKey, kept.sendKey)
        XCTAssertEqual(try vault.load("g3").registered?.challenge, value)
        try vault.forget("g3")
    }

    /// Leaving a group turns push off there first, then drops the group and
    /// the send key: the left group's members get a registration of kinds 0,
    /// and what they held before is under a key the phone no longer signs
    /// with, so its next registration anywhere carries a new one.
    func testLeavingTurnsPushOffThereAndRetiresTheSendKey() throws {
        let vault = vault()
        defer { clean(vault) }
        let me = Data(repeating: 1, count: 16)
        let token = Data(repeating: 7, count: 32)
        let face = Data(repeating: 4, count: 16)
        let on: Push.Registration
        do {
            on = try XCTUnwrap(try vault.register("left", me: me, token: token, env: Push.Env.apns, kinds: [.copies],
                                                  face: face))
        } catch PushVault.Failure.keychain(let s) {
            throw XCTSkip("no keychain here (\(s))")
        }
        let stays = try XCTUnwrap(try vault.register("stays", me: me, token: token, env: Push.Env.apns, kinds: [.copies],
                                                     face: face))
        let before = try vault.sender()
        XCTAssertTrue(try vault.keep(challenge: Data(repeating: 9, count: 16) + before.keyHint!))
        let off = try XCTUnwrap(try vault.leaving("left"))
        XCTAssertGreaterThan(off.seq, on.seq)
        XCTAssertNil(off.keyHint, "push off carries no send key")
        XCTAssertEqual(try vault.load("left").frame, off.frame, "the frame the members get is the one turning it off")
        XCTAssertEqual(try vault.load("left").kinds, 0)
        XCTAssertNil(try vault.leaving("left"), "already off: nothing more")
        XCTAssertFalse(try vault.left("left"), "another group stays")
        XCTAssertEqual(try vault.groups(), ["stays"])
        let after = try vault.sender()
        XCTAssertNil(after.sendKey)
        XCTAssertNil(after.challenge)
        XCTAssertEqual(after.token, token, "the token stays")
        // The group the phone stays in registers again under a new send key.
        let again = try XCTUnwrap(try vault.register("stays", me: me, token: token, env: Push.Env.apns, kinds: [.copies],
                                                     face: face))
        XCTAssertNotEqual(again.keyHint, stays.keyHint)
        XCTAssertNotEqual(try vault.sender().sendKey, before.sendKey)
        XCTAssertNil(try vault.load("stays").registered?.challenge)
        // Leaving the last group gives the token up: the sender goes whole.
        XCTAssertNotNil(try vault.leaving("stays"))
        XCTAssertTrue(try vault.left("stays"))
        XCTAssertNil(try vault.sender().token)
        XCTAssertNil(try vault.sender().sendKey)
        XCTAssertEqual(try vault.items().count, 0)
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
        let face = Data(repeating: 4, count: 16)
        do {
            try vault.register("g1", me: me, token: Data(repeating: 7, count: 32), env: Push.Env.apns,
                               kinds: [.copies, .events], face: face, devices: PushVault.Devices(members: [me], root: me))
        } catch PushVault.Failure.keychain(let s) {
            throw XCTSkip("no keychain here (\(s))")
        }
        try vault.opening("g1", sealing: [Push.Sealing(epoch: 1, secret: Data(count: 32))],
                          origins: [Push.Origin(key: Data(count: 70), rights: 1)], windowMS: 120_000, halted: false)
        let allowed: Set<String> = [
            // Sender
            "token", "env", "sendKey", "keyHint", "challenge",
            // Group
            "keys", "key", "seq", "highest", "face", "slot", "kinds", "frame", "registered", "keyDrawnMS", "me", "members", "root",
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
        // The extension's one app group is push's, never the app's group with
        // the group's file and the servers' credentials.
        func appGroups(_ path: String) throws -> [String] {
            let d = try Data(contentsOf: root.appendingPathComponent(path))
            let p = try PropertyListSerialization.propertyList(from: d, format: nil) as? [String: Any]
            return p?["com.apple.security.application-groups"] as? [String] ?? []
        }
        XCTAssertEqual(try appGroups("apps/ios/NotificationService/NotificationService.entitlements"), [PushMarks.appGroup])
        XCTAssertEqual(Set(try appGroups("apps/ios/CBB/CBB.entitlements")), ["group.tools.cbb", PushMarks.appGroup])
        // Only push's code names the push group.
        let sources = root.appendingPathComponent("apps/ios")
        let files = FileManager.default.enumerator(at: sources, includingPropertiesForKeys: nil)?
            .compactMap { $0 as? URL }.filter { $0.pathExtension == "swift" && !$0.path.contains("/.build/") } ?? []
        for f in files where !["PushVault.swift", "PushSetup.swift", "NotificationService.swift", "PushTests.swift",
                               "PushMarks.swift"].contains(f.lastPathComponent) {
            let text = try String(contentsOf: f, encoding: .utf8)
            XCTAssertFalse(text.contains("CBBPushKeychain") || text.contains("tools.cbb.push"), f.lastPathComponent)
        }
        // The app's own keychain queries name its access group, so an item in
        // the push group never answers one (the watch has a keychain of its
        // own; the tests make their own items).
        for f in files where !["PushVault.swift", "WatchKey.swift"].contains(f.lastPathComponent) && !f.path.contains("Tests/") {
            let text = try String(contentsOf: f, encoding: .utf8)
            guard text.contains("SecItem") || text.contains("SecKeyCreateRandomKey") else { continue }
            XCTAssertTrue(text.contains("inGroup("), "\(f.lastPathComponent) queries the keychain without the app's access group")
        }
    }

    func testAHintsOnlyMarkLastsUntilItsChangeIsApplied() throws {
        PushMarks.clock = { Date(timeIntervalSince1970: 100) }
        defer { PushMarks.clock = { Date() } }
        let defaults = try XCTUnwrap(UserDefaults(suiteName: "push-marks-\(UUID().uuidString)"))
        let gone = Data(repeating: 2, count: 16), me = Data(repeating: 1, count: 16)
        var g = PushVault.Group()
        g.members = [me, gone]
        g.root = me
        g.keyDrawnMS = 1_000
        XCTAssertFalse(PushMarks.hintsOnly("g", g, in: defaults))
        // A removal the app has not applied yet: hints only.
        PushMarks.mark("g", event: 2, device: gone, state: g, now: Date(timeIntervalSince1970: 2), in: defaults)
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
        PushMarks.mark("g", event: 2, device: gone, state: g, now: Date(timeIntervalSince1970: 9), in: defaults)
        XCTAssertFalse(PushMarks.hintsOnly("g", g, in: defaults))
        PushMarks.spend("g", g, in: defaults)
        // A new root the app knows already: nothing; one it does not: hints.
        g.members = [me, gone]
        PushMarks.mark("g", event: 4, device: me, state: g, now: Date(timeIntervalSince1970: 9), in: defaults)
        XCTAssertFalse(PushMarks.hintsOnly("g", g, in: defaults))
        PushMarks.mark("g", event: 4, device: gone, state: g, now: Date(timeIntervalSince1970: 9), in: defaults)
        XCTAssertTrue(PushMarks.hintsOnly("g", g, in: defaults))
        // Applied: the new root and its new key, and the mark for the old
        // root does not come back.
        g.root = gone
        g.keyDrawnMS = 9_500
        XCTAssertFalse(PushMarks.hintsOnly("g", g, in: defaults))
        // A stop: until a key drawn after it.
        PushMarks.mark("g", event: 6, device: nil, state: g, now: Date(timeIntervalSince1970: 10), in: defaults)
        XCTAssertTrue(PushMarks.hintsOnly("g", g, in: defaults))
        g.keyDrawnMS = 11_000
        XCTAssertFalse(PushMarks.hintsOnly("g", g, in: defaults))
        // An event naming a change that never comes (a removal of a device
        // that stays, a stop that is not there): spent once the app has
        // synced the group's records after it with a member other than the
        // device it names, taken in records newer than the mark, and those
        // records say it did not happen.
        let other = Data(repeating: 3, count: 16)
        PushMarks.spend("g", g, in: defaults)
        XCTAssertNil(PushMarks.all(defaults)["g"])
        func at(_ s: Double) -> Date { Date(timeIntervalSince1970: s) }
        PushMarks.mark("g", event: 2, device: gone, state: g, now: at(20), in: defaults)
        PushMarks.mark("g", event: 6, device: nil, state: g, now: at(21), in: defaults)
        XCTAssertTrue(PushMarks.hintsOnly("g", g, in: defaults))
        // A member that brought nothing newer than the marks has not heard
        // of the change either: nothing spent.
        PushMarks.synced("g", at: at(25), peers: [other], recordsAt: at(19), state: g, in: defaults)
        PushMarks.synced("g", at: at(25), peers: [other], recordsAt: nil, state: g, in: defaults)
        XCTAssertEqual(PushMarks.all(defaults)["g"]?.map(\.event), [2, 6], "no newer records: no mark spent")
        PushMarks.synced("g", at: at(20.5), peers: [other], recordsAt: at(20.2), state: g, in: defaults)
        XCTAssertTrue(PushMarks.hintsOnly("g", g, in: defaults), "the stop came after that sync")
        XCTAssertEqual(PushMarks.all(defaults)["g"]?.map(\.event), [6])
        PushMarks.mark("g", event: 2, device: gone, state: g, now: at(23), in: defaults)
        PushMarks.synced("g", at: at(24), peers: [gone], recordsAt: at(23.5), state: g, in: defaults)
        XCTAssertEqual(PushMarks.all(defaults)["g"]?.map(\.event), [2], "the device a mark names never clears it")
        PushMarks.synced("g", at: at(24), peers: [], recordsAt: at(23.5), state: g, in: defaults)
        XCTAssertTrue(PushMarks.hintsOnly("g", g, in: defaults), "no member: nothing synced")
        PushMarks.synced("g", at: at(24), peers: [other], recordsAt: at(23.5), state: g, in: defaults)
        XCTAssertFalse(PushMarks.hintsOnly("g", g, in: defaults))
        // A stop that is there stays in force whatever a sync brings, until
        // a key drawn after it.
        g.halted = true
        PushMarks.mark("g", event: 6, device: nil, state: g, now: at(30), in: defaults)
        PushMarks.synced("g", at: at(31), peers: [other], recordsAt: at(30.5), state: g, in: defaults)
        XCTAssertTrue(PushMarks.hintsOnly("g", g, in: defaults))
        g.keyDrawnMS = 32_000
        XCTAssertFalse(PushMarks.hintsOnly("g", g, in: defaults))
        // A mark ends a week after the app first met a member other than the
        // device it names; a phone that met none keeps it.
        g.halted = false
        let week: Double = 7 * 24 * 3600
        PushMarks.mark("g", event: 2, device: gone, state: g, now: at(40), in: defaults)
        XCTAssertTrue(PushMarks.hintsOnly("g", g, in: defaults))
        PushMarks.clock = { Date(timeIntervalSince1970: 40 + 30 * week) }
        XCTAssertTrue(PushMarks.hintsOnly("g", g, in: defaults), "a phone that met no member keeps a true mark")
        PushMarks.synced("g", at: at(50), peers: [gone], recordsAt: at(45), state: g, in: defaults)
        XCTAssertTrue(PushMarks.hintsOnly("g", g, in: defaults), "the device a mark names starts no week")
        PushMarks.synced("g", at: at(50), peers: [other], recordsAt: nil, state: g, in: defaults)
        PushMarks.clock = { Date(timeIntervalSince1970: 50 + week - 1) }
        XCTAssertTrue(PushMarks.hintsOnly("g", g, in: defaults), "the week counts from the first meeting")
        PushMarks.synced("g", at: at(60), peers: [other], recordsAt: nil, state: g, in: defaults)
        PushMarks.clock = { Date(timeIntervalSince1970: 50 + week) }
        XCTAssertFalse(PushMarks.hintsOnly("g", g, in: defaults))
        PushMarks.clock = { Date(timeIntervalSince1970: 100) }
        PushMarks.forget("g", in: defaults)
        XCTAssertNil(PushMarks.all(defaults)["g"])
    }

    /// A full list keeps the marks in force: one not in force goes first,
    /// and an event naming a device the group does not list never pushes
    /// one out.
    func testAFullListOfMarksKeepsTheOnesInForce() throws {
        PushMarks.clock = { Date(timeIntervalSince1970: 100) }
        defer { PushMarks.clock = { Date() } }
        let defaults = try XCTUnwrap(UserDefaults(suiteName: "push-marks-\(UUID().uuidString)"))
        let gone = Data(repeating: 2, count: 16), me = Data(repeating: 1, count: 16)
        var g = PushVault.Group()
        g.members = [me, gone]
        g.root = me
        g.keyDrawnMS = 1_000
        func at(_ s: Double) -> Date { Date(timeIntervalSince1970: s) }
        PushMarks.mark("g", event: 2, device: gone, state: g, now: at(2), in: defaults)
        for i in 0..<40 {
            PushMarks.mark("g", event: 2, device: Data(repeating: UInt8(10 + i), count: 16), state: g, now: at(3 + Double(i)),
                           in: defaults)
        }
        var list = try XCTUnwrap(PushMarks.all(defaults)["g"])
        XCTAssertEqual(list.count, PushMarks.max)
        XCTAssertEqual(list.first?.device, gone, "forty events naming no device of the group: the true mark stays")
        XCTAssertTrue(PushMarks.hintsOnly("g", g, in: defaults))
        // A stop in force pushes out one that is not, never the removal.
        PushMarks.mark("g", event: 6, device: nil, state: g, now: at(50), in: defaults)
        list = try XCTUnwrap(PushMarks.all(defaults)["g"])
        XCTAssertEqual(list.count, PushMarks.max)
        XCTAssertEqual(list.filter { $0.inForce(g) }.map(\.event), [2, 6])
        // Filled with marks in force, the oldest goes.
        for i in 0..<PushMarks.max {
            PushMarks.mark("g", event: 6, device: nil, state: g, now: at(60 + Double(i)), in: defaults)
        }
        list = try XCTUnwrap(PushMarks.all(defaults)["g"])
        XCTAssertEqual(list.count, PushMarks.max)
        XCTAssertTrue(list.allSatisfy { $0.event == 6 && $0.atMS >= 60_000 })
    }
    #endif
}
