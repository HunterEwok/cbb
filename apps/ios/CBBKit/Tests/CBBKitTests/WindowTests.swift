// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

#if canImport(Network)
@testable import CBBKit
import Foundation
import XCTest

/// A phone makes a group of 0.6, opens its pairing window, and a new phone
/// joins by its QR code, through the Rust core as the apps do.
final class WindowTests: XCTestCase {
    private func temporary(_ name: String) -> URL {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("cbb-core-window-\(name)-\(UUID().uuidString)")
        addTeardownBlock { try? FileManager.default.removeItem(at: dir) }
        return dir
    }

    /// Waits for a state named want, past the versions next gives.
    private func wait<S>(_ want: String, _ state: (S) -> String, _ version: (S) -> UInt64, _ failure: (S) -> Error?,
                         _ next: (UInt64) throws -> S) throws -> S {
        var v: UInt64 = 0
        for _ in 0..<200 {
            let s = try next(v)
            if state(s) == want { return s }
            if state(s) == "failed", let f = failure(s) { throw f }
            v = version(s)
        }
        XCTFail("no state \(want)")
        throw CancellationError()
    }

    func testAPhoneThatMadeItsGroupLetsANewPhoneJoinByItsWindow() throws {
        let root = SoftwareSigner(), key = SoftwareSigner()
        let dir = temporary("root")
        let made = try CorePairing.newGroup06(dir: dir, name: "Root phone", store: Records.hardware, rootPublic: root.publicKeyDER,
                                              publicKey: key.publicKeyDER) { try root.signature(digest: $0) }
        XCTAssertEqual(made.recovery.text.count, 4)
        XCTAssertFalse(made.recovery.qr.isEmpty)
        // Once only.
        XCTAssertThrowsError(try CorePairing.newGroup06(dir: dir, name: "Root phone", store: Records.hardware, rootPublic: root.publicKeyDER,
                                                        publicKey: key.publicKeyDER) { try root.signature(digest: $0) })

        let m = try CoreMember(.init(dir: dir, name: "Root phone", device: made.device, publicKeyDER: key.publicKeyDER, seal: CoreGroup.seal,
                                     cert: Data(), issuer: nil, groupCA: Data(), roots: [])) { try key.signature(digest: $0) }
        addTeardownBlock { m.stop() }
        _ = try m.listen(.home)
        let w = try CorePairing.Window(member: m, publicKey: root.publicKeyDER, addrs: ["127.0.0.1"]) { try root.signature(digest: $0) }
        defer { w.close() }
        XCTAssertTrue(w.qr.hasPrefix("cbb://pair?addr=127.0.0.1%3A"), w.qr)
        XCTAssertTrue(w.qr.hasSuffix("fp=\(w.fingerprint)"))

        let newKey = SoftwareSigner()
        let newDir = temporary("new")
        let j = try CorePairing.Joiner(dir: newDir, qr: w.qr, name: "Tablet", os: "android", publicKey: newKey.publicKeyDER) {
            try newKey.signature(digest: $0)
        }
        defer { j.close() }
        let atWindow = try wait("joining", { $0.state }, { $0.version }, { $0.failure }) { try w.next(after: $0, timeout: .milliseconds(100)) }
        let atJoiner = try wait("joining", { $0.state }, { $0.version }, { $0.failure }) { try j.next(after: $0, timeout: .milliseconds(100)) }
        let asked = try XCTUnwrap(atWindow.request)
        XCTAssertEqual(asked.code, try XCTUnwrap(atJoiner.shown).code, "both screens show one code")
        XCTAssertEqual(asked.name, "Tablet")
        XCTAssertEqual(atJoiner.shown?.name, "Root phone")
        w.answer(true)
        j.answer(true)
        let done = try wait("done", { $0.state }, { $0.version }, { $0.failure }) { try j.next(after: $0, timeout: .milliseconds(100)) }
        let admitted = try wait("done", { $0.state }, { $0.version }, { $0.failure }) { try w.next(after: $0, timeout: .milliseconds(100)) }
        XCTAssertEqual(done.group, made.group, "the new phone is in the group the phone made")
        XCTAssertEqual(admitted.name, "Tablet")
        // The new phone keeps the set where its member then starts.
        XCTAssertTrue(FileManager.default.fileExists(atPath: newDir.appendingPathComponent("group.cbor").path))
        let g = try m.group()
        XCTAssertEqual(g.rootDevice, made.device)
        XCTAssertEqual(g.devices.map(\.name).sorted(), ["Root phone", "Tablet"])
    }

    /// A phone's group of 0.6 with its member running, the root key that
    /// opens its windows.
    private func root() throws -> (made: CorePairing.Made, member: CoreMember, root: SoftwareSigner) {
        let root = SoftwareSigner(), key = SoftwareSigner()
        let dir = temporary("root")
        let made = try CorePairing.newGroup06(dir: dir, name: "Root phone", store: Records.hardware, rootPublic: root.publicKeyDER,
                                              publicKey: key.publicKeyDER) { try root.signature(digest: $0) }
        let m = try CoreMember(.init(dir: dir, name: "Root phone", device: made.device, publicKeyDER: key.publicKeyDER, seal: CoreGroup.seal,
                                     cert: Data(), issuer: nil, groupCA: Data(), roots: [])) { try key.signature(digest: $0) }
        addTeardownBlock { m.stop() }
        return (made, m, root)
    }

    private func window(_ m: CoreMember, _ root: SoftwareSigner) throws -> CorePairing.Window {
        try CorePairing.Window(member: m, publicKey: root.publicKeyDER, addrs: ["127.0.0.1"]) { try root.signature(digest: $0) }
    }

    private func joiner(_ name: String, _ qr: String) throws -> (CorePairing.Joiner, URL) {
        let k = SoftwareSigner()
        let dir = temporary(name)
        let j = try CorePairing.Joiner(dir: dir, qr: qr, name: name, os: "ios", publicKey: k.publicKeyDER) { try k.signature(digest: $0) }
        return (j, dir)
    }

    /// The first state named one of want, failed included.
    private func until<S>(_ want: Set<String>, _ state: (S) -> String, _ version: (S) -> UInt64,
                          _ next: (UInt64) throws -> S) throws -> S {
        var v: UInt64 = 0
        for _ in 0..<200 {
            let s = try next(v)
            if want.contains(state(s)) { return s }
            v = version(s)
        }
        XCTFail("none of \(want)")
        throw CancellationError()
    }

    func testAWindowNeedsTheMemberPortOpen() throws {
        let r = try root()
        XCTAssertThrowsError(try window(r.member, r.root))
    }

    func testACodeTheWindowsPersonSaysDoesNotMatchJoinsNoOneAndTheWindowTakesTheNextAttempt() throws {
        let r = try root()
        _ = try r.member.listen(.home)
        let w = try window(r.member, r.root)
        defer { w.close() }
        let (j, dir) = try joiner("Tablet", w.qr)
        defer { j.close() }
        _ = try until(["joining"], { $0.state }, { $0.version }) { try w.next(after: $0, timeout: .milliseconds(100)) }
        _ = try until(["joining"], { $0.state }, { $0.version }) { try j.next(after: $0, timeout: .milliseconds(100)) }
        j.answer(true)
        w.answer(false)
        XCTAssertEqual(try until(["done", "failed"], { $0.state }, { $0.version }) { try j.next(after: $0, timeout: .milliseconds(100)) }.state,
                       "failed")
        XCTAssertFalse(FileManager.default.fileExists(atPath: dir.appendingPathComponent("group.cbor").path), "the refused phone keeps no group")
        XCTAssertEqual(try r.member.group().devices.map(\.name), ["Root phone"])

        // The window stays open for the next attempt.
        let (second, _) = try joiner("Laptop", w.qr)
        defer { second.close() }
        let again = try until(["joining"], { $0.state }, { $0.version }) { try w.next(after: $0, timeout: .milliseconds(100)) }
        XCTAssertEqual(again.request?.name, "Laptop")
        _ = try until(["joining"], { $0.state }, { $0.version }) { try second.next(after: $0, timeout: .milliseconds(100)) }
        w.answer(true)
        second.answer(true)
        XCTAssertEqual(try until(["done", "failed"], { $0.state }, { $0.version }) { try second.next(after: $0, timeout: .milliseconds(100)) }.state,
                       "done")
        XCTAssertEqual(try r.member.group().devices.map(\.name).sorted(), ["Laptop", "Root phone"])
    }

    func testAClosedWindowLetsNoOneJoin() throws {
        let r = try root()
        _ = try r.member.listen(.home)
        let w = try window(r.member, r.root)
        let qr = w.qr
        w.close()
        if let pair = try? joiner("Tablet", qr) {
            let j = pair.0
            defer { j.close() }
            XCTAssertEqual(try until(["done", "failed"], { $0.state }, { $0.version }) { try j.next(after: $0, timeout: .milliseconds(100)) }.state,
                           "failed")
        }
        XCTAssertEqual(try r.member.group().devices.map(\.name), ["Root phone"])
    }

    func testAJoinerRefusesACodeThatIsNoWindows() {
        let k = SoftwareSigner()
        XCTAssertThrowsError(try CorePairing.Joiner(dir: temporary("x"), qr: "cbb://join?code=1", name: "Tablet", os: "ios",
                                                    publicKey: k.publicKeyDER) { try k.signature(digest: $0) })
    }
}
#endif
