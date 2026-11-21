// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

#if canImport(Network)
@testable import CBBKit
import Foundation
import XCTest

/// A phone makes a group of 0.6, opens its home window, and a new phone
/// joins by its QR code or six digits, through the Rust core as the apps do.
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
        XCTAssertTrue(w.qr.hasPrefix("cbb://pair?addr=127.0.0.1:"), w.qr)
        XCTAssertTrue(w.qr.hasSuffix("fp=\(w.fingerprint)&i=\(w.id)&c=\(w.digits)"), w.qr)
        XCTAssertTrue(w.digits.count == 6 && w.digits.allSatisfy(\.isASCII) && w.digits.allSatisfy(\.isNumber))

        let newKey = SoftwareSigner()
        let newDir = temporary("new")
        let j = try CorePairing.Joiner(dir: newDir, qr: w.qr, name: "Tablet", os: "android", publicKey: newKey.publicKeyDER) {
            try newKey.signature(digest: $0)
        }
        defer { j.close() }
        let done = try wait("done", { $0.state }, { $0.version }, { $0.failure }) { try j.next(after: $0, timeout: .milliseconds(100)) }
        let admitted = try wait("done", { $0.state }, { $0.version }, { $0.failure }) { try w.next(after: $0, timeout: .milliseconds(100)) }
        XCTAssertEqual(done.name, "Root phone", "the member that let it in")
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

    func testAWrongCodeJoinsNoOneAndWritesNothingAndThreeCloseTheWindow() throws {
        let r = try root()
        _ = try r.member.listen(.home)
        let w = try window(r.member, r.root)
        defer { w.close() }
        let wrong = w.qr.replacingOccurrences(of: "c=\(w.digits)", with: "c=" + (w.digits == "000000" ? "000001" : "000000"))
        var v: UInt64 = 0
        for n in 1...3 {
            let (j, dir) = try joiner("Wrong\(n)", wrong)
            defer { j.close() }
            let st = try until(["done", "failed"], { $0.state }, { $0.version }) { try j.next(after: $0, timeout: .milliseconds(100)) }
            XCTAssertEqual(st.state, "failed")
            XCTAssertTrue(st.failure?.message.contains("not the window's") == true, "\(String(describing: st.failure))")
            XCTAssertFalse(FileManager.default.fileExists(atPath: dir.appendingPathComponent("group.cbor").path), "the refused phone keeps no group")
            XCTAssertEqual(try r.member.group().devices.map(\.name), ["Root phone"], "nothing reached the records")
            // The window stays open for the next attempt, and closes after the third.
            let want = n < 3 ? "failed" : "closed"
            var seen = ""
            for _ in 0..<200 {
                let s = try w.next(after: v, timeout: .milliseconds(100))
                v = s.version
                if s.state == want { seen = s.state; break }
            }
            XCTAssertEqual(seen, want)
        }
        // Closed, the window takes not even the right digits.
        let (late, _) = try joiner("Late", w.qr)
        defer { late.close() }
        XCTAssertEqual(try until(["done", "failed"], { $0.state }, { $0.version }) { try late.next(after: $0, timeout: .milliseconds(100)) }.state,
                       "failed")
        XCTAssertEqual(try r.member.group().devices.map(\.name), ["Root phone"])
    }

    func testAWindowLetsOneDeviceJoinAndThenCloses() throws {
        let r = try root()
        _ = try r.member.listen(.home)
        let w = try window(r.member, r.root)
        defer { w.close() }
        let (first, _) = try joiner("Tablet", w.qr)
        defer { first.close() }
        XCTAssertEqual(try until(["done", "failed"], { $0.state }, { $0.version }) { try first.next(after: $0, timeout: .milliseconds(100)) }.state,
                       "done")
        let (second, _) = try joiner("Laptop", w.qr)
        defer { second.close() }
        XCTAssertEqual(try until(["done", "failed"], { $0.state }, { $0.version }) { try second.next(after: $0, timeout: .milliseconds(100)) }.state,
                       "failed")
        XCTAssertEqual(try r.member.group().devices.map(\.name).sorted(), ["Root phone", "Tablet"])
    }

    func testAJoinerTakesSixDigits() {
        let k = SoftwareSigner()
        for d in ["", "12345", "1234567", "12a456"] {
            XCTAssertThrowsError(try CorePairing.Joiner(dir: temporary("x"), qr: "", digits: d, name: "Tablet", os: "ios",
                                                        publicKey: k.publicKeyDER) { try k.signature(digest: $0) }, d)
        }
    }

    func testAWindowFoundByBonjourMakesTheCodeTheCoreReads() throws {
        let fp = String(repeating: "ab", count: 32), id = String(repeating: "11", count: 16)
        XCTAssertEqual(Discovery.windowLink(address: "[fd00::20]:8764", fingerprint: fp, id: id, digits: "123456"),
                       "cbb://pair?addr=[fd00::20]:8764&fp=\(fp)&i=\(id)&c=123456")
        XCTAssertEqual(Discovery.windowLink(address: "fe80::1%en0", fingerprint: fp, id: id, digits: "1"),
                       "cbb://pair?addr=fe80::1%25en0&fp=\(fp)&i=\(id)&c=1")
        let f = try XCTUnwrap(Discovery.member(instance: String(repeating: "0a", count: 16), txt: ["v=1", "g=x", "p=1", "f=\(fp)", "i=\(id)"]))
        XCTAssertTrue(f.pairing)
        XCTAssertEqual(f.windowID, id)
        XCTAssertEqual(f.fingerprint, fp)
        XCTAssertEqual(Discovery.windowTXT(group: "x", fingerprint: fp, id: id), ["v": "1", "g": "x", "p": "1", "f": fp, "i": id])
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
