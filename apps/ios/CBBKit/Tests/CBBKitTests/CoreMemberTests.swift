// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

#if canImport(Network)
@testable import CBBKit
import Foundation
import XCTest

/// The phone's member in the Rust core (CoreMember): a phone makes a group,
/// a second phone joins it by its window, and the two sync, follow the
/// button's rule and carry out the root's actions.
final class CoreMemberTests: XCTestCase {
    /// One phone of the group: its member, key and device ID.
    struct Phone {
        let member: CoreMember
        let key: SoftwareSigner
        let device: String
        let dir: URL
    }

    /// A group of two phones: a root that listens at home, and a phone that
    /// joined by its window and dials it.
    struct Group {
        let root: Phone
        let rootKey: SoftwareSigner
        let phone: Phone
        let port: UInt16
    }

    private func temporary(_ name: String) -> URL {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("cbb-core-member-\(name)-\(UUID().uuidString)")
        addTeardownBlock { try? FileManager.default.removeItem(at: dir) }
        return dir
    }

    private func start(_ dir: URL, _ name: String, _ device: String, _ key: SoftwareSigner) throws -> CoreMember {
        let m = try CoreMember(.init(dir: dir, name: name, device: device, publicKeyDER: key.publicKeyDER)) { try key.signature(digest: $0) }
        addTeardownBlock { m.stop() }
        return m
    }

    /// The root phone alone: its group made, its member running.
    private func rootPhone() throws -> (Phone, SoftwareSigner) {
        let rootKey = SoftwareSigner(), key = SoftwareSigner()
        let dir = temporary("root")
        let made = try CorePairing.newGroup(dir: dir, name: "Root phone", store: Records.hardware, rootPublic: rootKey.publicKeyDER,
                                            publicKey: key.publicKeyDER) { try rootKey.signature(digest: $0) }
        return (Phone(member: try start(dir, "Root phone", made.device, key), key: key, device: made.device, dir: dir), rootKey)
    }

    private func group() throws -> Group {
        let (root, rootKey) = try rootPhone()
        let port = try root.member.listen(.home)
        let w = try CorePairing.Window(member: root.member, publicKey: rootKey.publicKeyDER, addrs: ["127.0.0.1"]) {
            try rootKey.signature(digest: $0)
        }
        defer { w.close() }
        let key = SoftwareSigner()
        let dir = temporary("phone")
        let j = try CorePairing.Joiner(dir: dir, qr: w.qr, name: "Phone B", os: "ios", publicKey: key.publicKeyDER) {
            try key.signature(digest: $0)
        }
        defer { j.close() }
        var v: UInt64 = 0
        var device = ""
        for _ in 0..<200 {
            let s = try j.next(after: v, timeout: .milliseconds(100))
            if s.state == "done" { device = s.device; break }
            if s.state == "failed" { throw s.failure ?? CorePairing.Failure("the join failed") }
            v = s.version
        }
        XCTAssertFalse(device.isEmpty, "the phone joined")
        let phone = Phone(member: try start(dir, "Phone B", device, key), key: key, device: device, dir: dir)
        try phone.member.found(root.device, addrs: ["127.0.0.1:\(port)"], device: root.device)
        return Group(root: root, rootKey: rootKey, phone: phone, port: port)
    }

    private func until(_ what: String, _ cond: () throws -> Bool) async throws {
        for _ in 0..<500 {
            if try cond() { return }
            try await Task.sleep(for: .milliseconds(20))
        }
        XCTFail("timed out waiting for \(what)")
    }

    func testSyncsTheButtonAndCommands() async throws {
        let t = try group()
        let (a, b) = (t.root, t.phone)
        let up = try await b.member.wait(timeout: .seconds(10))
        XCTAssertTrue(up)
        try await until("a sees b") { a.member.connected().contains(b.device) }
        let peer = try XCTUnwrap(try b.member.peers().first { $0.device == a.device })
        XCTAssertEqual(peer.name, "Root phone")
        XCTAssertEqual(peer.role, "phone")

        // B's text reaches A, waits there for the button, and once taken
        // neither waits nor goes back.
        try b.member.copy("from phone B")
        try await until("the copy at A") { try a.member.waiting() != nil }
        let copy = try XCTUnwrap(try a.member.waiting())
        XCTAssertEqual(copy.origin, b.device)
        XCTAssertEqual(copy.text, "from phone B")
        XCTAssertEqual(try a.member.current()?.id, copy.id)
        try a.member.took(copy.id)
        XCTAssertNil(try a.member.waiting())
        XCTAssertFalse(try a.member.sends(board: copy.key))
        XCTAssertTrue(try a.member.sends(board: "copied on A"))

        // The root renames B and turns its sync off; B carries the order out.
        let sign = { [k = t.rootKey] (d: Data) throws -> Data in try k.signature(digest: d) }
        _ = try a.member.act(["action": .string("rename"), "device": .string(b.device), "name": .string("Desk phone")],
                             public: t.rootKey.publicKeyDER, sign: sign)
        XCTAssertTrue(try a.member.group().devices.contains { $0.device == b.device && $0.name == "Desk phone" })
        let r = try a.member.act(["action": .string("sync_off"), "device": .string(b.device)], public: t.rootKey.publicKeyDER, sign: sign)
        XCTAssertEqual(r["status"]?.string, "done", "\(r)")
        XCTAssertThrowsError(try a.member.act(["action": .string("rename"), "device": .string(b.device), "name": .string("x")],
                                              public: b.key.publicKeyDER) { try b.key.signature(digest: $0) },
                             "a key that is no admin's signs nothing the group takes")
    }

    /// The app in the background closes every connection; resumed, the
    /// phone connects again.
    func testPausesAndResumes() async throws {
        let t = try group()
        let b = t.phone
        let up = try await b.member.wait(timeout: .seconds(10))
        XCTAssertTrue(up)
        try b.member.pause()
        try await until("the pause") { b.member.connected().isEmpty }
        try b.member.resume()
        let again = try await b.member.wait(timeout: .seconds(10))
        XCTAssertTrue(again)
    }

    /// A change of the phone's sync reaches the peer's hellos at once:
    /// sync off says "own", on says "shared".
    func testReconnectsAtOnceAfterAModeChange() async throws {
        let t = try group()
        let (a, b) = (t.root, t.phone)
        try await until("a sees b") { a.member.connected().contains(b.device) }
        for (i, on) in [false, true, false, true].enumerated() {
            let mode = on ? "shared" : "own"
            try b.member.setSync(on: on)
            let start = Date()
            try await until("the peer's hello with mode \(mode), change \(i + 1)") {
                try a.member.peers().contains { $0.device == b.device && $0.mode == mode }
            }
            XCTAssertLessThan(Date().timeIntervalSince(start), 3, "change \(i + 1) took \(Date().timeIntervalSince(start)) s")
        }
    }

    /// A picture and a folder of files go from one phone to the other: the
    /// other fetches the sealed blob within its limit and opens the parts.
    func testNodesFetch() async throws {
        let t = try group()
        let (a, b) = (t.root, t.phone)
        try await until("a sees b") { a.member.connected().contains(b.device) }
        // A picture of 5 MiB and a bit, more than a fetch asks for ahead.
        var rng = SystemRandomNumberGenerator()
        let png = Data((0..<(5 << 20 + 1234)).map { _ in UInt8.random(in: 0...255, using: &rng) })
        let sent = try a.member.copyMedia([.data(png, type: "image/png")], board: true)
        XCTAssertEqual(sent.kind, .media)
        try await until("the picture at B") { try b.member.waiting()?.id == sent.id }
        let out = temporary("fetch")
        try FileManager.default.createDirectory(at: out, withIntermediateDirectories: true)
        let parts = try await b.member.fetch(sent.id, max: 64 << 20, into: out.appendingPathComponent("picture"))
        XCTAssertEqual(parts.count, 1)
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: parts[0].file)), png)

        // Files and a folder go the same way, with their paths.
        let src = out.appendingPathComponent("src")
        try FileManager.default.createDirectory(at: src, withIntermediateDirectories: true)
        try Data("one".utf8).write(to: src.appendingPathComponent("one.txt"))
        let files = try a.member.copyMedia([.folder(path: "docs"), .file(src.appendingPathComponent("one.txt"), path: "docs/one.txt")])
        try await until("the files at B") { try b.member.current()?.id == files.id }
        // Over the limit, nothing is fetched.
        do {
            _ = try await b.member.fetch(files.id, max: 1, into: out.appendingPathComponent("small"))
            XCTFail("fetched a copy over the limit")
        } catch is Core.Refusal {}
        let opened = try await b.member.fetch(files.id, max: 1 << 20, into: out.appendingPathComponent("files"))
        XCTAssertEqual(opened.map(\.path), ["docs", "docs/one.txt"])
        let file = try XCTUnwrap(opened.first { !$0.dir })
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: file.file)), Data("one".utf8))
    }

    /// why says what the phone sees: sync off first; a connected group with
    /// sync on has no reason that stops; the view carries the same reasons.
    func testSaysWhyItDoesNotSync() async throws {
        let t = try group()
        let b = t.phone
        try await until("b connected") { !(try b.member.peers().isEmpty) }
        XCTAssertFalse(try b.member.why().contains { $0.level == "stop" })
        try b.member.setSync(on: false)
        XCTAssertEqual(try b.member.why().first?.code, "sync_off")
        XCTAssertEqual(try b.member.view().warnings.first?.code, "sync_off", "the view carries the same reasons")
        try b.member.setSync(on: true)
        var away = WhyAway()
        (away.hub, away.forwarder, away.error) = (true, true, "no answer")
        let r = try b.member.why(away: away)
        XCTAssertEqual(r.first { $0.code == "forwarder_down" }?.detail, "no answer", "\(r)")
        XCTAssertTrue(try b.member.view(away: away).warnings.contains { $0.code == "forwarder_down" })
    }

    /// Calls from other threads while the member stops answer or fail, and
    /// never reach freed memory: an event's handler that called the member
    /// as the app restarted it crashed the Android app.
    func testStopsWhileCalled() throws {
        let m = try rootPhone().0.member
        let done = DispatchGroup()
        let calls = NSLock()
        var n = 0
        for _ in 0..<4 {
            DispatchQueue.global().async(group: done) {
                for _ in 0..<2_000 {
                    _ = try? m.current()
                    _ = try? m.peers()
                    calls.withLock { n += 1 }
                }
            }
        }
        Thread.sleep(forTimeInterval: 0.02)
        m.stop()
        done.wait()
        XCTAssertEqual(calls.withLock { n }, 8_000)
        XCTAssertThrowsError(try m.current()) { XCTAssertTrue($0 is CoreMember.Stopped) }
    }

    /// The root's own records, which the core builds, checks and signs with
    /// the root key outside it (cbb_core::root).
    func testTheRootSignsItsOwnRecordsInTheCore() throws {
        let (phone, rootKey) = try rootPhone()
        let m = phone.member
        let pub = rootKey.publicKeyDER
        let root = { (d: Data) throws -> Data in try rootKey.signature(digest: d) }
        func refused(_ f: () throws -> Void, _ line: UInt = #line) {
            XCTAssertThrowsError(try f(), line: line) { XCTAssertTrue($0 is Core.Refusal, "\($0)", line: line) }
        }
        refused { _ = try m.setKeyLevel(Records.levelFiles, public: phone.key.publicKeyDER) { try phone.key.signature(digest: $0) } }
        refused { _ = try m.setKeyLevel("any", public: pub, sign: root) }
        XCTAssertEqual(try m.setKeyLevel(Records.levelFiles, public: pub, sign: root), [])
        XCTAssertEqual(try m.group().keyLevel, Records.levelFiles)
        try m.setIncoming(ms: 120_000, public: pub, sign: root)
        XCTAssertEqual(try m.group().incomingMS, 120_000)
    }

    func testRefusesWhatItDoesNotKnowAndStops() throws {
        let m = try rootPhone().0.member
        XCTAssertThrowsError(try m.run("no such op", Optional<Int>.none, as: Int.self)) { e in
            XCTAssertTrue(e is Core.Refusal, "\(e)")
        }
        XCTAssertNil(try m.current())
        XCTAssertEqual(try m.peers(), [])
        m.stop()
        XCTAssertThrowsError(try m.current()) { XCTAssertTrue($0 is CoreMember.Stopped) }
    }

    /// The member keeps the tiles' order: a change shows in its view, and
    /// one that does not fit throws and changes nothing.
    func testKeepsTheTilesOrder() throws {
        let t = try group()
        let m = t.root.member
        let v = try m.view()
        XCTAssertFalse(v.custom)
        let me = try XCTUnwrap(v.devices.first?.id)
        let other = try XCTUnwrap(v.devices.dropFirst().first?.id)
        let after = try m.view(.new(name: "Desk", devices: [other]))
        XCTAssertTrue(after.custom)
        guard case let .collection(id, name, ds) = try XCTUnwrap(after.tiles.last) else { return XCTFail("no collection") }
        XCTAssertEqual(name, "Desk")
        XCTAssertEqual(ds.map(\.id), [other])
        XCTAssertThrowsError(try m.view(.rename(collection: id, name: String(repeating: "x", count: 65))))
        XCTAssertEqual(try m.view(.move(.collection(id), before: .device(me))).tiles.count, after.tiles.count)
        guard case .collection = try XCTUnwrap(m.view().tiles.first) else { return XCTFail("the collection did not move first") }
    }

    /// A folder without a group of 0.6, or a device ID the key does not
    /// make, starts no member.
    func testRefusesABadStart() throws {
        let k = SoftwareSigner()
        let dir = temporary("bad")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        XCTAssertThrowsError(try CoreMember(.init(dir: dir, name: "x", device: "nope", publicKeyDER: k.publicKeyDER)) {
            try k.signature(digest: $0)
        }) { XCTAssertTrue($0 is Core.Refusal, "\($0)") }
        let (phone, _) = try rootPhone()
        phone.member.stop()
        let wrong = String(repeating: "0", count: 32)
        XCTAssertThrowsError(try CoreMember(.init(dir: phone.dir, name: "x", device: wrong, publicKeyDER: phone.key.publicKeyDER)) {
            try phone.key.signature(digest: $0)
        }) { XCTAssertTrue($0 is Core.Refusal, "\($0)") }
    }

    /// The core's events read as the kit's.
    func testReadsTheEvents() throws {
        func e(_ json: String) -> CoreMember.Event? { CoreMember.event(Data(json.utf8)) }
        guard case let .write(text, kind, ttl)? = e(#"{"type":"write","text":"hi","kind":"secret","ttl_ms":5000}"#) else { return XCTFail() }
        XCTAssertEqual(text, "hi")
        XCTAssertEqual(kind, .secret)
        XCTAssertEqual(ttl, 5000)
        guard case let .copy(c)? = e(#"{"type":"copy","copy":{"id":"i","origin":"o","age_ms":3,"kind":"text","via":"copy","text":"t","media":null,"unread":false,"key":"t"}}"#) else {
            return XCTFail()
        }
        XCTAssertEqual(c.id, "i")
        XCTAssertEqual(c.ageMS, 3)
        guard case let .sync(off, by)? = e(#"{"type":"sync","off":true,"by":"Root phone"}"#) else { return XCTFail() }
        XCTAssertTrue(off)
        XCTAssertEqual(by, "Root phone")
        guard case let .panic(details)? = e(#"{"type":"panic","details":"panic: boom at member/src/x.rs:1:2"}"#) else { return XCTFail() }
        XCTAssertEqual(details, "panic: boom at member/src/x.rs:1:2")
        XCTAssertNil(e(#"{"type":"from the future"}"#))
        guard case .log? = e("not json") else { return XCTFail() }
    }

    /// The member's small calls: muting the phone and lifting it, a lost
    /// member; a peer's mute as the app shows it.
    func testSmallCalls() throws {
        let m = try rootPhone().0.member
        try m.setMute(untilMS: Records.ms(Date()) + 60_000)
        try m.setMute(untilMS: 0)
        try m.setMute(untilMS: nil)
        try m.lost("phone 0")

        let device = String(repeating: "0b", count: 16)
        let at = Date(timeIntervalSince1970: 1)
        XCTAssertEqual(CoreMember.Peer(device: device, muted: true, mutedForMS: 1000).mutedUntilMS(now: at), 2000)
        XCTAssertEqual(CoreMember.Peer(device: device, muted: true).mutedUntilMS(now: at), 0, "until an admin lifts it")
        XCTAssertNil(CoreMember.Peer(device: device).mutedUntilMS(now: at))
        XCTAssertFalse(CoreMember.Peer(device: device).servesMedia)
        let c = CoreMember.Copy(id: "i", origin: device, text: "t")
        XCTAssertEqual([c.text, c.key], ["t", ""])
        XCTAssertFalse(c.unread)
    }

    /// An invitation needs the root's or an admin's key and a hub to open
    /// its guest tunnel on: a group of phones has none.
    func testInvitingRefuses() throws {
        let (phone, rootKey) = try rootPhone()
        let m = phone.member
        XCTAssertThrowsError(try CorePairing.Inviting(member: m, publicKey: SoftwareSigner().publicKeyDER, expires: 600) {
            try rootKey.signature(digest: $0)
        })
        XCTAssertThrowsError(try CorePairing.Inviting(member: m, publicKey: rootKey.publicKeyDER, expires: 600) { try rootKey.signature(digest: $0) })
        XCTAssertThrowsError(try CorePairing.Inviting(member: m, publicKey: rootKey.publicKeyDER, expires: 600, hub: "not a device") {
            try rootKey.signature(digest: $0)
        })
    }

    /// The root phone's calls for away from home and the group's servers, alone in its group: its first period of
    /// server credentials is due, and the relay its root key sets renews them; it names no forwarder for itself, and it
    /// may be a hub without an admin key, as the root's own device; push and the notices answer, and the member port closes.
    func testTheRootPhonesAwayCalls() throws {
        let (phone, rootKey) = try rootPhone()
        let m = phone.member
        let pub = rootKey.publicKeyDER
        let root = { (d: Data) throws -> Data in try rootKey.signature(digest: d) }
        func refused(_ what: String, _ f: () throws -> Void, _ line: UInt = #line) {
            XCTAssertThrowsError(try f(), what, line: line)
        }
        XCTAssertTrue(try m.periods().due, "the root phone's first period is due")
        let pin = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
        refused("not a relay's key") { _ = try m.setRelays(["127.0.0.1:1 nope"], public: pub, sign: root) }
        refused("default goes alone") { _ = try m.setRelays(["default", "127.0.0.1:1 \(pin)"], public: pub, sign: root) }
        refused("a member key is no root key") { _ = try m.setRelays(["127.0.0.1:1 \(pin)"], public: phone.key.publicKeyDER) { try phone.key.signature(digest: $0) } }
        XCTAssertEqual(try m.setRelays(["127.0.0.1:9 \(pin)"], public: pub, sign: root), ["127.0.0.1:9"])
        XCTAssertEqual(try m.periods(), CoreMember.Periods(), "the relay's root key renewed the credentials")
        XCTAssertEqual(try m.renewPeriod(public: pub, sign: root), CoreMember.Periods())
        refused("the root names no forwarder for its own phone") { _ = try m.nameForwarder("Root phone", forwarder: "127.0.0.1:1", key: pin, public: pub, sign: root) }
        XCTAssertNil(try m.rootForwarder())
        XCTAssertEqual(try m.serveAsHub(port: 0, addrs: ["127.0.0.1:9"])?.hub, true, "the root's phone may be a hub")
        XCTAssertNotEqual(try m.stopHub()?.hub, true, "the root's phone stops being a hub")
        refused("a phone that is no hub cannot stop being one") { _ = try m.stopHub() }
        let on = try m.setAway(true)
        XCTAssertEqual(try m.awayStatus()?.isOn, on?.isOn)
        let off = try m.setAway(false)
        XCTAssertTrue(off == nil || off?.isOn == false, "sync away from home is off: \(String(describing: off))")

        if let face = try m.pushFace() { XCTAssertEqual(face.count, 16) }
        XCTAssertThrowsError(try m.setPush(Data([1, 2, 3])), "bytes that are no push registration")
        try m.setPush(nil)
        XCTAssertEqual(try m.pushRenewals(), [])
        try m.setEvidence([])
        _ = try m.notices()
        try m.rootChangeSeen()
        _ = try m.listen(.home)
        try m.unlisten(.home)
        try m.unlisten()
    }
}
#endif
