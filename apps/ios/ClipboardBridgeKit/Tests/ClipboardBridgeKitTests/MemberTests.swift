// SPDX-License-Identifier: AGPL-3.0-only

@testable import ClipboardBridgeKit
import Foundation
import XCTest

/// Checks the member protocol against the vectors that the Go tests write
/// (go test ./internal/node -update), and the engine and node by themselves.
final class MemberTests: XCTestCase {
    func vectors(_ name: String) throws -> Data {
        try Data(contentsOf: repoRoot().appendingPathComponent("testdata/interop/\(name)"))
    }

    func repoRoot() -> URL {
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<6 { url.deleteLastPathComponent() }
        return url
    }

    struct Vectors: Decodable {
        struct TS: Decodable { var text: String; var ok: Bool }
        struct Ev: Decodable { var json: AnyJSON; var valid: Bool }
        struct Order: Decodable { var a: AnyJSON; var b: AnyJSON; var later: Bool }
        var frames: [AnyJSON]
        var timestamps: [TS]
        var events: [Ev]
        var order: [Order]
        var bodies: [TS]
    }

    /// Keeps a JSON value as Foundation objects, to compare encodings.
    struct AnyJSON: Decodable {
        let value: Any
        init(from decoder: Decoder) throws {
            let c = try decoder.singleValueContainer()
            if let o = try? c.decode([String: AnyJSON].self) {
                value = o.mapValues(\.value)
            } else if let a = try? c.decode([AnyJSON].self) {
                value = a.map(\.value)
            } else if let b = try? c.decode(Bool.self) {
                value = b
            } else if let n = try? c.decode(Int64.self) {
                value = n
            } else if let s = try? c.decode(String.self) {
                value = s
            } else {
                value = NSNull()
            }
        }
        var data: Data { try! JSONSerialization.data(withJSONObject: value, options: [.fragmentsAllowed]) }
    }

    func testGoFrames() throws {
        let v = try JSONDecoder().decode(Vectors.self, from: vectors("member.json"))
        var decoded: [Member.Message] = []
        for goFrame in v.frames {
            let m = try Member.decode(body: goFrame.data)
            decoded.append(m)
            // Encoding it again gives the same JSON object as Go's.
            let encoded = try Member.encode(m)
            XCTAssertEqual(try Member.length(header: encoded.prefix(4)), encoded.count - 4)
            let mine = try JSONSerialization.jsonObject(with: encoded.dropFirst(4)) as! NSDictionary
            XCTAssertEqual(mine, goFrame.value as! NSDictionary)
        }
        guard case let .hello(role, h) = decoded[0] else { return XCTFail("frame 0 is \(decoded[0])") }
        XCTAssertEqual(role, .full)
        XCTAssertEqual(h.name, "pi")
        XCTAssertEqual(h.records, "q83vEjRWeJA=")
        XCTAssertEqual(h.current?.text, "hello <world> & \"you\" / ✓")
        XCTAssertEqual(h.current?.time, Member.Timestamp(wall: 1_761_024_000_000, logical: 3))
        XCTAssertEqual(h.current?.ageMS, 1500)
        guard case let .hello(_, markHello) = decoded[1] else { return XCTFail() }
        XCTAssertEqual(markHello.current?.isMark, true)
        XCTAssertEqual(markHello.current?.via, .phone)
        guard case let .event(univ?) = decoded[5] else { return XCTFail() }
        XCTAssertEqual(univ.via, .universalClipboard)
        XCTAssertEqual(decoded[6], .ping)
        XCTAssertEqual(decoded[7], .bye)
        XCTAssertEqual(decoded[8], .cert(Data("member certificate DER".utf8)))
        guard case let .records(rs) = decoded[9] else { return XCTFail() }
        XCTAssertEqual(rs.count, 2)
        XCTAssertEqual(rs[1].chain, [Data("admin CA".utf8)])
        func key(_ b: UInt8) -> Data { Data((0..<32).map { b + UInt8($0) }) }
        guard case let .hello(_, tunnelHello) = decoded[10] else { return XCTFail() }
        XCTAssertEqual(tunnelHello.tunnelKey, key(1))
        guard case let .tunnel(offer?) = decoded[11] else { return XCTFail("frame 11 is \(decoded[11])") }
        XCTAssertTrue(offer.isValid)
        XCTAssertEqual(offer, Member.TunnelOffer(hubKey: key(2), psk: key(3), endpoints: ["203.0.113.7:8764", "[2001:db8::7]:8764"]))
        XCTAssertEqual(decoded[12], .tunnel(Member.TunnelOffer(hubKey: key(4), psk: key(5))))
        // An obfuscated hub's settings, for the tunnel.
        guard case let .tunnel(hidden?) = decoded[13], let obf = hidden.obfuscation else {
            return XCTFail("frame 13 is \(decoded[13])")
        }
        XCTAssertNil(offer.obfuscation)
        XCTAssertEqual(obf.jc, 4)
        XCTAssertEqual(obf.h2, "16-65551")
        XCTAssertEqual(obf.headerProtectionKey, Data(repeating: 8, count: 32))
        let text = try obf.jsonText()
        XCTAssertEqual(try JSONDecoder().decode(Member.Obfuscation.self, from: Data(text.utf8)), obf)
        // The way to the hub's forwarder over VLESS.
        guard case let .tunnel(tunneled?) = decoded[14], let vless = tunneled.vless else {
            return XCTFail("frame 14 is \(decoded[14])")
        }
        XCTAssertNil(offer.vless)
        XCTAssertNil(hidden.vless)
        XCTAssertEqual(vless, Member.VLESS(endpoint: "203.0.113.9:443", publicKey: Data(repeating: 9, count: 32),
                                           shortID: "0123456789abcdef", serverName: "www.example.com",
                                           id: "5f0c1e2d-3b4a-4c5d-8e6f-7a8b9c0d1e2f"))
        let vlessText = try vless.jsonText()
        XCTAssertEqual(try JSONDecoder().decode(Member.VLESS.self, from: Data(vlessText.utf8)), vless)
        // A computer's hello says what it is.
        guard case let .hello(_, laptop) = decoded[15] else { return XCTFail("frame 15 is \(decoded[15])") }
        XCTAssertEqual(laptop.device, Member.DeviceInfo(form: "laptop", osVersion: "15.1", version: "0.5.0", mac: "a4:83:e7:01:02:0f"))
        XCTAssertEqual(laptop.device?.cleaned, laptop.device)
    }

    func testRecordsGoInMessagesOfAboutOneMiB() throws {
        // 1024 records of the largest body: more than one frame holds.
        let rs = (0..<1024).map { i in
            Member.Record(body: Data(repeating: UInt8(i % 256), count: 8 << 10), sig: Data(repeating: 1, count: 72))
        }
        XCTAssertThrowsError(try Member.encode(.records(rs)))
        let chunks = Member.Record.chunks(rs)
        XCTAssertGreaterThan(chunks.count, 8)
        XCTAssertEqual(Array(chunks.joined()), rs)
        for c in chunks {
            XCTAssertLessThanOrEqual(try Member.encode(.records(c)).count, Member.Record.chunk * 5 / 4)
        }
        XCTAssertEqual(Member.Record.chunks([]).count, 0)
    }

    func testDeviceInfoCleaned() {
        let bad = Member.DeviceInfo(form: "toaster", osVersion: String(repeating: "9", count: 33), version: "1\n2", mac: "A4:83:E7:01:02:0F")
        XCTAssertNil(bad.cleaned)
        XCTAssertEqual(Member.DeviceInfo(form: "phone", mac: "nope").cleaned, Member.DeviceInfo(form: "phone"))
    }

    func testTimestamps() throws {
        let v = try JSONDecoder().decode(Vectors.self, from: vectors("member.json"))
        for t in v.timestamps {
            XCTAssertEqual(Member.Timestamp(text: t.text) != nil, t.ok, "\"\(t.text)\"")
        }
        XCTAssertLessThan(Member.Timestamp(wall: 1, logical: 9), Member.Timestamp(wall: 2, logical: 0))
        XCTAssertEqual(Member.Timestamp(text: "17.4")?.description, "17.4")
    }

    func testEvents() throws {
        let v = try JSONDecoder().decode(Vectors.self, from: vectors("member.json"))
        for e in v.events {
            let ev = try? JSONDecoder().decode(Member.Event.self, from: e.json.data)
            XCTAssertEqual(ev?.isValid ?? false, e.valid, String(decoding: e.json.data, as: UTF8.self))
        }
        for o in v.order {
            let a = try JSONDecoder().decode(Member.Event.self, from: o.a.data)
            let b = try JSONDecoder().decode(Member.Event.self, from: o.b.data)
            XCTAssertEqual(a.isLater(than: b), o.later)
        }
    }

    func testBodies() throws {
        let v = try JSONDecoder().decode(Vectors.self, from: vectors("member.json"))
        XCTAssertGreaterThanOrEqual(v.bodies.count, 14)
        for b in v.bodies {
            XCTAssertEqual((try? Member.decode(body: Data(b.text.utf8))) != nil, b.ok, b.text)
        }
    }

    func testBadMessages() {
        XCTAssertThrowsError(try Member.decode(body: Data("{".utf8)))
        XCTAssertThrowsError(try Member.decode(body: Data(#"{"t":"hello","role":"toaster","hello":{}}"#.utf8)))
        XCTAssertThrowsError(try Member.decode(body: Data(#"{"t":"hello","role":"full"}"#.utf8)))
        // An event from a newer version is dropped, not an error.
        XCTAssertEqual(try Member.decode(body: Data(#"{"t":"event","event":{"kind":"image"}}"#.utf8)), .event(nil))
        XCTAssertEqual(try Member.decode(body: Data(#"{"t":"gift"}"#.utf8)), .unknown("gift"))
        // A hello whose current event does not decode has none.
        guard case let .hello(_, h) = try! Member.decode(body: Data(#"{"t":"hello","role":"full","hello":{"wall_ms":1,"current":{"kind":"image"}}}"#.utf8)) else {
            return XCTFail()
        }
        XCTAssertNil(h.current)
        XCTAssertThrowsError(try Member.length(header: Data([0x00, 0x70, 0x00, 0x01])))
    }

    struct CertVectors: Decodable {
        struct Case: Decodable { var name: String; var cert: Data; var now_ms: Int64; var device: String }
        var group_ca: Data
        var cases: [Case]
    }

    func testVerifyMember() throws {
        let v = try JSONDecoder().decode(CertVectors.self, from: vectors("member-certs.json"))
        for c in v.cases {
            let now = Date(timeIntervalSince1970: Double(c.now_ms) / 1000)
            let got = try? GroupCertificates.verifyMember(c.cert, groupCA: v.group_ca, now: now)
            XCTAssertEqual(got ?? "", c.device, c.name)
        }
        // A certificate ClipboardBridgeKit issues verifies too.
        let now = Date()
        let ca = SoftwareSigner()
        let caCert = try GroupCertificates.groupCA(signer: ca, now: now)
        let dev = SyncEngine.newID()
        let cert = try GroupCertificates.member(device: dev, publicKey: SoftwareSigner().publicKeyDER, ca: caCert, caSigner: ca, now: now)
        XCTAssertEqual(try GroupCertificates.verifyMember(cert, groupCA: caCert, now: now), dev)
        XCTAssertThrowsError(try GroupCertificates.verifyMember(cert, groupCA: v.group_ca, now: now))
    }

    // MARK: - The clock and the engine

    func testClock() {
        var wall: UInt64 = 1000
        let c = HybridClock(wallMS: { wall })
        XCTAssertEqual(c.now(), .init(wall: 1000, logical: 0))
        XCTAssertEqual(c.now(), .init(wall: 1000, logical: 1))
        wall = 999 // the wall clock went back
        XCTAssertEqual(c.now(), .init(wall: 1000, logical: 2))
        c.observe(.init(wall: 5000, logical: 7)) // a peer ahead
        XCTAssertEqual(c.latest, .init(wall: 5000, logical: 8))
        c.observe(.init(wall: 5000, logical: 3))
        XCTAssertEqual(c.latest, .init(wall: 5000, logical: 9))
        wall = 9000
        c.observe(.init(wall: 10, logical: 0))
        XCTAssertEqual(c.latest, .init(wall: 9000, logical: 0))
        let floored = HybridClock(floor: .init(wall: 20000, logical: 4), wallMS: { 100 })
        XCTAssertEqual(floored.now(), .init(wall: 20000, logical: 5))
    }

    func event(_ id: String, _ wall: UInt64, kind: Member.Kind = .text, text: String = "x", age: Int64 = 0) -> Member.Event {
        Member.Event(id: id, origin: "0123456789abcdef0123456789abcdef", time: .init(wall: wall, logical: 0), ageMS: age, kind: kind, text: text)
    }

    func testAheadRefused() throws {
        let now: UInt64 = 1_792_886_400_000 // 2026-10-25
        let e = SyncEngine(device: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", clock: HybridClock(wallMS: { now }), uptime: { 100 })
        let far = event("d0000000000000000000000000000000", Member.Timestamp.maxWall)
        XCTAssertEqual(e.received(far), .init(forward: nil, changed: false))
        XCTAssertEqual(try e.reconcile(Member.Hello(wallMS: Int64(now), current: far)), .init(forward: nil, changed: false))
        let near = event("e0000000000000000000000000000000", now + 6 * 24 * 3600 * 1000)
        XCTAssertEqual(e.received(near), .init(forward: near, changed: true))
    }

    func testEngine() throws {
        var up: TimeInterval = 100
        let e = SyncEngine(device: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", clock: HybridClock(wallMS: { 1000 }), uptime: { up })
        let a = event("a0000000000000000000000000000000", 2000, text: "first")
        XCTAssertEqual(e.received(a), .init(forward: a, changed: true))
        XCTAssertEqual(e.received(a), .init(forward: nil, changed: false)) // seen
        // An older event is forwarded but does not become current.
        let old = event("b0000000000000000000000000000000", 1500, text: "older")
        XCTAssertEqual(e.received(old), .init(forward: old, changed: false))
        XCTAssertEqual(e.usable?.text, "first")
        // A local event is later than everything seen.
        let mine = e.local(text: "from the phone", kind: .text)
        XCTAssertTrue(mine.isLater(than: a))
        XCTAssertEqual(mine.via, .phone)
        XCTAssertEqual(e.usable?.text, "from the phone")
        // An invalid event changes nothing.
        XCTAssertEqual(e.received(event("short", 9999)), .init(forward: nil, changed: false))

        // A secret arrives first as a mark, then with its text.
        let secret = event("c0000000000000000000000000000000", 9000, kind: .secret, text: "hunter2", age: 1000)
        XCTAssertTrue(try e.reconcile(.init(wallMS: 0, current: secret.mark)).changed)
        XCTAssertNil(e.usable) // a mark has no text
        XCTAssertEqual(e.hello(name: nil).current?.text, "")
        XCTAssertEqual(e.received(secret), .init(forward: secret, changed: true))
        XCTAssertEqual(e.usable?.text, "hunter2")
        XCTAssertEqual(e.hello(name: "iPhone").current?.text, "", "a hello never carries a secret's text")
        up += 58 // 59 s after the copy, which was a second before it arrived
        XCTAssertNotNil(e.usable)
        up += 1
        XCTAssertNil(e.usable)
        XCTAssertEqual(e.currentEvent?.ageMS, 60_000)

        XCTAssertThrowsError(try e.reconcile(.init(wallMS: 0, current: event("d0000000000000000000000000000000", 1, kind: .secret, text: "leak"))))
        XCTAssertThrowsError(try e.reconcile(.init(wallMS: 0, current: event("bad", 1))))
    }

    // MARK: - Two nodes over a pipe

    func testNodesSync() async throws {
        let (pa, pb) = Pipe.pair()
        let changes = Changes()
        let a = MemberNode(engine: SyncEngine(device: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", clock: HybridClock()), name: "iPhone")
        let b = MemberNode(engine: SyncEngine(device: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", clock: HybridClock()), name: "pi", role: .full,
                           onChange: { changes.add($0.text) })
        await a.send(text: "before", kind: .text)
        let ta = Task { try await a.serve(pa) }
        let tb = Task { try await b.serve(pb) }
        // b gets a's current event from its hello, then a later event.
        try await waitUntil { changes.all.contains("before") }
        await a.send(text: "after", kind: .text)
        try await waitUntil { changes.all.contains("after") }
        let bPeers = await b.peers
        XCTAssertEqual(bPeers, 1)
        await a.closeAll()
        try await ta.value
        try await tb.value // a goodbye ends it without an error
        let last = await b.usable?.text
        XCTAssertEqual(last, "after")
    }

    /// A store whose state stops secrets to every peer.
    final class NoSecretsStore: RecordStore, @unchecked Sendable {
        var digest: String? { nil }
        var all: [Member.Record] { [] }
        func add(_ rs: [Member.Record]) -> [Member.Record] { [] }
        func noSecrets(to device: String?) -> Bool { true }
    }

    func testNoSecretsSendsTheMark() async throws {
        // While the records stop secrets to a peer, it gets the mark of a
        // secret, never its text (docs/protocol.md, section 10, "Stopping
        // the exchange").
        let (pa, pb) = Pipe.pair()
        let changes = Changes()
        let a = MemberNode(engine: SyncEngine(device: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", clock: HybridClock()), name: "iPhone",
                           records: NoSecretsStore())
        let b = MemberNode(engine: SyncEngine(device: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", clock: HybridClock()), name: "pi", role: .full,
                           onChange: { changes.add($0.text) })
        let ta = Task { try await a.serve(pa) }
        let tb = Task { try await b.serve(pb) }
        await a.send(text: "plain", kind: .text)
        try await waitUntil { changes.all.contains("plain") }
        await a.send(text: "hunter2", kind: .secret)
        try await waitUntil { changes.all.contains("") }
        XCTAssertFalse(changes.all.contains("hunter2"))
        await a.closeAll()
        try await ta.value
        try await tb.value
    }

    func testFramesForGo() throws {
        // The frames Go decodes in TestSwiftMemberFrames.
        // Fixed values, so the file changes only with the encoding.
        let origin = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        let ev = Member.Event(id: "0123456789abcdef0123456789abcdef", origin: origin, via: .phone,
                              time: .init(wall: 1_761_024_000_000, logical: 0), ageMS: 12, kind: .text, text: "from Swift / <ok>")
        let secret = Member.Event(id: "fedcba9876543210fedcba9876543210", origin: origin, via: .phone,
                                  time: .init(wall: 1_761_024_000_000, logical: 1), ageMS: 0, kind: .secret, text: "hunter2")
        let hello = Member.Hello(wallMS: 1_761_024_000_500, current: secret.mark, name: "iPhone")
        let frames = try [
            Member.encode(.hello(.phone, hello)),
            Member.encode(.event(ev)),
            Member.encode(.event(secret)),
            Member.encode(.ping),
            Member.encode(.bye),
        ]
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted]
        let data = try enc.encode(frames)
        try (data + Data("\n".utf8)).write(to: repoRoot().appendingPathComponent("testdata/interop/swift-member.json"))
    }

    func waitUntil(_ cond: @escaping () -> Bool) async throws {
        for _ in 0..<200 {
            if cond() { return }
            try await Task.sleep(nanoseconds: 10_000_000)
        }
        XCTFail("timed out")
    }
}

final class Changes: @unchecked Sendable {
    private let lock = NSLock()
    private var texts: [String] = []
    func add(_ t: String) { lock.withLock { texts.append(t) } }
    var all: [String] { lock.withLock { texts } }
}

/// One end of an in-memory connection.
final class Pipe: ClosableTransport, @unchecked Sendable {
    private let lock = NSLock()
    private var buf = Data()
    private var closed = false
    private var waiter: CheckedContinuation<Void, Never>?
    weak var peer: Pipe?
    /// What a TLS transport would report as the peer's certificate.
    var peerCertificate: Data?
    /// What a TLS transport would report as the peer's chain.
    var chain: [Data] = []
    var peerChain: [Data] { chain }

    /// Whether either end closed it.
    var isClosed: Bool { lock.withLock { closed } }

    static func pair() -> (Pipe, Pipe) {
        let a = Pipe(), b = Pipe()
        (a.peer, b.peer) = (b, a)
        return (a, b)
    }

    private func deliver(_ d: Data) {
        let w: CheckedContinuation<Void, Never>? = lock.withLock {
            buf.append(d)
            defer { waiter = nil }
            return waiter
        }
        w?.resume()
    }

    func write(_ data: Data) async throws {
        guard let p = peer, !lock.withLock({ closed }) else { throw POSIXError(.EPIPE) }
        p.deliver(data)
    }

    func read(exactly n: Int) async throws -> Data {
        while true {
            let (out, isClosed): (Data?, Bool) = lock.withLock {
                if buf.count >= n {
                    let d = buf.prefix(n)
                    buf.removeFirst(n)
                    return (Data(d), false)
                }
                return (nil, closed)
            }
            if let out { return out }
            if isClosed { throw POSIXError(.ECONNRESET) }
            await withCheckedContinuation { (c: CheckedContinuation<Void, Never>) in
                let ready = lock.withLock {
                    if buf.count >= n || closed { return true }
                    waiter = c
                    return false
                }
                if ready { c.resume() }
            }
        }
    }

    func close() {
        for p in [self, peer].compactMap({ $0 }) {
            let w: CheckedContinuation<Void, Never>? = p.lock.withLock {
                p.closed = true
                defer { p.waiter = nil }
                return p.waiter
            }
            w?.resume()
        }
    }
}
