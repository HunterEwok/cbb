// SPDX-License-Identifier: AGPL-3.0-only

@testable import CBBKit
import Foundation
import XCTest

/// Signed commands (docs/protocol.md, section 15) and the sync mode in the
/// hello.
final class CommandTests: XCTestCase {
    let now = Date()
    let pc = "00112233445566778899aabbccddeeff"

    func testModeCommand() throws {
        let root = SoftwareSigner()
        let ca = try GroupCertificates.groupCA(signer: root, now: now, pathLength: 1)
        let c = try Commands.mode(to: pc, mode: "own", group: GroupCertificates.tag(groupCA: ca),
                                  by: "0123456789abcdef0123456789abcdef", now: now, signer: root)
        let b = try JSONDecoder().decode(Commands.Body.self, from: c.body)
        XCTAssertEqual(b.type, "mode")
        XCTAssertEqual(b.to, pc)
        XCTAssertEqual(b.expires_ms - b.time_ms, Commands.lifetimeMS)
        XCTAssertEqual(Commands.id(of: c)?.count, 32)
        XCTAssertNil(c.chain)
        XCTAssertThrowsError(try Commands.mode(to: pc, mode: "everything", group: "tag", by: "by", now: now, signer: root))
    }

    /// A hub command carries the forwarder and the clients; a result
    /// carries the new hub's offer, which the old hub passes on.
    func testHubCommand() throws {
        let root = SoftwareSigner()
        let client = PhoneHub.Client(device: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", key: Data(repeating: 1, count: 32), psk: Data(repeating: 2, count: 32))
        let c = try Commands.hub(to: pc, forwarder: ("203.0.113.9:8764", "AAAA"), clients: [client], group: "tag", by: "by",
                                 now: now, signer: root)
        let b = try JSONDecoder().decode(Commands.Body.self, from: c.body)
        XCTAssertEqual(b.type, "hub")
        XCTAssertNil(b.mode)
        XCTAssertEqual(b.hub?.forwarder?.endpoint, "203.0.113.9:8764")
        XCTAssertEqual(b.hub?.clients, [client])
        XCTAssertThrowsError(try Commands.hub(to: pc, forwarder: nil, clients: [client], group: "tag", by: "by", now: now, signer: root))
        let m = try Member.decode(body: Data(
            #"{"t":"result","result":{"id":"ab","status":"done","tunnel":{"hub_key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=","endpoints":["203.0.113.9:8764"]}}}"#.utf8))
        guard case let .result(r) = m, let offer = r.tunnel else { return XCTFail("no result with an offer") }
        XCTAssertEqual(offer.endpoints, ["203.0.113.9:8764"])
        let hub = PhoneHub(publicKey: Data(repeating: 9, count: 32), clients: [client])
        let moved = try XCTUnwrap(hub.movedOffer(device: client.device, newHub: pc, offer: offer))
        XCTAssertEqual(moved.hub, pc)
        XCTAssertTrue(moved.moved)
        XCTAssertEqual(moved.psk, client.psk)
        XCTAssertNil(hub.movedOffer(device: pc, newHub: pc, offer: offer))
        XCTAssertEqual(try Member.decode(body: Data(Member.encode(.tunnel(moved)).dropFirst(4))), .tunnel(moved))
    }

    /// A command and its result through the frames, as Go sends and reads them.
    func testMessages() throws {
        let c = Member.Record(body: Data("{}".utf8), sig: Data([1, 2]), chain: [Data([3])])
        for m in [Member.Message.command(c), .result(Member.CommandResult(id: "ab", status: "refused", reason: "why"))] {
            XCTAssertEqual(try Member.decode(body: Data(Member.encode(m).dropFirst(4))), m)
        }
        let h = try Member.decode(body: Data(#"{"t":"hello","role":"full","hello":{"wall_ms":1,"mode":"receive"}}"#.utf8))
        guard case let .hello(_, hello) = h else { return XCTFail("not a hello") }
        XCTAssertEqual(hello.mode, "receive")
        let odd = try Member.decode(body: Data(#"{"t":"hello","role":"full","hello":{"wall_ms":1,"mode":"everything"}}"#.utf8))
        guard case let .hello(_, oddHello) = odd else { return XCTFail("not a hello") }
        XCTAssertNil(oddHello.mode)
    }

    /// A paste command carries its way, Enter, kind and text, within the
    /// limits; paste-off carries nothing.
    func testPasteCommand() throws {
        let root = SoftwareSigner()
        let c = try Commands.paste(to: pc, text: "ls <dir>", enter: true, kind: "secret", group: "tag", by: pc, now: now, signer: root)
        let b = try JSONDecoder().decode(Commands.Body.self, from: c.body)
        XCTAssertEqual(b.type, "paste")
        XCTAssertEqual(b.mode, "paste")
        XCTAssertEqual(b.text, "ls <dir>")
        XCTAssertEqual(b.kind, "secret")
        XCTAssertEqual(b.enter, true)
        XCTAssertTrue(String(decoding: c.body, as: UTF8.self).contains("ls <dir>"))
        XCTAssertThrowsError(try Commands.paste(to: pc, text: "", group: "tag", by: pc, now: now, signer: root))
        XCTAssertThrowsError(try Commands.paste(to: pc, text: String(repeating: "x", count: Commands.maxTypeText + 1), method: "type",
                                                group: "tag", by: pc, now: now, signer: root))
        XCTAssertThrowsError(try Commands.paste(to: pc, text: "x", method: "drop", group: "tag", by: pc, now: now, signer: root))
        let off = try JSONDecoder().decode(Commands.Body.self, from: Commands.pasteOff(to: pc, group: "tag", by: pc, now: now, signer: root).body)
        XCTAssertEqual(off.type, "paste-off")
        XCTAssertNil(off.text)
    }

    /// The public key of testdata/interop/go-sealed-commands.json, whose
    /// secret Go opens the commands with.
    static func sealPublic() throws -> Data {
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<6 { url.deleteLastPathComponent() }
        struct V: Decodable { var `public`: Data }
        return try JSONDecoder().decode(V.self, from: Data(contentsOf: url.appendingPathComponent("testdata/interop/go-sealed-commands.json"))).public
    }

    /// A command to a device whose record has a key for sealed messages
    /// carries its orders sealed, through the core: the header stays, the
    /// text is gone, and the core takes the body as a command.
    func testSealedCommand() throws {
        let key = try Self.sealPublic()
        let c = try Commands.paste(to: pc, text: "a secret <text>", kind: "secret", group: "tag", by: pc, now: now, signer: SoftwareSigner(),
                                   seal: key)
        let text = String(decoding: c.body, as: UTF8.self)
        XCTAssertFalse(text.contains("a secret"))
        XCTAssertTrue(text.contains("\"sealed\":") && text.contains("\"v\":2"), text)
        XCTAssertNil(Core.bodyRefusal("command", c.body))
        let b = try JSONDecoder().decode(Commands.Body.self, from: c.body)
        XCTAssertEqual(b.type, "paste")
        XCTAssertEqual(b.to, pc)
        XCTAssertNil(b.text)
        XCTAssertThrowsError(try Commands.paste(to: pc, text: "x", group: "tag", by: pc, now: now, signer: SoftwareSigner(), seal: Data([1, 2, 3])))
    }

    /// Reads testdata/interop/go-sealed-commands.json, from Go: commands
    /// sealed to this member open with its secret, whose public key the
    /// core gives, and are refused without it or when they do not open.
    func testOpenGoSealedCommands() throws {
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<6 { url.deleteLastPathComponent() }
        struct C: Decodable {
            var name: String
            var command: Member.Record
            var ok: Bool
            var opens: Bool
            var mode: String?
            var text: String?
        }
        struct V: Decodable {
            var group_ca: Data
            var `self`: String
            var now_ms: Int64
            var secret: Data
            var `public`: Data
            var commands: [C]
        }
        let v = try JSONDecoder().decode(V.self, from: Data(contentsOf: url.appendingPathComponent("testdata/interop/go-sealed-commands.json")))
        XCTAssertEqual(try Core.sealPublic(v.secret), v.public)
        XCTAssertThrowsError(try Core.sealPublic(Data([1, 2, 3])))
        var set = RecordSet()
        _ = set.addAll([], groupCA: v.group_ca)
        var opened = 0
        for c in v.commands {
            let got = Result { try Commands.verify(c.command, records: set, me: v.`self`, nowMS: v.now_ms, secret: v.secret) }
            switch got {
            case let .success(b):
                XCTAssertTrue(c.ok && c.opens, c.name)
                XCTAssertEqual(b.mode, c.mode, c.name)
                XCTAssertEqual(b.text, c.text, c.name)
                XCTAssertThrowsError(try Commands.verify(c.command, records: set, me: v.`self`, nowMS: v.now_ms), c.name)
                opened += 1
            case let .failure(e):
                XCTAssertFalse(c.ok && c.opens, "\(c.name): \(e)")
            }
        }
        XCTAssertEqual(opened, 2)
    }

    /// A command for a member this one is not connected to goes through
    /// one that is, and the result comes back, once.
    func testCommandPassedOn() async throws {
        let (ia, ib, ih) = (String(repeating: "a", count: 32), String(repeating: "b", count: 32), String(repeating: "c", count: 32))
        final class Got: @unchecked Sendable {
            let lock = NSLock()
            var names: [String] = []
            func add(_ n: String) { lock.withLock { names.append(n) } }
            var all: [String] { lock.withLock { names } }
        }
        let got = Got()
        let a = MemberNode(engine: SyncEngine(device: ia, clock: HybridClock()), name: "iPhone")
        let hub = MemberNode(engine: SyncEngine(device: ih, clock: HybridClock()), name: "Hub", onCommand: { _, r in
            got.add("hub")
            return Member.CommandResult(id: Commands.id(of: r) ?? "", status: "done")
        })
        let b = MemberNode(engine: SyncEngine(device: ib, clock: HybridClock()), name: "Phone two", onCommand: { _, r in
            got.add("b")
            return Member.CommandResult(id: Commands.id(of: r) ?? "", status: "done")
        })
        let (p1, p2) = Pipe.pair()
        let (p3, p4) = Pipe.pair()
        let ts = [
            Task { try await a.serve(p1, peer: ih) },
            Task { try await hub.serve(p2, peer: ia) },
            Task { try await b.serve(p3, peer: ih) },
            Task { try await hub.serve(p4, peer: ib) },
        ]
        for _ in 0..<300 {
            if await a.peers == 1, await b.peers == 1, await hub.peers == 2 { break }
            try await Task.sleep(nanoseconds: 10_000_000)
        }
        let c = try Commands.mode(to: ib, mode: "own", group: "tag", by: ia, now: Date(), signer: SoftwareSigner())
        do {
            _ = try await a.command(c, to: ib)
            XCTFail("sent to a device that is not connected, without via")
        } catch MemberNode.Failure.notConnected {}
        do {
            _ = try await a.command(c, to: ib, via: ["d"])
            XCTFail("sent through a member that is not one of the hubs")
        } catch MemberNode.Failure.notConnected {}
        let r = try await a.command(c, to: ib, via: ["d", ih])
        XCTAssertEqual(r.status, "done")
        XCTAssertEqual(r.by, ib)
        XCTAssertEqual(got.all, ["b"])
        do {
            _ = try await a.command(c, to: ib, timeout: 0.3, via: [ih])
            XCTFail("the hub passed the same command on twice")
        } catch MemberNode.Failure.timedOut {}
        XCTAssertEqual(got.all, ["b"])
        await a.closeAll()
        await b.closeAll()
        await hub.closeAll()
        for t in ts { try await t.value }
    }

    /// A command goes to the named peer, and its result comes back; a phone
    /// refuses commands.
    func testCommandRoundTrip() async throws {
        let (da, db) = ("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
        let (pa, pb) = Pipe.pair()
        let a = MemberNode(engine: SyncEngine(device: da, clock: HybridClock()), name: "iPhone")
        let b = MemberNode(engine: SyncEngine(device: db, clock: HybridClock()), name: "Phone two")
        let ta = Task { try await a.serve(pa, peer: db) }
        let tb = Task { try await b.serve(pb, peer: da) }
        for _ in 0..<300 {
            if await a.peers == 1 { break }
            try await Task.sleep(nanoseconds: 10_000_000)
        }
        let c = try Commands.mode(to: db, mode: "own", group: "tag", by: da, now: now, signer: SoftwareSigner())
        let r = try await a.command(c, to: db)
        XCTAssertEqual(r.id, Commands.id(of: c))
        XCTAssertEqual(r.status, "refused")
        do {
            _ = try await a.command(c, to: "cccccccccccccccccccccccccccccccc")
            XCTFail("sent to a device that is not connected")
        } catch MemberNode.Failure.notConnected {}
        await a.closeAll()
        try await ta.value
        try await tb.value
    }

    /// Writes commands this kit signed, with the root key and with an admin
    /// CA's, and the records that name both, for internal/group's
    /// TestSwiftCommand, when
    /// CBB_INTEROP_OUT names a directory.
    func testCommandsForGo() throws {
        guard let dir = ProcessInfo.processInfo.environment["CBB_INTEROP_OUT"] else { return }
        let root = SoftwareSigner(), admin = SoftwareSigner()
        let ca = try GroupCertificates.groupCA(signer: root, now: now, pathLength: 1)
        let tag = GroupCertificates.tag(groupCA: ca)
        let adminCA = try GroupCertificates.adminCA(device: "fedcba9876543210fedcba9876543210", publicKey: admin.publicKeyDER,
                                                    root: ca, rootSigner: root)
        // The records name the root's own device and the admin phone, which
        // may sign every command.
        let by = "0123456789abcdef0123456789abcdef", adminBy = "fedcba9876543210fedcba9876543210"
        var set = RecordSet()
        try set.signed(.device(by, name: "Root", role: "phone", key: Records.keyHash(spki: SoftwareSigner().publicKeyDER), holdsRoot: true,
                               signer: root, now: now), root, groupCA: ca)
        try set.signed(.device(adminBy, name: "Admin", role: "phone", key: Records.keyHash(spki: SoftwareSigner().publicKeyDER),
                               admin: Records.keyHash(cert: adminCA), signer: root, now: now), root, groupCA: ca)
        struct Out: Encodable {
            var group_ca: Data
            var records: [Member.Record]
            var to: String
            var commands: [Member.Record]
        }
        let out = Out(group_ca: ca, records: set.records, to: pc, commands: [
            try Commands.mode(to: pc, mode: "receive", group: tag, by: by, now: now, signer: root),
            try Commands.mode(to: pc, mode: "receive", group: tag, by: adminBy, now: now, signer: admin, adminCA: adminCA),
            try Commands.hub(to: pc, forwarder: ("203.0.113.9:8764", "AAAA"),
                             clients: [PhoneHub.Client(device: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", key: Data(repeating: 1, count: 32),
                                                       psk: Data(repeating: 2, count: 32))],
                             group: tag, by: by, now: now, signer: root),
            try Commands.paste(to: pc, text: "echo <ok> & \"done\"\n", method: "type", enter: true, group: tag, by: adminBy, now: now,
                               signer: admin, adminCA: adminCA),
            try Commands.pasteOff(to: pc, group: tag, by: by, now: now, signer: root),
            try Commands.action(to: pc, name: "lock", group: tag, by: adminBy, now: now, signer: admin, adminCA: adminCA),
            try Commands.actionsOff(to: pc, group: tag, by: by, now: now, signer: root),
            try Commands.paste(to: pc, text: "sealed <text>", group: tag, by: adminBy, now: now, signer: admin, adminCA: adminCA,
                               seal: try Self.sealPublic()),
        ])
        // The last one is sealed, for Go to open: a phone opens none.
        for c in out.commands.dropLast() { XCTAssertNoThrow(try Commands.verify(c, records: set, me: pc, nowMS: Records.ms(now))) }
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        try (enc.encode(out) + Data("\n".utf8)).write(to: URL(fileURLWithPath: dir).appendingPathComponent("swift-command.json"))
    }

    /// Reads testdata/interop/v2-commands.json, from Go's
    /// TestGoCommandVectors: which commands for this phone count.
    func testGoCommands() throws {
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<6 { url.deleteLastPathComponent() }
        struct C: Decodable {
            var name: String
            var command: Member.Record
            var ok: Bool
            var mode: String?
        }
        struct V: Decodable {
            var group_ca: Data
            var records: [Member.Record]
            var `self`: String
            var now_ms: Int64
            var commands: [C]
        }
        let v = try JSONDecoder().decode(V.self, from: Data(contentsOf: url.appendingPathComponent("testdata/interop/v2-commands.json")))
        var set = RecordSet()
        XCTAssertEqual(set.addAll(v.records, groupCA: v.group_ca).count, v.records.count)
        XCTAssertEqual(v.commands.count, 17)
        for c in v.commands {
            let got = Result { try Commands.verify(c.command, records: set, me: v.`self`, nowMS: v.now_ms) }
            switch got {
            case let .success(b):
                XCTAssertTrue(c.ok, c.name)
                XCTAssertEqual(b.mode, c.mode, c.name)
                if b.type == "paste" {
                    XCTAssertTrue(b.enter == true && b.kind == "text" && b.text?.hasSuffix("\"done\"\n") == true, c.name)
                }
            case let .failure(e):
                XCTAssertFalse(c.ok, "\(c.name): \(e)")
            }
        }
    }

    /// Reads testdata/interop/v2-actions.json, from Go's
    /// TestGoActionVectors: action commands for a member, as Go checks them.
    func testGoActions() throws {
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<6 { url.deleteLastPathComponent() }
        struct C: Decodable {
            var name: String
            var command: Member.Record
            var ok: Bool
            var action: String?
        }
        struct V: Decodable {
            var group_ca: Data
            var records: [Member.Record]
            var `self`: String
            var now_ms: Int64
            var commands: [C]
        }
        let v = try JSONDecoder().decode(V.self, from: Data(contentsOf: url.appendingPathComponent("testdata/interop/v2-actions.json")))
        var set = RecordSet()
        XCTAssertEqual(set.addAll(v.records, groupCA: v.group_ca).count, v.records.count)
        XCTAssertEqual(v.commands.count, 6)
        for c in v.commands {
            switch Result(catching: { try Commands.verify(c.command, records: set, me: v.`self`, nowMS: v.now_ms) }) {
            case let .success(b):
                XCTAssertTrue(c.ok, c.name)
                XCTAssertEqual(b.action, c.action, c.name)
            case let .failure(e):
                XCTAssertFalse(c.ok, "\(c.name): \(e)")
            }
        }
    }

    func testActionCommands() throws {
        let root = SoftwareSigner()
        let ca = try GroupCertificates.groupCA(signer: root, now: now, pathLength: 1)
        let c = try Commands.action(to: pc, name: "reboot", group: GroupCertificates.tag(groupCA: ca), by: pc, now: now, signer: root)
        let b = try JSONDecoder().decode(Commands.Body.self, from: c.body)
        XCTAssertEqual(b.type, "action")
        XCTAssertEqual(b.action, "reboot")
        XCTAssertThrowsError(try Commands.action(to: pc, name: "Reboot now", group: "g", by: pc, now: now, signer: root))
        XCTAssertTrue(Commands.validActionName("cancel-shutdown"))
        for bad in ["", "-x", "1x", "X", String(repeating: "a", count: 33), "a b", "é"] {
            XCTAssertFalse(Commands.validActionName(bad), bad)
        }
    }

    /// The reason of a result is shown to a person: short, without control characters.
    func testCleanReason() {
        XCTAssertEqual(Member.cleanReason("the screen is locked"), "the screen is locked")
        XCTAssertEqual(Member.cleanReason(""), "")
        XCTAssertEqual(Member.cleanReason("a\u{1b}[2Jb\u{1b}]52;c;ZXZpbA==\u{07}c"), "a [2Jb ]52;c;ZXZpbA== c")
        XCTAssertEqual(Member.cleanReason("a\nb\tc\r"), "a b c ")
        XCTAssertEqual(Member.cleanReason("a\u{9b}b"), "a b")
        XCTAssertEqual(Member.cleanReason("écran verrouillé"), "écran verrouillé")
        XCTAssertEqual(Member.cleanReason(String(repeating: "a", count: 1000)).utf8.count, Member.maxReason)
        // A character that would cross the limit goes whole.
        XCTAssertEqual(Member.cleanReason(String(repeating: "a", count: Member.maxReason - 1) + "é"),
                       String(repeating: "a", count: Member.maxReason - 1))
        XCTAssertLessThanOrEqual(Member.cleanReason(String(repeating: "é", count: 300)).utf8.count, Member.maxReason)
    }
}
