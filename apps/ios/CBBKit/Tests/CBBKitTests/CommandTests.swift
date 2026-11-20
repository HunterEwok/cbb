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
        let h = try Member.decode(body: Data(#"{"t":"hello","role":"member","hello":{"wall_ms":1,"mode":"receive"}}"#.utf8))
        guard case let .hello(_, hello) = h else { return XCTFail("not a hello") }
        XCTAssertEqual(hello.mode, "receive")
        let odd = try Member.decode(body: Data(#"{"t":"hello","role":"member","hello":{"wall_ms":1,"mode":"everything"}}"#.utf8))
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
        // A paste of images or files names the copy by its event ID and is never typed.
        let copy = "00112233445566778899aabbccddeeff"
        let media = try JSONDecoder().decode(Commands.Body.self, from: Commands.paste(to: pc, text: copy, kind: "media", group: "tag",
                                                                                      by: pc, now: now, signer: root).body)
        XCTAssertEqual(media.kind, "media")
        XCTAssertEqual(media.mode, "paste")
        XCTAssertEqual(media.text, copy)
        XCTAssertThrowsError(try Commands.paste(to: pc, text: copy, method: "type", kind: "media", group: "tag", by: pc, now: now, signer: root))
        XCTAssertThrowsError(try Commands.paste(to: pc, text: "photo.png", kind: "media", group: "tag", by: pc, now: now, signer: root))
        XCTAssertThrowsError(try Commands.paste(to: pc, text: copy.uppercased(), kind: "media", group: "tag", by: pc, now: now, signer: root))
        XCTAssertThrowsError(try Commands.paste(to: pc, text: "x", kind: "file", group: "tag", by: pc, now: now, signer: root))
        let off = try JSONDecoder().decode(Commands.Body.self, from: Commands.pasteOff(to: pc, group: "tag", by: pc, now: now, signer: root).body)
        XCTAssertEqual(off.type, "paste-off")
        XCTAssertNil(off.text)
    }

    /// A phone group signs a paste of a copy of images or files with its
    /// root key, and the device it names takes it.
    func testPhoneGroupPasteCopyCommand() throws {
        let rootKey = SoftwareSigner()
        let g = try PhoneGroup.create(caSigner: rootKey, memberKey: SoftwareSigner().publicKeyDER, now: now)
        let copy = "00112233445566778899aabbccddeeff"
        let b = try Commands.verify(try g.pasteCopyCommand(to: pc, copyID: copy, enter: true, caSigner: rootKey, now: now),
                                    records: g.records, me: pc, nowMS: Records.ms(now))
        XCTAssertEqual(b.type, "paste")
        XCTAssertEqual(b.mode, "paste")
        XCTAssertEqual(b.kind, "media")
        XCTAssertEqual(b.text, copy)
        XCTAssertEqual(b.enter, true)
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

    /// A phone that is not connected to a command's receiver sends it to an
    /// admin phone it is connected to, the hub, which passes it on once
    /// (docs/protocol.md, section 15); the result comes back the same way.
    func testCommandPassedOn() async throws {
        let t = try CoreGroup(3, test: self)
        let (hub, a, b) = (t.phones[0], t.phones[1], t.phones[2])
        try await t.connect(1, to: 0)
        try await t.connect(2, to: 0)
        let c = try t.g.modeCommand(to: b.device, mode: "own", caSigner: t.ca, now: Date())
        async let result = a.member.command(c)
        let (token, from) = try await b.next("the command") { e -> (UInt64, String)? in
            if case let .command(token, from, _) = e { return (token, from) }
            return nil
        }
        XCTAssertEqual(from, hub.device)
        try b.member.answer(token, result: .init(id: "", status: "done"))
        let r = try await result
        XCTAssertEqual(r.status, "done")
        XCTAssertEqual(r.by, b.device)
        XCTAssertTrue(hub.all { if case .command = $0 { return true }; return nil }.isEmpty, "the hub does not take it itself")
        // The same command is not passed on again, not even after its
        // result went back: the receiver's cache is only a backstop.
        do {
            _ = try await a.member.command(c, timeout: .seconds(1))
            XCTFail("the hub passed the same command on twice")
        } catch CoreMember.Failure.timedOut {}
        XCTAssertEqual(b.all { if case .command = $0 { return true }; return nil }.count, 1)
    }

    /// A command goes to its receiver, whose app answers; a device that is
    /// not connected, with no hub between, gets nothing.
    func testCommandRoundTrip() async throws {
        let t = try CoreGroup(test: self)
        let (a, b) = (t.phones[0], t.phones[1])
        try await t.connect(1, to: 0)
        // Signed as it is sent, as an admin's app signs it: the member checks
        // a command before its app gets it, and `now` is as old as the suite.
        let c = try t.g.modeCommand(to: b.device, mode: "own", caSigner: t.ca, now: Date())
        async let result = a.member.command(c)
        let token = try await b.next("the command") { if case let .command(token, _, _) = $0 { return token }; return nil }
        try b.member.answer(token, result: .init(id: "", status: "refused", reason: "not now"))
        let r = try await result
        XCTAssertEqual(r.id, Commands.id(of: c))
        XCTAssertEqual(r.status, "refused")
        XCTAssertEqual(r.reason, "not now")
        // An expired one the member refuses itself; the app never sees it.
        let expired = try t.g.modeCommand(to: b.device, mode: "own", caSigner: t.ca, now: Date().addingTimeInterval(-60))
        let old = try await a.member.command(expired)
        XCTAssertEqual(old.status, "refused")
        XCTAssertEqual(b.all { if case .command = $0 { return true }; return nil }.count, 1)
        let other = try t.g.modeCommand(to: Member.newID(), mode: "own", caSigner: t.ca, now: Date())
        do {
            _ = try await a.member.command(other)
            XCTFail("sent to a device that is not connected")
        } catch CoreMember.Failure.notConnected {}
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
            try Commands.mute(to: pc, forMS: 3_600_000, group: tag, by: adminBy, now: now, signer: admin, adminCA: adminCA),
            try Commands.unmute(to: pc, group: tag, by: by, now: now, signer: root),
            try Commands.paste(to: pc, text: "00112233445566778899aabbccddeeff", kind: "media", group: tag, by: adminBy, now: now,
                               signer: admin, adminCA: adminCA),
        ])
        // The eighth is sealed, for Go to open: a phone opens none.
        for (i, c) in out.commands.enumerated() where i != 7 {
            XCTAssertNoThrow(try Commands.verify(c, records: set, me: pc, nowMS: Records.ms(now)))
        }
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

    /// A mute command carries its time, and none for until an unmute; a
    /// time past 30 days is refused. The hello carries a mute and reads a
    /// time out of range as 30 days, as Go does.
    func testMute() throws {
        let root = SoftwareSigner()
        let tag = "0123456789abcdef", by = "0123456789abcdef0123456789abcdef"
        for (ms, want) in [(Int64(900_000), Int64(900_000)), (0, nil)] {
            let c = try Commands.mute(to: pc, forMS: ms, group: tag, by: by, now: now, signer: root)
            XCTAssertEqual(try Commands.parse(c.body).for_ms, want)
        }
        XCTAssertThrowsError(try Commands.mute(to: pc, forMS: Commands.maxMuteMS + 1, group: tag, by: by, now: now, signer: root))
        XCTAssertNil(try Commands.parse(try Commands.unmute(to: pc, group: tag, by: by, now: now, signer: root).body).for_ms)

        var hello = Member.Hello(wallMS: 1)
        (hello.muted, hello.mutedForMS) = (true, 60_000)
        let h = try Member.encode(.hello(.phone, hello))
        XCTAssertEqual(try Member.decode(body: h.dropFirst(4)), .hello(.phone, hello))
        let none = try Member.encode(.hello(.phone, Member.Hello(wallMS: 1)))
        XCTAssertFalse(String(decoding: none.dropFirst(4), as: UTF8.self).contains("muted"))
        let long = Data(#"{"t":"hello","role":"member","hello":{"wall_ms":1,"muted":true,"muted_for_ms":99999999999}}"#.utf8)
        guard case let .hello(_, got) = try Member.decode(body: long) else { return XCTFail("no hello") }
        XCTAssertTrue(got.muted)
        XCTAssertEqual(got.mutedForMS, Commands.maxMuteMS)
    }

    /// Each command the root phone signs for a device of its group is
    /// sealed to that device, opens with its secret and passes its checks,
    /// with the fields of its kind.
    func testPhoneGroupCommands() throws {
        var t = try CoreGroup(test: self)
        let to = t.phones[1].device
        func open(_ c: Member.Record, me: String? = nil) throws -> Commands.Body {
            try Commands.verify(c, records: t.g.records, me: me ?? to, nowMS: Records.ms(Date()), secret: CoreGroup.seal)
        }
        let paste = try open(t.g.pasteCommand(to: to, text: "hello", method: "type", enter: true, secret: true, caSigner: t.ca, now: Date()))
        XCTAssertEqual([paste.type, paste.mode, paste.kind, paste.text], ["paste", "type", "secret", "hello"])
        XCTAssertEqual(paste.enter, true)
        XCTAssertEqual(paste.to, to)
        XCTAssertEqual(paste.by, t.g.device)
        let plain = try open(t.g.pasteCommand(to: to, text: "x", method: "paste", enter: false, secret: false, caSigner: t.ca, now: Date()))
        XCTAssertEqual(plain.kind, "text")
        let action = try open(t.g.actionCommand(to: to, name: "lock", caSigner: t.ca, now: Date()))
        XCTAssertEqual([action.type, action.action], ["action", "lock"])
        XCTAssertEqual(try open(t.g.actionsOffCommand(to: to, caSigner: t.ca, now: Date())).type, "actions-off")
        let mute = try open(t.g.muteCommand(to: to, forMS: 60_000, caSigner: t.ca, now: Date()))
        XCTAssertEqual(mute.type, "mute")
        XCTAssertEqual(mute.for_ms, 60_000)
        XCTAssertEqual(try open(t.g.unmuteCommand(to: to, caSigner: t.ca, now: Date())).type, "unmute")
        // A hub command goes only to a device of the hub order: not to a
        // plain phone, but to a computer the root marked forward-only, which
        // is left out of its own clients.
        let pc = Member.newID(), pcKey = SoftwareSigner()
        _ = try t.g.record(device: pc, name: "pi", role: "member", caps: Records.caps, os: "linux", key: Records.keyHash(spki: pcKey.publicKeyDER),
                           store: Records.file, seal: try Core.sealPublic(CoreGroup.seal), caSigner: t.ca, now: Date())
        let clients = [PhoneHub.Client(device: pc, key: Data(repeating: 1, count: 32), psk: Data(repeating: 2, count: 32)),
                       PhoneHub.Client(device: to, key: Data(repeating: 3, count: 32), psk: Data(repeating: 4, count: 32))]
        XCTAssertThrowsError(try t.g.hubCommand(to: to, forwarder: nil, clients: clients, caSigner: t.ca, now: Date()))
        XCTAssertThrowsError(try t.g.hubCommand(to: pc, forwarder: nil, clients: clients, caSigner: t.ca, now: Date()))
        XCTAssertNotNil(try t.g.markForwardOnly(device: pc, caSigner: t.ca, now: Date()))
        XCTAssertTrue(t.g.records.mayHost(pc))
        let hub = try open(t.g.hubCommand(to: pc, forwarder: ("203.0.113.9:8764", "AAAA"), clients: clients, caSigner: t.ca, now: Date()), me: pc)
        XCTAssertEqual(hub.type, "hub")
        XCTAssertEqual(hub.hub?.clients, [clients[1]])
        XCTAssertEqual(hub.hub?.forwarder?.endpoint, "203.0.113.9:8764")
        XCTAssertThrowsError(try t.g.hubCommand(to: Member.newID(), forwarder: nil, clients: [], caSigner: t.ca, now: Date()))
    }

    /// A computer the core admitted is noted once, with its home addresses;
    /// a claim the core dropped leaves the phone.
    func testNotesComputersAndDropsClaims() throws {
        var g = try CoreGroup(test: self).g
        let pc = Member.newID()
        g.noteComputer(device: pc, name: "Old", os: "linux", addrs: ["192.168.0.2:3276"], now: Date())
        g.noteComputer(device: pc, name: "PC", os: "linux", addrs: ["192.168.0.3:3276", "203.0.113.1:3276"], now: Date())
        let noted = g.computers.filter { $0.device == pc }
        XCTAssertEqual(noted.map(\.name), ["PC"])
        XCTAssertEqual(noted.first?.addrs, ["192.168.0.3:3276"])
        (g.claim, g.claimedFrom) = (Data([1]), pc)
        g.dropClaim()
        XCTAssertNil(g.claim)
        XCTAssertNil(g.claimedFrom)
    }
}
