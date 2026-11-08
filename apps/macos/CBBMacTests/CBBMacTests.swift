// SPDX-License-Identifier: AGPL-3.0-only

import Carbon.HIToolbox
import XCTest
@testable import CBB

final class CBBMacTests: XCTestCase {
    /// A message goes out as the Go service reads it: a JSON line with the
    /// payload's length, then the payload.
    func testEncode() throws {
        let data = try Control.encode(.init(op: "copy"), payload: Data("hi".utf8))
        let text = String(decoding: data, as: UTF8.self)
        XCTAssertEqual(text, "{\"len\":2,\"op\":\"copy\"}\nhi")
    }

    /// An answer is read only once all of it has come, and its devices
    /// keep what the service leaves out as false.
    func testDecode() throws {
        let line = #"{"op":"reply","len":3,"devices":[{"id":"ab12","name":"deck","role":"full","os":"linux","online":true,"self":true,"os_version":"Ubuntu 24.04","last_seen_ms":5,"mode":"own"},{"id":"cd34"}]}"#
        let whole = Data((line + "\nxyz").utf8)
        XCTAssertNil(try Control.decode(whole.prefix(10)))
        XCTAssertNil(try Control.decode(whole.dropLast()))
        let (header, body, used) = try XCTUnwrap(try Control.decode(whole + Data("more".utf8)))
        XCTAssertEqual(body, Data("xyz".utf8))
        XCTAssertEqual(used, whole.count)
        let devices = try XCTUnwrap(header.devices)
        XCTAssertEqual(devices[0].osVersion, "Ubuntu 24.04")
        XCTAssertTrue(devices[0].online && devices[0].isSelf)
        XCTAssertEqual(devices[0].lastSeenMS, 5)
        XCTAssertEqual(devices[0].mode.flatMap(SyncMode.init(rawValue:)), .own)
        XCTAssertNil(devices[1].mode)
        XCTAssertEqual(devices[1].name, "cd34")
        XCTAssertFalse(devices[1].admin || devices[1].online)
        XCTAssertEqual(devices[1].kind, .desktop)
        XCTAssertEqual(devices[0].systemWithVersion, "Ubuntu 24.04")
    }

    /// A mute goes out with its time as the service reads it, and a muted
    /// device, this Mac's mute and its sync turned off read back; the mute shows an
    /// alert that an admin ends.
    func testMute() throws {
        var h = Control.Header(op: "mute")
        h.forMS = 900_000
        XCTAssertEqual(String(decoding: try Control.encode(h), as: UTF8.self), "{\"for_ms\":900000,\"len\":0,\"op\":\"mute\"}\n")
        let line = #"{"op":"reply","status":{"device":"me","role":"full","version":"dev","group":"g","mode":"own","sync_until_ms":1700000000000,"muted":true,"muted_until_ms":0},"devices":[{"id":"ab12","muted":true,"muted_until_ms":1700000000000},{"id":"cd34"}]}"#
        let (header, _, _) = try XCTUnwrap(try Control.decode(Data((line + "\n").utf8)))
        let st = try XCTUnwrap(header.status)
        XCTAssertEqual(st.muted, true)
        XCTAssertNil(MacModel.date(ms: st.mutedUntilMS))
        XCTAssertEqual(st.mode, "own")
        XCTAssertEqual(MacModel.date(ms: st.syncUntilMS)?.timeIntervalSince1970, 1_700_000_000)
        let devices = try XCTUnwrap(header.devices)
        XCTAssertTrue(devices[0].muted)
        XCTAssertEqual(devices[0].mutedUntilMS, 1_700_000_000_000)
        XCTAssertFalse(devices[1].muted)
        let alerts = GroupAlerts.lines(st)
        XCTAssertEqual(alerts.count, 1)
        XCTAssertTrue(alerts[0].unmute)
        XCTAssertTrue(GroupAlerts.lines(Control.Status(device: "me", group: "g", role: "full", version: "dev")).isEmpty)
    }

    /// What cbb pair -app writes reads as the join's code, and its QR code
    /// draws.
    func testJoinCode() throws {
        let line = #"{"qr":"cbb://join?code=123456&addr=192.168.1.20%3A8764&fp=q83vEjRWeJA","expires":300,"port":8764}"#
        let code = try JSONDecoder().decode(MacModel.JoinCode.self, from: Data(line.utf8))
        XCTAssertEqual(code.expires, 300)
        XCTAssertEqual(code.port, 8764)
        XCTAssertTrue(code.qr.hasPrefix("cbb://join?code=123456"))
        let image = try XCTUnwrap(JoinSheet.qrImage(code.qr))
        XCTAssertGreaterThan(image.size.width, 20)
    }

    func testBadHeader() {
        XCTAssertThrowsError(try Control.decode(Data("not json\n".utf8)))
        XCTAssertThrowsError(try Control.decode(Data(repeating: 0x41, count: Control.maxHeader + 1)))
    }

    /// Every argument reaches cbb as one word, whatever a name holds.
    func testShellCommand() {
        let line = Admin.shellCommand("/usr/local/bin/cbb", ["rename", "ab12", "Bob's \"Mac\" $(x)"], answer: false, details: true)
        XCTAssertEqual(line, #"CBB_DEBUG=1 '/usr/local/bin/cbb' 'rename' 'ab12' 'Bob'\''s "Mac" $(x)'"#)
        XCTAssertEqual(Admin.shellCommand("/usr/local/bin/cbb", ["global", "on"], answer: true, details: false), "echo yes | '/usr/local/bin/cbb' 'global' 'on'")
        XCTAssertEqual(Admin.appleScript(shell: #"a "b" \c"#), #"do shell script "a \"b\" \\c" with administrator privileges"#)
        // cbb pair -qr reads the code from a file, never from the command line.
        XCTAssertEqual(Admin.shellCommand("/usr/local/bin/cbb", ["pair", "-qr"], answer: false, input: "/tmp/in's.txt", details: false),
                       #"'/usr/local/bin/cbb' 'pair' '-qr' < '/tmp/in'\''s.txt'"#)
    }

    /// Only the QR code of a device that listens, with its address and
    /// fingerprint, is admitted from the app.
    func testWaitingJoiner() {
        XCTAssertTrue(MacModel.isWaitingJoiner("cbb://join?code=123456&addr=192.0.2.7:8764&fp=AbC%2Bd%2F0="))
        XCTAssertFalse(MacModel.isWaitingJoiner("cbb://join?code=123456"))
        XCTAssertFalse(MacModel.isWaitingJoiner("https://cbb.tools/join?code=1&addr=a:1&fp=x"))
        XCTAssertFalse(MacModel.isWaitingJoiner(""))
    }

    func testAdminFailure() {
        XCTAssertEqual(Admin.failure("0:80: execution error: User canceled. (-128)"), .cancelled)
        XCTAssertEqual(
            Admin.failure("0:120: execution error: cbb: no device named nope in the group (1)"),
            .failed("no device named nope in the group", detail: "0:120: execution error: cbb: no device named nope in the group (1)")
        )
    }

    func testKind() {
        var phone = Control.Device(id: "1", name: "phone", role: "phone", os: "ios")
        XCTAssertEqual(phone.kind, .phone)
        phone.form = "tablet"
        XCTAssertEqual(phone.kind, .tablet)
        XCTAssertEqual(Control.Device(id: "2", name: "mac", os: "macos").kind, .laptop)
        XCTAssertEqual(Control.Device(id: "3", name: "pi", role: "lite").kind, .board)
    }

    func testOrbitSpots() {
        let spots = OrbitView.spots(count: 8, radii: [10, 20], center: .zero)
        XCTAssertEqual(spots.count, 8)
        XCTAssertEqual(spots[0].x, 0, accuracy: 1e-9)
        XCTAssertEqual(spots[0].y, -10, accuracy: 1e-9)
    }

    /// The watch request of the paste target names its target and that it
    /// holds no clipboard, as the service reads them.
    func testWatchRequest() throws {
        var h = Control.Header(op: "watch")
        h.inject = "desktop"
        h.pasteOnly = true
        let text = String(decoding: try Control.encode(h), as: UTF8.self)
        XCTAssertEqual(text, "{\"inject\":\"desktop\",\"len\":0,\"op\":\"watch\",\"paste_only\":true}\n")
        let line = #"{"op":"inject","seq":7,"method":"type","enter":true,"kind":"secret","name":"pi"}"#
        let (m, _, _) = try XCTUnwrap(try Control.decode(Data((line + "\n").utf8)))
        XCTAssertEqual(m.seq, 7)
        XCTAssertEqual(m.method, "type")
        XCTAssertEqual(m.enter, true)
        XCTAssertEqual(m.name, "pi")
    }

    /// Typing makes Return and Tab keys, and Unicode events of at most 20
    /// units that never split a surrogate pair.
    func testStrokes() {
        let strokes = Injector.strokes(for: "ab\n\tc")
        XCTAssertEqual(strokes, [.text(Array("ab".utf16)), .key(CGKeyCode(kVK_Return)), .key(CGKeyCode(kVK_Tab)), .text(Array("c".utf16))])
        let long = String(repeating: "x", count: 19) + "\u{1F600}"
        let split = Injector.strokes(for: long)
        XCTAssertEqual(split, [.text(Array(String(repeating: "x", count: 19).utf16)), .text(Array("\u{1F600}".utf16))])
        XCTAssertTrue(Injector.strokes(for: "").isEmpty)
    }

    /// The window's arrangement: the group's order, this Mac first, until
    /// the user changes it, kept for the group's tag, pruned once the list is whole, and a
    /// change that does not fit says so.
    @MainActor
    func testArrangement() throws {
        let defaults = try XCTUnwrap(UserDefaults(suiteName: "cbb-mac-arrange-test"))
        defaults.removePersistentDomain(forName: "cbb-mac-arrange-test")
        let model = MacModel(defaults: defaults)
        // CBB's Control, not Carbon's.
        func device(_ id: String, me: Bool = false) -> CBB.Control.Device {
            var d = Control.Device(id: id, name: id, role: "full")
            d.isSelf = me
            return d
        }
        let status = Control.Status(device: "me", group: "g1", role: "full", version: "dev")
        model.show(status: status, devices: [device("me", me: true), device("a"), device("b"), device("c")])
        XCTAssertEqual(model.arranged.map(\.id), ["d:me", "d:a", "d:b", "d:c"])
        XCTAssertNil(defaults.data(forKey: MacModel.arrangementKey))
        XCTAssertTrue(model.arrange(.new(name: "Office", devices: ["b", "c"])))
        XCTAssertEqual(model.arranged.map(\.id), ["d:me", "d:a", "c:c1"])
        XCTAssertEqual(model.collection(holding: "c")?.name, "Office")
        XCTAssertFalse(model.arrange(.rename(collection: "c1", name: String(repeating: "x", count: 65))))
        XCTAssertNotNil(model.message)
        // b leaves the group: the stored arrangement drops it.
        model.show(status: status, devices: [device("me", me: true), device("a"), device("c")])
        XCTAssertEqual(model.collection("c1")?.0.devices, ["c"])
        let stored = Arrangement.decode(defaults.data(forKey: MacModel.arrangementKey), group: "g1")
        XCTAssertEqual(stored.items.count, 3)
        // Another group starts afresh.
        model.show(status: Control.Status(device: "me", group: "g2", role: "full", version: "dev"), devices: [device("me", me: true), device("a")])
        XCTAssertEqual(model.arranged.map(\.id), ["d:me", "d:a"])
        defaults.removePersistentDomain(forName: "cbb-mac-arrange-test")
    }
}
