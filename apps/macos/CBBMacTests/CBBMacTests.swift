// SPDX-License-Identifier: AGPL-3.0-only

import Carbon.HIToolbox
import SwiftUI
import XCTest
@testable import CBB

final class CBBMacTests: XCTestCase {
    /// A message goes out as the Go service reads it: a JSON line with the
    /// payload's length, then the payload.
    /// A file fetched for a remote paste carries the quarantine mark, as
    /// cbb's own files do.
    func testFetchedFileIsQuarantined() throws {
        XCTAssertEqual(FetchedCopy.quarantine(at: Date(timeIntervalSince1970: 0x654321ab)), "0083;654321ab;CBB;")
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("cbb-mark-\(UUID().uuidString)")
        XCTAssertTrue(FileManager.default.createFile(atPath: url.path, contents: Data("x".utf8)))
        defer { try? FileManager.default.removeItem(at: url) }
        try FetchedCopy.markDownloaded(url)
        var buf = [CChar](repeating: 0, count: 64)
        let n = url.withUnsafeFileSystemRepresentation { getxattr($0!, "com.apple.quarantine", &buf, buf.count, 0, 0) }
        XCTAssertGreaterThan(n, 0)
        XCTAssertTrue(String(cString: Array(buf[0..<max(0, n)]) + [0]).hasPrefix("0083;"))
    }

    func testEncode() throws {
        let data = try Control.encode(.init(op: "copy"), payload: Data("hi".utf8))
        let text = String(decoding: data, as: UTF8.self)
        XCTAssertEqual(text, "{\"args\":{},\"len\":2,\"op\":\"copy\"}\nhi")
    }

    /// An answer is read only once all of it has come, and its devices
    /// keep what the service leaves out as false.
    func testDecode() throws {
        let line = #"{"len":3,"ok":{"devices":[{"id":"ab12","name":"deck","role":"member","caps":["admin","dials","hub"],"os":"linux","online":true,"self":true,"os_version":"Ubuntu 24.04","last_seen_ms":5,"mode":"own"},{"id":"cd34"}]}}"#
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
        XCTAssertTrue(devices[0].can("hub"))
        XCTAssertEqual(devices[0].mode, "own")
        XCTAssertNil(devices[1].mode)
        XCTAssertEqual(devices[1].name, "cd34")
        XCTAssertFalse(devices[1].admin || devices[1].online)
        XCTAssertEqual(devices[1].kind, .desktop)
        XCTAssertEqual(devices[0].systemWithVersion, "Ubuntu 24.04")
    }

    /// The status's reasons why the Mac does not sync read back with their
    /// parameters, and each code the core gives has words of its own.
    func testWhy() throws {
        let json = #"{"device":"me","group":"g","role":"member","version":"dev","why":[{"code":"tunnel_blocked","level":"stop","device":"pi","detail":"no answer"},{"code":"muted","level":"warn","until_ms":1700000000000}]}"#
        let st = try JSONDecoder().decode(Control.Status.self, from: Data(json.utf8))
        let why = try XCTUnwrap(st.why)
        XCTAssertEqual(why.map(\.code), ["tunnel_blocked", "muted"])
        XCTAssertEqual(why[0].device, "pi")
        XCTAssertNotNil(why[1].until)
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<4 { url.deleteLastPathComponent() }
        let data = try Data(contentsOf: url.appendingPathComponent("testdata/why/vectors.json"))
        struct Case: Decodable { var want: [WhyReason] }
        for c in try JSONDecoder().decode([Case].self, from: data) {
            for r in c.want {
                XCTAssertNotEqual(WhyList.title(r), Text(verbatim: r.code), r.code)
            }
        }
    }

    /// A mute goes out with its time as the service reads it, and a muted
    /// device, this Mac's mute and its sync turned off read back; the mute shows an
    /// alert that an admin ends.
    func testMute() throws {
        var h = Control.Header(op: "mute")
        h.forMS = 900_000
        XCTAssertEqual(String(decoding: try Control.encode(h), as: UTF8.self), "{\"args\":{\"for_ms\":900000},\"len\":0,\"op\":\"mute\"}\n")
        let line = #"{"ok":{"status":{"device":"me","role":"member","version":"dev","group":"g","mode":"own","sync_until_ms":1700000000000,"muted":true,"muted_until_ms":0},"devices":[{"id":"ab12","muted":true,"muted_until_ms":1700000000000},{"id":"cd34"}]}}"#
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
        XCTAssertTrue(GroupAlerts.lines(Control.Status(device: "me", group: "g", role: "member", version: "dev")).isEmpty)
        // This Mac itself is unmuted on the plain socket, without the
        // password; another device takes the administrator.
        let own = try XCTUnwrap(MacModel.ownMute("me", on: false, me: "me"))
        XCTAssertEqual(String(decoding: try Control.encode(own), as: UTF8.self), "{\"device\":\"me\",\"len\":0,\"op\":\"unmute\"}\n")
        XCTAssertEqual(MacModel.ownMute("me", on: true, forMS: 60000, me: "me")?.forMS, 60000)
        XCTAssertNil(MacModel.ownMute("ab12", on: false, me: "me"))
        XCTAssertNil(MacModel.ownMute("me", on: false, me: nil))
    }

    /// What cbb pair -app writes reads as the join's code, and its QR code
    /// draws.
    func testJoinCode() throws {
        let line = #"{"qr":"cbb://join?code=123456&addr=192.168.1.20%3A8764&fp=q83vEjRWeJA","expires":300,"port":8764}"#
        let code = try JSONDecoder().decode(MacModel.JoinCode.self, from: Data(line.utf8))
        XCTAssertEqual(code.expires, 300)
        XCTAssertEqual(code.port, 8764)
        XCTAssertTrue(code.qr.hasPrefix("cbb://join?code=123456"))
        XCTAssertEqual(code.digits, "123 456")
        let image = try XCTUnwrap(JoinSheet.qrImage(code.qr))
        XCTAssertGreaterThan(image.size.width, 20)
    }

    /// The status says a bug report waits, and the service's answer to bug
    /// reads as the sheet shows it.
    func testBugOffer() throws {
        let line = #"{"ok":{"status":{"device":"me","role":"member","version":"dev","bug":true}}}"#
        let (header, _, _) = try XCTUnwrap(try Control.decode(Data((line + "\n").utf8)))
        XCTAssertEqual(header.status?.bug, true)
        let body = #"{"report":{"v":1,"details":"panic: boom at member/src/x.rs:1:2","where":"member/src/x.rs:1:2"},"fingerprint":"f","post":"","url":"https://bug.cbb.tools/","action":"ask","offer_always":true,"fixed_in":"0.6.1"}"#
        let o = try XCTUnwrap(MacModel.bugOffer(Data(body.utf8)))
        XCTAssertEqual(o.action, "ask")
        XCTAssertTrue(o.offerAlways)
        XCTAssertEqual(o.fixedIn, "0.6.1")
        XCTAssertEqual(o.details, "panic: boom at member/src/x.rs:1:2")
        XCTAssertTrue(o.report.contains("\"where\" : \"member/src/x.rs:1:2\""), o.report)
        XCTAssertNil(MacModel.bugOffer(Data("{}".utf8)))
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

    /// The six digits a new device shows are typed with or without a space
    /// or a dash between them; anything else is no code.
    func testShownCode() {
        XCTAssertEqual(MacModel.shownCode("123456"), "123456")
        XCTAssertEqual(MacModel.shownCode("123 456"), "123456")
        XCTAssertEqual(MacModel.shownCode("123-456"), "123456")
        XCTAssertNil(MacModel.shownCode("12345"))
        XCTAssertNil(MacModel.shownCode("12a456"))
        XCTAssertNil(MacModel.shownCode("1234567"))
        XCTAssertNil(MacModel.shownCode("١٢٣٤٥٦"), "only ASCII digits")
    }

    /// The update the group passed around reads from the status.
    func testUpdate() throws {
        let line = #"{"ok":{"status":{"device":"me","role":"member","version":"0.5.0","group":"g","update":"0.6.0"}}}"#
        let (header, _, _) = try XCTUnwrap(try Control.decode(Data((line + "\n").utf8)))
        XCTAssertEqual(header.status?.update, "0.6.0")
    }

    func testAdminFailure() {
        XCTAssertEqual(Admin.failure("0:80: execution error: User canceled. (-128)"), .cancelled)
        XCTAssertEqual(
            Admin.failure("0:120: execution error: cbb: no device named nope in the group (1)"),
            .failed("no device named nope in the group", detail: "0:120: execution error: cbb: no device named nope in the group (1)")
        )
    }

    /// cbb runs as the user, with macOS's confirmation, except where it
    /// needs root itself; its exit codes say a cancelled prompt and an
    /// action only the administrator may take.
    func testAdminAsUser() throws {
        XCTAssertTrue(Admin.needsRoot(["update"]))
        XCTAssertTrue(Admin.needsRoot(["pair", "-app", "/tmp/x.json"]))
        XCTAssertFalse(Admin.needsRoot(["pair", "-qr"]))
        XCTAssertFalse(Admin.needsRoot(["remove", "ab12"]))
        XCTAssertEqual(try Admin.userResult(0, printed: "Removed.\n", stderr: ""), .done("Removed."))
        XCTAssertEqual(try Admin.userResult(77, printed: "", stderr: "cbb: only the administrator"), .needsAdmin)
        XCTAssertThrowsError(try Admin.userResult(75, printed: "", stderr: "")) { XCTAssertEqual($0 as? Admin.Failure, .cancelled) }
        XCTAssertThrowsError(try Admin.userResult(1, printed: "", stderr: "cbb: no device \"x\" in the group\n")) {
            XCTAssertEqual($0 as? Admin.Failure, .failed("no device \"x\" in the group", detail: "cbb: no device \"x\" in the group"))
        }
    }

    func testKind() {
        var phone = Control.Device(id: "1", name: "phone", role: "phone", os: "ios")
        XCTAssertEqual(phone.kind, .phone)
        phone.form = "tablet"
        XCTAssertEqual(phone.kind, .tablet)
        XCTAssertEqual(Control.Device(id: "2", name: "mac", os: "macos").kind, .laptop)
        XCTAssertEqual(Control.Device(id: "3", name: "board", os: "none").kind, .board)
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
        XCTAssertEqual(text, "{\"args\":{\"inject\":\"desktop\",\"paste_only\":true},\"len\":0,\"op\":\"watch\"}\n")
        let line = #"{"op":"inject","seq":7,"args":{"method":"type","enter":true,"kind":"secret","name":"pi"}}"#
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

    /// The window draws the member's view: its tiles in order, the
    /// devices in them, and whether the user changed the order; a change
    /// goes out as arrange takes it.
    @MainActor
    func testView() throws {
        let line = #"{"ok":{"view":{"tiles":[{"device":{"id":"me","self":true}},{"device":{"id":"a","online":true}},{"collection":{"id":"c1","name":"Office","devices":[{"id":"b"},{"id":"c"}]}}],"online":1,"others":3,"custom":true}}}"#
        let (header, _, _) = try XCTUnwrap(try Control.decode(Data((line + "\n").utf8)))
        let model = MacModel(defaults: try XCTUnwrap(UserDefaults(suiteName: "cbb-mac-view-test")))
        model.show(status: Control.Status(device: "me", group: "g1", role: "member", version: "dev"), view: try XCTUnwrap(header.view))
        XCTAssertEqual(model.arranged.map(\.id), ["d:me", "d:a", "c:c1"])
        XCTAssertEqual(model.devices.map(\.id), ["me", "a", "b", "c"])
        XCTAssertEqual(model.collection(holding: "c")?.name, "Office")
        XCTAssertTrue(model.customOrder)
        XCTAssertEqual(model.others.count, 3)

        var h = Control.Header(op: "arrange")
        h.arrange = try JSONDecoder().decode(Control.Change.self, from: Arrangement.Op.move(.device("a"), before: .collection("c1")).data)
        let text = String(decoding: try Control.encode(h), as: UTF8.self)
        XCTAssertEqual(text, #"{"args":{"arrange":{"before":{"collection":"c1"},"item":{"device":"a"},"op":"move"}},"len":0,"op":"arrange"}"# + "\n")
    }

    /// Settings fit their sheet: no row reaches past its edges (the language
    /// menu, sized to fit with its label, once widened every row to 608
    /// points and cut the rows' ends off). Laid out with a build's long
    /// version in a window that is never shown.
    @MainActor
    func testSettingsFit() throws {
        let model = MacModel(defaults: try XCTUnwrap(UserDefaults(suiteName: "cbb-mac-settings-test")))
        let version = "cbb v0.5.1-0.20261109114050-97499ee40fb3 darwin/arm64 with a longer tail"
        model.show(status: Control.Status(device: "me", group: "g1", role: "member", version: version), devices: [])
        let host = NSHostingView(rootView: SettingsView().environmentObject(model).modifier(Themed()))
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 800, height: 900), styleMask: [.titled], backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false
        window.contentView = host
        host.frame = NSRect(origin: .zero, size: host.fittingSize)
        host.layoutSubtreeIfNeeded()
        // Lists lay their rows out a turn later.
        RunLoop.main.run(until: Date().addingTimeInterval(0.3))
        host.layoutSubtreeIfNeeded()
        XCTAssertLessThanOrEqual(host.fittingSize.width, 460.5)
        var views: [NSView] = [host]
        var checked = 0
        while let v = views.popLast() {
            views += v.subviews
            guard !v.isHidden, v !== host, v.frame.width > 0 else { continue }
            let f = v.convert(v.bounds, to: host)
            XCTAssertGreaterThanOrEqual(f.minX, -0.5, "\(type(of: v)) starts left of Settings at \(f)")
            XCTAssertLessThanOrEqual(f.maxX, host.bounds.width + 0.5, "\(type(of: v)) ends right of Settings at \(f)")
            checked += 1
        }
        XCTAssertGreaterThan(checked, 3, "Settings laid out no views")
        window.contentView = nil
        window.close()
    }
}
