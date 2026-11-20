// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

@testable import CBBKit
import Foundation
import XCTest

/// The 0.6 member's group, notices, "who stays" list and events, read from
/// testdata/interop/member-group.json, which the Kotlin kit reads too.
final class GroupStateTests: XCTestCase {
    struct V: Decodable {
        var group: GroupState
        var notices: [Notice]
        var preview: ChangePreview
    }

    private var url: URL {
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<6 { url.deleteLastPathComponent() }
        return url.appendingPathComponent("testdata/interop/member-group.json")
    }

    func testGroup() throws {
        let g = try JSONDecoder().decode(V.self, from: Data(contentsOf: url)).group
        XCTAssertEqual(g.group, "q83vEjRWeJCrze8SNFZ4kA==")
        XCTAssertEqual(g.rootDevice, "AQEBAQEBAQEBAQEBAQEBAQ==")
        XCTAssertEqual(g.me.admin, "phone")
        XCTAssertFalse(g.isRoot)
        XCTAssertEqual(g.stop, "secrets")
        XCTAssertFalse(g.stopped)
        XCTAssertTrue(g.tooOld)
        XCTAssertTrue(g.changeArriving)
        XCTAssertFalse(g.updateNeeded)
        XCTAssertEqual(g.devices.map(\.name), ["Root phone", "Pixel", "Desk", "Old laptop"])
        XCTAssertEqual(g.devices.map(\.removedBy), ["", "", "", "root"])
        XCTAssertTrue(g.devices[2].frozen && g.devices[2].hub)
        var r = g
        r.me.device = g.rootDevice
        XCTAssertTrue(r.isRoot)
    }

    func testNotices() throws {
        let ns = try JSONDecoder().decode(V.self, from: Data(contentsOf: url)).notices
        XCTAssertEqual(ns.map(\.kind), ["admins_silent", "change_arriving", "root_room_waiting"])
        XCTAssertEqual(ns[0].args["days_left"], "5")
        XCTAssertEqual(ns.map(\.dismissable), [true, false, true])
        XCTAssertEqual(ns[2].args["percent"], "72")
    }

    func testPreview() throws {
        let p = try JSONDecoder().decode(V.self, from: Data(contentsOf: url)).preview
        XCTAssertTrue(p.waiting)
        XCTAssertEqual(p.rows.map(\.outcome), ["out", "admin_kept", "stays", "removed_earlier"])
        XCTAssertEqual(p.rows.map(\.frozen), [false, false, true, false])
    }

    func testEvents() throws {
        let top = try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as! [String: Any]
        let events = top["events"] as! [String: Any]
        func ev(_ name: String) throws -> CoreMember.Event? {
            CoreMember.event(try JSONSerialization.data(withJSONObject: events[name]!))
        }
        guard case let .state(s)? = try ev("state") else { return XCTFail("state") }
        XCTAssertTrue(s.halted && s.stopped)
        guard case let .notice(n)? = try ev("notice") else { return XCTFail("notice") }
        XCTAssertEqual(n.kind, "recovery_not_saved")
        guard case let .rootChanged(from, to, seq)? = try ev("root_changed") else { return XCTFail("root_changed") }
        XCTAssertEqual(from, "AQEBAQEBAQEBAQEBAQEBAQ==")
        XCTAssertEqual(to, "AgICAgICAgICAgICAgICAg==")
        XCTAssertEqual(seq, 2)
        guard case let .needKey(token, kind)? = try ev("need_key") else { return XCTFail("need_key") }
        XCTAssertEqual(token, 7)
        XCTAssertEqual(kind, "spare_admin")
        guard case let .keyDone(pub)? = try ev("key_done") else { return XCTFail("key_done") }
        XCTAssertEqual(pub, Data([4, 0, 1]))
        // A write event's kind still reads as the copy's kind.
        guard case let .write(_, k, _)? = CoreMember.event(Data(#"{"type":"write","text":"x","kind":"media"}"#.utf8)) else { return XCTFail("write") }
        XCTAssertEqual(k, .media)
    }

    func testRecoveryInput() throws {
        let e = JSONEncoder()
        e.outputFormatting = .sortedKeys
        XCTAssertEqual(String(decoding: try e.encode(RecoveryInput.qr("CBBR1X")), as: UTF8.self), #"{"qr":"CBBR1X"}"#)
        XCTAssertEqual(String(decoding: try e.encode(RecoveryInput.text("ABCD")), as: UTF8.self), #"{"text":"ABCD"}"#)
        XCTAssertEqual(String(decoding: try e.encode(RecoveryInput.secret(Data([1, 2]))), as: UTF8.self), #"{"secret":"AQI="}"#)
    }
}
